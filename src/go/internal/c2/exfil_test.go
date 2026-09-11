package c2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type exfilHarness struct {
	t         *testing.T
	dir       string
	files     *FileManager
	resumes   []string // "id:offset" requests fired
	assembler *ExfilAssembler
}

func newExfilHarness(t *testing.T) *exfilHarness {
	t.Helper()
	dir := t.TempDir()
	h := &exfilHarness{
		t:     t,
		dir:   dir,
		files: NewFileManager(dir),
	}
	h.assembler = NewExfilAssembler(dir, h.files, func(sessionID, transferID string, offset int64) {
		h.resumes = append(h.resumes, fmt.Sprintf("%s:%d", transferID, offset))
	})
	return h
}

func (h *exfilHarness) b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func (h *exfilHarness) expectFile(t *testing.T, name, content string) {
	t.Helper()
	path := filepath.Join(h.dir, "sess1", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("finalized file %s: %v", path, err)
	}
	if string(data) != content {
		t.Fatalf("content mismatch: got %q want %q", data, content)
	}
	recs := h.files.List()
	found := false
	for _, r := range recs {
		if r.Filename == name && r.SessionID == "sess1" && r.Size == int64(len(content)) {
			found = true
		}
	}
	if !found {
		t.Fatalf("file record for %s not registered", name)
	}
}

func TestExfilHappyPath(t *testing.T) {
	h := newExfilHarness(t)
	id := "abcdef0123456789"

	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_begin:%s:11:data.bin", id))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:0:%s", id, h.b64("hello ")))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:6:%s", id, h.b64("world")))
	sum := sha256.Sum256([]byte("hello world"))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_end:%s:%s", id, hex.EncodeToString(sum[:])))

	h.expectFile(t, "data.bin", "hello world")
	if len(h.resumes) != 0 {
		t.Fatalf("unexpected resume requests: %v", h.resumes)
	}
}

func TestExfilResumeOnGap(t *testing.T) {
	h := newExfilHarness(t)
	id := "abcdef0123456789"

	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_begin:%s:11:data.bin", id))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:0:%s", id, h.b64("hello ")))
	// Agent skipped ahead: gap at offset 6 → resume must be requested.
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:9:%s", id, h.b64("rld")))
	if len(h.resumes) != 1 || !strings.HasPrefix(h.resumes[0], id+":6") {
		t.Fatalf("expected resume request at offset 6, got %v", h.resumes)
	}
	// Agent continues from the server offset.
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:6:%s", id, h.b64("wor")))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:9:%s", id, h.b64("ld")))
	sum := sha256.Sum256([]byte("hello world"))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_end:%s:%s", id, hex.EncodeToString(sum[:])))

	h.expectFile(t, "data.bin", "hello world")
}

func TestExfilIncompleteEndKeepsPartialAndAsksResume(t *testing.T) {
	h := newExfilHarness(t)
	id := "abcdef0123456789"

	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_begin:%s:11:data.bin", id))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:0:%s", id, h.b64("hello ")))
	sum := sha256.Sum256([]byte("hello world"))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_end:%s:%s", id, hex.EncodeToString(sum[:])))

	// Nothing finalized, resume requested at offset 6, partial kept.
	if len(h.resumes) != 1 || !strings.HasPrefix(h.resumes[0], id+":6") {
		t.Fatalf("expected resume request at 6, got %v", h.resumes)
	}
	if _, err := os.Stat(filepath.Join(h.dir, ".parts", id+".part")); err != nil {
		t.Fatalf("partial must survive incomplete end: %v", err)
	}
}

func TestExfilHashMismatchDropsTransfer(t *testing.T) {
	h := newExfilHarness(t)
	id := "abcdef0123456789"

	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_begin:%s:5:data.bin", id))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:0:%s", id, h.b64("hello")))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_end:%s:%s", id, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))

	if _, err := os.Stat(filepath.Join(h.dir, "sess1", "data.bin")); err == nil {
		t.Fatal("corrupted transfer must not be finalized")
	}
	if _, err := os.Stat(filepath.Join(h.dir, ".parts", id+".part")); err == nil {
		t.Fatal("corrupted partial must be removed")
	}
}

func TestExfilServerRestartResumesFromPart(t *testing.T) {
	dir := t.TempDir()
	files := NewFileManager(dir)
	var resumes []string

	a1 := NewExfilAssembler(dir, files, func(sid, id string, off int64) {
		resumes = append(resumes, fmt.Sprintf("%s:%d", id, off))
	})
	id := "abcdef0123456789"
	a1.HandleOutput("sess1", fmt.Sprintf("file_begin:%s:11:data.bin", id))
	a1.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:0:%s", id, base64.StdEncoding.EncodeToString([]byte("hello "))))

	// "Restart": new assembler over the same directory.
	a2 := NewExfilAssembler(dir, files, func(sid, id2 string, off int64) {
		resumes = append(resumes, fmt.Sprintf("%s:%d", id2, off))
	})
	// Agent re-sends begin after reconnect.
	a2.HandleOutput("sess1", fmt.Sprintf("file_begin:%s:11:data.bin", id))
	// No resume request yet (begin does not ask unless offset>0 was detected...
	// actually the assembler asks immediately when it revives a partial).
	if len(resumes) == 0 || !strings.HasPrefix(resumes[0], id+":6") {
		t.Fatalf("expected revived partial to request resume at 6, got %v", resumes)
	}
	// Agent continues at 6.
	a2.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:6:%s", id, base64.StdEncoding.EncodeToString([]byte("world"))))
	sum := sha256.Sum256([]byte("hello world"))
	a2.HandleOutput("sess1", fmt.Sprintf("file_end:%s:%s", id, hex.EncodeToString(sum[:])))

	path := filepath.Join(dir, "sess1", "data.bin")
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "hello world" {
		t.Fatalf("resumed file wrong: %q err=%v", data, err)
	}
}

func TestExfilSanitizesFilenames(t *testing.T) {
	h := newExfilHarness(t)
	id := "abcdef0123456789"

	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_begin:%s:5:../../etc/passwd", id))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:0:%s", id, h.b64("hello")))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_end:%s:-", id))

	// filepath.Base neutralizes traversal; the file must land inside the
	// session dir, and no loot/escape may exist.
	h.expectFile(t, "passwd", "hello")
	if _, err := os.Stat(filepath.Join(h.dir, "etc")); err == nil {
		t.Fatal("traversal filename escaped the loot dir")
	}
}

func TestExfilRejectsBadIDsAndSizes(t *testing.T) {
	h := newExfilHarness(t)

	// Invalid transfer id chars
	h.assembler.HandleOutput("sess1", "file_begin:../evil:5:x.bin")
	h.assembler.HandleOutput("sess1", "file_begin:"+strings.Repeat("a", 100)+":5:x.bin")
	// Negative / garbage size
	h.assembler.HandleOutput("sess1", "file_begin:abcdef0123456789:-5:x.bin")
	h.assembler.HandleOutput("sess1", "file_begin:abcdef0123456789:notanumber:x.bin")
	// Chunk without begin
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:abcdef0123456789:0:%s", h.b64("orphan")))

	if recs := h.files.List(); len(recs) != 0 {
		t.Fatalf("nothing should be registered, got %v", recs)
	}
	entries, _ := os.ReadDir(filepath.Join(h.dir, ".parts"))
	if len(entries) != 0 {
		t.Fatalf("no partials should exist, got %v", entries)
	}
}

func TestExfilRejectsOversizedChunk(t *testing.T) {
	h := newExfilHarness(t)
	id := "abcdef0123456789"

	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_begin:%s:5:data.bin", id))
	// A base64 field far beyond the per-chunk cap must be dropped without
	// allocating/decoding (DoS guard), and the transfer must stay healthy.
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:0:%s", id, strings.Repeat("A", base64.StdEncoding.EncodedLen(16<<20))))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:0:%s", id, h.b64("hello")))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_end:%s:-", id))

	h.expectFile(t, "data.bin", "hello")
}

func TestExfilCapsConcurrentTransfers(t *testing.T) {
	h := newExfilHarness(t)

	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("%016x", i)
		h.assembler.HandleOutput("sess1", fmt.Sprintf("file_begin:%s:10:f%d.bin", id, i))
	}

	pending := h.assembler.PendingTransfers()
	if len(pending) != maxExfilTransfers {
		t.Fatalf("expected %d concurrent transfers cap, got %d", maxExfilTransfers, len(pending))
	}
}

func TestExfilLastAskCleanedOnCompletion(t *testing.T) {
	h := newExfilHarness(t)
	id := "abcdef0123456789"

	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_begin:%s:11:data.bin", id))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:0:%s", id, h.b64("hello ")))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_chunk:%s:6:%s", id, h.b64("world")))
	h.assembler.HandleOutput("sess1", fmt.Sprintf("file_end:%s:-", id))

	h.assembler.HandleAbortCheck(t, id)
}

func (e *ExfilAssembler) HandleAbortCheck(t *testing.T, id string) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.transfers[id]; ok {
		t.Fatalf("transfer %s must be gone after file_end", id)
	}
	if _, ok := e.lastAsk[id]; ok {
		t.Fatalf("lastAsk entry for %s must be cleaned after file_end", id)
	}
}
