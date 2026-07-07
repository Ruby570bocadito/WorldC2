package db

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditLogRotation handles automatic rotation of audit logs.
type AuditLogRotation struct {
	mu            sync.Mutex
	logDir        string
	maxFileSize   int64
	maxAge        time.Duration
	currentFile   *os.File
	currentSize   int64
	rotationCount int
}

// NewAuditLogRotation creates a new audit log rotation handler.
func NewAuditLogRotation(logDir string, maxFileSize int64, maxAge time.Duration) *AuditLogRotation {
	os.MkdirAll(logDir, 0700)
	return &AuditLogRotation{
		logDir:      logDir,
		maxFileSize: maxFileSize,
		maxAge:      maxAge,
	}
}

// Write writes a log entry, rotating if necessary.
func (r *AuditLogRotation) Write(entry string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if rotation is needed
	if r.currentFile == nil || r.currentSize >= r.maxFileSize {
		if err := r.rotate(); err != nil {
			return fmt.Errorf("rotate log: %w", err)
		}
	}

	n, err := r.currentFile.WriteString(entry + "\n")
	if err != nil {
		return fmt.Errorf("write log: %w", err)
	}
	r.currentSize += int64(n)
	return nil
}

// rotate creates a new log file and archives the old one.
func (r *AuditLogRotation) rotate() error {
	// Close current file if open
	if r.currentFile != nil {
		r.currentFile.Close()
	}

	// Generate new filename with timestamp
	now := time.Now()
	filename := fmt.Sprintf("audit_%s.log", now.Format("20060102_150405"))
	filepath := filepath.Join(r.logDir, filename)

	// Create new file
	f, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("create log file: %w", err)
	}

	r.currentFile = f
	r.currentSize = 0
	r.rotationCount++

	// Clean up old logs
	go r.cleanupOldLogs()

	log.Printf("[AUDIT] Log rotated to %s (rotation #%d)", filepath, r.rotationCount)
	return nil
}

// cleanupOldLogs removes logs older than maxAge.
func (r *AuditLogRotation) cleanupOldLogs() {
	cutoff := time.Now().Add(-r.maxAge)

	entries, err := os.ReadDir(r.logDir)
	if err != nil {
		log.Printf("[AUDIT] Failed to read log dir: %v", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			path := filepath.Join(r.logDir, entry.Name())
			if err := os.Remove(path); err != nil {
				log.Printf("[AUDIT] Failed to remove old log %s: %v", path, err)
			} else {
				log.Printf("[AUDIT] Removed old log: %s", entry.Name())
			}
		}
	}
}

// Close closes the current log file.
func (r *AuditLogRotation) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.currentFile != nil {
		return r.currentFile.Close()
	}
	return nil
}

// Stats returns rotation statistics.
func (r *AuditLogRotation) Stats() map[string]interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()

	return map[string]interface{}{
		"rotation_count": r.rotationCount,
		"current_size":   r.currentSize,
		"max_size":       r.maxFileSize,
		"max_age":        r.maxAge.String(),
		"log_dir":        r.logDir,
	}
}
