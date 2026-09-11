package module

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Manifest defines a dynamic module that can be pushed to agents.
type Manifest struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Platform    string            `json:"platform"` // "windows", "linux", "darwin", "all"
	Arch        string            `json:"arch"`     // "amd64", "arm64", "any"
	Description string            `json:"description"`
	Type        string            `json:"type"` // "ps1", "sh", "binary", "dll"
	Commands    []string          `json:"commands"`
	Files       map[string]string `json:"files"` // filename → base64 content
	HMAC        string            `json:"hmac"`  // HMAC-SHA256 signature
	Author      string            `json:"author"`
	Created     time.Time         `json:"created"`
}

// PackedModule is sent over the wire to an agent.
type PackedModule struct {
	Manifest Manifest `json:"manifest"`
	Payload  string   `json:"payload"` // base64 of the module content
}

// Store manages the module repository on the C2 server.
type Store struct {
	baseDir string
	modules map[string]*Manifest
	mu      sync.RWMutex
	hmacKey []byte
}

// NewStore creates a module store.
func NewStore(baseDir string, hmacKey []byte) *Store {
	os.MkdirAll(baseDir, 0755)
	s := &Store{
		baseDir: baseDir,
		modules: make(map[string]*Manifest),
		hmacKey: hmacKey,
	}
	s.loadFromDisk()
	return s
}

func (s *Store) loadFromDisk() {
	entries, _ := os.ReadDir(s.baseDir)
	for _, e := range entries {
		if e.IsDir() {
			manifestPath := filepath.Join(s.baseDir, e.Name(), "manifest.json")
			m, err := s.loadManifest(manifestPath)
			if err != nil {
				continue
			}
			// Tamper-evidence: a manifest that carries a signature which no
			// longer validates (edited on disk, or signed with a different
			// signing key) is rejected outright. Unsigned manifests are
			// accepted with a notice so the bundled example modules load.
			if m.HMAC != "" && !s.Verify(m) {
				log.Printf("[MODULES] rejecting %q: manifest HMAC verification failed (file modified or signed with another key)", m.Name)
				continue
			}
			if m.HMAC == "" {
				log.Printf("[MODULES] loaded unsigned module %q (re-push it via the API to have it signed)", m.Name)
			}
			s.modules[m.Name] = m
		}
	}
}

func (s *Store) loadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// List returns all available modules.
func (s *Store) List() []*Manifest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Manifest, 0, len(s.modules))
	for _, m := range s.modules {
		result = append(result, m)
	}
	return result
}

// Get returns a module by name.
func (s *Store) Get(name string) *Manifest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.modules[name]
}

// sanitizeModuleName rejects empty names and path separators so a malicious
// manifest cannot escape the module directory (path traversal).
func sanitizeModuleName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("module name is required")
	}
	if name != filepath.Base(name) || strings.ContainsAny(name, `\..:/`) {
		return "", fmt.Errorf("invalid module name %q", name)
	}
	return name, nil
}

// Register adds a module to the store.
func (s *Store) Register(m *Manifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	clean, err := sanitizeModuleName(m.Name)
	if err != nil {
		return err
	}
	m.Name = clean

	// Create module directory
	modDir := filepath.Join(s.baseDir, m.Name)
	os.MkdirAll(modDir, 0755)

	// Save payload files first so a bad payload can't leave a half-registered
	// manifest behind.
	for filename, contentB64 := range m.Files {
		content, err := base64.StdEncoding.DecodeString(contentB64)
		if err != nil {
			return fmt.Errorf("decode %s: %w", filename, err)
		}
		filename = filepath.Base(filename)
		if filename == "." || filename == ".." || filename == "/" {
			return fmt.Errorf("invalid payload filename")
		}
		filePath := filepath.Join(modDir, filename)
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			return fmt.Errorf("save %s: %w", filename, err)
		}
	}

	// Compute and set HMAC over the COMPACT serialization with the HMAC
	// field empty — the exact same input Verify() will re-serialize later.
	m.HMAC = ""
	m.Created = time.Now()
	sigData, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("serialize manifest: %w", err)
	}
	m.HMAC = s.computeHMAC(sigData)

	// Save manifest (indented for readability; signature covers the
	// canonical compact form, not the on-disk formatting).
	manifestPath := filepath.Join(modDir, "manifest.json")
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize manifest: %w", err)
	}
	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		return fmt.Errorf("save manifest: %w", err)
	}

	s.modules[m.Name] = m
	return nil
}

// Pack prepares a module for sending to an agent.
func (s *Store) Pack(name string) (*PackedModule, error) {
	s.mu.RLock()
	m, ok := s.modules[name]
	if ok && m.HMAC != "" && !s.Verify(m) {
		s.mu.RUnlock()
		return nil, fmt.Errorf("module %q: manifest HMAC verification failed — re-register it before pushing", name)
	}
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("module not found: %s", name)
	}

	packed := &PackedModule{Manifest: *m}

	// Read the first payload file as the main payload
	modDir := filepath.Join(s.baseDir, name)
	entries, _ := os.ReadDir(modDir)
	for _, e := range entries {
		if !e.IsDir() && !strings.HasSuffix(e.Name(), ".json") {
			data, err := os.ReadFile(filepath.Join(modDir, e.Name()))
			if err == nil {
				packed.Payload = base64.StdEncoding.EncodeToString(data)
				break
			}
		}
	}

	return packed, nil
}

// Verify checks the HMAC signature of a module manifest. It never mutates
// the manifest (safe to call concurrently with readers): verification runs
// over a shallow copy with the HMAC field cleared, matching exactly what
// Register() signed.
func (s *Store) Verify(m *Manifest) bool {
	if m == nil || m.HMAC == "" || len(s.hmacKey) == 0 {
		return false
	}
	cp := *m
	cp.HMAC = ""
	data, err := json.Marshal(&cp)
	if err != nil {
		return false
	}
	expected := s.computeHMAC(data)
	if expected == "" {
		return false
	}
	return hmac.Equal([]byte(m.HMAC), []byte(expected))
}

func (s *Store) computeHMAC(data []byte) string {
	if len(s.hmacKey) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write(data)
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// Delete removes a module from the store.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean, err := sanitizeModuleName(name)
	if err != nil {
		return err
	}
	delete(s.modules, clean)
	return os.RemoveAll(filepath.Join(s.baseDir, clean))
}

// GetPayloadPath returns the path to a module's payload file.
func (s *Store) GetPayloadPath(name string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	modDir := filepath.Join(s.baseDir, name)
	entries, _ := os.ReadDir(modDir)
	for _, e := range entries {
		if !e.IsDir() && !strings.HasSuffix(e.Name(), ".json") {
			return filepath.Join(modDir, e.Name()), nil
		}
	}
	return "", fmt.Errorf("no payload found for module %s", name)
}
