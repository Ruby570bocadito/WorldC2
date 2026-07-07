package db

import (
	"fmt"
	"log"
)

// Migration represents a database schema migration.
type Migration struct {
	Version int
	Name    string
	Up      string
	Down    string
}

// Migrations returns all available migrations in order.
func Migrations() []Migration {
	return []Migration{
		{
			Version: 1,
			Name:    "initial_schema",
			Up: `
				CREATE TABLE IF NOT EXISTS sessions (
					id TEXT PRIMARY KEY,
					agent_id TEXT UNIQUE,
					hostname TEXT,
					os TEXT,
					arch TEXT,
					username TEXT,
					is_admin INTEGER DEFAULT 0,
					public_ip TEXT,
					local_ip TEXT,
					mac_address TEXT,
					first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
					last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
					state TEXT DEFAULT 'active'
				);
				CREATE TABLE IF NOT EXISTS tasks (
					id TEXT PRIMARY KEY,
					session_id TEXT REFERENCES sessions(id),
					command TEXT NOT NULL,
					output TEXT DEFAULT '',
					exit_code INTEGER DEFAULT 0,
					success INTEGER DEFAULT 0,
					issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
					completed_at DATETIME
				);
				CREATE TABLE IF NOT EXISTS operators (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					username TEXT UNIQUE NOT NULL,
					password_hash TEXT NOT NULL,
					role TEXT DEFAULT 'operator',
					created_at DATETIME DEFAULT CURRENT_TIMESTAMP
				);
				CREATE TABLE IF NOT EXISTS audit_log (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					operator_id INTEGER,
					action TEXT NOT NULL,
					detail TEXT,
					timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
				);
				CREATE INDEX IF NOT EXISTS idx_tasks_session ON tasks(session_id);
				CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);
				CREATE INDEX IF NOT EXISTS idx_tasks_issued ON tasks(issued_at);
			`,
			Down: `
				DROP TABLE IF EXISTS audit_log;
				DROP TABLE IF EXISTS operators;
				DROP TABLE IF EXISTS tasks;
				DROP TABLE IF EXISTS sessions;
			`,
		},
		{
			Version: 2,
			Name:    "add_session_fingerprint",
			Up: `
				ALTER TABLE sessions ADD COLUMN fingerprint TEXT;
				ALTER TABLE sessions ADD COLUMN agent_version TEXT DEFAULT '1.0.0';
				ALTER TABLE sessions ADD COLUMN transport TEXT DEFAULT 'tcp';
				ALTER TABLE sessions ADD COLUMN privilege TEXT DEFAULT 'user';
			`,
			Down: `
				-- SQLite doesn't support DROP COLUMN in older versions
				-- This is a no-op for downgrade
			`,
		},
		{
			Version: 3,
			Name:    "add_task_metadata",
			Up: `
				ALTER TABLE tasks ADD COLUMN operator_id INTEGER;
				ALTER TABLE tasks ADD COLUMN task_type TEXT DEFAULT 'command';
				ALTER TABLE tasks ADD COLUMN metadata TEXT;
				CREATE INDEX IF NOT EXISTS idx_tasks_operator ON tasks(operator_id);
			`,
			Down: `
				-- No-op for downgrade
			`,
		},
		{
			Version: 4,
			Name:    "add_credential_vault",
			Up: `
				CREATE TABLE IF NOT EXISTS credentials (
					id TEXT PRIMARY KEY,
					username TEXT,
					password TEXT,
					domain TEXT,
					host TEXT,
					service TEXT,
					source TEXT,
					notes TEXT,
					captured DATETIME DEFAULT CURRENT_TIMESTAMP
				);
				CREATE INDEX IF NOT EXISTS idx_creds_username ON credentials(username);
				CREATE INDEX IF NOT EXISTS idx_creds_domain ON credentials(domain);
			`,
			Down: `
				DROP TABLE IF EXISTS credentials;
			`,
		},
		{
			Version: 5,
			Name:    "add_file_records",
			Up: `
				CREATE TABLE IF NOT EXISTS file_records (
					id TEXT PRIMARY KEY,
					session_id TEXT REFERENCES sessions(id),
					filename TEXT,
					module TEXT,
					size INTEGER,
					path TEXT,
					created DATETIME DEFAULT CURRENT_TIMESTAMP
				);
				CREATE INDEX IF NOT EXISTS idx_files_session ON file_records(session_id);
			`,
			Down: `
				DROP TABLE IF EXISTS file_records;
			`,
		},
		{
			Version: 6,
			Name:    "add_server_secrets",
			Up: `
				CREATE TABLE IF NOT EXISTS server_secrets (
					key TEXT PRIMARY KEY,
					value BLOB NOT NULL,
					created_at DATETIME DEFAULT CURRENT_TIMESTAMP
				);
			`,
			Down: `
				DROP TABLE IF EXISTS server_secrets;
			`,
		},
		{
			Version: 7,
			Name:    "add_task_queue",
			Up: `
				CREATE TABLE IF NOT EXISTS task_queue (
					id TEXT PRIMARY KEY,
					session_id TEXT NOT NULL,
					command TEXT NOT NULL,
					status TEXT DEFAULT 'pending',
					result TEXT DEFAULT '',
					exit_code INTEGER DEFAULT 0,
					success INTEGER DEFAULT 0,
					created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
					delivered_at DATETIME,
					completed_at DATETIME,
					operator_id INTEGER,
					timeout_sec INTEGER DEFAULT 30
				);
				CREATE INDEX IF NOT EXISTS idx_task_queue_session ON task_queue(session_id);
				CREATE INDEX IF NOT EXISTS idx_task_queue_status ON task_queue(status);
			`,
			Down: `
				DROP TABLE IF EXISTS task_queue;
			`,
		},
		{
			Version: 8,
			Name:    "add_team_collaboration",
			Up: `
				CREATE TABLE IF NOT EXISTS session_notes (
					id TEXT PRIMARY KEY,
					session_id TEXT NOT NULL,
					operator_id INTEGER,
					content TEXT NOT NULL,
					created_at DATETIME DEFAULT CURRENT_TIMESTAMP
				);
				CREATE TABLE IF NOT EXISTS session_locks (
					session_id TEXT PRIMARY KEY,
					operator_id INTEGER NOT NULL,
					locked_at DATETIME DEFAULT CURRENT_TIMESTAMP
				);
				CREATE TABLE IF NOT EXISTS agent_profiles (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL,
					beacon_interval INTEGER DEFAULT 5,
					jitter REAL DEFAULT 0.3,
					transport TEXT DEFAULT 'tls',
					created_at DATETIME DEFAULT CURRENT_TIMESTAMP
				);
				CREATE INDEX IF NOT EXISTS idx_notes_session ON session_notes(session_id);
			`,
			Down: `
				DROP TABLE IF EXISTS session_notes;
				DROP TABLE IF EXISTS session_locks;
				DROP TABLE IF EXISTS agent_profiles;
			`,
		},
	}
}

// Migrate applies all pending migrations.
func (d *DB) Migrate() error {
	log.Println("[DB] Running migrations...")

	migrations := Migrations()

	for _, m := range migrations {
		// Check if migration already applied
		var count int
		err := d.conn.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='migrations'`).Scan(&count)
		if err != nil {
			return fmt.Errorf("check migrations table: %w", err)
		}

		// Create migrations table if it doesn't exist
		if count == 0 {
			_, err = d.conn.Exec(`CREATE TABLE IF NOT EXISTS migrations (
				version INTEGER PRIMARY KEY,
				name TEXT NOT NULL,
				applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)`)
			if err != nil {
				return fmt.Errorf("create migrations table: %w", err)
			}
		}

		// Check if this version is already applied
		var exists int
		err = d.conn.QueryRow(`SELECT COUNT(*) FROM migrations WHERE version = ?`, m.Version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check migration version: %w", err)
		}

		if exists > 0 {
			log.Printf("[DB] Migration %d (%s) already applied", m.Version, m.Name)
			continue
		}

		// Apply migration
		log.Printf("[DB] Applying migration %d: %s", m.Version, m.Name)

		// Split SQL statements and execute each
		statements := splitSQL(m.Up)
		for _, stmt := range statements {
			if stmt == "" {
				continue
			}
			if _, err := d.conn.Exec(stmt); err != nil {
				return fmt.Errorf("migration %d (%s) failed: %w", m.Version, m.Name, err)
			}
		}

		// Record migration
		_, err = d.conn.Exec(`INSERT INTO migrations (version, name) VALUES (?, ?)`, m.Version, m.Name)
		if err != nil {
			return fmt.Errorf("record migration: %w", err)
		}

		log.Printf("[DB] Migration %d applied successfully", m.Version)
	}

	log.Println("[DB] All migrations applied")
	return nil
}

// Rollback rolls back the last applied migration.
func (d *DB) Rollback() error {
	// Get last applied migration
	var version int
	var name string
	err := d.conn.QueryRow(`SELECT version, name FROM migrations ORDER BY version DESC LIMIT 1`).Scan(&version, &name)
	if err != nil {
		return fmt.Errorf("no migrations to rollback")
	}

	// Find migration
	migrations := Migrations()
	var target Migration
	for _, m := range migrations {
		if m.Version == version {
			target = m
			break
		}
	}

	if target.Name == "" {
		return fmt.Errorf("migration %d not found", version)
	}

	log.Printf("[DB] Rolling back migration %d: %s", version, name)

	// Execute down migration
	statements := splitSQL(target.Down)
	for _, stmt := range statements {
		if stmt == "" {
			continue
		}
		if _, err := d.conn.Exec(stmt); err != nil {
			return fmt.Errorf("rollback %d (%s) failed: %w", version, name, err)
		}
	}

	// Remove migration record
	_, err = d.conn.Exec(`DELETE FROM migrations WHERE version = ?`, version)
	if err != nil {
		return fmt.Errorf("remove migration record: %w", err)
	}

	log.Printf("[DB] Migration %d rolled back", version)
	return nil
}

// GetMigrationVersion returns the current database version.
func (d *DB) GetMigrationVersion() (int, error) {
	var version int
	err := d.conn.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM migrations`).Scan(&version)
	return version, err
}

func splitSQL(sql string) []string {
	var statements []string
	var current string

	for _, line := range splitLines(sql) {
		line = trimSpace(line)
		if line == "" || line[0] == '-' {
			continue
		}
		current += line + " "
	}

	if current != "" {
		statements = append(statements, current)
	}

	return statements
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	lines = append(lines, s[start:])
	return lines
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
