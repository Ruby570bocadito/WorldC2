package db

// Operator account security (r19): TOTP MFA state and the brute-force
// lockout, both living in the operators table via migration 11.
//
// Design decisions worth keeping:
//   - The TOTP secret is stored with the SAME column encryptor as vault
//     credentials (d.enc) whenever a master key is configured: a database
//     dump must not hand out the MFA factor any more than it may hand out
//     loot passwords. Without a master key the secret lands plaintext —
//     exactly the documented trade-off the credentials table already makes
//     (protecting the file itself is the deployment's job, see README).
//   - The lockout is CONSECUTIVE failures since the last success, with an
//     auto-expiring lock window. No failed-at history, no manual unlock:
//     an auto-expiring lock cannot be weaponized into a permanent DoS of
//     the admin account, which a manual-unlock design could.
//   - Every failure path returns typed sentinel errors so the HTTP layer
//     can audit "locked" separately while answering the CLIENT with the
//     same generic "invalid credentials" body (no username or lock-state
//     oracle).

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrOperatorLocked is returned by the auth path when the account is inside
// its lockout window. The login handler maps it to the SAME generic 401 as
// a wrong password (no account-existence or lock-state oracle) but audits
// it as auth_locked.
var ErrOperatorLocked = errors.New("operator account is locked")

// ErrInvalidCode marks an authenticator-code check failure in the login /
// enable / disable flows. Same treatment: generic to the client,
// distinguishable internally.
var ErrInvalidCode = errors.New("invalid authenticator code")

// lockoutThreshold is how many consecutive failed attempts trip the lock.
// The per-IP login rate limiter (10/min) throttles a single source; this
// threshold adds the per-ACCOUNT line: distributed guesses hit a wall that
// survives server restarts (it lives in the DB, not in memory).
const lockoutThreshold = 5

// lockoutDuration is how long the lock stays up after tripping. Short
// enough that a legitimate operator locked by their own typo storm waits
// minutes, not a support ticket; long enough that automated guessing gains
// nothing (5 tries, then 5 minutes of wall = at most 1 guess per minute
// per account across ALL sources combined).
const lockoutDuration = 5 * time.Minute

// operatorAuthState is the full security-relevant row of one operator.
type operatorAuthState struct {
	ID             int
	Username       string
	PasswordHash   string
	Role           string
	CreatedAt      time.Time
	TOTPSecret     string // decrypted; "" when none stored
	TOTPEnabled    bool
	FailedAttempts int
	LockedUntil    sql.NullTime
}

// loadOperatorAuthState reads one operator's full auth row (decoding the
// TOTP secret through the column encryptor when present). Returns
// sql.ErrNoRows for an unknown username — callers fold that into the same
// generic failure as a bad password.
func (d *DB) loadOperatorAuthState(username string) (*operatorAuthState, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	st := &operatorAuthState{}
	var secret string
	var enabled int
	err := d.conn.QueryRow(`
                SELECT id, username, password_hash, role, created_at,
                       totp_secret, totp_enabled, failed_attempts, locked_until
                FROM operators WHERE username=?`, username,
	).Scan(&st.ID, &st.Username, &st.PasswordHash, &st.Role, &st.CreatedAt,
		&secret, &enabled, &st.FailedAttempts, &st.LockedUntil)
	if err != nil {
		return nil, err
	}
	if secret != "" && d.enc != nil {
		if plain, derr := d.enc.DecryptString(secret); derr == nil {
			secret = plain
		}
		// Decrypt failure leaves the stored value in place: code checks
		// then reject everything against it — fail-closed by construction.
	}
	st.TOTPSecret = secret
	st.TOTPEnabled = enabled == 1
	return st, nil
}

// registerAuthFailure increments the consecutive-failure counter and trips
// the lock when the threshold is crossed. The counter deliberately does
// NOT decay with time: only a successful login resets it. The update
// passes the counter through SQL (failed_attempts+1) instead of trusting
// the value read earlier — concurrent failures on the same account stay
// accurate without holding a transaction open across bcrypt.
func (d *DB) registerAuthFailure(operatorID int, trip bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if trip {
		until := time.Now().Add(lockoutDuration)
		_, _ = d.conn.Exec(
			`UPDATE operators SET failed_attempts=0, locked_until=? WHERE id=?`,
			until, operatorID,
		)
		return
	}
	_, _ = d.conn.Exec(
		`UPDATE operators SET failed_attempts=failed_attempts+1 WHERE id=?`, operatorID,
	)
}

// registerAuthSuccess clears the failure counter and any stale lock row.
func (d *DB) registerAuthSuccess(operatorID int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, _ = d.conn.Exec(
		`UPDATE operators SET failed_attempts=0, locked_until=NULL WHERE id=?`, operatorID,
	)
}

// checkOperatorLock consults (and, when expired, clears) the lockout
// window.
func (d *DB) checkOperatorLock(st *operatorAuthState) bool {
	return st.LockedUntil.Valid && st.LockedUntil.Time.After(time.Now())
}

// RegisterAuthFailure records one failed login-stage attempt for an
// account whose PASSWORD was correct but whose second factor was not —
// the TOTP stage of the login flow. Guessing codes must trip the same
// per-account wall as guessing passwords. Unknown usernames are a no-op
// (the login flow has already failed them with the generic error).
func (d *DB) RegisterAuthFailure(username string) {
	st, err := d.loadOperatorAuthState(username)
	if err != nil {
		return
	}
	d.registerAuthFailure(st.ID, st.FailedAttempts+1 >= lockoutThreshold)
}

// RegisterAuthSuccess clears the lockout state after a fully successful
// login (both stages). Unknown usernames are a no-op.
func (d *DB) RegisterAuthSuccess(username string) {
	st, err := d.loadOperatorAuthState(username)
	if err != nil {
		return
	}
	d.registerAuthSuccess(st.ID)
}

// SetOperatorPassword replaces an operator's password hash (self-service
// change flow: the handler verifies the CURRENT password before calling
// this). bcrypt format validated the same way CreateOperatorWithHash does.
func (d *DB) SetOperatorPassword(id int, passwordHash string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(passwordHash) < 59 || (passwordHash[:4] != "$2a$" && passwordHash[:4] != "$2b$") {
		return fmt.Errorf("invalid bcrypt hash format")
	}
	res, err := d.conn.Exec(`UPDATE operators SET password_hash=?, failed_attempts=0, locked_until=NULL WHERE id=?`, passwordHash, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetTOTPSecret stores (or replaces) the DISABLED secret for an operator,
// encrypted with the column encryptor when a master key is configured.
// The account stays totp_enabled=0 until EnableTOTP flips the flag —
// setup alone never gates a login.
func (d *DB) SetTOTPSecret(id int, secret string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	stored := secret
	if d.enc != nil && secret != "" {
		ct, err := d.enc.EncryptString(secret)
		if err != nil {
			return fmt.Errorf("encrypt totp secret: %w", err)
		}
		stored = ct
	}
	res, err := d.conn.Exec(
		`UPDATE operators SET totp_secret=?, totp_enabled=0 WHERE id=?`, stored, id,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// EnableTOTP flips the MFA flag after the handler confirmed the operator
// can produce a valid code for the stored secret. Without a stored secret
// this is a no-op error — enabling nothing would silently drop the factor.
func (d *DB) EnableTOTP(id int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var secret string
	if err := d.conn.QueryRow(`SELECT totp_secret FROM operators WHERE id=?`, id).Scan(&secret); err != nil {
		return err
	}
	if secret == "" {
		return fmt.Errorf("no pending totp setup for this operator")
	}
	_, err := d.conn.Exec(`UPDATE operators SET totp_enabled=1 WHERE id=?`, id)
	return err
}

// DisableTOTP turns MFA off and wipes the stored secret (enabled or not) —
// a disabled-but-retained secret would be dead weight waiting to be
// re-enabled by a bug.
func (d *DB) DisableTOTP(id int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	res, err := d.conn.Exec(
		`UPDATE operators SET totp_secret='', totp_enabled=0 WHERE id=?`, id,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// OperatorTOTPState is the login path's view of one operator's MFA status.
type OperatorTOTPState struct {
	Enabled bool
	Secret  string // decrypted; "" when disabled
}

// GetOperatorTOTPState loads the MFA state by username for the login flow.
// An unknown username yields the zero state (disabled, no secret) — the
// login handler treats it identically to "no MFA configured" and the
// generic credential failure already covers the oracle.
func (d *DB) GetOperatorTOTPState(username string) (*OperatorTOTPState, error) {
	st, err := d.loadOperatorAuthState(username)
	if err != nil {
		return &OperatorTOTPState{}, nil
	}
	return &OperatorTOTPState{Enabled: st.TOTPEnabled, Secret: st.TOTPSecret}, nil
}

// OperatorActivityRow is the per-account audit summary the Operators view
// renders: when the account last did anything, how much it did in the last
// 30 days, and when it last logged in.
type OperatorActivityRow struct {
	LastActivity sql.NullTime
	Events30d    int
	LastLogin    sql.NullTime
}

// OperatorActivity returns one summary row per operator id, sourced from
// the audit trail (operator_id has been populated by the middleware since
// r18 — this is the query that column was written for). Operators without
// audit history are absent from the map; the caller renders "never".
//
// The aggregates are scanned as TEXT and parsed in Go: SQLite's MAX()
// over a DATETIME column loses the declared affinity in the result
// expression, and the driver hands the raw "YYYY-MM-DD HH:MM:SS" (UTC,
// CURRENT_TIMESTAMP format) through — a direct scan into sql.NullTime
// fails with an unsupported-type error, which is exactly the kind of
// silent contract break this query must not have.
func (d *DB) OperatorActivity() (map[int]OperatorActivityRow, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	since := time.Now().Add(-30 * 24 * time.Hour)
	rows, err := d.conn.Query(`
                SELECT operator_id,
                       MAX(timestamp)                                              AS last_activity,
                       SUM(CASE WHEN timestamp >= datetime(?, 'unixepoch') THEN 1 ELSE 0 END) AS events_30d,
                       MAX(CASE WHEN action = 'auth_success' THEN timestamp END)   AS last_login
                FROM audit_log
                WHERE operator_id > 0
                GROUP BY operator_id`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[int]OperatorActivityRow)
	for rows.Next() {
		var id int
		var row OperatorActivityRow
		var lastActivity, lastLogin sql.NullString
		if err := rows.Scan(&id, &lastActivity, &row.Events30d, &lastLogin); err != nil {
			return nil, err
		}
		row.LastActivity = parseSQLiteTimestamp(lastActivity)
		row.LastLogin = parseSQLiteTimestamp(lastLogin)
		out[id] = row
	}
	return out, rows.Err()
}

// parseSQLiteTimestamp converts the audit trail's CURRENT_TIMESTAMP text
// ("2006-01-02 15:04:05", UTC) into a NullTime; NULL or unparseable input
// stays invalid rather than zeroing into a lie.
func parseSQLiteTimestamp(s sql.NullString) sql.NullTime {
	if !s.Valid || s.String == "" {
		return sql.NullTime{}
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", s.String, time.UTC)
	if err != nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t, Valid: true}
}

// CountOperators returns the number of operator accounts. Feeds the
// enriched /api/status payload (r19): a fleet-wide count an operator can
// compare against expectations — an unexpected jump is the cheapest
// possible rogue-account alarm.
func (d *DB) CountOperators() (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var n int
	err := d.conn.QueryRow(`SELECT COUNT(*) FROM operators`).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Healthy reports whether the database answers a round-trip ping. The
// enriched /api/status exposes it as db_ok — an operational flag behind
// the authenticated gate, never on the public liveness route.
func (d *DB) Healthy() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.conn.Ping() == nil
}
