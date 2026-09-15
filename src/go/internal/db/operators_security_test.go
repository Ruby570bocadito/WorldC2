package db

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// seedTestOperator creates a fresh operator with a known bcrypt password
// and returns its row id.
func seedTestOperator(t *testing.T, d *DB, username, password string) int {
	t.Helper()
	if err := d.CreateOperator(username, password, "operator"); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	id, err := d.OperatorIDByUsername(username)
	if err != nil || id == 0 {
		t.Fatalf("resolve id: %v", err)
	}
	return id
}

// TestOperatorLockout pins the brute-force contract: N consecutive wrong
// passwords trip the lock, the correct password inside the window answers
// ErrOperatorLocked (NOT a success — that would leak the lock state to a
// lucky guesser), the lock auto-expires, and one success resets the counter.
func TestOperatorLockout(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "lockout.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	const user, pass = "locky", "correct-horse-battery"
	seedTestOperator(t, d, user, pass)

	// Four failures: still allowed to try (each a generic invalid creds).
	for i := 0; i < lockoutThreshold-1; i++ {
		if _, err := d.AuthenticateOperator(user, "wrong-"+string(rune('a'+i))); err == nil {
			t.Fatalf("wrong password must fail (attempt %d)", i+1)
		}
	}

	// Fifth failure trips the lock (it still answers the generic error —
	// the lock applies to the NEXT attempt), after which even the correct
	// password answers ErrOperatorLocked — the typed error proves the
	// lockout sits in FRONT of bcrypt.
	if _, err := d.AuthenticateOperator(user, "still-wrong"); err == nil || err.Error() != "invalid credentials" {
		t.Fatalf("5th wrong password must still answer generic error, got %v", err)
	}
	if _, err := d.AuthenticateOperator(user, pass); !errors.Is(err, ErrOperatorLocked) {
		t.Fatalf("correct password while locked: want ErrOperatorLocked, got %v", err)
	}
	// A wrong password while locked must ALSO answer the typed error (the
	// lock gate runs before the hash compare).
	if _, err := d.AuthenticateOperator(user, "nope"); !errors.Is(err, ErrOperatorLocked) {
		t.Fatalf("wrong password while locked: want ErrOperatorLocked, got %v", err)
	}

	// Expire the lock manually (production: 5 minutes pass). The correct
	// password logs in and resets everything.
	if _, err := d.conn.Exec(`UPDATE operators SET locked_until=? WHERE username=?`, time.Now().Add(-time.Second), user); err != nil {
		t.Fatalf("expire lock: %v", err)
	}
	if _, err := d.AuthenticateOperator(user, pass); err != nil {
		t.Fatalf("login after lock expiry: %v", err)
	}

	// Counter reset: another 4 failures must NOT trip the lock.
	for i := 0; i < lockoutThreshold-1; i++ {
		if _, err := d.AuthenticateOperator(user, "wrong"); !errors.Is(err, ErrOperatorLocked) && err == nil {
			t.Fatalf("wrong password must fail (post-reset attempt %d)", i+1)
		}
	}
	if _, err := d.AuthenticateOperator(user, pass); err != nil {
		t.Fatalf("correct password after 4 post-reset failures must succeed, got %v", err)
	}
}

// TestUnknownUserNoLockoutLeak pins that an unknown username answers the
// same opaque error as a wrong password — the lockout must not become a
// username-existence oracle.
func TestUnknownUserNoLockoutLeak(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "oracle.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	_, known := d.AuthenticateOperator("ghost-user", "whatever")
	if known == nil || known.Error() != "invalid credentials" {
		t.Fatalf("unknown user must answer 'invalid credentials', got %v", known)
	}
}

// TestTOTPEnrollmentFlow pins the DB half of the MFA lifecycle: a stored
// secret is DISABLED by default, EnableTOTP refuses to enable nothing,
// and DisableTOTP wipes both the flag and the secret.
func TestTOTPEnrollmentFlow(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "totp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	id := seedTestOperator(t, d, "mfa_op", "some-long-password")

	// Enable with no pending setup must refuse.
	if err := d.EnableTOTP(id); err == nil {
		t.Fatal("EnableTOTP without a stored secret must error")
	}

	if err := d.SetTOTPSecret(id, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"); err != nil {
		t.Fatalf("set secret: %v", err)
	}

	// After setup the state is: secret present, NOT enabled.
	st, err := d.GetOperatorTOTPState("mfa_op")
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if st.Secret != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Fatalf("secret round-trip: got %q", st.Secret)
	}
	if st.Enabled {
		t.Fatal("a freshly stored secret must NOT be enabled")
	}

	// Setup again (secret replacement) must keep the disabled state.
	if err := d.SetTOTPSecret(id, "MFRGGZDFMZTWQ2LK"); err != nil {
		t.Fatalf("re-set secret: %v", err)
	}
	st, _ = d.GetOperatorTOTPState("mfa_op")
	if st.Enabled {
		t.Fatal("re-setup must not enable")
	}

	if err := d.EnableTOTP(id); err != nil {
		t.Fatalf("enable: %v", err)
	}
	st, _ = d.GetOperatorTOTPState("mfa_op")
	if !st.Enabled || st.Secret != "MFRGGZDFMZTWQ2LK" {
		t.Fatalf("enabled state wrong: %+v", st)
	}

	// Disable wipes everything.
	if err := d.DisableTOTP(id); err != nil {
		t.Fatalf("disable: %v", err)
	}
	st, _ = d.GetOperatorTOTPState("mfa_op")
	if st.Enabled || st.Secret != "" {
		t.Fatalf("after disable both flag and secret must be gone: %+v", st)
	}
}

// TestTOTPSecretEncryptedAtRest pins the storage contract: with a master
// key configured, the stored totp_secret column is ciphertext (v2 prefix),
// never the plaintext the API returned. A database dump must not leak the
// MFA factor.
func TestTOTPSecretEncryptedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "totp_enc.db")
	d, err := OpenWithEncryption(path, []byte("test-master-key-material"))
	if err != nil {
		t.Fatalf("open encrypted: %v", err)
	}
	defer d.Close()

	id := seedTestOperator(t, d, "enc_op", "some-long-password")
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if err := d.SetTOTPSecret(id, secret); err != nil {
		t.Fatalf("set secret: %v", err)
	}

	var stored string
	if err := d.conn.QueryRow(`SELECT totp_secret FROM operators WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if stored == secret {
		t.Fatal("totp_secret stored in PLAINTEXT with a master key configured")
	}
	if len(stored) < 3 || stored[:3] != "v2." {
		t.Fatalf("expected v2 ciphertext prefix, got %q", stored[:min(10, len(stored))])
	}

	// The read path decrypts transparently.
	st, _ := d.GetOperatorTOTPState("enc_op")
	if st.Secret != secret {
		t.Fatalf("read path must decrypt, got %q", st.Secret)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestOperatorActivitySummary pins the Operators-view aggregation: audit
// rows attributed to an operator produce last_activity, events_30d and
// last_login (only from auth_success rows); an operator with no history is
// absent from the map.
func TestOperatorActivitySummary(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "activity.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	id := seedTestOperator(t, d, "busy_op", "some-long-password")
	other := seedTestOperator(t, d, "quiet_op", "some-long-password")

	// Busy operator: a login, an API call, and one event from 40 days ago
	// (outside the 30d window).
	if _, err := d.conn.Exec(
		`INSERT INTO audit_log (operator_id, action, detail, timestamp) VALUES (?, 'auth_success', 'login', datetime('now'))`, id,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.Exec(
		`INSERT INTO audit_log (operator_id, action, detail, timestamp) VALUES (?, 'api_call', 'call', datetime('now'))`, id,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.Exec(
		`INSERT INTO audit_log (operator_id, action, detail, timestamp) VALUES (?, 'api_call', 'old', datetime('now', '-40 days'))`, id,
	); err != nil {
		t.Fatal(err)
	}

	act, err := d.OperatorActivity()
	if err != nil {
		t.Fatalf("activity: %v", err)
	}

	row, ok := act[id]
	if !ok {
		t.Fatal("busy operator must appear in the activity map")
	}
	if row.Events30d != 2 {
		t.Fatalf("events_30d = %d, want 2 (the 40-day-old row is outside the window)", row.Events30d)
	}
	if !row.LastActivity.Valid || !row.LastLogin.Valid {
		t.Fatalf("last_activity/last_login must be set: %+v", row)
	}
	if _, ok := act[other]; ok {
		t.Fatal("operator without audit history must be absent (the view renders 'never')")
	}
}

// TestSetOperatorPassword pins the self-service password change at DB
// level: the new hash authenticates, the old one does not, and the change
// clears any outstanding lockout state (an operator who proves ownership
// of the current password is not an attacker).
func TestSetOperatorPassword(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "passwd.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	id := seedTestOperator(t, d, "changer", "old-password-value")

	if err := d.SetOperatorPassword(id, "not-a-bcrypt-hash"); err == nil {
		t.Fatal("non-bcrypt hash must be rejected")
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte("new-password-value"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetOperatorPassword(id, string(newHash)); err != nil {
		t.Fatalf("set password: %v", err)
	}

	if _, err := d.AuthenticateOperator("changer", "old-password-value"); err == nil {
		t.Fatal("old password must no longer authenticate")
	}
	if _, err := d.AuthenticateOperator("changer", "new-password-value"); err != nil {
		t.Fatalf("new password must authenticate: %v", err)
	}

	if err := d.SetOperatorPassword(99999, string(newHash)); err == nil {
		t.Fatal("unknown operator id must error (no phantom updates)")
	}
}
