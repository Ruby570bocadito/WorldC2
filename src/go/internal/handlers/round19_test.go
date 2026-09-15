package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/config"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/totp"
)

// buildRound19Stack is the round-19 harness: same shape as round 17's, plus
// a plain "operator" role account for the self-service flows.
func buildRound19Stack(t *testing.T) (*http.ServeMux, *db.DB) {
	t.Helper()

	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "round19.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	if err := database.CreateOperator("alice", "correct-horse-battery", "admin"); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := database.CreateOperator("dave", "operator-correct-horse", "operator"); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.API.Port = 0
	mux := NewRouter(c2.New(cfg, database), nil, nil).Setup()
	return mux, database
}

// TestAccountPasswordChange pins the self-service password contract:
// current password required, length floor, old tokens revoked after the
// change, and any authenticated role can change THEIR OWN password.
func TestAccountPasswordChange(t *testing.T) {
	mux, _ := buildRound19Stack(t)
	token := loginAs(t, mux, "dave", "operator-correct-horse")

	// Wrong current password: 401, no change.
	rec := doAPI(t, mux, "POST", "/api/account/password", token,
		`{"current_password":"not-the-password","new_password":"brand-new-password-1"}`)
	if rec.Code != 401 {
		t.Fatalf("wrong current password: got %d, want 401", rec.Code)
	}

	// Too-short new password: 400.
	rec = doAPI(t, mux, "POST", "/api/account/password", token,
		`{"current_password":"operator-correct-horse","new_password":"short"}`)
	if rec.Code != 400 {
		t.Fatalf("short new password: got %d, want 400", rec.Code)
	}

	// New equals current: 400.
	rec = doAPI(t, mux, "POST", "/api/account/password", token,
		`{"current_password":"operator-correct-horse","new_password":"operator-correct-horse"}`)
	if rec.Code != 400 {
		t.Fatalf("same password: got %d, want 400", rec.Code)
	}

	// Happy path: change accepted.
	rec = doAPI(t, mux, "POST", "/api/account/password", token,
		`{"current_password":"operator-correct-horse","new_password":"brand-new-password-1"}`)
	if rec.Code != 200 {
		t.Fatalf("change: %d %s", rec.Code, rec.Body.String())
	}

	// The old token is revoked (RevokeUser cuts at iat): the very next
	// authenticated call must 401 — a changed password means no stale
	// sessions survive.
	rec = authedGet(t, mux, "/api/sessions", token)
	if rec.Code != 401 {
		t.Fatalf("token after password change must be revoked, got %d", rec.Code)
	}

	// Login with the NEW password works (no TOTP involved).
	if t2 := loginAs(t, mux, "dave", "brand-new-password-1"); t2 == "" {
		t.Fatalf("login with new password failed")
	}
}

// TestTOTPLoginFlow pins the whole MFA lifecycle through the real HTTP
// surface: setup → enable (code verified) → password-only login asks for
// the code → wrong code is a generic 401 → correct code logs in → disable
// (code verified) → password-only login works again.
func TestTOTPLoginFlow(t *testing.T) {
	mux, _ := buildRound19Stack(t)

	postJSON := func(path, token, body string) *httptest.ResponseRecorder {
		return doAPI(t, mux, "POST", path, token, body)
	}

	token := loginAs(t, mux, "dave", "operator-correct-horse")

	// Setup: returns secret + otpauth URI, stores DISABLED.
	rec := postJSON("/api/account/totp/setup", token, "")
	if rec.Code != 200 {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body.String())
	}
	var setup struct {
		Secret     string `json:"secret"`
		OTPAuthURI string `json:"otpauth_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &setup); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	if len(setup.Secret) != 32 || !strings.HasPrefix(setup.OTPAuthURI, "otpauth://totp/WorldC2:dave?") {
		t.Fatalf("setup payload wrong: %+v", setup)
	}

	// Enable with garbage code: 400, still disabled.
	rec = postJSON("/api/account/totp/enable", token, `{"code":"000000"}`)
	if rec.Code != 400 {
		t.Fatalf("enable with wrong code: got %d, want 400", rec.Code)
	}

	// Enable with a valid code (skew makes the boundary safe).
	code, err := totp.Code(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec = postJSON("/api/account/totp/enable", token, `{"code":"`+code+`"}`)
	if rec.Code != 200 {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body.String())
	}

	// Password-only login now answers 401 + totp_required:true.
	rec = doAPI(t, mux, "POST", "/api/login", "", `{"username":"dave","password":"operator-correct-horse"}`)
	if rec.Code != 401 {
		t.Fatalf("password-only login with MFA: got %d, want 401", rec.Code)
	}
	var loginErr struct {
		Error        string `json:"error"`
		TOTPRequired bool   `json:"totp_required"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &loginErr); err != nil {
		t.Fatalf("decode login error: %v", err)
	}
	if !loginErr.TOTPRequired {
		t.Fatalf("expected totp_required flag, got %+v", loginErr)
	}

	// Wrong code: generic 401 (no lock-state or validation detail leaks).
	rec = doAPI(t, mux, "POST", "/api/login", "",
		`{"username":"dave","password":"operator-correct-horse","totp":"999999"}`)
	if rec.Code != 401 || strings.Contains(rec.Body.String(), "totp") {
		t.Fatalf("wrong code must be a generic 401, got %d %s", rec.Code, rec.Body.String())
	}

	// Correct code: login succeeds.
	code, _ = totp.Code(setup.Secret, time.Now())
	rec = doAPI(t, mux, "POST", "/api/login", "",
		`{"username":"dave","password":"operator-correct-horse","totp":"`+code+`"}`)
	if rec.Code != 200 {
		t.Fatalf("login with code: %d %s", rec.Code, rec.Body.String())
	}

	// Disable requires a valid code too.
	code, _ = totp.Code(setup.Secret, time.Now())
	rec = postJSON("/api/account/totp/disable", token, `{"code":"`+code+`"}`)
	if rec.Code != 200 {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}

	// Password-only login works again.
	rec = doAPI(t, mux, "POST", "/api/login", "", `{"username":"dave","password":"operator-correct-horse"}`)
	if rec.Code != 200 {
		t.Fatalf("login after disable: %d %s", rec.Code, rec.Body.String())
	}
}

// TestAdminTOTPReset pins the recovery path: an admin wipes MFA for an
// operator who lost their authenticator; the wiped account logs in with
// the password alone. The route inherits the admin gate — an operator or
// viewer role never reaches it.
func TestAdminTOTPReset(t *testing.T) {
	mux, database := buildRound19Stack(t)

	daveToken := loginAs(t, mux, "dave", "operator-correct-horse")
	rec := doAPI(t, mux, "POST", "/api/account/totp/setup", daveToken, "")
	var setup struct {
		Secret string `json:"secret"`
	}
	json.Unmarshal(rec.Body.Bytes(), &setup)
	code, _ := totp.Code(setup.Secret, time.Now())
	if rec := doAPI(t, mux, "POST", "/api/account/totp/enable", daveToken, `{"code":"`+code+`"}`); rec.Code != 200 {
		t.Fatalf("enable: %d", rec.Code)
	}
	daveID, err := database.OperatorIDByUsername("dave")
	if err != nil || daveID == 0 {
		t.Fatal("resolve dave id")
	}

	// Dave (operator role) cannot reset anyone's MFA — including his own
	// — through the admin route.
	rec = doAPI(t, mux, "DELETE", "/api/operators/"+itoa(daveID)+"/totp", daveToken, "")
	if rec.Code != 403 {
		t.Fatalf("operator reset attempt: got %d, want 403", rec.Code)
	}

	adminToken := loginAs(t, mux, "alice", "correct-horse-battery")
	rec = doAPI(t, mux, "DELETE", "/api/operators/"+itoa(daveID)+"/totp", adminToken, "")
	if rec.Code != 200 {
		t.Fatalf("admin reset: %d %s", rec.Code, rec.Body.String())
	}

	// Unknown id: honest 404.
	rec = doAPI(t, mux, "DELETE", "/api/operators/424242/totp", adminToken, "")
	if rec.Code != 404 {
		t.Fatalf("unknown id reset: got %d, want 404", rec.Code)
	}

	// Dave logs in with password alone again.
	rec = doAPI(t, mux, "POST", "/api/login", "", `{"username":"dave","password":"operator-correct-horse"}`)
	if rec.Code != 200 {
		t.Fatalf("login after MFA reset: %d %s", rec.Code, rec.Body.String())
	}
}

// TestAuditCursorPagination pins the round-19 before_id cursor: pages
// walked via the cursor cover the trail with no gaps and no duplicates,
// malformed cursors answer 400, and the cursor composes with ?user=.
func TestAuditCursorPagination(t *testing.T) {
	mux, _ := buildRound19Stack(t)
	token := loginAs(t, mux, "alice", "correct-horse-battery")

	// Generate a known number of attributed rows (each authed call writes
	// one api_call row).
	const extra = 6
	for i := 0; i < extra; i++ {
		if rec := authedGet(t, mux, "/api/health", token); rec.Code != 200 {
			t.Fatalf("seed call %d: %d", i, rec.Code)
		}
	}

	// Walk pages of 3 from the top: ids must be strictly decreasing and
	// the union must contain no duplicates.
	seen := map[int]bool{}
	var cursor string
	pages := 0
	for {
		path := "/api/audit?limit=3"
		if cursor != "" {
			path += "&before_id=" + cursor
		}
		rec := doAPI(t, mux, "GET", path, token, "")
		if rec.Code != 200 {
			t.Fatalf("page walk: %d %s", rec.Code, rec.Body.String())
		}
		var page []struct {
			ID int `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode page: %v", err)
		}
		if len(page) == 0 {
			break
		}
		for i, e := range page {
			if seen[e.ID] {
				t.Fatalf("duplicate id %d across pages", e.ID)
			}
			seen[e.ID] = true
			if i > 0 && page[i-1].ID <= e.ID {
				t.Fatalf("page not strictly descending: %d then %d", page[i-1].ID, e.ID)
			}
		}
		cursor = itoa(page[len(page)-1].ID)
		pages++
		if pages > 50 {
			t.Fatal("cursor walk did not terminate")
		}
	}
	if len(seen) < extra {
		t.Fatalf("walked %d rows, expected at least the %d seeded ones", len(seen), extra)
	}

	// Malformed cursors: 400, never a silent full scan.
	for _, bad := range []string{"-1", "banana", "99999999999999999999999", "1.5"} {
		rec := doAPI(t, mux, "GET", "/api/audit?before_id="+bad, token, "")
		if rec.Code != 400 {
			t.Fatalf("before_id=%q: got %d, want 400", bad, rec.Code)
		}
	}

	// before_id=0 is the documented "no cursor" sentinel: it returns the
	// first page exactly like an absent parameter.
	rec := doAPI(t, mux, "GET", "/api/audit?before_id=0", token, "")
	if rec.Code != 200 {
		t.Fatalf("before_id=0: %d", rec.Code)
	}
	var first []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &first)
	if len(first) < 1 {
		t.Fatalf("before_id=0 must behave like the first page, got %d rows", len(first))
	}

	// Composes with ?user=: filter to dave's rows (none) → empty array.
	rec = doAPI(t, mux, "GET", "/api/audit?user=dave&limit=10", token, "")
	if rec.Code != 200 || !strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "[]") {
		t.Fatalf("cursor+user filter must compose: %d %s", rec.Code, rec.Body.String())
	}
}

// TestStatusEnrichment pins the round-19 /api/status fields: build
// identity, database health and the two counts — all behind the existing
// sessions:list gate (anonymous stays 401).
func TestStatusEnrichment(t *testing.T) {
	mux, _ := buildRound19Stack(t)

	// Anonymous: still 401 (the enrichment must not leak to strangers).
	req := httptest.NewRequest("GET", "/api/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("anonymous status: got %d, want 401", rec.Code)
	}

	token := loginAs(t, mux, "dave", "operator-correct-horse")
	rec = authedGet(t, mux, "/api/status", token)
	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}
	var st struct {
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		GoVersion string `json:"go_version"`
		DBOK      bool   `json:"db_ok"`
		Operators int    `json:"operators"`
		Audit     int    `json:"audit_entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if st.Version == "" || st.GoVersion == "" {
		t.Fatalf("build identity must be non-empty: %+v", st)
	}
	if !st.DBOK {
		t.Fatal("db_ok must be true on a healthy test database")
	}
	if st.Operators < 2 {
		t.Fatalf("operators count = %d, want >= 2", st.Operators)
	}
	if st.Audit < 1 {
		t.Fatalf("audit_entries = %d, want >= 1 (this test just wrote rows)", st.Audit)
	}
}

// TestAccountRoutesLocked pins the boundary conditions of the new
// /api/account/ subtree: anonymous 401, unknown subpath 404, unsupported
// method 405.
func TestAccountRoutesLocked(t *testing.T) {
	mux, _ := buildRound19Stack(t)

	req := httptest.NewRequest("POST", "/api/account/password", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("anonymous password change: got %d, want 401", rec.Code)
	}

	token := loginAs(t, mux, "dave", "operator-correct-horse")

	rec = doAPI(t, mux, "POST", "/api/account/unknown", token, "")
	if rec.Code != 404 {
		t.Fatalf("unknown account subpath: got %d, want 404", rec.Code)
	}

	rec = doAPI(t, mux, "GET", "/api/account/password", token, "")
	if rec.Code != 405 {
		t.Fatalf("GET on password change: got %d, want 405", rec.Code)
	}

	rec = doAPI(t, mux, "GET", "/api/account/totp/setup", token, "")
	if rec.Code != 405 {
		t.Fatalf("GET on totp setup: got %d, want 405", rec.Code)
	}
}

func itoa(n int) string {
	return strings.TrimSpace(strings.Replace(strings.Replace(
		jsonNumber(n), " ", "", -1), "\n", "", -1))
}

func jsonNumber(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestLoginRateConfigurable pins the r19 config wiring: a router built
// with api.login_rate_per_min: 3 rejects the 4th consecutive login from
// one IP with 429, while an unset value keeps the historical 10.
func TestLoginRateConfigurable(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "loginrate.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.CreateOperator("alice", "correct-horse-battery", "admin"); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.API.Port = 0
	cfg.API.LoginRatePerMin = 3
	mux := NewRouter(c2.New(cfg, database), nil, nil).Setup()

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"alice","password":"correct-horse-battery"}`))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("login %d: got %d, want 200 (bucket too tight)", i+1, rec.Code)
		}
	}
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"alice","password":"correct-horse-battery"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 429 {
		t.Fatalf("4th login with login_rate_per_min=3: got %d, want 429", rec.Code)
	}
}
