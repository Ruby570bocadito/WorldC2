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
)

// vaultDelete issues an authenticated DELETE against the test mux.
func vaultDelete(t *testing.T, mux *http.ServeMux, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("DELETE", path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// vaultGet issues an authenticated GET against the test mux.
func vaultGet(t *testing.T, mux *http.ServeMux, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// storeCred POSTs a credential and returns the minted ID.
func storeCred(t *testing.T, mux *http.ServeMux, token, body string) string {
	t.Helper()
	rec := adminPost(t, mux, token, "/api/vault", body)
	if rec.Code != 200 {
		t.Fatalf("store credential: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.ID == "" {
		t.Fatalf("store response: %s", rec.Body.String())
	}
	return resp.ID
}

// TestVaultDeleteLifecycle covers the round-15 DELETE /api/vault contract:
// create → delete answers 200, a second delete answers 404 precisely (the
// db layer now reports affected rows), and the listing reflects the removal.
func TestVaultDeleteLifecycle(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	id := storeCred(t, mux, token, `{"username":"svc-backup","password":"P@ss","host":"dc01.corp"}`)

	rec := vaultDelete(t, mux, token, "/api/vault?id="+id)
	if rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}

	// The ID must be gone from the listing…
	rec = vaultGet(t, mux, token, "/api/vault")
	var creds []db.CredentialRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &creds); err != nil {
		t.Fatalf("list: %s", rec.Body.String())
	}
	for _, c := range creds {
		if c.ID == id {
			t.Fatalf("deleted credential %s still listed", id)
		}
	}

	// …and a repeat delete must be a 404, not a silent 200.
	if rec := vaultDelete(t, mux, token, "/api/vault?id="+id); rec.Code != 404 {
		t.Fatalf("repeat delete: %d, want 404", rec.Code)
	}
}

// TestVaultDeleteAuthorization pins the permission mapping: vault:delete is
// admin-only, so an operator (who CAN read and create) must get 403 on
// DELETE — permanent loot removal is a different privilege from capture.
func TestVaultDeleteAuthorization(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	admin := login(t, mux)

	// A role-limited operator via the operators API.
	rec := adminPost(t, mux, admin, "/api/operators", `{"username":"opkid","password":"another-correct-horse","role":"operator"}`)
	if rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("create operator: %d %s", rec.Code, rec.Body.String())
	}
	opToken := loginAs(t, mux, "opkid", "another-correct-horse")

	id := storeCred(t, mux, opToken, `{"username":"lowvalue","password":"x"}`)

	if rec := vaultGet(t, mux, opToken, "/api/vault"); rec.Code != 200 {
		t.Fatalf("operator read: %d (vault:read — must pass)", rec.Code)
	}
	if rec := vaultDelete(t, mux, opToken, "/api/vault?id="+id); rec.Code != 403 {
		t.Fatalf("operator delete: %d, want 403 (vault:delete is admin-only)", rec.Code)
	}
}

// TestVaultSearchCap closes the round-14 residual: the ?q= search term used
// to accept unbounded lengths (the search runs in Go over decrypted rows,
// so a megabyte term forced that work per request).
func TestVaultSearchCap(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	storeCred(t, mux, token, `{"username":"needle","host":"dc01.corp"}`)

	rec := vaultGet(t, mux, token, "/api/vault?q=needle")
	if rec.Code != 200 {
		t.Fatalf("short query: %d %s", rec.Code, rec.Body.String())
	}

	rec = vaultGet(t, mux, token, "/api/vault?q="+strings.Repeat("x", 257))
	if rec.Code != 400 {
		t.Fatalf("257-char query: %d, want 400", rec.Code)
	}
}

// reportStack wires the auth stack while keeping the database handle, so
// tests can backdate rows directly (the API sets captured/last_seen to now,
// which no window could ever exclude).
func reportStack(t *testing.T) (*http.ServeMux, *db.DB, string) {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "report.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	if err := database.CreateOperator("alice", "correct-horse-battery", "admin"); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.API.Port = 0
	mux := NewRouter(c2.New(cfg, database), nil, nil).Setup()
	return mux, database, login(t, mux)
}

// reportSummary decodes the fields the tests assert on. The report structs
// carry no json tags, so the wire names are the Go names.
type reportSummary struct {
	Summary struct {
		TotalSessions    int `json:"TotalSessions"`
		TotalCredentials int `json:"TotalCredentials"`
	} `json:"Summary"`
	Sessions []struct {
		ID string `json:"ID"`
	} `json:"Sessions"`
	Credentials []struct {
		Username string `json:"Username"`
	} `json:"Credentials"`
}

// TestReportDaysWindow pins the round-15 ?days= parameter: it FILTERS the
// report content (sessions by last_seen, credentials by captured) instead of
// only relabeling the printed dates, and invalid values answer 400.
func TestReportDaysWindow(t *testing.T) {
	mux, database, token := reportStack(t)

	// One fresh capture (API path) and one 30-day-stale row (direct DB).
	storeCred(t, mux, token, `{"username":"fresh","host":"web01.corp"}`)
	stale := &db.CredentialRecord{ID: "cred-stale", Username: "stale", Captured: time.Now().Add(-30 * 24 * time.Hour)}
	if err := database.AddCredential(stale); err != nil {
		t.Fatalf("seed stale credential: %v", err)
	}
	freshSess := &db.SessionRecord{ID: "sess-fresh", AgentID: "agent-fresh", LastSeen: time.Now(), State: "active", OS: "windows"}
	staleSess := &db.SessionRecord{ID: "sess-stale", AgentID: "agent-stale", LastSeen: time.Now().Add(-30 * 24 * time.Hour), State: "active", OS: "linux"}
	for _, s := range []*db.SessionRecord{freshSess, staleSess} {
		if err := database.UpsertSession(s); err != nil {
			t.Fatalf("seed session: %v", err)
		}
	}

	t.Run("invalid days answer 400", func(t *testing.T) {
		for _, q := range []string{"?days=0", "?days=91", "?days=-3", "?days=banana", "?days=99999999999999999999"} {
			rec := authedGet(t, mux, "/api/report"+q, token)
			if rec.Code != 400 {
				t.Errorf("%s: %d, want 400 (body: %s)", q, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("narrow window filters stale rows", func(t *testing.T) {
		rec := authedGet(t, mux, "/api/report?format=json&days=1&download=1", token)
		if rec.Code != 200 {
			t.Fatalf("narrow report: %d %s", rec.Code, rec.Body.String())
		}
		var rs reportSummary
		if err := json.Unmarshal(rec.Body.Bytes(), &rs); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if rs.Summary.TotalCredentials != 1 || rs.Summary.TotalSessions != 1 {
			t.Fatalf("1-day window must keep only fresh rows: %+v", rs.Summary)
		}
		if len(rs.Credentials) != 1 || rs.Credentials[0].Username != "fresh" {
			t.Fatalf("stale credential leaked into the window: %+v", rs.Credentials)
		}
	})

	t.Run("wide window keeps everything", func(t *testing.T) {
		rec := authedGet(t, mux, "/api/report?format=json&days=90&download=1", token)
		if rec.Code != 200 {
			t.Fatalf("wide report: %d %s", rec.Code, rec.Body.String())
		}
		var rs reportSummary
		if err := json.Unmarshal(rec.Body.Bytes(), &rs); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if rs.Summary.TotalCredentials != 2 || rs.Summary.TotalSessions != 2 {
			t.Fatalf("90-day window must include both fresh and stale rows: %+v", rs.Summary)
		}
	})
}
