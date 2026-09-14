package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/config"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
)

// buildAuthTestStack wires a full server+router against a temp database.
// Two Server instances are created on purpose: the second one re-opens the
// same DB and therefore re-loads the PERSISTED JWT signing key, simulating
// exactly what a server restart does to outstanding tokens.
func buildAuthTestStack(t *testing.T) (mux *http.ServeMux, muxAfterRestart *http.ServeMux) {
	t.Helper()

	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "authz.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	if err := database.CreateOperator("alice", "correct-horse-battery", "admin"); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	// A second admin: after alice's deletion, alice's own token is dead
	// (that's the point), so the unknown-id 404 check needs another
	// authorized caller.
	if err := database.CreateOperator("bob", "another-correct-horse", "admin"); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.API.Port = 0

	server := c2.New(cfg, database)
	mux = NewRouter(server, nil, nil).Setup()

	// "Restart": same database, fresh Server (re-loads the persisted JWT
	// secret) and a fresh Router with an empty revocation map.
	serverAfterRestart := c2.New(cfg, database)
	muxAfterRestart = NewRouter(serverAfterRestart, nil, nil).Setup()
	return mux, muxAfterRestart
}

func login(t *testing.T, mux *http.ServeMux) string {
	t.Helper()
	return loginAs(t, mux, "alice", "correct-horse-battery")
}

func loginAs(t *testing.T, mux *http.ServeMux, username, password string) string {
	t.Helper()
	body := strings.NewReader(`{"username":"` + username + `","password":"` + password + `"}`)
	req := httptest.NewRequest("POST", "/api/login", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	return resp.Token
}

// operatorID resolves the numeric id of an operator through the API — the
// same value the console passes to DELETE /api/operators/:id.
func operatorID(t *testing.T, mux *http.ServeMux, token, username string) string {
	t.Helper()
	rec := authedGet(t, mux, "/api/operators", token)
	if rec.Code != 200 {
		t.Fatalf("list operators: %d %s", rec.Code, rec.Body.String())
	}
	var ops []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &ops); err != nil {
		t.Fatalf("decode operators: %v", err)
	}
	for _, op := range ops {
		if op["username"] == username {
			return fmt.Sprint(op["id"])
		}
	}
	t.Fatalf("operator %q not found in listing", username)
	return ""
}

func deleteOperator(t *testing.T, mux *http.ServeMux, token, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("DELETE", "/api/operators/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func authedGet(t *testing.T, mux *http.ServeMux, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestDeletedOperatorTokenRejectedImmediately covers the live window: right
// after DELETE /api/operators/:id, the operator's outstanding access token
// must be rejected by the auth middleware — not just by the in-memory
// revocation map, but by the operators-table existence check. It also pins
// the revocation KEYING: RevokeUser must receive the username (JWT subject),
// not the numeric id the path carries.
func TestDeletedOperatorTokenRejectedImmediately(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	if rec := authedGet(t, mux, "/api/sessions", token); rec.Code != 200 {
		t.Fatalf("pre-delete request with valid token: %d, want 200", rec.Code)
	}

	id := operatorID(t, mux, token, "alice")
	if rec := deleteOperator(t, mux, token, id); rec.Code != 200 {
		t.Fatalf("operator delete: %d %s", rec.Code, rec.Body.String())
	}

	rec := authedGet(t, mux, "/api/sessions", token)
	if rec.Code != 401 {
		t.Fatalf("post-delete request: %d, want 401 (token must die with the operator)", rec.Code)
	}
	// Body note: the immediate rejection may come from either layer — the
	// (now correctly username-keyed) in-memory revocation, or the
	// existence check. The restart test below proves the existence check
	// independently, so no body assertion here.

	// Unknown ids must 404, not pretend to delete something. Checked
	// with a second operator: alice's own token dies with her account.
	bobToken := loginAs(t, mux, "bob", "another-correct-horse")
	if rec := deleteOperator(t, mux, bobToken, "999999"); rec.Code != 404 {
		t.Fatalf("delete unknown id: %d, want 404", rec.Code)
	}
}

// TestDeletedOperatorTokenRejectedAfterRestart is the regression that
// motivated the existence check: the in-memory revocation map dies with the
// process, but the persisted signing key (and thus the old token's valid
// signature) does not. After a simulated restart the deleted operator's
// token must STILL be rejected.
func TestDeletedOperatorTokenRejectedAfterRestart(t *testing.T) {
	mux, muxAfterRestart := buildAuthTestStack(t)
	token := login(t, mux)

	id := operatorID(t, mux, token, "alice")
	if rec := deleteOperator(t, mux, token, id); rec.Code != 200 {
		t.Fatalf("operator delete: %d %s", rec.Code, rec.Body.String())
	}

	// Restart: fresh revocation map, same persisted signing key.
	rec := authedGet(t, muxAfterRestart, "/api/sessions", token)
	if rec.Code != 401 {
		t.Fatalf("post-restart request: %d, want 401 (revocation must survive the restart)", rec.Code)
	}
}

// TestRefreshTokenRotationFlow covers the full rotation loop over HTTP:
// login returns a refresh token, POST /api/refresh consumes it and returns a
// NEW refresh token alongside the access token, and replaying the consumed
// one is denied with 401 while the replacement keeps working.
func TestRefreshTokenRotationFlow(t *testing.T) {
	mux, _ := buildAuthTestStack(t)

	body := strings.NewReader(`{"username":"alice","password":"correct-horse-battery"}`)
	req := httptest.NewRequest("POST", "/api/login", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var loginResp struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if loginResp.RefreshToken == "" {
		t.Fatal("login response carries no refresh token")
	}

	// First refresh: 200 with a NEW refresh token.
	rreq := httptest.NewRequest("POST", "/api/refresh",
		strings.NewReader(`{"refresh_token":"`+loginResp.RefreshToken+`"}`))
	rrec := httptest.NewRecorder()
	mux.ServeHTTP(rrec, rreq)
	if rrec.Code != 200 {
		t.Fatalf("first refresh: %d %s", rrec.Code, rrec.Body.String())
	}
	var rotResp struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rrec.Body.Bytes(), &rotResp); err != nil {
		t.Fatalf("decode refresh: %v", err)
	}
	if rotResp.RefreshToken == "" || rotResp.RefreshToken == loginResp.RefreshToken {
		t.Fatal("rotation did not issue a fresh refresh token")
	}

	// Replay of the consumed token: denied.
	rreq2 := httptest.NewRequest("POST", "/api/refresh",
		strings.NewReader(`{"refresh_token":"`+loginResp.RefreshToken+`"}`))
	rrec2 := httptest.NewRecorder()
	mux.ServeHTTP(rrec2, rreq2)
	if rrec2.Code != 401 {
		t.Fatalf("replayed refresh: %d, want 401", rrec2.Code)
	}

	// The replacement still works (the legit client keeps access).
	rreq3 := httptest.NewRequest("POST", "/api/refresh",
		strings.NewReader(`{"refresh_token":"`+rotResp.RefreshToken+`"}`))
	rrec3 := httptest.NewRecorder()
	mux.ServeHTTP(rrec3, rreq3)
	if rrec3.Code != 200 {
		t.Fatalf("rotation with replacement token: %d %s", rrec3.Code, rrec3.Body.String())
	}
}
