package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/config"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
)

// buildRound17Stack wires a full server+router against a temp database with
// an admin (alice) and a viewer (bob) — the two roles the round-17 audit
// contract distinguishes.
func buildRound17Stack(t *testing.T) (*http.ServeMux, *db.DB) {
	t.Helper()

	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "round17.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	if err := database.CreateOperator("alice", "correct-horse-battery", "admin"); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := database.CreateOperator("bob", "viewer-correct-horse", "viewer"); err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	if err := database.CreateOperator("carol", "auditor-correct-horse", "auditor"); err != nil {
		t.Fatalf("create auditor: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.API.Port = 0
	mux := NewRouter(c2.New(cfg, database), nil, nil).Setup()
	return mux, database
}

// TestAuditContract pins the round-17 /api/audit contract: gated by the
// audit:read PERMISSION (admin AND auditor — the permission rbac.go has
// carried since the early rounds finally wired to an endpoint), GET-only,
// JSON array body with the documented field names, and the trail actually
// records this very test's calls (the audit middleware writes one api_call
// row per request).
func TestAuditContract(t *testing.T) {
	mux, _ := buildRound17Stack(t)
	adminToken := login(t, mux)
	viewerToken := loginAs(t, mux, "bob", "viewer-correct-horse")
	auditorToken := loginAs(t, mux, "carol", "auditor-correct-horse")

	// Unauthenticated: no trail for strangers.
	req := httptest.NewRequest("GET", "/api/audit", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("unauthenticated audit: got %d, want 401", rec.Code)
	}

	// Viewer: audit:read is not in the viewer role — 403.
	req = httptest.NewRequest("GET", "/api/audit", nil)
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("viewer audit: got %d, want 403", rec.Code)
	}

	// Auditor: the trail is the auditor's whole job — 200 by design.
	req = httptest.NewRequest("GET", "/api/audit", nil)
	req.Header.Set("Authorization", "Bearer "+auditorToken)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("auditor audit: got %d, want 200 (audit:read)", rec.Code)
	}

	// Method gate: POST is not a trail operation.
	req = httptest.NewRequest("POST", "/api/audit", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 405 {
		t.Fatalf("POST audit: got %d, want 405", rec.Code)
	}

	// Admin: 200 with a JSON array whose newest entry is an api_call.
	req = httptest.NewRequest("GET", "/api/audit", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("admin audit: %d %s", rec.Code, rec.Body.String())
	}
	var entries []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode audit response: %v (body: %.100s)", err, rec.Body.String())
	}
	if len(entries) == 0 {
		t.Fatalf("audit trail empty after several audited calls")
	}
	for k, want := range map[string]bool{"id": true, "action": true, "detail": true, "created": true} {
		if _, ok := entries[0][k]; ok != want {
			t.Errorf("first audit entry: field %q present=%v, want %v", k, ok, want)
		}
	}
	if entries[0]["action"] != "api_call" {
		t.Errorf("newest entry action = %v, want api_call", entries[0]["action"])
	}
}

// TestAuditLimitAndFilter pins the ?limit= and ?action= parameters: strict
// bounds with 400s, exact page sizes, and exact event-type filtering.
func TestAuditLimitAndFilter(t *testing.T) {
	mux, _ := buildRound17Stack(t)
	token := login(t, mux)

	get := func(path string) (int, string) {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	count := func(body string) int {
		var entries []map[string]interface{}
		if err := json.Unmarshal([]byte(body), &entries); err != nil {
			t.Fatalf("decode: %v (body: %.100s)", err, body)
		}
		return len(entries)
	}

	// Page size is honored.
	code, body := get("/api/audit?limit=1")
	if code != 200 || count(body) != 1 {
		t.Fatalf("limit=1: %d %s", code, body)
	}

	// Strict bounds.
	for _, bad := range []string{"0", "-1", "501", "banana", "99999999999999999999"} {
		code, _ = get("/api/audit?limit=" + bad)
		if code != 400 {
			t.Errorf("limit=%s: got %d, want 400", bad, code)
		}
	}

	// Exact action filter: auth_success exists after login; a nonsense
	// action returns an (empty) array, never an error.
	code, body = get("/api/audit?action=auth_success")
	if code != 200 {
		t.Fatalf("action=auth_success: %d", code)
	}
	if count(body) < 1 {
		t.Fatalf("no auth_success entry after login")
	}
	for _, e := range entriesOf(t, body) {
		if e["action"] != "auth_success" {
			t.Fatalf("filter leaked another action: %v", e["action"])
		}
	}

	code, body = get("/api/audit?action=no-such-action-ever")
	if code != 200 || count(body) != 0 {
		t.Errorf("unknown action: %d %s", code, body)
	}

	// Over-long filter is rejected before it reaches the SQL layer.
	code, _ = get("/api/audit?action=" + strings.Repeat("x", 65))
	if code != 400 {
		t.Errorf("65-char action: got %d, want 400", code)
	}
}

func entriesOf(t *testing.T, body string) []map[string]interface{} {
	t.Helper()
	var entries []map[string]interface{}
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return entries
}

// TestTaskHistoryPagination walks the paginated task history through the
// API exactly like the console's "Load more" does: page after page via the
// opaque composite cursor, collecting every task — no duplicates, no gaps —
// including a tie group of two tasks sharing one timestamp.
func TestTaskHistoryPagination(t *testing.T) {
	mux, database := buildRound17Stack(t)
	token := login(t, mux)

	if err := database.UpsertSession(&db.SessionRecord{
		ID: "sess-p", AgentID: "agent-p", Hostname: "page-host",
		State: "active", FirstSeen: time.Now(), LastSeen: time.Now(),
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// 7 tasks: 5 with distinct timestamps + a tie group of 2 sharing one.
	// The tie group is the whole point of the composite cursor.
	base := time.Now().Add(-1 * time.Hour).UTC()
	want := map[string]bool{}
	times := []time.Time{
		base.Add(1 * time.Second),
		base.Add(2 * time.Second),
		base.Add(3 * time.Second),
		base.Add(4 * time.Second),
		base.Add(4 * time.Second), // tie
		base.Add(5 * time.Second),
		base.Add(6 * time.Second),
	}
	for i, ts := range times {
		id := fmt.Sprintf("task-%02d", i)
		if err := database.InsertTask(&db.TaskRecord{
			ID: id, SessionID: "sess-p", Command: "cmd-" + id, IssuedAt: ts,
		}); err != nil {
			t.Fatalf("seed task: %v", err)
		}
		want[id] = true
	}

	get := func(path string) (int, map[string]interface{}) {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			return rec.Code, nil
		}
		var data map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return rec.Code, data
	}

	got := map[string]bool{}
	pages := 0
	path := "/api/sessions/sess-p?limit=3"
	for {
		code, data := get(path)
		if code != 200 {
			t.Fatalf("page %d: code %d (%s)", pages, code, path)
		}
		tasks, _ := data["tasks"].([]interface{})
		if pages > 0 && len(tasks) == 0 {
			t.Fatalf("cursor produced an empty page before exhausting history")
		}
		pages++
		for _, raw := range tasks {
			task, _ := raw.(map[string]interface{})
			id, _ := task["ID"].(string)
			if got[id] {
				t.Fatalf("duplicate task across pages: %s", id)
			}
			got[id] = true
		}
		hasMore, _ := data["has_more"].(bool)
		if !hasMore {
			break
		}
		next, _ := data["next_page"].(map[string]interface{})
		before, _ := next["before"].(string)
		beforeID, _ := next["before_id"].(string)
		if before == "" || beforeID == "" {
			t.Fatalf("has_more=true but next_page cursor incomplete: %v", next)
		}
		path = "/api/sessions/sess-p?limit=3&before=" + url.QueryEscape(before) + "&before_id=" + url.QueryEscape(beforeID)
	}

	if len(got) != len(want) {
		t.Fatalf("pagination lost rows: got %d unique tasks, want %d", len(got), len(want))
	}
	for id := range want {
		if !got[id] {
			t.Errorf("task %s never returned", id)
		}
	}

	// Strict limits: 0, 201 and garbage → 400.
	for _, bad := range []string{"0", "201", "banana"} {
		req := httptest.NewRequest("GET", "/api/sessions/sess-p?limit="+bad, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Errorf("limit=%s: got %d, want 400", bad, rec.Code)
		}
	}

	// before without before_id → 400 (composite cursor, no half cursors).
	req := httptest.NewRequest("GET", "/api/sessions/sess-p?before=2026-01-01", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Errorf("before without before_id: got %d, want 400", rec.Code)
	}

	// Hostile cursor → 400, not 500.
	req = httptest.NewRequest("GET", "/api/sessions/sess-p?before=%27%20OR%201%3D1%20--&before_id=x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Errorf("hostile cursor: got %d, want 400", rec.Code)
	}
}

// TestMetricsBuildInfo pins the round-17 worldc2_build_info gauge: one
// labeled sample, value 1, with version/commit/go_version labels present
// and properly quoted.
func TestMetricsBuildInfo(t *testing.T) {
	mux, _ := buildRound17Stack(t)
	token := login(t, mux)

	req := httptest.NewRequest("GET", "/api/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("metrics: %d", rec.Code)
	}
	body := rec.Body.String()

	if !strings.Contains(body, "# HELP worldc2_build_info ") ||
		!strings.Contains(body, "# TYPE worldc2_build_info gauge") {
		t.Fatalf("build_info HELP/TYPE missing:\n%s", body)
	}

	var sample string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "worldc2_build_info{") {
			sample = line
			break
		}
	}
	if sample == "" {
		t.Fatalf("no labeled worldc2_build_info sample in:\n%s", body)
	}

	for _, want := range []string{`version="dev"`, `commit="unknown"`, `go_version="`} {
		if !strings.Contains(sample, want) {
			t.Errorf("build_info sample %q missing label %s", sample, want)
		}
	}
	fields := strings.Fields(sample)
	if len(fields) != 2 || fields[1] != "1" {
		t.Errorf("build_info sample must be a single '1', got %q", sample)
	}
}
