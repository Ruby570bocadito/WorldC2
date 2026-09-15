package handlers

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/config"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
)

// TestMetricsContract pins the round-16 /api/metrics contract: the
// endpoint is authenticated (401 without a token), gated by
// sessions:list (same privilege as /api/status), and speaks the
// Prometheus text exposition format — one HELP/TYPE header pair per
// metric plus the sample itself.
func TestMetricsContract(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	// Unauthenticated scrapes are refused: telemetry counts are still
	// operational intelligence (uptime alone fingerprints a target).
	req := httptest.NewRequest("GET", "/api/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("unauthenticated metrics: got %d, want 401", rec.Code)
	}

	req = httptest.NewRequest("GET", "/api/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("metrics: got %d %s", rec.Code, rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") || !strings.Contains(ct, "version=0.0.4") {
		t.Fatalf("content-type: got %q, want Prometheus text version=0.0.4", ct)
	}

	body := rec.Body.String()
	required := []string{
		"worldc2_build_info",
		"worldc2_uptime_seconds",
		"worldc2_sessions_active",
		"worldc2_sessions_total",
		"worldc2_tasks_total",
		"worldc2_vault_credentials",
		"worldc2_files_stored",
		"worldc2_webhooks_configured",
		"worldc2_webhooks_delivered_total",
		"worldc2_webhooks_failed_total",
		"worldc2_listeners",
		"worldc2_go_goroutines",
		"worldc2_go_heap_alloc_bytes",
	}
	for _, m := range required {
		if !strings.Contains(body, "# HELP "+m+" ") || !strings.Contains(body, "# TYPE "+m+" gauge") {
			t.Errorf("metric %s missing HELP/TYPE header", m)
		}
		// Labeled samples (build_info) render as name{...}; plain
		// ones as name value.
		if !strings.Contains(body, "\n"+m+" ") && !strings.Contains(body, "\n"+m+"{") {
			t.Errorf("metric %s missing sample line", m)
		}
	}

	// No credential material may ever leak into metrics: only counts.
	if strings.Contains(body, "password") || strings.Contains(body, "cred-") {
		t.Errorf("metrics leak credential-shaped data")
	}

	// Samples must be bare numbers (no 1e+06 float formatting).
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "worldc2_") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				t.Fatalf("malformed sample line %q", line)
			}
			v := fields[1]
			if strings.ContainsAny(v, "eE") {
				t.Errorf("sample %s uses exponent formatting: %q", fields[0], v)
			}
		}
	}
}

// TestMetricsValuesTrackReality seeds a credential and verifies the
// gauges actually move — a metrics endpoint that always prints zeros is
// worse than none.
func TestMetricsValuesTrackReality(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	get := func() map[string]string {
		req := httptest.NewRequest("GET", "/api/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("metrics: %d", rec.Code)
		}
		out := map[string]string{}
		for _, line := range strings.Split(rec.Body.String(), "\n") {
			if strings.HasPrefix(line, "worldc2_") {
				f := strings.Fields(line)
				out[f[0]] = f[1]
			}
		}
		return out
	}

	before := get()

	// Seed one credential through the API.
	rec := adminPost(t, mux, token, "/api/vault", `{"username":"metric-user","password":"P@ss"}`)
	if rec.Code != 200 {
		t.Fatalf("store credential: %d %s", rec.Code, rec.Body.String())
	}

	after := get()
	if after["worldc2_vault_credentials"] == before["worldc2_vault_credentials"] {
		t.Fatalf("vault gauge did not move: %s -> %s", before["worldc2_vault_credentials"], after["worldc2_vault_credentials"])
	}
	if after["worldc2_vault_credentials"] == "0" {
		t.Fatalf("vault gauge still zero after one insert")
	}
	if after["worldc2_uptime_seconds"] == "" {
		t.Fatalf("uptime gauge missing")
	}
}

// TestSessionsDaysWindow pins the round-16 ?days= filter on
// /api/sessions: strict parsing (shared with the report), filtering by
// last_seen, and an untouched default (no parameter → everything).
func TestSessionsDaysWindow(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "days.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.CreateOperator("alice", "correct-horse-battery", "admin"); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	old := &db.SessionRecord{
		ID: "sess-old", AgentID: "agent-old", Hostname: "old-host",
		State: "active", FirstSeen: time.Now().Add(-30 * 24 * time.Hour),
		LastSeen: time.Now().Add(-30 * 24 * time.Hour),
	}
	fresh := &db.SessionRecord{
		ID: "sess-fresh", AgentID: "agent-fresh", Hostname: "fresh-host",
		State: "active", FirstSeen: time.Now(), LastSeen: time.Now(),
	}
	if err := database.UpsertSession(old); err != nil {
		t.Fatalf("seed old: %v", err)
	}
	if err := database.UpsertSession(fresh); err != nil {
		t.Fatalf("seed fresh: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.API.Port = 0
	mux := NewRouter(c2.New(cfg, database), nil, nil).Setup()
	token := login(t, mux)

	get := func(path string) (int, string) {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	code, body := get("/api/sessions")
	if code != 200 {
		t.Fatalf("no window: %d %s", code, body)
	}
	if !strings.Contains(body, "sess-old") || !strings.Contains(body, "sess-fresh") {
		t.Fatalf("no window must return everything, got %s", body)
	}

	code, body = get("/api/sessions?days=7")
	if code != 200 {
		t.Fatalf("days=7: %d %s", code, body)
	}
	if strings.Contains(body, "sess-old") {
		t.Fatalf("days=7 must exclude a session last seen 30 days ago, got %s", body)
	}
	if !strings.Contains(body, "sess-fresh") {
		t.Fatalf("days=7 must include the fresh session, got %s", body)
	}

	code, body = get("/api/sessions?days=90")
	if code != 200 || !strings.Contains(body, "sess-old") {
		t.Fatalf("days=90 must include the old session: %d %s", code, body)
	}

	for _, bad := range []string{"0", "-1", "91", "banana", "99999999999999999999"} {
		code, _ = get("/api/sessions?days=" + bad)
		if code != 400 {
			t.Errorf("days=%s: got %d, want 400", bad, code)
		}
	}
}

// TestFilesDaysWindow pins the round-16 ?days= filter on /api/files:
// records created outside the window disappear, the default is untouched,
// and invalid windows answer 400 before any listing happens.
func TestFilesDaysWindow(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "files-days.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.CreateOperator("alice", "correct-horse-battery", "admin"); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	// file_records carries a FOREIGN KEY to sessions — seed the parent row
	// first (old record attached to it, so both rows share the session).
	if err := database.UpsertSession(&db.SessionRecord{
		ID: "sess-x", AgentID: "agent-x", Hostname: "host-x",
		State: "active", FirstSeen: time.Now(), LastSeen: time.Now(),
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	oldRec := &db.FileRecord{
		ID: "file-old", SessionID: "sess-x", Filename: "old.bin",
		Module: "collect", Created: time.Now().Add(-30 * 24 * time.Hour),
	}
	if err := database.InsertFileRecord(oldRec); err != nil {
		t.Fatalf("seed old record: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.API.Port = 0
	server := c2.New(cfg, database)
	// Start() attaches the persistence layer to the loot manager; the test
	// never starts the server, so mirror that wiring here (otherwise
	// List() only sees the in-memory records and the old row is invisible).
	server.Files().SetDB(database)
	mux := NewRouter(server, nil, nil).Setup()
	token := login(t, mux)

	// Store a fresh record through the API (also proves the merge of
	// memory + DB rows still works under the filter).
	rec := adminPost(t, mux, token, "/api/files",
		`{"session_id":"sess-x","filename":"fresh.bin","module":"collect","data":"aGk="}`)
	if rec.Code != 200 {
		t.Fatalf("store fresh: %d %s", rec.Code, rec.Body.String())
	}

	get := func(path string) (int, string) {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	code, body := get("/api/files")
	if code != 200 || !strings.Contains(body, "old.bin") || !strings.Contains(body, "fresh.bin") {
		t.Fatalf("no window must return everything: %d %s", code, body)
	}

	code, body = get("/api/files?days=7")
	if code != 200 {
		t.Fatalf("days=7: %d", code)
	}
	if strings.Contains(body, "old.bin") {
		t.Fatalf("days=7 must exclude a 30-day-old record, got %s", body)
	}
	if !strings.Contains(body, "fresh.bin") {
		t.Fatalf("days=7 must include the fresh record, got %s", body)
	}

	for _, bad := range []string{"0", "-3", "91", "soon", "99999999999999999999"} {
		code, _ = get("/api/files?days=" + bad)
		if code != 400 {
			t.Errorf("days=%s: got %d, want 400", bad, code)
		}
	}
}
