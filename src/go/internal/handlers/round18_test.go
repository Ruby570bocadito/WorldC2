package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// doAPI issues an arbitrary method against the mux with a bearer token.
func doAPI(t *testing.T, mux *http.ServeMux, method, path, token string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// createWebhook registers a destination through the real API and returns its ID.
func createWebhook(t *testing.T, mux *http.ServeMux, token, url string) string {
	t.Helper()
	rec := adminPost(t, mux, token, "/api/webhooks", fmt.Sprintf(`{"url":%q,"timeout_ms":3000}`, url))
	if rec.Code != 201 {
		t.Fatalf("create webhook: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	return resp.ID
}

// webhookTest fires the test endpoint and decodes the outcome body.
func webhookTest(t *testing.T, mux *http.ServeMux, token, id string) map[string]any {
	t.Helper()
	rec := doAPI(t, mux, "POST", "/api/webhooks/test?id="+id, token, "")
	if rec.Code != 200 {
		t.Fatalf("webhook test: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode test result: %v", err)
	}
	return out
}

// TestAuditUserFilter pins the round-18 /api/audit ?user= contract end to
// end: every authenticated api_call is attributed to the exact account
// (X-Auth-UID resolved by the auth middleware), the filter answers with
// only that account's rows, unknown usernames give an empty array (no
// existence oracle) and over-long filters are a 400.
func TestAuditUserFilter(t *testing.T) {
	mux, _ := buildRound17Stack(t)
	adminToken := login(t, mux)

	// Generate attributed traffic: a couple of authenticated calls.
	authedGet(t, mux, "/api/sessions", adminToken)
	authedGet(t, mux, "/api/health", adminToken) // health has no auth — anonymous
	_ = adminToken

	rec := authedGet(t, mux, "/api/audit?limit=500", adminToken)
	if rec.Code != 200 {
		t.Fatalf("audit list: %d", rec.Code)
	}
	var all []struct {
		ID       int    `json:"id"`
		Action   string `json:"action"`
		Detail   string `json:"detail"`
		Operator string `json:"operator"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &all); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("expected audit rows")
	}
	// The trail must carry attributed rows now — api_call by alice.
	sawAttributed := false
	for _, e := range all {
		if e.Action == "api_call" && e.Operator == "alice" && strings.Contains(e.Detail, "by alice") {
			sawAttributed = true
		}
	}
	if !sawAttributed {
		t.Fatal("no api_call row attributed to alice — attribution broken")
	}

	// ?user=alice: only alice rows come back.
	rec = authedGet(t, mux, "/api/audit?limit=500&user=alice", adminToken)
	var alice []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &alice); err != nil {
		t.Fatalf("decode user-filtered: %v", err)
	}
	if len(alice) == 0 {
		t.Fatal("user=alice returned zero rows")
	}
	for _, e := range alice {
		if e["operator"] != "alice" {
			t.Fatalf("user filter leaked operator %v", e["operator"])
		}
	}

	// Unknown user: empty array 200 (no existence oracle).
	rec = authedGet(t, mux, "/api/audit?limit=500&user=who-is-this", adminToken)
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("unknown user must answer [] 200, got %d %s", rec.Code, rec.Body.String())
	}

	// Over-long filter: 400.
	rec = authedGet(t, mux, "/api/audit?limit=500&user="+strings.Repeat("x", 65), adminToken)
	if rec.Code != 400 {
		t.Fatalf("over-long user filter: %d, want 400", rec.Code)
	}
}

// TestAuditHeaderSpoofIgnored pins the z_bugs header-strip: X-Auth-* are
// server-SET response headers of the auth middleware, never client input.
// The login route audits WITHOUT auth, so before the fix a client-sent
// X-Auth-User: admin forged "by admin" attribution on an anonymous call.
func TestAuditHeaderSpoofIgnored(t *testing.T) {
	mux, _ := buildRound17Stack(t)

	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"alice","password":"correct-horse-battery"}`))
	req.Header.Set("X-Auth-User", "admin")
	req.Header.Set("X-Auth-Role", "admin")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("login with spoofed headers: %d", rec.Code)
	}

	adminToken := login(t, mux)
	rec = authedGet(t, mux, "/api/audit?limit=50&action=api_call", adminToken)
	var rows []struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, r := range rows {
		if strings.Contains(r.Detail, "by admin") && strings.Contains(r.Detail, "/api/login") {
			t.Fatalf("spoofed header forged attribution: %q", r.Detail)
		}
	}
}

// TestWebhookTestDelivery pins POST /api/webhooks/test: admin-gated,
// 404 on unknown IDs, 405 on GET, delivered:true against a live receiver,
// delivered:false (200, honest body) against a dead one — and the attempt
// folds into the same ledger GET /api/webhooks exposes.
func TestWebhookTestDelivery(t *testing.T) {
	mux, _ := buildRound17Stack(t)
	adminToken := login(t, mux)
	viewerToken := loginAs(t, mux, "bob", "viewer-correct-horse")

	// Method guard.
	if rec := authedGet(t, mux, "/api/webhooks/test?id=x", adminToken); rec.Code != 405 {
		t.Fatalf("GET on test endpoint: %d, want 405", rec.Code)
	}

	// Missing and unknown IDs.
	if rec := doAPI(t, mux, "POST", "/api/webhooks/test", adminToken, ""); rec.Code != 400 {
		t.Fatalf("missing id: %d, want 400", rec.Code)
	}
	if rec := doAPI(t, mux, "POST", "/api/webhooks/test?id=wh-nope", adminToken, ""); rec.Code != 404 {
		t.Fatalf("unknown id: %d, want 404", rec.Code)
	}

	// Viewer is outside the admin gate.
	if rec := doAPI(t, mux, "POST", "/api/webhooks/test?id=wh-nope", viewerToken, ""); rec.Code != 403 {
		t.Fatalf("viewer: %d, want 403", rec.Code)
	}

	// Live receiver: delivery must report success.
	hits := 0
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(200)
	}))
	defer sink.Close()
	id1 := createWebhook(t, mux, adminToken, sink.URL)
	res := webhookTest(t, mux, adminToken, id1)
	if res["delivered"] != true || hits != 1 {
		t.Fatalf("live sink: delivered=%v hits=%d", res["delivered"], hits)
	}

	// Dead destination (nothing listens on the port): delivered:false with
	// a bounded error text, but still HTTP 200 — the test worked.
	id2 := createWebhook(t, mux, adminToken, "http://127.0.0.1:1/sink")
	rec := doAPI(t, mux, "POST", "/api/webhooks/test?id="+id2, adminToken, "")
	if rec.Code != 200 {
		t.Fatalf("dead sink status: %d", rec.Code)
	}
	var dead map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &dead); err != nil {
		t.Fatalf("decode dead result: %v", err)
	}
	if dead["delivered"] != false || dead["error"] == "" {
		t.Fatalf("dead sink body: %v", dead)
	}

	// The attempts landed in the delivery ledger the console renders.
	rec = authedGet(t, mux, "/api/webhooks", adminToken)
	var views []struct {
		ID    string `json:"id"`
		Stats struct {
			Delivered  int64  `json:"delivered"`
			Failed     int64  `json:"failed"`
			LastStatus string `json:"last_status"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &views); err != nil {
		t.Fatalf("decode webhook list: %v", err)
	}
	for _, v := range views {
		if v.ID == id1 && (v.Stats.Delivered < 1 || v.Stats.LastStatus != "ok") {
			t.Fatalf("ledger missing ok attempt: %+v", v.Stats)
		}
		if v.ID == id2 && v.Stats.Failed < 1 {
			t.Fatalf("ledger missing failed attempt: %+v", v.Stats)
		}
	}
}

// TestMetricsAuditGauges checks the two audit gauges exist in the scrape.
func TestMetricsAuditGauges(t *testing.T) {
	mux, _ := buildRound17Stack(t)
	adminToken := login(t, mux)
	rec := authedGet(t, mux, "/api/metrics", adminToken)
	if rec.Code != 200 {
		t.Fatalf("metrics: %d", rec.Code)
	}
	body := rec.Body.String()
	for _, name := range []string{
		"worldc2_audit_entries",
		"worldc2_audit_pruned_total",
	} {
		if !strings.Contains(body, "# TYPE "+name+" gauge") || !strings.Contains(body, name+" ") {
			t.Fatalf("metrics missing %s", name)
		}
	}
}
