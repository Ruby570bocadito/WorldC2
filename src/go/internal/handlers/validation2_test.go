package handlers

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// authedGetQuery is authedGet with an arbitrary query string.
func authedGetQuery(t *testing.T, mux *http.ServeMux, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestReportDownload pins the round-14 delivery fix: ?download=1 serves the
// report CONTENT (with Content-Disposition attachment), not the JSON
// {path,status} envelope the round-13 Dashboard button used to save as
// worldc2-report.txt. The default (no download) keeps the documented
// envelope, and unknown formats now answer 400 instead of text bytes.
func TestReportDownload(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	// text download: real report body + attachment header.
	rec := authedGetQuery(t, mux, "/api/report?format=text&download=1", token)
	if rec.Code != 200 {
		t.Fatalf("text download: %d %s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".txt") {
		t.Errorf("content-disposition = %q", cd)
	}
	if !strings.Contains(rec.Body.String(), "ENGAGEMENT REPORT") {
		t.Errorf("body is not the report content (head: %.120s)", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"status":"generated"`) {
		t.Errorf("body still the metadata envelope: %.120s", rec.Body.String())
	}

	// csv download: CSV content type, header row present.
	rec = authedGetQuery(t, mux, "/api/report?format=csv&download=1", token)
	if rec.Code != 200 {
		t.Fatalf("csv download: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content-type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "WORLDC2 C2 - Engagement Report") {
		t.Errorf("csv body unexpected: %.120s", rec.Body.String())
	}

	// json download (new generator): parses as JSON.
	rec = authedGetQuery(t, mux, "/api/report?format=json&download=1", token)
	if rec.Code != 200 {
		t.Fatalf("json download: %d %s", rec.Code, rec.Body.String())
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Errorf("json download is not JSON: %v", err)
	}

	// Default (no download=1): documented {path,status} envelope survives.
	rec = authedGetQuery(t, mux, "/api/report?format=text", token)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"generated"`) {
		t.Errorf("default envelope broken: %d %.120s", rec.Code, rec.Body.String())
	}

	// Unknown format: honest 400 (used to fall through to text with a 200).
	rec = authedGetQuery(t, mux, "/api/report?format=banana", token)
	if rec.Code != 400 {
		t.Errorf("unknown format: got %d, want 400", rec.Code)
	}
}

// TestVaultValidation pins the round-14 caps on POST /api/vault (transversal
// pass part 2): per-field length caps, at least one identifying field, and
// method hygiene (PUT answers 405 instead of the listing).
func TestVaultValidation(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	cases := []struct {
		name string
		body string
	}{
		{"username over 128", `{"username":"` + strings.Repeat("u", 129) + `"}`},
		{"password over 512", `{"username":"u","password":"` + strings.Repeat("p", 513) + `"}`},
		{"host over 255", `{"host":"` + strings.Repeat("h", 256) + `"}`},
		{"service over 64", `{"service":"` + strings.Repeat("s", 65) + `"}`},
		{"source over 128", `{"source":"` + strings.Repeat("s", 129) + `"}`},
		{"notes over 2000", `{"username":"u","notes":"` + strings.Repeat("n", 2001) + `"}`},
		{"all fields empty", `{}`},
		{"only notes (no identifier)", `{"notes":"context without a credential"}`},
	}
	for _, tc := range cases {
		rec := adminPost(t, mux, token, "/api/vault", tc.body)
		if rec.Code != 400 {
			t.Errorf("%s: got %d, want 400 (body: %s)", tc.name, rec.Code, rec.Body.String())
		}
	}

	// A legitimate credential still lands, and the listing shows it.
	rec := adminPost(t, mux, token, "/api/vault", `{"username":"svc-backup","password":"hunter2","domain":"CORP","host":"dc01"}`)
	if rec.Code != 200 {
		t.Fatalf("valid credential: %d %s", rec.Code, rec.Body.String())
	}
	var stored struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &stored); err != nil || stored.ID == "" || stored.Status != "stored" {
		t.Fatalf("create response: %v (%s)", err, rec.Body.String())
	}
	if list := authedGet(t, mux, "/api/vault", token); list.Code != 200 || !strings.Contains(list.Body.String(), "svc-backup") {
		t.Errorf("listing after create: %d %s", list.Code, list.Body.String())
	}

	// Method hygiene: PUT used to fall through to the listing.
	put := httptest.NewRequest("PUT", "/api/vault", strings.NewReader(`{}`))
	put.Header.Set("Authorization", "Bearer "+token)
	putRec := httptest.NewRecorder()
	mux.ServeHTTP(putRec, put)
	if putRec.Code != 405 {
		t.Errorf("PUT /api/vault: got %d, want 405", putRec.Code)
	}
}

// TestMTLSCertValidation pins the round-14 agent_id policy: it becomes an
// X.509 CommonName, so >64 chars or characters outside [A-Za-z0-9._-] are
// rejected with 400 BEFORE the mTLS-enabled gate (bad input answers 400
// even on a stack with mTLS disabled — validation is fail-fast).
func TestMTLSCertValidation(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	bad := []struct {
		name string
		id   string
	}{
		{"65 chars", strings.Repeat("a", 65)},
		{"space", "agent one"},
		{"slash", "agent/../../etc"},
		{"control char", "agent\x07bell"},
		{"unicode", "agënt"},
	}
	for _, tc := range bad {
		rec := adminPost(t, mux, token, "/api/mtls/cert", `{"agent_id":"`+tc.id+`"}`)
		if rec.Code != 400 {
			t.Errorf("%s: got %d, want 400 (body: %s)", tc.name, rec.Code, rec.Body.String())
		}
	}

	// A valid id passes validation and the mTLS path issues a real
	// certificate whose CommonName is exactly the (now-validated) id —
	// proof the value traveled sanitized into the X.509 subject.
	rec := adminPost(t, mux, token, "/api/mtls/cert", `{"agent_id":"workstation-42.corp.local"}`)
	if rec.Code != 200 {
		t.Fatalf("valid id: %d %s", rec.Code, rec.Body.String())
	}
	var cert struct {
		AgentID string `json:"agent_id"`
		CertPEM string `json:"cert_pem"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cert); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cert.AgentID != "workstation-42.corp.local" {
		t.Errorf("agent_id = %q", cert.AgentID)
	}
	if !strings.Contains(cert.CertPEM, "BEGIN CERTIFICATE") {
		t.Errorf("cert_pem missing certificate")
	}
	if block, _ := pem.Decode([]byte(cert.CertPEM)); block == nil {
		t.Errorf("cert_pem does not decode")
	} else if x, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Errorf("parse cert: %v", err)
	} else if x.Subject.CommonName != "workstation-42.corp.local" {
		t.Errorf("CommonName = %q, want the validated agent_id", x.Subject.CommonName)
	}
}
