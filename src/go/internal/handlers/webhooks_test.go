package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// adminPost posts a JSON body to an admin-only endpoint and returns the recorder.
func adminPost(t *testing.T, mux *http.ServeMux, token, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestWebhookCreateValidation pins the round-13 validation of POST /api/webhooks:
// length caps (url/headers), a real forwarding timeout (0 used to mean an
// unlimited http.Client timeout — a hung goroutine per dead endpoint) and an
// event allowlist (unknown filters silently never fired). Defaults survive
// (timeout 0 -> 5000ms, empty events -> forward everything).
func TestWebhookCreateValidation(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	t.Run("valid payload with defaults", func(t *testing.T) {
		rec := adminPost(t, mux, token, "/api/webhooks", `{"url":"https://siem.example/hook"}`)
		if rec.Code != 201 {
			t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("rejections", func(t *testing.T) {
		cases := []struct {
			name string
			body string
		}{
			{"url over 2048 chars", `{"url":"https://a.example/` + strings.Repeat("x", 2048) + `"}`},
			{"17 headers", `{"url":"https://a.example","headers":{` + manyHeaders(17) + `}}`},
			{"empty header key", `{"url":"https://a.example","headers":{"":"v"}}`},
			{"header value over 1024", `{"url":"https://a.example","headers":{"X":"` + strings.Repeat("v", 1025) + `"}}`},
			{"timeout under 100ms", `{"url":"https://a.example","timeout_ms":50}`},
			{"timeout over 60s", `{"url":"https://a.example","timeout_ms":70000}`},
			{"unknown event type", `{"url":"https://a.example","events":["banana"]}`},
			{"unknown event mixed with valid", `{"url":"https://a.example","events":["task_result","nope"]}`},
		}
		for _, tc := range cases {
			rec := adminPost(t, mux, token, "/api/webhooks", tc.body)
			if rec.Code != 400 {
				t.Errorf("%s: got %d, want 400 (body: %s)", tc.name, rec.Code, rec.Body.String())
			}
		}
	})
}

// TestWebhooksListContract covers the round-13 listing contract: after a
// create, GET answers id/url/headers/timeout_ms/events with the timeout in
// milliseconds (the old raw struct leaked nanoseconds), and the DELETE
// lifecycle answers 200 then 404.
func TestWebhooksListContract(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	rec := adminPost(t, mux, token, "/api/webhooks",
		`{"url":"https://siem.example/hook","timeout_ms":2500,"events":["task_result"]}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("decode create response: %v", err)
	}

	get := authedGet(t, mux, "/api/webhooks", token)
	if get.Code != 200 {
		t.Fatalf("list: %d %s", get.Code, get.Body.String())
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(get.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("list has %d rows, want 1", len(rows))
	}
	row := rows[0]
	if row["url"] != "https://siem.example/hook" {
		t.Errorf("url = %v", row["url"])
	}
	if row["timeout_ms"].(float64) != 2500 {
		t.Errorf("timeout_ms = %v, want 2500", row["timeout_ms"])
	}
	if row["id"] != created.ID {
		t.Errorf("id = %v, want %q", row["id"], created.ID)
	}

	// DELETE via query param, then a second delete is an honest 404.
	del := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("DELETE", "/api/webhooks?id="+id, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, req)
		return r
	}
	if d := del(created.ID); d.Code != 200 {
		t.Fatalf("delete: %d %s", d.Code, d.Body.String())
	}
	if d := del(created.ID); d.Code != 404 {
		t.Fatalf("re-delete: %d, want 404", d.Code)
	}
}

// TestNotesValidation pins the round-13 length caps on session notes: the
// rows are permanent, so an unbounded body is a disk-fill vector.
func TestNotesValidation(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	longID := `{"session_id":"` + strings.Repeat("s", 129) + `","content":"x"}`
	if rec := adminPost(t, mux, token, "/api/notes", longID); rec.Code != 400 {
		t.Errorf("session_id over 128: got %d, want 400", rec.Code)
	}
	longBody := `{"session_id":"abc","content":"` + strings.Repeat("x", 10001) + `"}`
	if rec := adminPost(t, mux, token, "/api/notes", longBody); rec.Code != 400 {
		t.Errorf("content over 10000: got %d, want 400", rec.Code)
	}
	// A legitimate note still lands (the sessions FK is not enforced for
	// notes' session_id, only the caps are new).
	ok := `{"session_id":"abc","content":"clean note"}`
	if rec := adminPost(t, mux, token, "/api/notes", ok); rec.Code != 200 {
		t.Errorf("valid note: got %d %s", rec.Code, rec.Body.String())
	}
}

// manyHeaders builds "k0":"v0",... with n entries for inline embedding.
func manyHeaders(n int) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, fmt.Sprintf(`"k%d":"v%d"`, i, i))
	}
	return strings.Join(parts, ",")
}
