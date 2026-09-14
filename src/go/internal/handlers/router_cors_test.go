package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestParseAllowedOrigins pins the contract of the CORS allowlist builder:
// exact origins survive (normalized), blanks are dropped, and any wildcard
// entry is a loud startup failure instead of a silently permissive deploy.
func TestParseAllowedOrigins(t *testing.T) {
	t.Run("empty config means no cross-origin at all", func(t *testing.T) {
		got := parseAllowedOrigins(nil)
		if len(got) != 0 {
			t.Fatalf("empty config produced allowlist %v", got)
		}
	})

	t.Run("origins are normalized and exact", func(t *testing.T) {
		got := parseAllowedOrigins([]string{
			"http://localhost:5173/",
			" https://console.example.com ",
			"https://c2.ops.io",
		})
		for _, want := range []string{
			"http://localhost:5173",
			"https://console.example.com",
			"https://c2.ops.io",
		} {
			if !got[want] {
				t.Fatalf("origin %q missing from allowlist %v", want, got)
			}
		}
		if len(got) != 3 {
			t.Fatalf("allowlist has %d entries, want 3: %v", len(got), got)
		}
	})

	t.Run("wildcard entries panic", func(t *testing.T) {
		for _, bad := range []string{"*", "https://*.example.com"} {
			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Fatalf("wildcard %q did not panic", bad)
					} else if !strings.Contains(r.(string), "wildcard") {
						t.Fatalf("panic for %q missing context: %v", bad, r)
					}
				}()
				parseAllowedOrigins([]string{bad})
			}()
		}
	})
}

// TestCORSAllowlistBehavior exercises the middleware itself: the configured
// origin gets Access-Control-Allow-Origin (plus Vary for cache correctness),
// anything else gets nothing, and an empty allowlist never emits CORS
// headers — the regression guard for the hardcoded dev-origins era.
func TestCORSAllowlistBehavior(t *testing.T) {
	body := func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusOK) }

	t.Run("configured origin is echoed", func(t *testing.T) {
		r := &Router{allowedOrigins: parseAllowedOrigins([]string{"https://console.example"})}
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.Header.Set("Origin", "https://console.example")
		rec := httptest.NewRecorder()
		r.corsMiddleware()(body)(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://console.example" {
			t.Fatalf("ACAO = %q, want the configured origin", got)
		}
		if got := rec.Header().Get("Vary"); !strings.Contains(got, "Origin") {
			t.Fatalf("Vary = %q, want it to include Origin", got)
		}
	})

	t.Run("unconfigured origin gets no CORS headers", func(t *testing.T) {
		r := &Router{allowedOrigins: parseAllowedOrigins([]string{"https://console.example"})}
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()
		r.corsMiddleware()(body)(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("ACAO leaked for unconfigured origin: %q", got)
		}
	})

	t.Run("empty allowlist never emits CORS headers", func(t *testing.T) {
		r := &Router{}
		for _, origin := range []string{
			"http://localhost:9090",
			"http://127.0.0.1:9090",
			"http://localhost:5173",
		} {
			req := httptest.NewRequest("GET", "/api/status", nil)
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			r.corsMiddleware()(body)(rec, req)
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Fatalf("default config leaked ACAO %q for %s", got, origin)
			}
		}
	})

	t.Run("preflight for unconfigured origin short-circuits without CORS grant", func(t *testing.T) {
		r := &Router{}
		req := httptest.NewRequest("OPTIONS", "/api/sessions", nil)
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()
		r.corsMiddleware()(body)(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("preflight status = %d, want 200 (preflights stay answerable)", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("preflight leaked ACAO %q", got)
		}
	})
}
