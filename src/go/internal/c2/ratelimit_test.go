package c2

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestLimiter(t *testing.T, proxies []string) *RateLimiter {
	t.Helper()
	rl := NewRateLimiter(2, time.Minute) // small bucket: 3rd request fails
	if err := rl.SetTrustedProxies(proxies); err != nil {
		t.Fatalf("SetTrustedProxies: %v", err)
	}
	return rl
}

func request(remote, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

// TestRateLimitBasic pins the token bucket: maxReq+1 hits exhaust it.
func TestRateLimitBasic(t *testing.T) {
	rl := newTestLimiter(t, nil)
	for i := 0; i < 2; i++ {
		if !rl.Allow("10.1.1.5") {
			t.Fatalf("request %d denied within budget", i+1)
		}
	}
	if rl.Allow("10.1.1.5") {
		t.Fatal("bucket did not exhaust after maxReq requests")
	}
	// Another IP is unaffected.
	if !rl.Allow("10.1.1.6") {
		t.Fatal("independent IP denied")
	}
}

// TestClientIPNoTrustedProxy: without trusted proxies the XFF header is
// ignored — an attacker cannot rotate the bucket by spoofing it.
func TestClientIPNoTrustedProxy(t *testing.T) {
	rl := newTestLimiter(t, nil)
	got := rl.clientIP(request("203.0.113.7:4444", "1.2.3.4, 5.6.7.8"))
	if got != "203.0.113.7" {
		t.Fatalf("got %q, want socket peer 203.0.113.7", got)
	}
}

// TestClientIPTrustedProxyChain: behind a trusted proxy the real client is
// the rightmost XFF hop not claimed to be trusted.
func TestClientIPTrustedProxyChain(t *testing.T) {
	rl := newTestLimiter(t, []string{"127.0.0.1", "10.0.0.0/8"})

	// proxy → client
	if got := rl.clientIP(request("127.0.0.1:5555", "198.51.100.9")); got != "198.51.100.9" {
		t.Fatalf("single hop: got %q", got)
	}
	// proxy → proxy → client
	if got := rl.clientIP(request("10.1.2.3:5555", "198.51.100.9, 10.0.0.2")); got != "198.51.100.9" {
		t.Fatalf("chained: got %q", got)
	}
	// proxy → client proxy → final client: the client-run proxy is not
	// trusted, so IT is the keying IP (spoofed entries after it are ignored).
	if got := rl.clientIP(request("127.0.0.1:5555", "1.2.3.4, 192.0.2.1")); got != "192.0.2.1" {
		t.Fatalf("untrusted client proxy: got %q, want 192.0.2.1", got)
	}
	// Malformed hops are skipped.
	if got := rl.clientIP(request("127.0.0.1:5555", "garbage, 198.51.100.9")); got != "198.51.100.9" {
		t.Fatalf("malformed hop: got %q", got)
	}
	// All hops trusted → leftmost (set by our own edge).
	if got := rl.clientIP(request("127.0.0.1:5555", "10.0.0.1, 10.0.0.2")); got != "10.0.0.1" {
		t.Fatalf("all trusted: got %q, want 10.0.0.1", got)
	}
	// Trusted peer without XFF → socket peer.
	if got := rl.clientIP(request("127.0.0.1:5555", "")); got != "127.0.0.1" {
		t.Fatalf("no xff: got %q", got)
	}
}

// TestRateLimitPerXFFClient: two clients behind the same proxy get separate
// buckets, and exhausting one does not touch the other.
func TestRateLimitPerXFFClient(t *testing.T) {
	rl := newTestLimiter(t, []string{"127.0.0.1"})

	mw := RateLimitMiddleware(rl)
	handler := mw(func(w http.ResponseWriter, _ *http.Request) {})

	do := func(xff string) int {
		rec := httptest.NewRecorder()
		handler(rec, request("127.0.0.1:1111", xff))
		return rec.Code
	}

	for i := 0; i < 2; i++ {
		if code := do("198.51.100.9"); code != http.StatusOK {
			t.Fatalf("client A request %d: got %d", i+1, code)
		}
	}
	if code := do("198.51.100.9"); code != http.StatusTooManyRequests {
		t.Fatalf("client A over budget: got %d, want 429", code)
	}
	if code := do("198.51.100.10"); code != http.StatusOK {
		t.Fatalf("client B should be unaffected: got %d", code)
	}
	// And the proxy peer itself is never the bucket behind XFF.
	if code := do("garbage"); code != http.StatusOK {
		t.Fatalf("unparseable xff fell back incorrectly: got %d", code)
	}
}

// TestSetTrustedProxiesValidation: garbage config fails loudly.
func TestSetTrustedProxiesValidation(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	if err := rl.SetTrustedProxies([]string{"10.0.0.0/8", "not-an-ip"}); err == nil {
		t.Fatal("invalid entry accepted")
	}
	if err := rl.SetTrustedProxies([]string{"10.0.0.0/8", "127.0.0.1", "::1"}); err != nil {
		t.Fatalf("valid entries rejected: %v", err)
	}
}
