package c2

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter implements a simple token bucket rate limiter per IP.
type RateLimiter struct {
	clients map[string]*clientLimiter
	mu      sync.Mutex
	maxReq  int
	window  time.Duration
	// trustedProxies are CIDRs whose X-Forwarded-For may override the
	// socket address when keying the bucket (see clientIP).
	trustedProxies []*net.IPNet
}

type clientLimiter struct {
	tokens     int
	lastRefill time.Time
}

// NewRateLimiter creates a rate limiter allowing maxReq requests per window.
func NewRateLimiter(maxReq int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		clients: make(map[string]*clientLimiter),
		maxReq:  maxReq,
		window:  window,
	}
}

// SetTrustedProxies configures the IPs/CIDRs of reverse proxies in front of
// the API. Each entry must be a valid IP or CIDR; an invalid entry is an
// error so deployments fail fast instead of silently keying the bucket on a
// spoofable header.
func (rl *RateLimiter) SetTrustedProxies(entries []string) error {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		if _, ipnet, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, ipnet)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			return fmt.Errorf("invalid trusted proxy %q: not an IP or CIDR", e)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	rl.mu.Lock()
	rl.trustedProxies = nets
	rl.mu.Unlock()
	return nil
}

// isTrusted reports whether ip falls inside a configured trusted proxy.
func (rl *RateLimiter) isTrusted(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range rl.trustedProxies {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// clientIP resolves the rate-limiting key for a request. With no trusted
// proxies configured (the default) it is always the socket peer — an
// attacker-supplied X-Forwarded-For can never rotate the bucket. Behind a
// trusted proxy it walks X-Forwarded-For right-to-left and keys on the
// first hop NOT claimed to be a trusted proxy (the standard semantics for
// proxy chains), falling back to the leftmost entry when every hop is
// trusted and to the socket peer when nothing valid remains.
func (rl *RateLimiter) clientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || peer == "" {
		peer = r.RemoteAddr
	}
	if !rl.isTrusted(peer) {
		return peer
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}

	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := net.ParseIP(strings.TrimSpace(hops[i]))
		if hop == nil {
			continue // malformed entry: skip it
		}
		if !rl.isTrusted(hop.String()) {
			return hop.String()
		}
	}
	// Every hop is trusted — the leftmost was set by our own edge proxy.
	leftmost := net.ParseIP(strings.TrimSpace(hops[0]))
	if leftmost != nil {
		return leftmost.String()
	}
	return peer
}

// Allow checks if a request from the given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	client, exists := rl.clients[ip]
	if !exists {
		rl.clients[ip] = &clientLimiter{
			tokens:     rl.maxReq - 1,
			lastRefill: time.Now(),
		}
		return true
	}

	// Refill tokens based on elapsed time (proper token bucket)
	elapsed := time.Since(client.lastRefill)
	if elapsed > 0 {
		tokensToAdd := int(float64(elapsed) / float64(rl.window) * float64(rl.maxReq))
		if tokensToAdd > 0 {
			client.tokens = min(client.tokens+tokensToAdd, rl.maxReq)
			client.lastRefill = time.Now()
		}
	}

	if client.tokens <= 0 {
		return false
	}

	client.tokens--
	return true
}

// Cleanup removes stale entries older than 2x the window.
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-2 * rl.window)
	for ip, client := range rl.clients {
		if client.lastRefill.Before(cutoff) {
			delete(rl.clients, ip)
		}
	}
}

// RateLimitMiddleware returns an HTTP middleware that rate limits by IP.
func RateLimitMiddleware(rl *RateLimiter) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := rl.clientIP(r)

			if !rl.Allow(ip) {
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			next(w, r)
		}
	}
}

// MaxBodySizeMiddleware returns an HTTP middleware that limits request body size.
func MaxBodySizeMiddleware(maxBytes int64) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next(w, r)
		}
	}
}
