package c2

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter implements a simple token bucket rate limiter per IP.
type RateLimiter struct {
	clients map[string]*clientLimiter
	mu      sync.Mutex
	maxReq  int
	window  time.Duration
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip == "" {
				ip = r.RemoteAddr
			}

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
