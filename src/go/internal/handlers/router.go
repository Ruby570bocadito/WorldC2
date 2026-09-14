package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2"
)

// Router sets up all HTTP routes with middleware.
type Router struct {
	server      *c2.Server
	rateLimiter *c2.RateLimiter
	// loginLimiter is a tighter, dedicated bucket for /api/login: the
	// global limiter allows 60 req/min shared with the whole API, which is
	// far too permissive for password guessing against a single endpoint.
	loginLimiter *c2.RateLimiter
	// allowedOrigins is the exact-match CORS allowlist (config
	// api.allowed_origins). Empty (the default) means no cross-origin
	// browser access: the bundled console is same-origin and needs none.
	allowedOrigins map[string]bool
}

// NewRouter creates a new router with middleware. trustedProxies lists the
// IPs/CIDRs of reverse proxies in front of the API (used to resolve real
// client IPs for rate limiting); empty means "no proxy, trust the socket".
// allowedOrigins is the CORS allowlist; a "*" entry panics — wildcard CORS
// would let any web page read the C2 API from a victim's browser.
func NewRouter(server *c2.Server, trustedProxies []string, allowedOrigins []string) *Router {
	rateLimiter := c2.NewRateLimiter(60, time.Minute)
	if err := rateLimiter.SetTrustedProxies(trustedProxies); err != nil {
		// NewRouter cannot return an error without breaking the wiring, but
		// a misconfigured proxy list would silently key the bucket on a
		// spoofable header — refuse to start instead.
		panic(fmt.Sprintf("trusted_proxies: %v", err))
	}
	return &Router{
		server:         server,
		rateLimiter:    rateLimiter,
		loginLimiter:   c2.NewRateLimiter(10, time.Minute),
		allowedOrigins: parseAllowedOrigins(allowedOrigins),
	}
}

// parseAllowedOrigins builds the exact-match CORS allowlist. Blank and
// trailing-slash variants are normalized; a wildcard entry panics — a C2
// must never hand out wildcard CORS, and failing fast beats a silently
// permissive deployment. Exported behavior is testable without a server.
func parseAllowedOrigins(entries []string) map[string]bool {
	origins := make(map[string]bool, len(entries))
	for _, o := range entries {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		if o == "" {
			continue
		}
		if strings.Contains(o, "*") {
			panic(fmt.Sprintf("api.allowed_origins: wildcard %q rejected — list exact origins only", o))
		}
		origins[o] = true
	}
	return origins
}

// Setup configures all API routes and returns the mux.
func (r *Router) Setup() *http.ServeMux {
	mux := http.NewServeMux()

	// Start rate limiter cleanup
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-r.server.Quit():
				return
			case <-ticker.C:
				r.rateLimiter.Cleanup()
			}
		}
	}()

	// Middleware chain
	cors := r.corsMiddleware()
	auth := r.authMiddleware()
	admin := r.adminMiddleware()
	audit := r.auditMiddleware()
	rate := c2.RateLimitMiddleware(r.rateLimiter)
	loginLimit := c2.RateLimitMiddleware(r.loginLimiter)
	perm := r.requirePermission

	// Public endpoints
	mux.HandleFunc("/api/login", cors(audit(rate(loginLimit(r.handleLogin)))))
	mux.HandleFunc("/api/refresh", cors(audit(rate(r.handleRefresh))))
	// Liveness only: no operational telemetry on an unauthenticated route.
	mux.HandleFunc("/api/health", cors(audit(rate(r.handleHealth))))

	// Authenticated operational telemetry (moved off the public health route)
	mux.HandleFunc("/api/status", cors(auth(audit(rate(perm("sessions:list")(r.handleStatus))))))

	// Sessions
	mux.HandleFunc("/api/sessions", cors(auth(audit(rate(perm("sessions:list")(r.handleListSessions))))))
	mux.HandleFunc("/api/sessions/", cors(auth(audit(rate(r.permByMethod("sessions:view", "sessions:kill")(r.handleSessionDetail))))))

	// Commands
	mux.HandleFunc("/api/cmd", cors(auth(audit(rate(perm("commands:execute")(r.handleCommand))))))
	mux.HandleFunc("/api/broadcast", cors(auth(audit(rate(perm("commands:broadcast")(r.handleBroadcast))))))

	// Modules
	mux.HandleFunc("/api/modules", cors(auth(audit(rate(r.permByMethod("modules:list", "modules:push")(r.handleModules))))))
	mux.HandleFunc("/api/modules/push", cors(auth(audit(rate(perm("modules:push")(r.handleModulePush))))))
	mux.HandleFunc("/api/modules/", cors(auth(audit(rate(perm("modules:delete")(r.handleModuleDelete))))))

	// Infrastructure
	mux.HandleFunc("/api/socks", cors(auth(audit(rate(perm("socks:start")(r.handleSOCKS))))))
	mux.HandleFunc("/api/vault", cors(auth(audit(rate(r.permByMethod("vault:read", "vault:create")(r.handleVault))))))
	mux.HandleFunc("/api/files", cors(auth(audit(rate(r.filesPerm(r.handleFiles))))))
	mux.HandleFunc("/api/files/download/", cors(auth(audit(rate(perm("files:download")(r.handleFileDownload))))))
	mux.HandleFunc("/api/files/", cors(auth(audit(rate(perm("files:delete")(r.handleFileDelete))))))
	mux.HandleFunc("/api/portfwd", cors(auth(audit(rate(perm("portfwd:start")(r.handlePortFwd))))))

	// Operators (admin only)
	mux.HandleFunc("/api/operators", cors(auth(admin(audit(rate(r.handleOperators))))))
	mux.HandleFunc("/api/operators/", cors(auth(admin(audit(rate(r.handleOperatorDelete))))))

	// Team collaboration
	// Notes and profiles: reads are gated by collab:read (every role has
	// it — a viewer or auditor must be able to see operator notes), writes
	// by collab:write (admin/operator only).
	mux.HandleFunc("/api/notes", cors(auth(audit(rate(r.permByMethod("collab:read", "collab:write")(r.handleNotes))))))
	mux.HandleFunc("/api/lock", cors(auth(audit(rate(perm("collab:write")(r.handleLock))))))
	mux.HandleFunc("/api/profiles", cors(auth(audit(rate(r.permByMethod("collab:read", "collab:write")(r.handleProfiles))))))
	mux.HandleFunc("/api/profiles/", cors(auth(audit(rate(perm("collab:write")(r.handleProfileDelete))))))

	// Reporting
	mux.HandleFunc("/api/report", cors(auth(audit(rate(perm("report:generate")(r.handleReport))))))

	// SIEM webhooks (admin only)
	mux.HandleFunc("/api/webhooks", cors(auth(admin(audit(rate(r.handleWebhooks))))))

	// mTLS certificate generation (admin only)
	mux.HandleFunc("/api/mtls/cert", cors(auth(admin(audit(rate(r.handleMTLSCert))))))

	// SPA frontend
	r.serveSPA(mux)

	return mux
}

// corsMiddleware adds security headers and CORS.
func (r *Router) corsMiddleware() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "0")
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")

			origin := req.Header.Get("Origin")
			if origin != "" && r.allowedOrigins[origin] {
				// Exact-match allowlist from api.allowed_origins.
				// Empty list (default) = no CORS headers at all:
				// the bundled console is same-origin.
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if req.Method == "OPTIONS" {
				w.WriteHeader(200)
				return
			}
			next(w, req)
		}
	}
}

// authMiddleware validates JWT tokens.
func (r *Router) authMiddleware() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			authHeader := req.Header.Get("Authorization")
			if authHeader == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="WORLDC2 C2"`)
				http.Error(w, `{"error":"missing token"}`, 401)
				return
			}

			// Require the exact "Bearer " scheme: raw tokens and
			// Basic auth credentials are rejected.
			if !strings.HasPrefix(authHeader, "Bearer ") {
				w.Header().Set("WWW-Authenticate", `Bearer realm="WORLDC2 C2"`)
				http.Error(w, `{"error":"authorization scheme must be Bearer"}`, 401)
				return
			}
			token := authHeader[len("Bearer "):]

			username, role, err := r.server.TokenManager().ValidateToken(token)
			if err != nil {
				// Resolved client IP (trusted-proxy aware): behind a
				// proxy the raw RemoteAddr would log the proxy for
				// every invalid-token attempt.
				r.server.DB().LogAction(0, "auth_failed", r.rateLimiter.ResolveClientIP(req))
				http.Error(w, `{"error":"invalid or expired token"}`, 401)
				return
			}

			// Existence check: a deleted operator's outstanding JWTs
			// must not keep working. The in-memory RevokeUser map
			// loses entries on restart while the signing key (and
			// thus old tokens' validity) does not — checking the
			// operators table per request closes that window for
			// good. Tiny table, one indexed lookup.
			if exists, err := r.server.DB().OperatorExists(username); err != nil || !exists {
				r.server.DB().LogAction(0, "auth_failed", r.rateLimiter.ResolveClientIP(req))
				http.Error(w, `{"error":"operator no longer exists"}`, 401)
				return
			}

			req.Header.Set("X-Auth-User", username)
			req.Header.Set("X-Auth-Role", role)
			next(w, req)
		}
	}
}

// adminMiddleware restricts access to admin users.
func (r *Router) adminMiddleware() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			if req.Header.Get("X-Auth-Role") != "admin" {
				http.Error(w, `{"error":"admin access required"}`, 403)
				return
			}
			next(w, req)
		}
	}
}

// auditMiddleware logs API calls and enforces request body limits.
func (r *Router) auditMiddleware() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			// Body size limit: small for JSON control endpoints,
			// larger for file/module uploads.
			if req.Body != nil {
				limit := int64(1 << 20) // 1 MiB
				if strings.HasPrefix(req.URL.Path, "/api/files") ||
					req.URL.Path == "/api/modules/push" {
					limit = 64 << 20 // 64 MiB
				}
				req.Body = http.MaxBytesReader(w, req.Body, limit)
			}

			ip := r.rateLimiter.ResolveClientIP(req)
			user := req.Header.Get("X-Auth-User")
			if user == "" {
				user = "anonymous"
			}
			r.server.DB().LogAction(0, "api_call", req.Method+" "+req.URL.Path+" from "+ip+" by "+user)
			next(w, req)
		}
	}
}

// filesPerm selects the permission per method on /api/files: GET lists loot
// (files:download), POST stores artifacts (files:upload) and DELETE purges
// the whole listing (files:delete — the same capability the per-id route
// enforces, so no role gains a bulk action its single-file route lacked).
func (r *Router) filesPerm(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			r.requirePermission("files:download")(next)(w, req)
		case http.MethodPost:
			r.requirePermission("files:upload")(next)(w, req)
		case http.MethodDelete:
			r.requirePermission("files:delete")(next)(w, req)
		default:
			http.Error(w, "method not allowed", 405)
		}
	}
}

// requirePermissionByMethod enforces readPerm for safe methods (GET/HEAD)
// and mutatingPerm for the rest — so a read-only role can view but not act.
func (r *Router) permByMethod(readPerm, mutatingPerm string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			p := mutatingPerm
			if req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == http.MethodOptions {
				p = readPerm
			}
			r.requirePermission(p)(next)(w, req)
		}
	}
}

// requirePermission checks RBAC permissions.
func (r *Router) requirePermission(permission string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			role := req.Header.Get("X-Auth-Role")
			if role == "" {
				http.Error(w, `{"error":"authentication required"}`, 401)
				return
			}
			if !r.server.RBAC().HasPermission(role, permission) {
				r.server.DB().LogAction(0, "auth_denied", req.Method+" "+req.URL.Path+" by "+req.Header.Get("X-Auth-User")+" ("+role+")")
				http.Error(w, `{"error":"insufficient permissions"}`, 403)
				return
			}
			next(w, req)
		}
	}
}
