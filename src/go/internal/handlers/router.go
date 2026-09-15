package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2"
)

// Router sets up all HTTP routes with middleware.
type Router struct {
	server      *c2.Server
	rateLimiter *c2.RateLimiter
	// loginLimiter is a tighter, dedicated bucket for /api/login: the
	// global limiter allows 240 req/min shared with the whole API, which
	// is far too permissive for password guessing against a single
	// endpoint. The per-minute ceiling is configurable
	// (api.login_rate_per_min, r19) and defaults to the historical 10.
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
	// 240/min (4 req/s sustained) per client IP. The old ceiling of 60 was
	// below the console's own baseline: App polls /api/health every 5s, the
	// Dashboard another 5s cycle and the Audit view a 10s one — ~25-30
	// req/min PER OPEN CONSOLE. Two operators behind one NAT/VPN IP tripped
	// the limiter during normal browsing (and the grown E2E suite hit the
	// same wall, which is what uncovered the arithmetic). Bruteforce is
	// handled by the dedicated login limiter (api.login_rate_per_min,
	// default 10/min on /api/login) plus the per-account lockout in the
	// DB; this global bucket only stops floods.
	rateLimiter := c2.NewRateLimiter(240, time.Minute)
	if err := rateLimiter.SetTrustedProxies(trustedProxies); err != nil {
		// NewRouter cannot return an error without breaking the wiring, but
		// a misconfigured proxy list would silently key the bucket on a
		// spoofable header — refuse to start instead.
		panic(fmt.Sprintf("trusted_proxies: %v", err))
	}
	// Login bucket: configurable per-minute ceiling (r19), defaulting to
	// the historical 10/min when the key is absent or non-positive. The
	// per-ACCOUNT lockout in the DB is the primary guess-rate wall; this
	// bucket bounds bcrypt work per source IP on top of it.
	loginRatePerMin := 10
	if cfg := server.Config(); cfg != nil && cfg.API.LoginRatePerMin > 0 {
		loginRatePerMin = cfg.API.LoginRatePerMin
	}
	return &Router{
		server:         server,
		rateLimiter:    rateLimiter,
		loginLimiter:   c2.NewRateLimiter(loginRatePerMin, time.Minute),
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
	// Prometheus-format metrics: same gate as /api/status (counts and
	// gauges only — no credential material, no session identifiers).
	mux.HandleFunc("/api/metrics", cors(auth(audit(rate(perm("sessions:list")(r.handleMetrics))))))

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
	mux.HandleFunc("/api/vault", cors(auth(audit(rate(r.vaultPerms(r.handleVault))))))
	mux.HandleFunc("/api/files", cors(auth(audit(rate(r.filesPerm(r.handleFiles))))))
	mux.HandleFunc("/api/files/download/", cors(auth(audit(rate(perm("files:download")(r.handleFileDownload))))))
	mux.HandleFunc("/api/files/", cors(auth(audit(rate(perm("files:delete")(r.handleFileDelete))))))
	mux.HandleFunc("/api/portfwd", cors(auth(audit(rate(perm("portfwd:start")(r.handlePortFwd))))))

	// Operators (admin only)
	mux.HandleFunc("/api/operators", cors(auth(admin(audit(rate(r.handleOperators))))))
	mux.HandleFunc("/api/operators/", cors(auth(admin(audit(rate(r.handleOperatorDelete))))))

	// Own account: self-service password change and TOTP MFA enrollment
	// (r19). Any authenticated role — the handler resolves the operator
	// from the server-set X-Auth-* identity, never from the request, so
	// an operator can ONLY ever act on their own account. The subtree
	// dispatcher rejects unknown paths with 404 and unsupported methods
	// with 405.
	mux.HandleFunc("/api/account/", cors(auth(audit(rate(r.handleAccount)))))

	// Audit trail — read API over the append-only audit_log table every
	// middleware already writes to. Gated by the audit:read PERMISSION
	// (rbac.go: admin AND auditor), not the admin middleware: reviewing
	// the trail is the auditor's whole job and the permission existed for
	// exactly that purpose since the first rounds — round 17 finally
	// wires an endpoint to it.
	mux.HandleFunc("/api/audit", cors(auth(audit(rate(perm("audit:read")(r.handleAudit))))))

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
	// Test delivery for one destination (r18): fires a synthetic event
	// synchronously and folds the attempt into the same per-destination
	// ledger the automatic path keeps. Admin — the same gate as webhook
	// CRUD: destination URLs are the sensitive part and the test is the
	// one that exercises them.
	mux.HandleFunc("/api/webhooks/test", cors(auth(admin(audit(rate(r.handleWebhookTest))))))

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

			// Strip client-supplied identity headers (r18, z_bugs fix):
			// X-Auth-* are SERVER-SET by the auth middleware — they are the
			// middleware's output channel, not an input. Unauthenticated
			// routes (login, health, refresh) run audit WITHOUT auth, so a
			// client-sent X-Auth-User: admin would land in the audit trail
			// as "by admin" — forged attribution on the very log whose job
			// is forensics. CORS is the outermost wrapper on every route,
			// so the wipe runs before anything reads these headers.
			req.Header.Del("X-Auth-User")
			req.Header.Del("X-Auth-Role")
			req.Header.Del("X-Auth-UID")

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
			// good. Tiny table, one indexed lookup. The same
			// query resolves the numeric ID the audit middleware
			// attributes the call with (X-Auth-UID) — one lookup,
			// two answers.
			uid, uerr := r.server.DB().OperatorIDByUsername(username)
			if uerr != nil || uid == 0 {
				r.server.DB().LogAction(0, "auth_failed", r.rateLimiter.ResolveClientIP(req))
				http.Error(w, `{"error":"operator no longer exists"}`, 401)
				return
			}

			req.Header.Set("X-Auth-User", username)
			req.Header.Set("X-Auth-Role", role)
			req.Header.Set("X-Auth-UID", strconv.Itoa(uid))
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
			// Attribute the call to the exact operator account:
			// since the auth middleware resolves X-Auth-UID,
			// "who did this" lives in a queryable column
			// (audit_log.operator_id) instead of only inside the
			// free-text detail — that is what makes the r18
			// ?user= filter meaningful. System/anonymous calls
			// keep 0.
			uid := 0
			if raw := req.Header.Get("X-Auth-UID"); raw != "" {
				if n, nerr := strconv.Atoi(raw); nerr == nil && n > 0 {
					uid = n
				}
			}
			r.server.DB().LogAction(uid, "api_call", req.Method+" "+req.URL.Path+" from "+ip+" by "+user)
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

// vaultPerms maps the vault endpoint to its three distinct permissions.
// permByMethod only speaks two levels, and DELETE is a different privilege
// (vault:delete, admin-only — permanent removal of loot) from POST
// (vault:create): the generic wrapper would have required vault:create to
// delete and never exercised vault:delete at all. Unsupported methods
// answer 405 before any permission check, matching the handler switch.
func (r *Router) vaultPerms(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var p string
		switch req.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			p = "vault:read"
		case http.MethodPost:
			p = "vault:create"
		case http.MethodDelete:
			p = "vault:delete"
		default:
			http.Error(w, `{"error":"method not allowed"}`, 405)
			return
		}
		r.requirePermission(p)(next)(w, req)
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
