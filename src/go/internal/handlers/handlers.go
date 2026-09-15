package handlers

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/auth"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2/session"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/crypto"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/module"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/reporting"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/siem"
)

// handleLogin authenticates an operator and returns JWT tokens.
func (r *Router) handleLogin(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}

	var loginReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(req.Body).Decode(&loginReq); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}

	operator, err := r.server.DB().AuthenticateOperator(loginReq.Username, loginReq.Password)
	if err != nil {
		// Audit the resolved client IP (trusted-proxy aware), not the
		// raw RemoteAddr — behind a reverse proxy the raw address
		// would blame the proxy for every failed attempt.
		r.server.DB().LogAction(0, "auth_failed", r.rateLimiter.ResolveClientIP(req))
		http.Error(w, `{"error":"invalid credentials"}`, 401)
		return
	}

	token, err := r.server.TokenManager().GenerateToken(operator.Username, operator.Role)
	if err != nil {
		http.Error(w, `{"error":"token generation failed"}`, 500)
		return
	}

	refreshToken, err := r.server.TokenManager().GenerateRefreshToken(operator.Username)
	if err != nil {
		http.Error(w, `{"error":"refresh token generation failed"}`, 500)
		return
	}

	r.server.DB().LogAction(0, "auth_success", operator.Username+" logged in")

	r.server.SIEM().Forward(siem.SIEMEvent{
		EventType: "operator_login",
		Source:    "c2_server",
		Data: map[string]interface{}{
			"username": operator.Username,
			"role":     operator.Role,
			"remote":   r.rateLimiter.ResolveClientIP(req),
		},
	})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":         token,
		"refresh_token": refreshToken,
		"expires_in":    43200,
		"user":          operator.Username,
		"role":          operator.Role,
	})
}

// handleRefresh issues a new access token from a refresh token.
func (r *Router) handleRefresh(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}

	var refreshReq struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(req.Body).Decode(&refreshReq); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}

	username, err := r.server.TokenManager().RotateRefreshToken(refreshReq.RefreshToken)
	if err != nil {
		// Includes the replay of an already-consumed refresh token: the
		// legitimate client holds the replacement, so a replayed one is
		// unambiguously a copy — deny without hinting which case failed.
		http.Error(w, `{"error":"invalid refresh token"}`, 401)
		return
	}

	operators, err := r.server.DB().ListOperators()
	if err != nil {
		http.Error(w, `{"error":"database error"}`, 500)
		return
	}

	// Reject refresh tokens for operators that no longer exist instead
	// of silently minting a token with an invented role.
	operatorRole := ""
	for _, op := range operators {
		if op["username"] == username {
			if r, ok := op["role"].(string); ok {
				operatorRole = r
			}
			break
		}
	}
	if operatorRole == "" {
		http.Error(w, `{"error":"operator not found"}`, 401)
		return
	}
	if !auth.IsValidRole(operatorRole) {
		// A legacy row with a missing/unknown role would authenticate and
		// then fail every RBAC check — fail the refresh with the real cause.
		http.Error(w, `{"error":"operator role is not a valid RBAC role"}`, 403)
		return
	}

	newToken, err := r.server.TokenManager().GenerateToken(username, operatorRole)
	if err != nil {
		http.Error(w, `{"error":"token generation failed"}`, 500)
		return
	}

	// Rotation: every successful refresh also mints a NEW refresh token.
	// The presented one was consumed by RotateRefreshToken above, so the
	// window of any single refresh token is now one use.
	newRefresh, err := r.server.TokenManager().GenerateRefreshToken(username)
	if err != nil {
		http.Error(w, `{"error":"refresh token generation failed"}`, 500)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":         newToken,
		"refresh_token": newRefresh,
		"expires_in":    43200,
	})
}

// handleHealth returns a minimal liveness payload. It is the only public
// endpoint besides login/refresh: no session counts, listener details or
// uptime leak to unauthenticated callers (liveness is all that load balancers
// and the Docker healthcheck need). The full telemetry lives in /api/status.
func (r *Router) handleHealth(w http.ResponseWriter, req *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
	})
}

// handleStatus returns the operational telemetry that used to be exposed on
// the public /api/health: active session count, listeners and uptime. It is
// authenticated and gated by sessions:list so only real operators see it.
func (r *Router) handleStatus(w http.ResponseWriter, req *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "ok",
		"active_sessions": r.server.ActiveSessions(),
		"listeners":       r.server.ListenerCount(),
		"uptime_seconds":  r.server.UptimeSeconds(),
	})
}

// handleListSessions returns all active sessions.
func (r *Router) handleListSessions(w http.ResponseWriter, req *http.Request) {
	sessions, _ := r.server.DB().ListActiveSessions()
	if sessions == nil {
		sessions = []db.SessionRecord{}
	}
	json.NewEncoder(w).Encode(sessions)
}

// handleSessionDetail returns session details and tasks.
func (r *Router) handleSessionDetail(w http.ResponseWriter, req *http.Request) {
	id := req.URL.Path[len("/api/sessions/"):]
	// Reject empty IDs and control characters (e.g. %00 path injection)
	// before they reach any lookup.
	if id == "" || strings.ContainsFunc(id, func(rr rune) bool { return rr < 0x20 || rr == 0x7f }) {
		http.Error(w, "invalid session id", 400)
		return
	}
	if req.Method == "DELETE" {
		// ?purge=true hard-deletes the session record (tasks and
		// persisted loot included); without it the agent is killed
		// and the row stays as historical record with state "killed".
		purge := req.URL.Query().Get("purge") == "true"
		if purge {
			if err := r.server.PurgeSession(id); err != nil {
				http.Error(w, err.Error(), 404)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "purged"})
			return
		}
		if err := r.server.KillAgent(id); err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "killed"})
		return
	}
	sess, err := r.server.DB().GetSession(id)
	if err != nil || sess == nil {
		http.Error(w, `{"error":"session not found"}`, 404)
		return
	}
	tasks, _ := r.server.DB().GetSessionTasks(id)
	json.NewEncoder(w).Encode(map[string]interface{}{"session": sess, "tasks": tasks})
}

// handleCommand executes a command on an agent.
func (r *Router) handleCommand(w http.ResponseWriter, req *http.Request) {
	validated, ok := ValidateCommandRequest(w, req)
	if !ok {
		return
	}
	result, err := r.server.CreateTaskWithContext(req.Context(), validated.AgentID, validated.Command, validated.Timeout)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(result)
}

// handleBroadcast sends a command to all active agents.
func (r *Router) handleBroadcast(w http.ResponseWriter, req *http.Request) {
	command, ok := ValidateBroadcastRequest(w, req)
	if !ok {
		return
	}
	results := r.server.BroadcastTaskWithContext(req.Context(), command)
	json.NewEncoder(w).Encode(results)
}

// handleModules lists or registers modules.
func (r *Router) handleModules(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		modules := r.server.ModuleStore().List()
		json.NewEncoder(w).Encode(modules)
		return
	}
	if req.Method == "POST" {
		var m module.Manifest
		if err := json.NewDecoder(req.Body).Decode(&m); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), 400)
			return
		}
		if err := r.server.ModuleStore().Register(&m); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "registered", "name": m.Name})
	}
}

// handleModulePush pushes a module to an agent.
func (r *Router) handleModulePush(w http.ResponseWriter, req *http.Request) {
	var pushReq struct {
		ModuleName string `json:"module"`
		AgentID    string `json:"agent_id"`
	}
	if err := json.NewDecoder(req.Body).Decode(&pushReq); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}

	packed, err := r.server.ModuleStore().Pack(pushReq.ModuleName)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	target := pushReq.AgentID
	if target == "" {
		r.server.Sessions().Range(func(k, v interface{}) bool {
			sess := v.(*session.Session)
			if sess.IsActive() {
				target = sess.ID
				return false
			}
			return true
		})
	}
	if target == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "no active agents"})
		return
	}

	data, _ := json.Marshal(packed)
	cmd := fmt.Sprintf("module_load:%s", base64.StdEncoding.EncodeToString(data))

	result, err := r.server.CreateTask(target, cmd, 30)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error(), "status": "failed"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "pushed",
		"module":  pushReq.ModuleName,
		"agent":   target,
		"success": result.Success,
		"output":  result.Output,
	})
}

// handleModuleDelete deletes a module.
func (r *Router) handleModuleDelete(w http.ResponseWriter, req *http.Request) {
	if req.Method != "DELETE" {
		http.Error(w, "method not allowed", 405)
		return
	}
	name := req.URL.Path[len("/api/modules/"):]
	if err := r.server.ModuleStore().Delete(name); err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "name": name})
}

// handleSOCKS manages SOCKS5 proxies.
func (r *Router) handleSOCKS(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		json.NewEncoder(w).Encode(r.server.SOCKS5().ListProxies())
		return
	}
	var sockReq struct {
		SessionID string `json:"session_id"`
		Port      int    `json:"port"`
	}
	if err := json.NewDecoder(req.Body).Decode(&sockReq); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	if req.Method == "DELETE" {
		r.server.SOCKS5().StopProxy(sockReq.SessionID)
		json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
		return
	}

	if sockReq.SessionID == "" {
		r.server.Sessions().Range(func(k, v interface{}) bool {
			s := v.(*session.Session)
			if s.IsActive() {
				sockReq.SessionID = s.ID
				return false
			}
			return true
		})
	}

	dialFn := func(target string) (net.Conn, error) {
		var sess *session.Session
		r.server.Sessions().Range(func(k, v interface{}) bool {
			s := v.(*session.Session)
			if s.IsActive() && (s.AgentID == sockReq.SessionID || s.ID == sockReq.SessionID || s.Hostname == sockReq.SessionID) {
				sess = s
				return false
			}
			return true
		})
		if sess == nil {
			return nil, fmt.Errorf("session not found")
		}
		return r.server.Tunnels().OpenTunnel(sess, target)
	}

	addr, err := r.server.SOCKS5().StartProxy(sockReq.SessionID, sockReq.Port, dialFn)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"address": addr, "status": "started"})
}

// handleVault manages the credential vault.
func (r *Router) handleVault(w http.ResponseWriter, req *http.Request) {
	// Round-14 method hygiene: anything that is not a read or a create
	// used to fall through to the listing (a PUT answered the full vault).
	switch req.Method {
	case http.MethodPost, http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		http.Error(w, "method not allowed", 405)
		return
	}

	if req.Method == "POST" {
		var c c2.Credential
		if err := json.NewDecoder(req.Body).Decode(&c); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		// Round-14 caps (transversal pass part 2): vault rows are
		// permanent SQLite entries, so unbounded fields are a disk-fill
		// vector — the same pattern notes got in round 13.
		if err := validateCredential(&c); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 400)
			return
		}
		id := r.server.Vault().Add(c)
		json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "stored"})
		return
	}
	query := req.URL.Query().Get("q")
	if query != "" {
		json.NewEncoder(w).Encode(r.server.Vault().Search(query))
	} else {
		json.NewEncoder(w).Encode(r.server.Vault().List())
	}
}

// validateCredential enforces the round-14 transversal caps on vault
// entries: every string field is bounded, and at least one identifying
// field must be present (a row with nothing in it is pure noise).
func validateCredential(c *c2.Credential) error {
	fields := []struct {
		name string
		val  string
		max  int
	}{
		{"username", c.Username, 128},
		{"password", c.Password, 512},
		{"domain", c.Domain, 128},
		{"host", c.Host, 255},
		{"service", c.Service, 64},
		{"source", c.Source, 128},
		{"notes", c.Notes, 2000},
	}
	meaningful := false
	for _, f := range fields {
		if len(f.val) > f.max {
			return fmt.Errorf("%s must be %d characters or fewer", f.name, f.max)
		}
		if f.name != "notes" && f.val != "" {
			meaningful = true
		}
	}
	if !meaningful {
		return fmt.Errorf("credential needs at least one of username, password, domain, host, service or source")
	}
	return nil
}

// handleFiles manages exfiltrated files.
func (r *Router) handleFiles(w http.ResponseWriter, req *http.Request) {
	// Bulk purge: DELETE /api/files removes every loot record and blob
	// (current run + persisted rows). The per-id route keeps handling
	// single-file purges; this is the "wipe the board" action and requires
	// the same files:delete capability.
	if req.Method == "DELETE" {
		purged, err := r.server.Files().PurgeAll()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "purged",
			"purged": purged,
		})
		return
	}
	if req.Method == "POST" {
		var fileReq struct {
			SessionID string `json:"session_id"`
			Filename  string `json:"filename"`
			Module    string `json:"module"`
			Data      string `json:"data"`
		}
		if err := json.NewDecoder(req.Body).Decode(&fileReq); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		rec, err := r.server.Files().Store(fileReq.SessionID, fileReq.Filename, fileReq.Module, []byte(fileReq.Data))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(rec)
		return
	}
	json.NewEncoder(w).Encode(r.server.Files().List())
}

// handleFileDownload downloads an exfiltrated file.
func (r *Router) handleFileDownload(w http.ResponseWriter, req *http.Request) {
	id := req.URL.Path[len("/api/files/download/"):]
	data, rec, err := r.server.Files().Read(id)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": rec.Filename}))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

// handleFileDelete purges a single exfiltrated file (blob on disk, current
// listing and persisted record). Ids are server-generated "file-<hex>"
// strings; anything else is rejected before it reaches the manager.
func (r *Router) handleFileDelete(w http.ResponseWriter, req *http.Request) {
	if req.Method != "DELETE" {
		http.Error(w, "method not allowed", 405)
		return
	}
	id := req.URL.Path[len("/api/files/"):]
	if id == "" || strings.ContainsAny(id, "/\\") ||
		strings.ContainsFunc(id, func(rr rune) bool { return rr < 0x20 || rr == 0x7f }) {
		http.Error(w, "invalid file id", 400)
		return
	}
	if err := r.server.Files().Delete(id); err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// handlePortFwd manages port forwarding.
func (r *Router) handlePortFwd(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		json.NewEncoder(w).Encode(r.server.PortFwds().List())
		return
	}
	if req.Method == "DELETE" {
		id := req.URL.Query().Get("id")
		if err := r.server.PortFwds().Stop(id); err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
		return
	}
	var fwdReq struct {
		SessionID  string `json:"session_id"`
		LocalPort  int    `json:"local_port"`
		RemoteHost string `json:"remote_host"`
		RemotePort int    `json:"remote_port"`
	}
	if err := json.NewDecoder(req.Body).Decode(&fwdReq); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}

	dialFn := func(target string) (net.Conn, error) {
		var sess *session.Session
		r.server.Sessions().Range(func(k, v interface{}) bool {
			s := v.(*session.Session)
			if s.AgentID == fwdReq.SessionID || s.ID == fwdReq.SessionID {
				sess = s
				return false
			}
			return true
		})
		if sess == nil {
			return nil, fmt.Errorf("session not found")
		}
		return r.server.Tunnels().OpenTunnel(sess, target)
	}

	fwd, err := r.server.PortFwds().Start(fwdReq.SessionID, fwdReq.LocalPort, fwdReq.RemoteHost, fwdReq.RemotePort, dialFn)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(fwd)
}

// handleOperators manages operator accounts.
func (r *Router) handleOperators(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		operators, err := r.server.DB().ListOperators()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(operators)
		return
	}
	if req.Method == "POST" {
		var opReq struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(req.Body).Decode(&opReq); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		if opReq.Username == "" || opReq.Password == "" {
			http.Error(w, "username and password required", 400)
			return
		}
		if opReq.Role == "" {
			opReq.Role = "operator"
		}
		if !auth.IsValidRole(opReq.Role) {
			// Without this check a typo like "Admin" would create an
			// operator that logs in but fails every permission check.
			http.Error(w, `{"error":"role must be one of: admin, operator, viewer, auditor"}`, 400)
			return
		}
		if err := r.server.DB().CreateOperator(opReq.Username, opReq.Password, opReq.Role); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		r.server.DB().LogAction(0, "operator_create", opReq.Username)
		json.NewEncoder(w).Encode(map[string]string{"status": "created", "username": opReq.Username})
	}
}

// handleOperatorDelete deletes an operator.
func (r *Router) handleOperatorDelete(w http.ResponseWriter, req *http.Request) {
	if req.Method != "DELETE" {
		http.Error(w, "method not allowed", 405)
		return
	}
	idStr := req.URL.Path[len("/api/operators/"):]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "invalid operator id", 400)
		return
	}
	// Resolve the operator FIRST: (a) an unknown id must 404 instead of
	// pretending to delete something, and (b) revocation is keyed by
	// USERNAME (the JWT subject), not by the numeric id — revoking the
	// raw path segment would silently revoke nothing.
	op, err := r.server.DB().GetOperatorByID(id)
	if err != nil {
		http.Error(w, "operator not found", 404)
		return
	}
	if err := r.server.DB().DeleteOperator(idStr); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// Invalidate outstanding JWTs for this operator. The persistence of the
	// signing key means an in-memory revocation alone would be lost on
	// restart; the auth middleware additionally checks operator existence
	// on every request, so both layers have to be bypassed to keep a dead
	// operator's token alive.
	r.server.TokenManager().RevokeUser(op.Username)
	r.server.DB().LogAction(0, "operator_delete", op.Username+" (id "+idStr+")")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "username": op.Username})
}

// handleNotes manages session notes.
func (r *Router) handleNotes(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		var noteReq struct {
			SessionID string `json:"session_id"`
			Content   string `json:"content"`
		}
		if err := json.NewDecoder(req.Body).Decode(&noteReq); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		if noteReq.SessionID == "" || noteReq.Content == "" {
			http.Error(w, "session_id and content required", 400)
			return
		}
		// Length caps (round 13): notes live in SQLite forever, so an
		// unbounded body is a disk-fill vector and a console render hazard.
		if len(noteReq.SessionID) > 128 {
			http.Error(w, `{"error":"session_id must be 128 characters or fewer"}`, 400)
			return
		}
		if len(noteReq.Content) > 10000 {
			http.Error(w, `{"error":"content must be 10000 characters or fewer"}`, 400)
			return
		}
		r.server.DB().AddSessionNote(noteReq.SessionID, 0, noteReq.Content)
		json.NewEncoder(w).Encode(map[string]string{"status": "added"})
		return
	}
	sessionID := req.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "session_id required", 400)
		return
	}
	notes, err := r.server.DB().GetSessionNotes(sessionID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(notes)
}

// handleLock manages session locks.
func (r *Router) handleLock(w http.ResponseWriter, req *http.Request) {
	var lockReq struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"`
	}
	if err := json.NewDecoder(req.Body).Decode(&lockReq); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	if lockReq.SessionID == "" {
		http.Error(w, "session_id required", 400)
		return
	}
	if lockReq.Action == "lock" {
		r.server.DB().LockSession(lockReq.SessionID, 0)
		json.NewEncoder(w).Encode(map[string]string{"status": "locked"})
	} else {
		r.server.DB().UnlockSession(lockReq.SessionID)
		json.NewEncoder(w).Encode(map[string]string{"status": "unlocked"})
	}
}

// profileTransports is the allowlist of transport names a profile may pin.
// It mirrors the listener names the server actually admits (plus the tls
// alias used by the agent chain); anything else used to be stored verbatim.
var profileTransports = map[string]bool{
	"tls": true, "http": true, "dns": true, "webrtc": true, "ws": true, "tcp": true,
}

// handleProfiles manages agent configuration profiles.
func (r *Router) handleProfiles(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		var profReq struct {
			Name           string  `json:"name"`
			BeaconInterval int     `json:"beacon_interval"`
			Jitter         float64 `json:"jitter"`
			Transport      string  `json:"transport"`
		}
		if err := json.NewDecoder(req.Body).Decode(&profReq); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		// Input validation (round 12): the endpoint used to store anything
		// verbatim — empty names, negative intervals, nonsensical jitter
		// and unknown transports ended up as permanent garbage rows the
		// new Profiles console would dutifully render.
		profReq.Name = strings.TrimSpace(profReq.Name)
		if profReq.Name == "" || len(profReq.Name) > 64 {
			http.Error(w, `{"error":"name is required (1-64 characters)"}`, 400)
			return
		}
		if profReq.BeaconInterval == 0 {
			profReq.BeaconInterval = 5
		}
		if profReq.BeaconInterval < 1 || profReq.BeaconInterval > 3600 {
			http.Error(w, `{"error":"beacon_interval must be between 1 and 3600 seconds"}`, 400)
			return
		}
		if profReq.Jitter == 0 {
			profReq.Jitter = 0.3
		}
		if profReq.Jitter < 0 || profReq.Jitter > 0.95 {
			http.Error(w, `{"error":"jitter must be between 0 and 0.95"}`, 400)
			return
		}
		if profReq.Transport == "" {
			profReq.Transport = "tls"
		}
		if !profileTransports[profReq.Transport] {
			http.Error(w, `{"error":"unknown transport (allowed: dns, http, tcp, tls, webrtc, ws)"}`, 400)
			return
		}
		id := fmt.Sprintf("profile-%x", time.Now().UnixNano())
		r.server.DB().CreateAgentProfile(id, profReq.Name, profReq.BeaconInterval, profReq.Jitter, profReq.Transport)
		json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "created"})
		return
	}
	profiles, err := r.server.DB().ListAgentProfiles()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(profiles)
}

// handleProfileDelete removes an agent configuration profile by id. Writes
// are gated by collab:write at the route level (same as profile creation).
// Deleting a missing id is a 404, not a silent no-op: the console distinguishes
// "already gone" from "gone now".
func (r *Router) handleProfileDelete(w http.ResponseWriter, req *http.Request) {
	if req.Method != "DELETE" {
		http.Error(w, "method not allowed", 405)
		return
	}
	id := req.URL.Path[len("/api/profiles/"):]
	if id == "" || strings.ContainsFunc(id, func(rr rune) bool { return rr < 0x20 || rr == 0x7f }) {
		http.Error(w, "invalid profile id", 400)
		return
	}
	if err := r.server.DB().DeleteAgentProfile(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "profile not found", 404)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "id": id})
}

// handleReport generates engagement reports.
func (r *Router) handleReport(w http.ResponseWriter, req *http.Request) {
	format := req.URL.Query().Get("format")
	if format == "" {
		format = "text"
	}
	switch format {
	case "text", "csv", "json":
	default:
		// Unknown formats used to fall through to the text generator
		// silently; a typo'd curl got the wrong bytes with a 200.
		http.Error(w, `{"error":"format must be text, csv or json"}`, 400)
		return
	}

	sessions, err := r.server.DB().ListAllSessions()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	creds, err := r.server.DB().ListCredentials()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Attribute the report to the authenticated operator instead of a
	// hardcoded "admin".
	operator := req.Header.Get("X-Auth-User")
	if operator == "" {
		operator = "unknown"
	}

	report := &reporting.EngagementReport{
		Title:     "WORLDC2 C2 Engagement Report",
		Operator:  operator,
		StartDate: time.Now().Add(-24 * time.Hour),
		EndDate:   time.Now(),
		Summary: reporting.ReportSummary{
			TotalSessions:    len(sessions),
			TotalCredentials: len(creds),
			UniqueOS:         make(map[string]int),
		},
	}

	for _, s := range sessions {
		report.Sessions = append(report.Sessions, reporting.SessionReport{
			ID: s.ID, AgentID: s.AgentID, Hostname: s.Hostname,
			OS: s.OS, Arch: s.Arch, Username: s.Username,
			IsAdmin: s.IsAdmin, PublicIP: s.PublicIP,
			FirstSeen: s.FirstSeen, LastSeen: s.LastSeen,
			State: s.State, TaskCount: s.TaskCount,
		})
		if s.State == "active" {
			report.Summary.ActiveSessions++
		}
		report.Summary.UniqueOS[s.OS]++
	}

	for _, c := range creds {
		report.Credentials = append(report.Credentials, reporting.CredentialReport{
			Username: c.Username, Password: c.Password, Domain: c.Domain,
			Host: c.Host, Service: c.Service, Source: c.Source, Captured: c.Captured,
		})
	}

	report.Summary.UniqueHosts = len(report.Summary.UniqueOS)

	var path string
	switch format {
	case "csv":
		path, err = r.server.Reporter().GenerateCSV(report)
	case "json":
		// Round 14: format=json was advertised (README, OpenAPI) but the
		// handler silently produced the text report instead.
		path, err = r.server.Reporter().GenerateJSON(report)
	default:
		path, err = r.server.Reporter().GenerateText(report)
	}

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Round 14: ?download=1 serves the report CONTENT as a download.
	// Without it the default response is the documented JSON envelope
	// {path, status} — which the round-13 Dashboard button mistakenly
	// saved to disk as worldc2-report.txt (metadata, never the report).
	if req.URL.Query().Get("download") == "1" {
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		ct := "text/plain; charset=utf-8"
		switch format {
		case "csv":
			ct = "text/csv; charset=utf-8"
		case "json":
			ct = "application/json"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(path)}))
		w.Write(data)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"path": path, "status": "generated"})
}

// handleWebhooks manages SIEM webhook destinations. Destinations are
// persisted in the webhooks table (migration 9) and re-hydrated into the
// SIEM forwarder on server start, so they survive restarts.

// knownSIEMEvents is the allowlist of event types a webhook may subscribe
// to — exactly the strings the server emits. Before round 13 any value was
// stored verbatim, and an unknown filter string meant the webhook silently
// never fired (contains() gates forwarding), a misconfig no operator could
// see until an incident was missed.
var knownSIEMEvents = map[string]bool{
	"agent_killed": true, "agent_purged": true, "operator_login": true,
	"session_disconnect": true, "session_error": true, "session_established": true,
	"session_passive": true, "task_result": true,
}

// webhookView is the JSON contract of the webhook listing: explicit fields
// and the timeout as milliseconds (the siem.WebhookConfig struct marshals
// time.Duration as bare nanoseconds, unusable for clients).
type webhookView struct {
	ID        string            `json:"id"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	TimeoutMS int64             `json:"timeout_ms"`
	Events    []string          `json:"events"`
}

func (r *Router) handleWebhooks(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		var whReq struct {
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			Timeout int               `json:"timeout_ms"`
			Events  []string          `json:"events"`
		}
		if err := json.NewDecoder(req.Body).Decode(&whReq); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		// Input validation (round 13): length caps and sane bounds on top
		// of the scheme check below.
		if len(whReq.URL) > 2048 {
			http.Error(w, `{"error":"url must be 2048 characters or fewer"}`, 400)
			return
		}
		if len(whReq.Headers) > 16 {
			http.Error(w, `{"error":"at most 16 headers"}`, 400)
			return
		}
		for k, v := range whReq.Headers {
			if k == "" || len(k) > 128 || len(v) > 1024 {
				http.Error(w, `{"error":"header keys must be non-empty (max 128) and values max 1024"}`, 400)
				return
			}
		}
		if whReq.Timeout == 0 {
			whReq.Timeout = 5000
		}
		if whReq.Timeout < 100 || whReq.Timeout > 60000 {
			// 0 previously meant "no client timeout" (http.Client treats
			// <=0 as unlimited): a dead endpoint would hang a forwarding
			// goroutine forever. Every webhook now has a real timeout.
			http.Error(w, `{"error":"timeout_ms must be between 100 and 60000"}`, 400)
			return
		}
		for _, ev := range whReq.Events {
			if !knownSIEMEvents[ev] {
				http.Error(w, `{"error":"unknown event type `+ev+` (allowed: agent_killed, agent_purged, operator_login, session_disconnect, session_error, session_established, session_passive, task_result)"}`, 400)
				return
			}
		}
		u, err := url.Parse(whReq.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			// Only absolute http(s) URLs: prevents file:// and
			// custom-scheme SSRF abuse from the webhook forwarder.
			http.Error(w, `url must be an absolute http(s) URL`, 400)
			return
		}
		id := newWebhookID()
		cfg := siem.WebhookConfig{
			ID:      id,
			URL:     whReq.URL,
			Headers: whReq.Headers,
			Timeout: time.Duration(whReq.Timeout) * time.Millisecond,
			Events:  whReq.Events,
		}
		// Persist first: if the DB write fails the destination must NOT
		// become live in-memory only (it would silently diverge from the
		// hydrated set on the next restart).
		if err := r.server.DB().SaveWebhook(&db.WebhookRecord{
			ID:        id,
			URL:       cfg.URL,
			Headers:   cfg.Headers,
			TimeoutMS: whReq.Timeout,
			Events:    cfg.Events,
		}); err != nil {
			log.Printf("[API] persist webhook: %v", err)
			http.Error(w, "failed to persist webhook", 500)
			return
		}
		r.server.SIEM().AddWebhook(cfg)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "added", "id": id})

	case http.MethodDelete:
		id := req.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing webhook id (?id=...)", 400)
			return
		}
		removed := r.server.SIEM().RemoveWebhook(id)
		deleted, err := r.server.DB().DeleteWebhook(id)
		if err != nil {
			log.Printf("[API] delete webhook %s: %v", id, err)
			http.Error(w, "failed to delete webhook", 500)
			return
		}
		if !removed && !deleted {
			http.Error(w, "webhook not found", 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"deleted": true})

	default:
		// GET: return the actual webhook list — the OpenAPI spec documents
		// this endpoint as "List of webhooks". Mapped through webhookView
		// so clients see timeout_ms instead of raw nanoseconds.
		configs := r.server.SIEM().ListWebhooks()
		views := make([]webhookView, 0, len(configs))
		for _, wh := range configs {
			events := wh.Events
			if events == nil {
				events = []string{}
			}
			headers := wh.Headers
			if headers == nil {
				headers = map[string]string{}
			}
			views = append(views, webhookView{
				ID:        wh.ID,
				URL:       wh.URL,
				Headers:   headers,
				TimeoutMS: wh.Timeout.Milliseconds(),
				Events:    events,
			})
		}
		json.NewEncoder(w).Encode(views)
	}
}

// newWebhookID mints a random identifier for a webhook destination
// (crypto/rand, not predictable counters — the ID is referenced by DELETE).
func newWebhookID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is catastrophic but must not panic the API;
		// fall back to a time-derived ID rather than an empty one.
		return fmt.Sprintf("wh-%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("wh-%s", hex.EncodeToString(b))
}

// handleMTLSCert generates mTLS client certificates for agents.
func (r *Router) handleMTLSCert(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}

	var certReq struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(req.Body).Decode(&certReq); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}

	// Round-14 validation (transversal pass part 2): the agent_id
	// becomes the X.509 CommonName, so it is capped at the conventional
	// 64-char ub-common-name and restricted to a safe charset. Until
	// now any string up to the 1 MiB body limit — control characters,
	// slashes, whatever — went straight into a certificate signed by
	// the engagement CA. Validation deliberately runs BEFORE the mTLS
	// enabled check: malformed input answers 400 regardless of config.
	if certReq.AgentID == "" {
		certReq.AgentID = fmt.Sprintf("agent-%x", time.Now().UnixNano())
	} else if len(certReq.AgentID) > 64 || !validAgentID(certReq.AgentID) {
		http.Error(w, `{"error":"agent_id must be 1-64 characters of [A-Za-z0-9._-]"}`, 400)
		return
	}

	if !r.server.MTLSEnabled() {
		http.Error(w, `{"error":"mTLS not enabled"}`, 500)
		return
	}

	agentCert, err := crypto.GenerateAgentCert(r.server.CACert(), r.server.CAKey(), certReq.AgentID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), 500)
		return
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.server.CACert().Raw})
	agentCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agentCert.Certificate[0]})
	var agentKeyPEM []byte
	if ecKey, ok := agentCert.PrivateKey.(*ecdsa.PrivateKey); ok {
		keyBytes, _ := x509.MarshalECPrivateKey(ecKey)
		agentKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_id":    certReq.AgentID,
		"cert_pem":    string(agentCertPEM),
		"key_pem":     string(agentKeyPEM),
		"ca_pem":      string(caPEM),
		"mtls_server": fmt.Sprintf("%s:%d", r.server.Config().Server.Host, r.server.Config().Server.Port),
	})
}

// validAgentID reports whether s is a safe CommonName for an agent
// certificate: alphanumeric plus dot, underscore and dash, no spaces or
// control characters.
func validAgentID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}
