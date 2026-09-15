package handlers

// Account endpoints (r19): every operator manages THEIR OWN credential
// hygiene — self-service password change and opt-in TOTP MFA. The routes
// live under /api/account/* and are gated by plain authentication (any
// role): an account holder must always be able to harden their own
// account, and the handler re-verifies ownership anyway by resolving the
// operator from the SERVER-SET X-Auth-* headers, never from the request
// body or query string.
//
// Security posture worth keeping in one place:
//   - Password change requires the CURRENT password (session hijacking a
//     token alone is not enough to lock the real owner out) and revokes
//     every outstanding token for the user afterwards — access AND
//     refresh (RevokeUser cuts at iat, and rotation validates through the
//     same path), so a stolen session cannot outlive the change.
//   - TOTP setup/enable is a two-step flow: setup stores a DISABLED
//     secret and returns it once; enable requires a valid code proving
//     the operator actually enrolled their authenticator. A secret that
//     was never confirmed never gates a login.
//   - Disable requires a valid code for the CURRENT secret: malware with
//     only the bearer token cannot strip MFA silently.
//   - The admin MFA reset (DELETE /api/operators/{id}/totp) wipes the
//     factor for a locked-out operator (lost phone) — it never reveals
//     the secret, only removes it, and lands in the audit trail.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/totp"
	"golang.org/x/crypto/bcrypt"
)

// minPasswordLength is the floor for NEW passwords set through the
// self-service change. Existing accounts (created before this round, or
// seeded from config with the documented test hash) are not retroactively
// re-judged — the floor applies where a new secret is being chosen.
const minPasswordLength = 10

// maxPasswordLength keeps bcrypt's 72-byte input boundary honest and stops
// a hostile body from shipping kilobytes of secret material into a hash
// that would silently truncate it anyway.
const maxPasswordLength = 128

// handleAccount dispatches the /api/account/ subtree.
func (r *Router) handleAccount(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/api/account/password":
		r.handleAccountPassword(w, req)
	case "/api/account/totp/status":
		r.handleAccountTOTPStatus(w, req)
	case "/api/account/totp/setup":
		r.handleAccountTOTPSetup(w, req)
	case "/api/account/totp/enable":
		r.handleAccountTOTPEnable(w, req)
	case "/api/account/totp/disable":
		r.handleAccountTOTPDisable(w, req)
	default:
		http.Error(w, `{"error":"not found"}`, 404)
	}
}

// handleAccountTOTPStatus reports whether the CALLER's account has MFA
// enabled — a single boolean, no secret material. The console's security
// panel needs exactly this to choose between "set up" and "disable" UI.
// GET /api/account/totp/status
func (r *Router) handleAccountTOTPStatus(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	_, user, ok := r.accountIdentity(w, req)
	if !ok {
		return
	}
	state, err := r.server.DB().GetOperatorTOTPState(user)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled": state.Enabled,
		// pending: a setup exists but was never confirmed with a code —
		// the panel resumes the enrollment flow instead of restarting it.
		"pending": !state.Enabled && state.Secret != "",
	})
}

// accountIdentity resolves the authenticated operator from the middleware's
// server-set headers. An empty/invalid uid means the route was reached
// without the auth middleware in front (a wiring bug) — refuse rather than
// act on an unknown account.
func (r *Router) accountIdentity(w http.ResponseWriter, req *http.Request) (int, string, bool) {
	uid, err := strconv.Atoi(req.Header.Get("X-Auth-UID"))
	user := req.Header.Get("X-Auth-User")
	if err != nil || uid <= 0 || user == "" {
		http.Error(w, `{"error":"identity not resolved"}`, 500)
		return 0, "", false
	}
	return uid, user, true
}

// handleAccountPassword changes the caller's own password.
// POST /api/account/password {current_password, new_password}
func (r *Router) handleAccountPassword(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	uid, user, ok := r.accountIdentity(w, req)
	if !ok {
		return
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, 400)
		return
	}

	// The current password check runs through the SAME bcrypt verification
	// the login flow uses ( AuthenticateOperator): it is itself a
	// credential check, so failures count toward the account lockout and a
	// locked account cannot verify at all — brute-forcing the current
	// password through this endpoint hits the same wall as the login form.
	if _, err := r.server.DB().AuthenticateOperator(user, body.CurrentPassword); err != nil {
		http.Error(w, `{"error":"current password is incorrect"}`, 401)
		return
	}

	if len(body.NewPassword) < minPasswordLength || len(body.NewPassword) > maxPasswordLength {
		http.Error(w, `{"error":"new password must be between 10 and 128 characters"}`, 400)
		return
	}
	if body.NewPassword == body.CurrentPassword {
		http.Error(w, `{"error":"new password must differ from the current one"}`, 400)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error":"hash failed"}`, 500)
		return
	}
	if err := r.server.DB().SetOperatorPassword(uid, string(hash)); err != nil {
		http.Error(w, `{"error":"database error"}`, 500)
		return
	}

	// Kill every outstanding token (access + refresh): after a credential
	// change the only safe session is a fresh one. The caller re-logs-in
	// with the new password immediately — the console does it for them.
	r.server.TokenManager().RevokeUser(user)
	r.server.DB().LogAction(uid, "operator_password_change", "password changed for "+user)

	json.NewEncoder(w).Encode(map[string]interface{}{"status": "changed"})
}

// handleAccountTOTPSetup starts enrollment: generate a secret, store it
// DISABLED, return it exactly once with the otpauth URI.
// POST /api/account/totp/setup
func (r *Router) handleAccountTOTPSetup(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	uid, user, ok := r.accountIdentity(w, req)
	if !ok {
		return
	}

	// Re-setup while enabled is refused on purpose: an enabled account
	// must go through disable (code check) first — otherwise a hijacked
	// session could silently swap the second factor for its own.
	state, err := r.server.DB().GetOperatorTOTPState(user)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, 500)
		return
	}
	if state.Enabled {
		http.Error(w, `{"error":"TOTP already enabled — disable it first"}`, 409)
		return
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		http.Error(w, `{"error":"secret generation failed"}`, 500)
		return
	}
	if err := r.server.DB().SetTOTPSecret(uid, secret); err != nil {
		http.Error(w, `{"error":"database error"}`, 500)
		return
	}

	uri := totp.ProvisioningURI(secret, user, "WorldC2")
	r.server.DB().LogAction(uid, "operator_totp_setup", "pending enrollment for "+user)

	json.NewEncoder(w).Encode(map[string]string{
		"secret":      secret,
		"otpauth_uri": uri,
	})
}

// handleAccountTOTPEnable finishes enrollment: the operator proves they
// scanned/typed the secret by producing one valid code.
// POST /api/account/totp/enable {code}
func (r *Router) handleAccountTOTPEnable(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	uid, user, ok := r.accountIdentity(w, req)
	if !ok {
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, 400)
		return
	}

	state, err := r.server.DB().GetOperatorTOTPState(user)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, 500)
		return
	}
	if state.Secret == "" {
		http.Error(w, `{"error":"no pending TOTP setup — run setup first"}`, 400)
		return
	}
	if state.Enabled {
		http.Error(w, `{"error":"TOTP already enabled"}`, 409)
		return
	}
	// totp.Validate is constant-time per candidate and rejects malformed
	// input before any decode — garbage codes answer 400 honestly.
	if !totp.Validate(state.Secret, strings.TrimSpace(body.Code), time.Now()) {
		http.Error(w, `{"error":"invalid code"}`, 400)
		return
	}
	if err := r.server.DB().EnableTOTP(uid); err != nil {
		http.Error(w, `{"error":"database error"}`, 500)
		return
	}

	r.server.DB().LogAction(uid, "operator_totp_enable", "MFA enabled for "+user)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "enabled"})
}

// handleAccountTOTPDisable turns MFA off. The CURRENT secret must still
// validate — possession of the bearer token alone must not be able to
// strip the second factor.
// POST /api/account/totp/disable {code}
func (r *Router) handleAccountTOTPDisable(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	uid, user, ok := r.accountIdentity(w, req)
	if !ok {
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, 400)
		return
	}

	state, err := r.server.DB().GetOperatorTOTPState(user)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, 500)
		return
	}
	if !state.Enabled {
		http.Error(w, `{"error":"TOTP is not enabled"}`, 409)
		return
	}
	if !totp.Validate(state.Secret, strings.TrimSpace(body.Code), time.Now()) {
		http.Error(w, `{"error":"invalid code"}`, 400)
		return
	}
	if err := r.server.DB().DisableTOTP(uid); err != nil {
		http.Error(w, `{"error":"database error"}`, 500)
		return
	}

	r.server.DB().LogAction(uid, "operator_totp_disable", "MFA disabled for "+user)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "disabled"})
}
