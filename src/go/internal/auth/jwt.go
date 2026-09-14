package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// JWT represents a JSON Web Token (simplified, HMAC-SHA256 only).
type JWT struct {
	Header    jwtHeader
	Payload   jwtPayload
	Signature string
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtPayload struct {
	Sub       string `json:"sub"`
	Role      string `json:"role"`
	TokenUse  string `json:"token_use"` // "access" or "refresh"
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	// Jti (JWT ID) identifies refresh tokens so rotations can deny replays
	// of an already-consumed token. Access tokens carry none (stateless).
	Jti string `json:"jti,omitempty"`
}

// Token type values.
const (
	TokenUseAccess  = "access"
	TokenUseRefresh = "refresh"
)

// TokenManager handles JWT token generation and validation.
type TokenManager struct {
	secretKey     []byte
	tokenDuration time.Duration
	issuer        string

	// revokedBefore maps username -> unix timestamp: tokens for that user
	// with an issued-at (iat) strictly older than the timestamp are rejected.
	// It backs RevokeUser, so deleting an operator (or otherwise revoking
	// access) invalidates every token minted before that moment, even ones
	// whose HMAC is still valid and whose signing key survives restarts.
	revokedMu     sync.RWMutex
	revokedBefore map[string]int64

	// Refresh rotation (round 10): consumed refresh-token jtis are recorded
	// here; presenting the same refresh token twice is denied with 401 so
	// a stolen token cannot be replayed after the legitimate client has
	// rotated. Entries are pruned lazily (expired or past a sanity cap).
	usedMu         sync.Mutex
	usedRefreshJti map[string]int64 // jti -> expiry unix
}

// NewTokenManager creates a new JWT token manager.
func NewTokenManager(secretKey []byte, tokenDuration time.Duration) *TokenManager {
	if len(secretKey) == 0 {
		secretKey = generateSecretKey()
	}
	return &TokenManager{
		secretKey:      secretKey,
		tokenDuration:  tokenDuration,
		issuer:         "worldc2-c2",
		revokedBefore:  make(map[string]int64),
		usedRefreshJti: make(map[string]int64),
	}
}

// RevokeUser invalidates every outstanding token for the given username that
// was issued up to and including the revocation moment. Tokens minted
// afterwards (e.g. a re-created operator with the same name) remain valid.
// The cut is conservative (now+1s, because iat has 1-second resolution): a
// token legitimately minted within the same second as the revocation is
// rejected too — erring on the safe side of the window. Revocations live for
// the lifetime of the process; the signing key is persisted in the secrets
// store, so without this registry a deleted operator would keep working until
// their token expired.
func (tm *TokenManager) RevokeUser(username string) {
	tm.revokedMu.Lock()
	defer tm.revokedMu.Unlock()
	tm.revokedBefore[username] = time.Now().Unix() + 1
}

func (tm *TokenManager) sign(headerB64, payloadB64 string) string {
	mac := hmac.New(sha256.New, tm.secretKey)
	mac.Write([]byte(headerB64 + "." + payloadB64))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (tm *TokenManager) buildToken(sub, role, tokenUse string, ttl time.Duration) (string, error) {
	return tm.buildTokenJti(sub, role, tokenUse, ttl, "")
}

// buildTokenJti is buildToken with an optional jti for refresh tokens.
func (tm *TokenManager) buildTokenJti(sub, role, tokenUse string, ttl time.Duration, jti string) (string, error) {
	now := time.Now().Unix()

	header := jwtHeader{Alg: "HS256", Typ: "JWT"}
	payload := jwtPayload{
		Sub:       sub,
		Role:      role,
		TokenUse:  tokenUse,
		IssuedAt:  now,
		ExpiresAt: now + int64(ttl.Seconds()),
		Jti:       jti,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	return headerB64 + "." + payloadB64 + "." + tm.sign(headerB64, payloadB64), nil
}

// GenerateToken creates a new access JWT for the given user.
func (tm *TokenManager) GenerateToken(username, role string) (string, error) {
	return tm.buildToken(username, role, TokenUseAccess, tm.tokenDuration)
}

// GenerateRefreshToken creates a long-lived refresh token carrying a unique
// jti so rotations can deny replays of a consumed token. Refresh tokens carry
// token_use=refresh and are rejected by ValidateToken, so a leaked refresh
// token cannot be replayed against the API.
func (tm *TokenManager) GenerateRefreshToken(username string) (string, error) {
	jti, err := randomJti()
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	return tm.buildTokenJti(username, TokenUseRefresh, TokenUseRefresh, refreshDuration, jti)
}

const refreshDuration = 24 * time.Hour

// decodeRefreshPayload extracts the payload of a signature-verified refresh
// token and enforces the jti boundary: a refresh token without a jti cannot
// take part in one-time-use tracking, so honoring it would accept the SAME
// token on every presentation — an unbounded replay window against the
// rotation contract. Pre-rotation tokens were only ever issued with a 24h
// expiry, so any that still show up are replaying a stale credential; the
// operator is asked to log in again (fail-closed).
func decodeRefreshPayload(tokenString string) (jwtPayload, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return jwtPayload{}, fmt.Errorf("malformed token")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwtPayload{}, fmt.Errorf("invalid payload encoding")
	}
	var payload jwtPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil || payload.Jti == "" {
		return jwtPayload{}, fmt.Errorf("invalid refresh payload")
	}
	return payload, nil
}

// RotateRefreshToken consumes a refresh token and issues its replacement —
// the rotation contract: each refresh token works exactly once.
//   - A replay of an already-consumed token is DENIED (the legitimate client
//     holds its replacement; whoever presents the old one is replaying it).
//   - Family-wide revocation on reuse was considered and deliberately left
//     out: the console shares localStorage across tabs, and a stale second
//     tab could lock its own operator out. Binding refresh tokens per device
//     is the proper fix and is tracked as follow-up design work.
//
// Returns the username and the jti of the NEW refresh token.
func (tm *TokenManager) RotateRefreshToken(oldToken string) (username string, err error) {
	// Decode WITHOUT consuming: we need the jti + expiry to record usage
	// only after full validation succeeds.
	sub, _, tokenUse, err := tm.validate(oldToken)
	if err != nil {
		return "", err
	}
	if tokenUse != TokenUseRefresh {
		return "", fmt.Errorf("not a refresh token")
	}

	payload, err := decodeRefreshPayload(oldToken)
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	tm.usedMu.Lock()
	defer tm.usedMu.Unlock()
	tm.pruneUsedLocked(now)
	if _, consumed := tm.usedRefreshJti[payload.Jti]; consumed {
		return "", fmt.Errorf("refresh token already consumed")
	}
	tm.usedRefreshJti[payload.Jti] = payload.ExpiresAt
	return sub, nil
}

// pruneUsedLocked drops consumed-jti entries whose tokens have expired.
// Caller holds usedMu.
func (tm *TokenManager) pruneUsedLocked(now int64) {
	for jti, exp := range tm.usedRefreshJti {
		if exp < now {
			delete(tm.usedRefreshJti, jti)
		}
	}
}

func randomJti() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValidateRefreshToken validates a refresh token and returns the username.
// It enforces the same jti boundary as rotation: pre-rotation no-jti
// refresh tokens are rejected (they cannot be tracked for one-time use).
func (tm *TokenManager) ValidateRefreshToken(tokenString string) (string, error) {
	sub, _, tokenUse, err := tm.validate(tokenString)
	if err != nil {
		return "", err
	}
	if tokenUse != TokenUseRefresh {
		return "", fmt.Errorf("not a refresh token")
	}
	if _, err := decodeRefreshPayload(tokenString); err != nil {
		return "", err
	}
	return sub, nil
}

// ValidateToken validates an access JWT token and returns the username and role.
func (tm *TokenManager) ValidateToken(tokenString string) (username, role string, err error) {
	sub, role, tokenUse, err := tm.validate(tokenString)
	if err != nil {
		return "", "", err
	}
	if tokenUse == TokenUseRefresh {
		return "", "", fmt.Errorf("refresh token cannot be used for API access")
	}
	return sub, role, nil
}

// validate performs signature, algorithm and expiration checks.
func (tm *TokenManager) validate(tokenString string) (sub, role, tokenUse string, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid token format")
	}

	signature := parts[2]

	// Decode and verify the header BEFORE trusting any claims: this pins
	// the algorithm and prevents header-confusion attacks.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", "", fmt.Errorf("invalid header encoding")
	}
	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", "", "", fmt.Errorf("invalid header")
	}
	if header.Alg != "HS256" {
		return "", "", "", fmt.Errorf("unexpected signing algorithm %q", header.Alg)
	}

	expectedSig := tm.sign(parts[0], parts[1])
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", "", "", fmt.Errorf("invalid signature")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", "", fmt.Errorf("invalid payload encoding")
	}

	var payload jwtPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return "", "", "", fmt.Errorf("invalid payload")
	}

	if payload.TokenUse == "" {
		// Tokens issued before token_use existed are treated as access.
		payload.TokenUse = TokenUseAccess
	}

	if time.Now().Unix() > payload.ExpiresAt {
		return "", "", "", fmt.Errorf("token expired")
	}

	// Reject tokens minted before a per-user revocation event.
	tm.revokedMu.RLock()
	minIat, revoked := tm.revokedBefore[payload.Sub]
	tm.revokedMu.RUnlock()
	if revoked && payload.IssuedAt < minIat {
		return "", "", "", fmt.Errorf("token revoked for user %q", payload.Sub)
	}

	return payload.Sub, payload.Role, payload.TokenUse, nil
}

// GetSecretKey returns the secret key (for sharing with agents if needed).
func (tm *TokenManager) GetSecretKey() []byte {
	return tm.secretKey
}

func generateSecretKey() []byte {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return key
}
