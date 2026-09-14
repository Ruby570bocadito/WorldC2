package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
}

// NewTokenManager creates a new JWT token manager.
func NewTokenManager(secretKey []byte, tokenDuration time.Duration) *TokenManager {
	if len(secretKey) == 0 {
		secretKey = generateSecretKey()
	}
	return &TokenManager{
		secretKey:     secretKey,
		tokenDuration: tokenDuration,
		issuer:        "worldc2-c2",
		revokedBefore: make(map[string]int64),
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
	now := time.Now().Unix()

	header := jwtHeader{Alg: "HS256", Typ: "JWT"}
	payload := jwtPayload{
		Sub:       sub,
		Role:      role,
		TokenUse:  tokenUse,
		IssuedAt:  now,
		ExpiresAt: now + int64(ttl.Seconds()),
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

// GenerateRefreshToken creates a long-lived refresh token.
// Refresh tokens carry token_use=refresh and are rejected by ValidateToken,
// so a leaked refresh token cannot be replayed against the API.
func (tm *TokenManager) GenerateRefreshToken(username string) (string, error) {
	return tm.buildToken(username, TokenUseRefresh, TokenUseRefresh, 24*time.Hour)
}

// ValidateRefreshToken validates a refresh token and returns the username.
func (tm *TokenManager) ValidateRefreshToken(tokenString string) (string, error) {
	sub, _, tokenUse, err := tm.validate(tokenString)
	if err != nil {
		return "", err
	}
	if tokenUse != TokenUseRefresh {
		return "", fmt.Errorf("not a refresh token")
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
