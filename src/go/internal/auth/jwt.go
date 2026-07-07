package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
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
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// TokenManager handles JWT token generation and validation.
type TokenManager struct {
	secretKey     []byte
	tokenDuration time.Duration
	issuer        string
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
	}
}

// GenerateToken creates a new JWT token for the given user.
func (tm *TokenManager) GenerateToken(username, role string) (string, error) {
	now := time.Now().Unix()

	header := jwtHeader{Alg: "HS256", Typ: "JWT"}
	payload := jwtPayload{
		Sub:       username,
		Role:      role,
		IssuedAt:  now,
		ExpiresAt: now + int64(tm.tokenDuration.Seconds()),
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64

	mac := hmac.New(sha256.New, tm.secretKey)
	mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + signature, nil
}

// ValidateToken validates a JWT token and returns the username and role.
func (tm *TokenManager) ValidateToken(tokenString string) (username, role string, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]
	signature := parts[2]

	// Verify signature
	mac := hmac.New(sha256.New, tm.secretKey)
	mac.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", "", fmt.Errorf("invalid signature")
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("invalid payload encoding")
	}

	var payload jwtPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return "", "", fmt.Errorf("invalid payload")
	}

	// Check expiration
	if time.Now().Unix() > payload.ExpiresAt {
		return "", "", fmt.Errorf("token expired")
	}

	return payload.Sub, payload.Role, nil
}

// GetSecretKey returns the secret key (for sharing with agents if needed).
func (tm *TokenManager) GetSecretKey() []byte {
	return tm.secretKey
}

// GenerateRefreshToken creates a long-lived refresh token.
func (tm *TokenManager) GenerateRefreshToken(username string) (string, error) {
	now := time.Now().Unix()

	header := jwtHeader{Alg: "HS256", Typ: "JWT"}
	payload := jwtPayload{
		Sub:       username,
		Role:      "refresh",
		IssuedAt:  now,
		ExpiresAt: now + int64(24*time.Hour.Seconds()), // 24h refresh token
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64

	mac := hmac.New(sha256.New, tm.secretKey)
	mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + signature, nil
}

func generateSecretKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}
