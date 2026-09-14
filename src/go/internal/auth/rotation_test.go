package auth

import (
	"strings"
	"testing"
	"time"
)

// TestRefreshRotationOneTimeUse pins the rotation contract added in round 10:
// every refresh token works exactly once via RotateRefreshToken — the first
// rotation consumes it (and the caller mints a replacement), the second
// presentation is denied.
func TestRefreshRotationOneTimeUse(t *testing.T) {
	tm := NewTokenManager(nil, 12*time.Hour)

	old, err := tm.GenerateRefreshToken("alice")
	if err != nil {
		t.Fatalf("generate refresh: %v", err)
	}
	if !strings.Contains(old, ".") {
		t.Fatal("token shape broken")
	}

	// First rotation: accepted.
	if _, err := tm.RotateRefreshToken(old); err != nil {
		t.Fatalf("first rotation rejected: %v", err)
	}

	// Second rotation with the SAME token: denied (replay).
	if _, err := tm.RotateRefreshToken(old); err == nil {
		t.Fatal("replayed refresh token accepted")
	}
}

// TestRotationRejectsAccessTokens keeps the token_use boundary: an access
// token must never be accepted by the rotation path (it has no jti and the
// wrong token_use).
func TestRotationRejectsAccessTokens(t *testing.T) {
	tm := NewTokenManager(nil, 12*time.Hour)
	access, err := tm.GenerateToken("alice", "admin")
	if err != nil {
		t.Fatalf("generate access: %v", err)
	}
	if _, err := tm.RotateRefreshToken(access); err == nil {
		t.Fatal("access token accepted by RotateRefreshToken")
	}
}

// TestRotationValidatesSignature: a tampered refresh token is rejected
// before any jti bookkeeping happens.
func TestRotationValidatesSignature(t *testing.T) {
	tm := NewTokenManager(nil, 12*time.Hour)
	tok, err := tm.GenerateRefreshToken("alice")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	parts := strings.Split(tok, ".")
	forged := parts[0] + ".eyJzdWIiOiJldmlsIn0." + parts[2]
	if _, err := tm.RotateRefreshToken(forged); err == nil {
		t.Fatal("forged refresh token accepted")
	}
}
