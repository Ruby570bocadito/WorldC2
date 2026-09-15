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

// TestRotationRejectsLegacyNoJtiTokens pins the removal of the pre-rotation
// compat shim (round 12): a refresh token without a jti cannot be tracked
// for one-time use, so the old shim accepted the SAME token on every
// presentation — an unbounded replay window. Signature-valid no-jti refresh
// tokens are now rejected outright (fail-closed); a legacy operator simply
// logs in again.
func TestRotationRejectsLegacyNoJtiTokens(t *testing.T) {
	tm := NewTokenManager(nil, 12*time.Hour)

	// A signature-valid refresh token WITHOUT jti: exactly the shape the
	// pre-rotation fleet minted (buildToken leaves jti empty).
	legacy, err := tm.buildToken("alice", "admin", TokenUseRefresh, time.Hour)
	if err != nil {
		t.Fatalf("build legacy refresh: %v", err)
	}

	if _, err := tm.RotateRefreshToken(legacy); err == nil {
		t.Fatal("legacy no-jti refresh token accepted by rotation")
	}
	// Repeated presentations stay denied too — the shim used to accept
	// them every single time.
	if _, err := tm.RotateRefreshToken(legacy); err == nil {
		t.Fatal("legacy no-jti refresh token accepted on replay")
	}

	// ValidateRefreshToken keeps the same boundary: a no-jti refresh token
	// is not a valid refresh credential, not even for inspection.
	if _, err := tm.ValidateRefreshToken(legacy); err == nil {
		t.Fatal("legacy no-jti refresh token accepted by ValidateRefreshToken")
	}
}

// TestRevokeThenImmediateRelogin pins the r19 revocation precision: after
// RevokeUser, a token minted BEFORE it is rejected, and a token minted
// AFTER it (even within the same millisecond window a seconds-only iat
// could not classify) validates — the password-change → immediate
// re-login flow must not bounce the owner.
func TestRevokeThenImmediateRelogin(t *testing.T) {
	tm := NewTokenManager(nil, time.Hour)

	oldToken, err := tm.GenerateToken("dave", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tm.ValidateToken(oldToken); err != nil {
		t.Fatalf("pre-revocation token must validate: %v", err)
	}

	// Separate the mint and the revoke by a few milliseconds so the test
	// never lands inside the 1ms classification window (a token minted in
	// the SAME millisecond as the revocation is allowed — the ambiguity
	// window shrank from 1s to 1ms by design).
	time.Sleep(5 * time.Millisecond)
	tm.RevokeUser("dave")

	// The outstanding token dies.
	if _, _, err := tm.ValidateToken(oldToken); err == nil {
		t.Fatal("pre-revocation token must be rejected after RevokeUser")
	}

	// A fresh login minted immediately after the revocation LIVES.
	fresh, err := tm.GenerateToken("dave", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tm.ValidateToken(fresh); err != nil {
		t.Fatalf("post-revocation login must validate even in the same second: %v", err)
	}

	// Refresh tokens minted before the revocation die too (rotation runs
	// through the same validate path).
	oldRefresh, err := tm.GenerateRefreshToken("dave")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	tm.RevokeUser("dave")
	if _, err := tm.RotateRefreshToken(oldRefresh); err == nil {
		t.Fatal("pre-revocation refresh token must be rejected")
	}
	freshRefresh, _ := tm.GenerateRefreshToken("dave")
	if _, err := tm.RotateRefreshToken(freshRefresh); err != nil {
		t.Fatalf("post-revocation refresh token must rotate: %v", err)
	}
}
