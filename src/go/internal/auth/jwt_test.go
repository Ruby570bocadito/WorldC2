package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func newTestManager(t *testing.T) *TokenManager {
	t.Helper()
	return NewTokenManager([]byte("test-secret-key-for-unit-tests"), 12*time.Hour)
}

func TestTokenRoundtrip(t *testing.T) {
	tm := newTestManager(t)
	tok, err := tm.GenerateToken("alice", "admin")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	user, role, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if user != "alice" || role != "admin" {
		t.Fatalf("got user=%q role=%q, want alice/admin", user, role)
	}
}

func TestTokenExpired(t *testing.T) {
	tm := newTestManager(t)
	tok, err := tm.buildToken("bob", "operator", TokenUseAccess, -1*time.Second)
	if err != nil {
		t.Fatalf("buildToken: %v", err)
	}
	if _, _, err := tm.ValidateToken(tok); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestRefreshTokenCannotAccessAPI(t *testing.T) {
	tm := newTestManager(t)
	refresh, err := tm.GenerateRefreshToken("carol")
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}
	if _, _, err := tm.ValidateToken(refresh); err == nil {
		t.Fatal("refresh token must not validate as access token")
	}
	// ...and the refresh path must accept it.
	if user, err := tm.ValidateRefreshToken(refresh); err != nil || user != "carol" {
		t.Fatalf("ValidateRefreshToken: user=%q err=%v", user, err)
	}
	// ...while an access token must be rejected as refresh.
	access, _ := tm.GenerateToken("carol", "operator")
	if _, err := tm.ValidateRefreshToken(access); err == nil {
		t.Fatal("access token must not validate as refresh token")
	}
}

func TestAlgorithmPinning(t *testing.T) {
	tm := newTestManager(t)
	tok, _ := tm.GenerateToken("dave", "viewer")

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed test token")
	}
	// Craft a header claiming "none" — must be rejected before signature checks.
	noneHeader, _ := json.Marshal(jwtHeader{Alg: "none", Typ: "JWT"})
	forged := base64.RawURLEncoding.EncodeToString(noneHeader) + "." + parts[1] + "." + parts[2]
	if _, _, err := tm.ValidateToken(forged); err == nil {
		t.Fatal("alg=none token must be rejected")
	}
}

func TestSignatureTamper(t *testing.T) {
	tm := newTestManager(t)
	tok, _ := tm.GenerateToken("eve", "operator")

	parts := strings.Split(tok, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	// Escalate the role inside the payload and keep the original signature.
	tampered := strings.Replace(string(payload), `"role":"operator"`, `"role":"admin"`, 1)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(tampered)) + "." + parts[2]
	if _, _, err := tm.ValidateToken(forged); err == nil {
		t.Fatal("payload tampering must break the signature check")
	}
}

func TestRevokeUserInvalidatesOldTokens(t *testing.T) {
	tm := newTestManager(t)

	access, _ := tm.GenerateToken("frank", "operator")
	refresh, _ := tm.GenerateRefreshToken("frank")

	if _, _, err := tm.ValidateToken(access); err != nil {
		t.Fatalf("pre-revocation token should be valid: %v", err)
	}

	tm.RevokeUser("frank")

	if _, _, err := tm.ValidateToken(access); err == nil {
		t.Fatal("access token must be rejected after RevokeUser")
	}
	if _, err := tm.ValidateRefreshToken(refresh); err == nil {
		t.Fatal("refresh token must be rejected after RevokeUser")
	}

	// Tokens issued after the revocation event remain valid.
	time.Sleep(1100 * time.Millisecond) // iat has 1s resolution
	newTok, _ := tm.GenerateToken("frank", "operator")
	if _, _, err := tm.ValidateToken(newTok); err != nil {
		t.Fatalf("post-revocation token should be valid: %v", err)
	}
}

func TestRevocationIsScopedPerUser(t *testing.T) {
	tm := newTestManager(t)
	alice, _ := tm.GenerateToken("alice", "admin")
	bob, _ := tm.GenerateToken("bob", "operator")

	tm.RevokeUser("alice")

	if _, _, err := tm.ValidateToken(alice); err == nil {
		t.Fatal("alice token must be rejected after revoking alice")
	}
	if _, _, err := tm.ValidateToken(bob); err != nil {
		t.Fatalf("bob token must stay valid: %v", err)
	}
}

func TestConcurrentValidationAndRevocation(t *testing.T) {
	tm := newTestManager(t)
	// gina gets revoked in a loop while hank's (never revoked) token is
	// validated in parallel — exercises the revocation registry under
	// contention; the race detector is the real assertion here.
	tok, _ := tm.GenerateToken("hank", "operator")

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			tm.RevokeUser("gina")
		}
	}()
	for i := 0; i < 200; i++ {
		if _, _, err := tm.ValidateToken(tok); err != nil {
			t.Fatalf("ValidateToken raced unsafely: %v", err)
		}
	}
	<-done
}
