package totp

import (
	"strings"
	"testing"
	"time"
)

// rfcSecret is the RFC 4226/6238 reference secret: the ASCII string
// "12345678901234567890", Base32-encoded. The RFC's TOTP table (SHA-1) was
// computed with it, so the 6-digit expectations below are the last 6 digits
// of the published 8-digit values — an INDEPENDENT oracle, not a
// round-trip of our own implementation.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// TestRFC6238Vectors pins the implementation against the published RFC
// table (SHA-1, T0=0, step 30). 6-digit codes are the last 6 of the RFC's
// 8-digit columns: e.g. T=59 → 94287082 → 287082.
func TestRFC6238Vectors(t *testing.T) {
	// want8 is the RFC's published 8-digit column (SHA-1); the expectation
	// for our 6-digit code is its last 6 characters — e.g. T=59 →
	// 94287082 → "287082". That derivation is the RFC's own truncation
	// arithmetic (mod 10^6 of the same 31-bit value), not a round-trip of
	// this implementation.
	cases := []struct {
		unix  int64
		want8 string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		got, err := Code(rfcSecret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("T=%d: %v", c.unix, err)
		}
		if len(got) != 6 {
			t.Fatalf("T=%d: got %q, want 6 digits", c.unix, got)
		}
		want6 := c.want8[len(c.want8)-6:]
		if got != want6 {
			t.Errorf("T=%d: got %q want %q (rfc8=%s)", c.unix, got, want6, c.want8)
		}
	}
}

// TestValidateWindow pins the ±1 step acceptance: a code computed at T is
// valid at T, T+30 and T-30 (skew neighbours) and invalid at T±60.
func TestValidateWindow(t *testing.T) {
	base := time.Unix(1700000000, 0)
	code, err := Code(rfcSecret, base)
	if err != nil {
		t.Fatal(err)
	}
	if !Validate(rfcSecret, code, base) {
		t.Error("code should validate at its own step")
	}
	if !Validate(rfcSecret, code, base.Add(Step)) {
		t.Error("code should validate one step ahead (skew)")
	}
	if !Validate(rfcSecret, code, base.Add(-Step)) {
		t.Error("code should validate one step behind (skew)")
	}
	if Validate(rfcSecret, code, base.Add(2*Step)) {
		t.Error("code two steps ahead must be rejected")
	}
	if Validate(rfcSecret, code, base.Add(-2*Step)) {
		t.Error("code two steps behind must be rejected")
	}
}

// TestValidateRejectsGarbage pins the input validation: wrong length,
// non-digits, empty secret, malformed base32 and empty codes all reject
// without panicking.
func TestValidateRejectsGarbage(t *testing.T) {
	base := time.Unix(1700000000, 0)
	bad := []string{"", "12345", "1234567", "abcdef", "12 456", "12345a", "±12345"}
	for _, code := range bad {
		if Validate(rfcSecret, code, base) {
			t.Errorf("garbage code %q must be rejected", code)
		}
	}
	if Validate("", "123456", base) {
		t.Error("empty secret must be rejected")
	}
	if Validate("not-base32!!!", "123456", base) {
		t.Error("malformed base32 secret must be rejected (not panic)")
	}
}

// TestNormalize pins the manual-entry tolerance: lowercase, spaces and
// dashes in pasted secrets must not break provisioning round-trips.
func TestNormalize(t *testing.T) {
	pretty := "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
	base := time.Unix(1700000000, 0)
	code, err := Code(rfcSecret, base)
	if err != nil {
		t.Fatal(err)
	}
	if !Validate(pretty, code, base) {
		t.Error("formatted/lowercased secret must validate identically")
	}
}

// TestGenerateSecretShape pins the generator: 160 bits → 32 Base32 chars,
// alphabet A-Z2-7, and two consecutive secrets must differ (rand-backed).
func TestGenerateSecretShape(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 {
		t.Fatalf("secret length = %d, want 32 base32 chars", len(a))
	}
	for _, c := range a {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", c) {
			t.Fatalf("invalid base32 char %q in %q", string(c), a)
		}
	}
	b, _ := GenerateSecret()
	if a == b {
		t.Error("two generated secrets must never match")
	}
	// Generated secrets must validate round-trip.
	now := time.Now()
	code, _ := Code(a, now)
	if !Validate(a, code, now) {
		t.Error("generated secret must validate its own code")
	}
}

// TestProvisioningURI pins the otpauth URI: components, escaping of a
// hostile username (no parameter injection) and parameter order stability
// (url.Values.Encode sorts — the URI is deterministic).
func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI(rfcSecret, "admin", "WorldC2")
	want := "otpauth://totp/WorldC2:admin?algorithm=SHA1&digits=6&issuer=WorldC2&period=30&secret=" + rfcSecret
	if uri != want {
		t.Errorf("got %q want %q", uri, want)
	}

	hostile := ProvisioningURI(rfcSecret, "a&b=1 c", "Is sue")
	if strings.Contains(hostile, "a&b=1") {
		t.Errorf("username must be path-escaped: %q", hostile)
	}
	if !strings.HasPrefix(hostile, "otpauth://totp/Is%20sue:a%26b%3D1%20c?") {
		t.Errorf("unexpected escaping: %q", hostile)
	}
}
