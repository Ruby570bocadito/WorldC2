// Package totp implements RFC 6238 time-based one-time passwords with the
// standard library only (crypto/hmac + crypto/sha1): no new module
// dependencies, matching the house rule every round so far.
//
// Supported: 6-digit codes (the authenticator-app default), SHA-1, 30-second
// steps and a validation skew of ±1 step — the interoperable profile every
// mainstream authenticator (Google Authenticator, Aegis, 1Password, Authy)
// ships by default.
//
// Security notes for reviewers:
//   - Validate compares with hmac.Equal (constant time), never ==.
//   - Validation walks the CURRENT time step and the skew neighbours and
//     accepts if ANY matches, which absorbs clock drift between server and
//     phone without widening the brute-force surface beyond 3 codes/step.
//   - Secrets are generated with crypto/rand and encoded Base32 (RFC 4648,
//     no padding) — the format every authenticator expects when you type or
//     paste a manual setup key.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Step is the RFC 6238 default time window: 30 seconds.
const Step = 30 * time.Second

// Digits is the code length produced and accepted: 6, the authenticator-app
// default. The RFC's 8-digit variant exists but no mainstream app defaults
// to it, and accepting two lengths only widens the input-validation surface.
const Digits = 6

// Skew is how many steps on either side of the current one are accepted
// during validation. 1 tolerates ±30s of clock drift — enough for phones
// synced by NTP, small enough to keep the per-step guessing window at 3
// codes (the per-IP login rate limiter and the DB account lockout are the
// real defenses).
const Skew = 1

// codec is the Base32 alphabet authenticators accept for manual entry:
// A-Z and 2-7, no padding (pad characters break some apps' paste handler).
var codec = base32.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").WithPadding(base32.NoPadding)

// GenerateSecret creates a new 20-byte (160-bit) secret and returns it
// Base32-encoded. 160 bits is the RFC 4226 recommendation; 20 bytes encode
// to exactly 32 Base32 characters, the display length authenticators format
// in groups of 4.
func GenerateSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return codec.EncodeToString(raw), nil
}

// normalize strips separators and lowercases a user-entered secret so both
// "abcd efgh" and "abcdefgh" resolve to the same key.
func normalize(secret string) string {
	s := strings.ToUpper(secret)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}

// Code computes the 6-digit code for the given secret at time t. Exported
// for tests and the provisioning round-trip; the server's only production
// caller is Validate.
func Code(secret string, t time.Time) (string, error) {
	key, err := codec.DecodeString(normalize(secret))
	if err != nil {
		return "", fmt.Errorf("decode totp secret: %w", err)
	}
	counter := uint64(t.Unix()) / uint64(Step/time.Second)
	return hotp(key, counter), nil
}

// hotp is RFC 4226: HMAC-SHA-1 over the big-endian counter, dynamic
// truncation, mod 10^digits, zero-padded.
func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation: the low 4 bits of the last byte pick the offset.
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	code := bin % 1000000 // 10^Digits
	return fmt.Sprintf("%06d", code)
}

// Validate reports whether code is a valid 6-digit TOTP for secret at time
// t, accepting the current step and Skew neighbours (newer AND older: a
// phone a few seconds ahead is as common as one a few seconds behind).
// Comparison is constant time per candidate via hmac.Equal; the function
// returns true on the FIRST match, which leaks only "which of ≤3 candidates
// matched" — the same 1-bit-per-attempt signal every TOTP verifier exposes,
// and worthless against an attacker who cannot guess the key.
func Validate(secret, code string, t time.Time) bool {
	if len(code) != Digits {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}

	key, err := codec.DecodeString(normalize(secret))
	if err != nil {
		return false
	}

	step := uint64(t.Unix()) / uint64(Step/time.Second)
	given := []byte(code)
	for i := uint64(0); i <= Skew; i++ {
		if i == 0 {
			if hmac.Equal(given, []byte(hotp(key, step))) {
				return true
			}
			continue
		}
		// Guard the underflow: near-epoch times would wrap uint64 and
		// produce a nonsense counter — harmless, but skip it honestly.
		if step >= i && hmac.Equal(given, []byte(hotp(key, step-i))) {
			return true
		}
		if hmac.Equal(given, []byte(hotp(key, step+i))) {
			return true
		}
	}
	return false
}

// escapeLabel escapes one otpauth label segment. url.PathEscape alone
// leaves &, = and ? intact (they are legal in a path segment), but QR
// scanners and hand-parsers disagree about them inside the label — escape
// them explicitly so a hostile username ("a&b=1") cannot inject extra
// parameters into the URI the operator scans.
func escapeLabel(s string) string {
	s = url.PathEscape(s)
	s = strings.ReplaceAll(s, "&", "%26")
	s = strings.ReplaceAll(s, "=", "%3D")
	s = strings.ReplaceAll(s, "?", "%3F")
	return s
}

// ProvisioningURI builds the otpauth:// URI authenticators scan as a QR
// code (RFC 6238 de-facto standard, as coined by the Google Authenticator
// key URI format):
//
//	otpauth://totp/<issuer>:<account>?secret=<s>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30
//
// The account label and issuer are escaped — a username containing '&' or
// spaces must not be able to inject extra query parameters into the URI the
// operator scans.
func ProvisioningURI(secret, account, issuer string) string {
	label := escapeLabel(issuer) + ":" + escapeLabel(account)
	q := url.Values{}
	q.Set("secret", normalize(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}
