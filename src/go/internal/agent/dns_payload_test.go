package agent

import (
	"encoding/base64"
	"testing"
)

// wireNameLen computes the on-the-wire length of a dotted name (one length
// byte per label plus the terminating zero byte) and rejects labels over 63.
func wireNameLen(t *testing.T, name string) int {
	t.Helper()
	wire := 1 // terminating zero
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			l := i - start
			if l > 63 {
				t.Fatalf("label too long (%d chars): %q", l, name[start:i])
			}
			wire += 1 + l
			start = i + 1
		}
	}
	return wire
}

// TestMaxDNSPayloadBoundsQueryName checks the payload-size computation for
// normal and pathological domain lengths: the payload must never be negative
// and the wire query built with it must respect DNS name limits (<= 255 bytes
// on the wire, labels <= 63 chars) so nothing is silently truncated.
func TestMaxDNSPayloadBoundsQueryName(t *testing.T) {
	domains := []string{
		"c2.example.com",         // typical (14 chars)
		"t1.c2.evil.example.com", // 23 chars
		"",                       // degenerate
	}

	for _, d := range domains {
		payload := maxDNSPayload(len(d))
		if payload < 0 {
			t.Fatalf("domain %q: negative payload %d", d, payload)
		}
		if payload <= 0 {
			continue // nothing fits — fine, Write clamps to 32
		}
		data := make([]byte, payload)
		for i := range data {
			data[i] = byte('a' + i%26)
		}
		q := buildDNSQuery("0123456789abcdef", d, data)
		name, ok := qnameOf(q)
		if !ok {
			t.Fatalf("domain %q: query name could not be parsed back", d)
		}
		if wire := wireNameLen(t, name); wire > 255 {
			t.Fatalf("domain %q (len %d): wire name %d bytes exceeds 255", d, len(d), wire)
		}
	}
}

// TestMaxDNSPayloadLongDomainClamps verifies that an absurdly long domain
// cannot make the computed payload negative, and that dialDNS rejects such a
// domain up front instead of silently emitting a corrupt wire name (a label
// longer than 63 bytes truncates its length byte and breaks every query).
func TestMaxDNSPayloadLongDomainClamps(t *testing.T) {
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'x'
	}
	d := string(long) + ".com"

	if payload := maxDNSPayload(len(d)); payload < 0 {
		t.Fatalf("long domain: negative payload %d", payload)
	}

	if _, err := dialDNS("127.0.0.1:53531", d); err == nil {
		t.Fatal("dialDNS must reject a domain that cannot fit in a DNS name")
	}
	if _, err := dialDNS("127.0.0.1:53531", ""); err == nil {
		t.Fatal("dialDNS must reject an empty domain")
	}
	if _, err := dialDNS("127.0.0.1:53531", "c2.example.com"); err != nil {
		t.Fatalf("dialDNS rejects a valid domain: %v", err)
	}
}

// qnameOf parses the question name out of a query built by buildDNSQuery.
func qnameOf(q []byte) (string, bool) {
	if len(q) < 12 {
		return "", false
	}
	var name string
	off := 12
	for {
		if off >= len(q) {
			return "", false
		}
		l := int(q[off])
		if l == 0 {
			break
		}
		if off+1+l > len(q) {
			return "", false
		}
		if len(name) > 0 {
			name += "."
		}
		name += string(q[off+1 : off+1+l])
		off += 1 + l
	}
	return name, true
}

// decodeLabelsForTest mirrors the server's decodeDNSSubdomain (the first
// label is the session id and is not part of the payload).
func decodeLabelsForTest(sub string) []byte {
	var out []byte
	start := 0
	first := true
	for i := 0; i <= len(sub); i++ {
		if i == len(sub) || sub[i] == '.' {
			label := sub[start:i]
			start = i + 1
			if label == "" {
				continue
			}
			if first {
				first = false
				continue
			}
			if b, err := base64.RawURLEncoding.DecodeString(label); err == nil {
				out = append(out, b...)
			}
		}
	}
	return out
}
