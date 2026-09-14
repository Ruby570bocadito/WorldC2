package agent

import "testing"

func TestNormalizePort(t *testing.T) {
	cases := []struct {
		in, def, want string
	}{
		{"", "8445", "8445"},     // empty keeps default
		{"9000", "8445", "9000"}, // valid override
		{"1", "8445", "1"},       // lower bound
		{"65535", "8445", "65535"},
		{"65536", "8445", "8445"},  // out of range
		{"0", "8445", "8445"},      // invalid: port 0
		{"abc", "8445", "8445"},    // non-numeric
		{"90a0", "8445", "8445"},   // mixed
		{"-1", "8445", "8445"},     // sign
		{" 8445", "8445", "8445"},  // whitespace
		{"123456", "8445", "8445"}, // too long
	}
	for _, c := range cases {
		if got := normalizePort(c.in, c.def); got != c.want {
			t.Errorf("normalizePort(%q, %q) = %q, want %q", c.in, c.def, got, c.want)
		}
	}
}

func TestSetTransportPorts(t *testing.T) {
	a := New("127.0.0.1:8443")

	// Defaults intact without flags.
	if a.httpPort != "8445" || a.wsPort != "8446" || a.webrtcPort != "8447" || a.agentDnsPort != "8444" {
		t.Fatalf("unexpected defaults: %s/%s/%s/%s", a.httpPort, a.wsPort, a.webrtcPort, a.agentDnsPort)
	}

	// Empty flags keep defaults.
	a.SetTransportPorts("", "", "", "")
	if a.httpPort != "8445" || a.wsPort != "8446" {
		t.Fatalf("empty flags must keep defaults: %s/%s", a.httpPort, a.wsPort)
	}

	// Valid overrides applied.
	a.SetTransportPorts("9001", "9002", "9003", "9004")
	if a.httpPort != "9001" || a.wsPort != "9002" || a.webrtcPort != "9003" || a.agentDnsPort != "9004" {
		t.Fatalf("overrides not applied: %s/%s/%s/%s", a.httpPort, a.wsPort, a.webrtcPort, a.agentDnsPort)
	}

	// Invalid values keep the CURRENT value (not the compiled default).
	a.SetTransportPorts("http", "70000", "-5", "8x")
	if a.httpPort != "9001" || a.wsPort != "9002" || a.webrtcPort != "9003" || a.agentDnsPort != "9004" {
		t.Fatalf("invalid flags must keep current ports: %s/%s/%s/%s", a.httpPort, a.wsPort, a.webrtcPort, a.agentDnsPort)
	}
}
