package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the entire C2 server configuration.
type Config struct {
	Server    ServerConfig     `yaml:"server"`
	API       APIConfig        `yaml:"api"`
	Transport TransportConfig  `yaml:"transport"`
	Database  DatabaseConfig   `yaml:"database"`
	TLS       TLSConfig        `yaml:"tls"`
	Logging   LoggingConfig    `yaml:"logging"`
	Audit     AuditConfig      `yaml:"audit"`
	Operators []OperatorConfig `yaml:"operators"`
}

// AuditConfig holds audit-trail policy. The trail is append-only; the only
// delete path is the retention pruner, and RetentionDays is the switch.
type AuditConfig struct {
	// RetentionDays bounds how long an audit row lives: rows older than
	// this are pruned at startup and then hourly. 0 (default) keeps the
	// trail forever — the historical behaviour — so an operator must
	// explicitly opt in to pruning. 1..3650 are accepted as-is.
	RetentionDays int `yaml:"retention_days"`
}

// TransportConfig holds multi-transport listener configuration.
type TransportConfig struct {
	HTTPPort   uint16   `yaml:"http_port"`
	WSPort     uint16   `yaml:"ws_port"`
	WebRTCPort uint16   `yaml:"webrtc_port"` // 0 disables the WebRTC transport
	DNSPort    uint16   `yaml:"dns_port"`
	DNSDomains []string `yaml:"dns_domains"`
}

// ServerConfig holds C2 listener configuration.
type ServerConfig struct {
	Host           string        `yaml:"host"`
	Port           uint16        `yaml:"port"`
	MaxSessions    uint32        `yaml:"max_sessions"`
	SessionTimeout time.Duration `yaml:"session_timeout"`
	// TrustedProxies lists IPs/CIDRs of reverse proxies whose
	// X-Forwarded-For header the API may believe (rate limiting key).
	// Empty (default) = never trust the header.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// APIConfig holds REST API configuration.
type APIConfig struct {
	Port uint16 `yaml:"port"`
	// AllowedOrigins lists the exact origins (scheme://host[:port]) allowed
	// to call the API from another origin via CORS. The bundled console is
	// served same-origin and needs no entry; this list exists for external
	// tooling or a separately hosted console in development. Empty (default)
	// means no cross-origin browser access at all. A "*" entry is rejected
	// at startup — a C2 must never hand out wildcard CORS.
	AllowedOrigins []string `yaml:"allowed_origins"`
	// LoginRatePerMin caps POST /api/login per client IP per minute (r19).
	// 0/unset keeps the historical 10 — the brute-force backstop for
	// single-source guessing. The per-ACCOUNT lockout (5 consecutive
	// failures → 5-minute wall, operators_security.go) is the primary
	// guess-rate control; this bucket additionally bounds bcrypt work
	// per IP. Raise it only when many operators legitimately share one
	// egress IP (VPN/NAT) — the browser E2E suite does exactly that.
	LoginRatePerMin int `yaml:"login_rate_per_min"`
}

// DatabaseConfig holds database connection info.
type DatabaseConfig struct {
	DSN string `yaml:"dsn"` // SQLite database file
}

// TLSConfig holds TLS certificate configuration.
type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	AutoCert   bool   `yaml:"auto_cert"`   // Auto-generate self-signed
	MTLS       bool   `yaml:"mtls"`        // Require agent client certificates (provision via /api/mtls/client-cert)
	MinVersion string `yaml:"min_version"` // "1.2" or "1.3"
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // "debug", "info", "warn", "error"
	Output string `yaml:"output"` // "stdout", "file"
	File   string `yaml:"file"`
}

// OperatorConfig holds credentials for C2 operators.
type OperatorConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"` // bcrypt hash
	Role     string `yaml:"role"`     // "admin", "operator", "viewer"
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:           "0.0.0.0",
			Port:           8443,
			MaxSessions:    5000,
			SessionTimeout: 5 * time.Minute,
		},
		API: APIConfig{
			Port: 9090,
		},
		Transport: TransportConfig{
			HTTPPort:   8445,
			WSPort:     8446,
			WebRTCPort: 8447,
			DNSPort:    0,
			DNSDomains: []string{},
		},
		Database: DatabaseConfig{
			DSN: "worldc2.db",
		},
		TLS: TLSConfig{
			Enabled:    true,
			AutoCert:   true,
			MTLS:       false,
			MinVersion: "1.3",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Output: "stdout",
		},
	}
}

// Load reads config from a YAML file.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

// Validate checks structural constraints that would otherwise surface as
// cryptic "address already in use" bind errors, a session reaper that kills
// everything instantly, or a TLS floor that is silently ignored. Fail-fast
// at startup: a misconfigured C2 must refuse to start rather than run
// half-configured. DNS and WebRTC ports of 0 legitimately disable those
// transports; the main C2, API, HTTP and WS listeners do not have a
// disable mode and must be set and mutually distinct.
func (c *Config) Validate() error {
	var errs []string

	required := []struct {
		name string
		port uint16
	}{
		{"server.port", c.Server.Port},
		{"api.port", c.API.Port},
		{"transport.http_port", c.Transport.HTTPPort},
		{"transport.ws_port", c.Transport.WSPort},
	}
	if c.Transport.WebRTCPort > 0 {
		required = append(required, struct {
			name string
			port uint16
		}{"transport.webrtc_port", c.Transport.WebRTCPort})
	}
	if c.Transport.DNSPort > 0 {
		required = append(required, struct {
			name string
			port uint16
		}{"transport.dns_port", c.Transport.DNSPort})
	}
	seen := make(map[uint16]string, len(required))
	for _, r := range required {
		if r.port == 0 {
			errs = append(errs, r.name+" must be non-zero")
			continue
		}
		if other, dup := seen[r.port]; dup {
			errs = append(errs, fmt.Sprintf("%s and %s both use port %d", r.name, other, r.port))
			continue
		}
		seen[r.port] = r.name
	}

	if c.Server.MaxSessions == 0 {
		errs = append(errs, "server.max_sessions must be non-zero")
	}
	if c.Server.SessionTimeout <= 0 {
		errs = append(errs, `server.session_timeout must be positive (e.g. "300s") — 0 would reap sessions instantly`)
	}
	switch c.TLS.MinVersion {
	case "", "1.2", "1.3":
	default:
		errs = append(errs, fmt.Sprintf("tls.min_version %q not supported (use \"1.2\" or \"1.3\")", c.TLS.MinVersion))
	}
	switch c.Logging.Level {
	case "", "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Sprintf("logging.level %q not supported (debug|info|warn|error)", c.Logging.Level))
	}
	if c.Logging.Output == "file" && c.Logging.File == "" {
		errs = append(errs, "logging.output=file requires logging.file")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Save writes config to a YAML file.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
