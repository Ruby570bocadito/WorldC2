package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the entire C2 server configuration.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	API       APIConfig       `yaml:"api"`
	Transport TransportConfig `yaml:"transport"`
	Database  DatabaseConfig  `yaml:"database"`
	TLS       TLSConfig       `yaml:"tls"`
	Logging   LoggingConfig   `yaml:"logging"`
	Operators []OperatorConfig `yaml:"operators"`
}

// TransportConfig holds multi-transport listener configuration.
type TransportConfig struct {
	HTTPPort   uint16   `yaml:"http_port"`
	WSPort     uint16   `yaml:"ws_port"`
	DNSPort    uint16   `yaml:"dns_port"`
	DNSDomains []string `yaml:"dns_domains"`
}

// ServerConfig holds C2 listener configuration.
type ServerConfig struct {
	Host               string        `yaml:"host"`
	Port               uint16        `yaml:"port"`
	MaxSessions        uint32        `yaml:"max_sessions"`
	HeartbeatInterval  time.Duration `yaml:"heartbeat_interval"`
	SessionTimeout     time.Duration `yaml:"session_timeout"`
	ReconnectMaxBackoff time.Duration `yaml:"reconnect_max_backoff"`
}

// APIConfig holds REST API configuration.
type APIConfig struct {
	Port uint16 `yaml:"port"`
}

// DatabaseConfig holds database connection info.
type DatabaseConfig struct {
	Driver string `yaml:"driver"` // "sqlite" or "postgres"
	DSN    string `yaml:"dsn"`
}

// TLSConfig holds TLS certificate configuration.
type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	AutoCert   bool   `yaml:"auto_cert"`   // Auto-generate self-signed
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
			Host:                "0.0.0.0",
			Port:                8443,
			MaxSessions:         5000,
			HeartbeatInterval:   30 * time.Second,
			SessionTimeout:      5 * time.Minute,
			ReconnectMaxBackoff: 5 * time.Minute,
		},
		API: APIConfig{
			Port: 9090,
		},
		Transport: TransportConfig{
			HTTPPort:   8445,
			WSPort:     8446,
			DNSPort:    0,
			DNSDomains: []string{},
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			DSN:    "ctrlworldc2.db",
		},
		TLS: TLSConfig{
			Enabled:  true,
			AutoCert: true,
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

// Save writes config to a YAML file.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
