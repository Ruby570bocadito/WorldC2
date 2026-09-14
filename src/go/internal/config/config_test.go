package config

import "testing"

// TestDefaultConfigIsValid pins the floor: the shipped defaults must always
// pass Validate — a regression in DefaultConfig would brick every server
// that boots without a config file.
func TestDefaultConfigIsValid(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
}

// TestValidateCatchesMisconfiguration covers the fail-fast cases that used to
// surface as cryptic bind errors or a session reaper killing everything.
func TestValidateCatchesMisconfiguration(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string // substring expected in the error
	}{
		{
			name:   "duplicate ports",
			mutate: func(c *Config) { c.API.Port = c.Server.Port },
			want:   "both use port",
		},
		{
			name:   "zero api port",
			mutate: func(c *Config) { c.API.Port = 0 },
			want:   "api.port must be non-zero",
		},
		{
			name:   "zero session timeout",
			mutate: func(c *Config) { c.Server.SessionTimeout = 0 },
			want:   "reap sessions instantly",
		},
		{
			name:   "zero max sessions",
			mutate: func(c *Config) { c.Server.MaxSessions = 0 },
			want:   "max_sessions must be non-zero",
		},
		{
			name:   "unsupported tls floor",
			mutate: func(c *Config) { c.TLS.MinVersion = "1.1" },
			want:   "tls.min_version",
		},
		{
			name:   "unknown log level",
			mutate: func(c *Config) { c.Logging.Level = "verbose" },
			want:   "logging.level",
		},
		{
			name:   "file output without path",
			mutate: func(c *Config) { c.Logging.Output = "file" },
			want:   "requires logging.file",
		},
		{
			name:   "transport port collision with api",
			mutate: func(c *Config) { c.Transport.HTTPPort = c.API.Port },
			want:   "both use port",
		},
	}
	for _, tc := range cases {
		cfg := DefaultConfig()
		tc.mutate(cfg)
		err := cfg.Validate()
		if err == nil {
			t.Errorf("%s: Validate accepted a misconfiguration", tc.name)
			continue
		}
		if !contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not mention %q", tc.name, err.Error(), tc.want)
		}
	}
}

// TestValidateAllowsDisabledOptionalTransports: DNS and WebRTC ports of 0
// legitimately disable those transports and must not fail validation.
func TestValidateAllowsDisabledOptionalTransports(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Transport.DNSPort = 0
	cfg.Transport.WebRTCPort = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled optional transports rejected: %v", err)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
