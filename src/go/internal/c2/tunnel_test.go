package c2

import (
	"encoding/base64"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2/session"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/proto"
)

// mockConn is an in-memory net.Conn used to test framing.
type mockConn struct {
	mu     sync.Mutex
	data   []byte
	closes int
	closed chan struct{}
}

func newMockConn() *mockConn { return &mockConn{closed: make(chan struct{})} }

func (m *mockConn) Read(b []byte) (int, error) { <-m.closed; return 0, net.ErrClosed }
func (m *mockConn) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = append(m.data, b...)
	return len(b), nil
}
func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closes++
	select {
	case <-m.closed:
	default:
		close(m.closed)
	}
	return nil
}
func (m *mockConn) written() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.data...)
}
func (m *mockConn) closedCount() int                   { m.mu.Lock(); defer m.mu.Unlock(); return m.closes }
func (m *mockConn) LocalAddr() net.Addr                { return addrAny("mock") }
func (m *mockConn) RemoteAddr() net.Addr               { return addrAny("mock") }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func timeoutAfter(d time.Duration) <-chan time.Time { return time.After(d) }

func TestTunnelRoutingByExactID(t *testing.T) {
	tm := NewTunnelManager()

	// Two tunnels whose IDs share a prefix must not cross-route data.
	t1 := &Tunnel{ID: "tun-aaaa", Target: "a", dataCh: make(chan []byte, 1), closeCh: make(chan struct{})}
	t1.running.Store(true)
	t2 := &Tunnel{ID: "tun-aaab", Target: "b", dataCh: make(chan []byte, 1), closeCh: make(chan struct{})}
	t2.running.Store(true)
	tm.tunnels[t1.ID] = t1
	tm.tunnels[t2.ID] = t2

	payload := base64.StdEncoding.EncodeToString([]byte("hello-b"))
	tm.HandleTunnelResult(&proto.TaskResult{Output: "tunnel_data:tun-aaab:" + payload})

	select {
	case got := <-t2.dataCh:
		if string(got) != "hello-b" {
			t.Fatalf("t2 got %q, want hello-b", got)
		}
	default:
		t.Fatal("t2 should have received the data")
	}
	select {
	case got := <-t1.dataCh:
		t.Fatalf("t1 must NOT receive data addressed to t2 (got %q)", got)
	default:
	}
}

func TestTunnelCloseOnErrDoesNotSelfDeadlock(t *testing.T) {
	tm := NewTunnelManager()
	t1 := &Tunnel{ID: "tun-err", Target: "a", dataCh: make(chan []byte, 1), closeCh: make(chan struct{})}
	t1.running.Store(true)
	tm.tunnels[t1.ID] = t1

	done := make(chan struct{})
	go func() {
		tm.HandleTunnelResult(&proto.TaskResult{Output: "tunnel_err:tun-err:refused"})
		close(done)
	}()

	select {
	case <-done:
		// Success: previously this self-deadlocked (RLock -> Close -> Lock).
	case <-timeoutAfter(2 * time.Second):
		t.Fatal("HandleTunnelResult deadlocked on tunnel_err path")
	}

	if _, ok := tm.tunnels["tun-err"]; ok {
		t.Fatal("tunnel should have been removed after tunnel_err")
	}
}

func TestTunnelUnknownIDIsIgnored(t *testing.T) {
	tm := NewTunnelManager()
	tm.HandleTunnelResult(&proto.TaskResult{Output: "tunnel_data:tun-nope:" + base64.StdEncoding.EncodeToString([]byte("x"))})
	tm.HandleTunnelResult(&proto.TaskResult{Output: "not a tunnel message"})
}

func TestSessionWriteFramingUnderConcurrency(t *testing.T) {
	mock := newMockConn()
	sess := session.NewSession(mock, "tcp")
	sess.EncKey = make([]byte, 32)
	sess.SessionToken = make([]byte, 24)

	const writers = 8
	const perWriter = 20
	done := make(chan struct{})
	for i := 0; i < writers; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < perWriter; j++ {
				if err := sess.SendEnvelope(proto.EnvelopeType_ENVELOPE_TYPE_DISCONNECT, nil); err != nil {
					t.Errorf("SendEnvelope: %v", err)
					return
				}
			}
		}()
	}
	for i := 0; i < writers; i++ {
		<-done
	}

	// Every frame must be intact: 4-byte length + protobuf payload.
	buf := mock.written()
	frames := 0
	for len(buf) > 0 {
		if len(buf) < 4 {
			t.Fatalf("truncated frame header, %d stray bytes", len(buf))
		}
		length := int(buf[0])<<24 | int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if length <= 0 || length > len(buf)-4 {
			t.Fatalf("corrupt frame length %d with %d bytes available", length, len(buf)-4)
		}
		buf = buf[4+length:]
		frames++
	}
	if frames != writers*perWriter {
		t.Fatalf("expected %d frames, parsed %d", writers*perWriter, frames)
	}
}

func TestSessionCloseIsIdempotentAfterKill(t *testing.T) {
	mock := newMockConn()
	sess := session.NewSession(mock, "tcp")
	sess.SetState(session.StateKilled)

	// Before the fix, Close() returned early for killed sessions leaving the
	// connection open forever.
	sess.Close()
	sess.Close()

	select {
	case <-sess.Done():
	default:
		t.Fatal("Close() must run even when the state is Killed")
	}
	if m := mock.closedCount(); m == 0 {
		t.Fatal("underlying connection must be closed")
	}
}
