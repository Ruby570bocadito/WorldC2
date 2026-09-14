package c2

import (
	"net"
	"testing"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2/session"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/proto"
)

// newReaperTestTunnel registers a tunnel for the given session following the
// same pattern as tunnel_test.go: direct registration (OpenTunnel would try
// a real SendEnvelope, which needs negotiated session keys).
func newReaperTestTunnel(t *testing.T, tm *TunnelManager, sess *session.Session) *Tunnel {
	t.Helper()
	tun := &Tunnel{
		ID:      newTunnelID(),
		Session: sess,
		Target:  "10.0.0.1:80",
		dataCh:  make(chan []byte, 128),
		closeCh: make(chan struct{}),
	}
	tun.running.Store(true)
	tun.lastActiveNano.Store(time.Now().UnixNano())
	tm.mu.Lock()
	tm.tunnels[tun.ID] = tun
	tm.mu.Unlock()
	return tun
}

func TestReaperClosesIdleTunnel(t *testing.T) {
	tm := NewTunnelManager()
	sess := session.NewSession(nil, "tcp")
	tun := newReaperTestTunnel(t, tm, sess)

	// Simulate a tunnel idle for longer than the reap threshold.
	tun.lastActiveNano.Store(time.Now().Add(-2 * tunnelIdleTimeout).UnixNano())

	tm.reapOnce()

	tm.mu.RLock()
	_, alive := tm.tunnels[tun.ID]
	tm.mu.RUnlock()
	if alive {
		t.Fatal("idle tunnel was not reaped")
	}
	select {
	case <-tun.closeCh:
	default:
		t.Error("tunnel closeCh should be closed after reap")
	}
}

func TestReaperKeepsActiveTunnel(t *testing.T) {
	tm := NewTunnelManager()
	sess := session.NewSession(nil, "tcp")
	tun := newReaperTestTunnel(t, tm, sess)

	tm.reapOnce()

	tm.mu.RLock()
	_, alive := tm.tunnels[tun.ID]
	tm.mu.RUnlock()
	if !alive {
		t.Fatal("active tunnel must survive the reap sweep")
	}
	tm.Close(tun.ID)
}

func TestSessionCloseTearsDownTunnels(t *testing.T) {
	tm := NewTunnelManager()
	sess := session.NewSession(nil, "tcp")

	// Simulate the server-side wiring (Server.Start admission path).
	tm.WatchSession(sess)

	tun1 := newReaperTestTunnel(t, tm, sess)
	tun2 := newReaperTestTunnel(t, tm, sess)

	// A tunnel of ANOTHER session must not be touched.
	other := session.NewSession(nil, "tcp")
	tunOther := newReaperTestTunnel(t, tm, other)

	// Session must be "active" from the tunnel's point of view.
	if sess.IsStale(time.Hour) {
		t.Fatal("test prerequisite: session must not be stale")
	}

	sess.Close()

	tm.mu.RLock()
	_, t1 := tm.tunnels[tun1.ID]
	_, t2 := tm.tunnels[tun2.ID]
	_, tO := tm.tunnels[tunOther.ID]
	tm.mu.RUnlock()

	if t1 || t2 {
		t.Error("tunnels of the closed session must be torn down")
	}
	if !tO {
		t.Error("tunnels of other sessions must survive")
	}
}

func TestTunnelActivityResetsIdleClock(t *testing.T) {
	tm := NewTunnelManager()
	sess := session.NewSession(nil, "tcp")
	tun := newReaperTestTunnel(t, tm, sess)

	// Age the tunnel, then feed it activity via the result path.
	tun.lastActiveNano.Store(time.Now().Add(-tunnelIdleTimeout).UnixNano())
	tm.HandleTunnelResult(&proto.TaskResult{TaskId: "x", Output: "tunnel_data:" + tun.ID + ":" + "aGVsbG8="})

	if idle := time.Since(time.Unix(0, tun.lastActiveNano.Load())); idle > time.Minute {
		t.Fatalf("HandleTunnelResult must refresh lastActive (idle=%s)", idle)
	}

	// SendData also refreshes (session has a nil conn: SendEnvelope errors,
	// but the activity stamp happens before the send attempt).
	tun.lastActiveNano.Store(time.Now().Add(-tunnelIdleTimeout).UnixNano())
	_ = tm.SendData(tun.ID, []byte("ping"))
	if idle := time.Since(time.Unix(0, tun.lastActiveNano.Load())); idle > time.Minute {
		t.Fatalf("SendData must refresh lastActive (idle=%s)", idle)
	}

	tm.Close(tun.ID)
}

func TestReaperStopsOnQuit(t *testing.T) {
	tm := NewTunnelManager()
	quit := make(chan struct{})
	tm.StartReaper(quit)
	close(quit) // reaper goroutine must exit promptly; -race will catch abuse
	time.Sleep(50 * time.Millisecond)
}

// Compile-time guard: tunnels still satisfy net.Conn semantics used by the
// SOCKS5/portfwd relay (deadlines remain no-ops by design — documented in
// DEVELOPER_GUIDE).
var _ net.Conn = (*tunnelConn)(nil)
