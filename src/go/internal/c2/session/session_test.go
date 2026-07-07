package session

import (
	"net"
	"testing"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/crypto"
	proto "github.com/Ruby570bocadito/WorldC2/src/go/internal/proto"
)

func TestNewSession(t *testing.T) {
	sess := NewSession(nil, "tcp")

	if sess.ID == "" {
		t.Error("Session ID should not be empty")
	}

	if sess.State() != StateNew {
		t.Errorf("Initial state = %v, want %v", sess.State(), StateNew)
	}

	if sess.Transport != "tcp" {
		t.Errorf("Transport = %v, want tcp", sess.Transport)
	}

	if sess.pendingTasks == nil {
		t.Error("pendingTasks should be initialized")
	}
}

func TestSessionStateTransitions(t *testing.T) {
	sess := NewSession(nil, "tcp")

	// Test all state transitions
	sess.SetState(StateKeyExchange)
	if sess.State() != StateKeyExchange {
		t.Errorf("State = %v, want %v", sess.State(), StateKeyExchange)
	}

	sess.SetState(StateActive)
	if !sess.IsActive() {
		t.Error("Session should be active")
	}

	sess.SetState(StatePassive)
	if sess.IsActive() {
		t.Error("Session should not be active in passive state")
	}

	sess.SetState(StateKilled)
	if sess.State() != StateKilled {
		t.Errorf("State = %v, want %v", sess.State(), StateKilled)
	}
}

func TestSessionTouch(t *testing.T) {
	sess := NewSession(nil, "tcp")
	originalLastSeen := sess.LastSeen

	time.Sleep(10 * time.Millisecond)
	sess.Touch()

	if !sess.LastSeen.After(originalLastSeen) {
		t.Error("Touch should update LastSeen")
	}
}

func TestSessionIsStale(t *testing.T) {
	sess := NewSession(nil, "tcp")

	// Fresh session should not be stale
	if sess.IsStale(5 * time.Minute) {
		t.Error("Fresh session should not be stale")
	}

	// Set LastSeen to 10 minutes ago
	sess.LastSeen = time.Now().Add(-10 * time.Minute)

	if !sess.IsStale(5 * time.Minute) {
		t.Error("Session should be stale after 10 minutes with 5 min timeout")
	}
}

func TestSessionSequenceNumbers(t *testing.T) {
	sess := NewSession(nil, "tcp")

	// Test monotonic increment
	seq1 := sess.NextTxSeq()
	seq2 := sess.NextTxSeq()

	if seq2 <= seq1 {
		t.Errorf("TxSeq should be monotonic: %d <= %d", seq2, seq1)
	}

	seq3 := sess.NextRxSeq()
	seq4 := sess.NextRxSeq()

	if seq4 <= seq3 {
		t.Errorf("RxSeq should be monotonic: %d <= %d", seq4, seq3)
	}
}

func TestSessionPendingTasks(t *testing.T) {
	sess := NewSession(nil, "tcp")

	// Register a task
	ch := sess.RegisterPendingTask("task-1")
	if ch == nil {
		t.Fatal("RegisterPendingTask should return a channel")
	}

	// Resolve the task
	result := &proto.TaskResult{TaskId: "task-1", Success: true}
	sess.ResolveTask("task-1", result)

	// Check result was received
	select {
	case r := <-ch:
		if r != result {
			t.Error("Received result should match sent result")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for task result")
	}
}

func TestSessionResolveNonExistentTask(t *testing.T) {
	sess := NewSession(nil, "tcp")

	// Should not panic
	sess.ResolveTask("nonexistent", nil)
}

func TestSessionClose(t *testing.T) {
	sess := NewSession(nil, "tcp")

	cleanupCalled := false
	sess.OnClose(func() {
		cleanupCalled = true
	})

	sess.Close()

	if !cleanupCalled {
		t.Error("OnClose handlers should be called")
	}

	if sess.State() != StateDisconnected {
		t.Errorf("State after close = %v, want %v", sess.State(), StateDisconnected)
	}

	// Check done channel
	select {
	case <-sess.Done():
		// Expected
	case <-time.After(1 * time.Second):
		t.Fatal("Done channel should be closed")
	}
}

func TestSessionDoubleClose(t *testing.T) {
	sess := NewSession(nil, "tcp")

	sess.Close()

	// Second close should not panic
	sess.Close()
}

func TestSessionIDUniqueness(t *testing.T) {
	ids := make(map[string]bool)

	for i := 0; i < 100; i++ {
		sess := NewSession(nil, "tcp")
		if ids[sess.ID] {
			t.Errorf("Duplicate session ID: %s", sess.ID)
		}
		ids[sess.ID] = true
	}
}

func TestSessionStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateNew, "new"},
		{StateKeyExchange, "key_exchange"},
		{StateActive, "active"},
		{StatePassive, "passive"},
		{StateDisconnected, "disconnected"},
		{StateKilled, "killed"},
		{State(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestSessionCrypto(t *testing.T) {
	sess := NewSession(nil, "tcp")

	// Generate key pair
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	sess.KeyPair = kp

	// Derive session keys
	salt := make([]byte, 32)
	encKey, hmacKey, token, err := crypto.DeriveSessionKeys(make([]byte, 32), salt)
	if err != nil {
		t.Fatalf("DeriveSessionKeys() error = %v", err)
	}

	sess.EncKey = encKey
	sess.HmacKey = hmacKey
	sess.SessionToken = token

	// Verify keys are set
	if len(sess.EncKey) != crypto.SessionKeySize {
		t.Errorf("EncKey size = %d, want %d", len(sess.EncKey), crypto.SessionKeySize)
	}

	if len(sess.SessionToken) != crypto.TokenSize {
		t.Errorf("SessionToken size = %d, want %d", len(sess.SessionToken), crypto.TokenSize)
	}
}

// MockConn is a mock net.Conn for testing.
type MockConn struct {
	ReadData  []byte
	WriteData []byte
	Closed    bool
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	if len(m.ReadData) == 0 {
		return 0, nil
	}
	n = copy(b, m.ReadData)
	m.ReadData = m.ReadData[n:]
	return n, nil
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	m.WriteData = append(m.WriteData, b...)
	return len(b), nil
}

func (m *MockConn) Close() error {
	m.Closed = true
	return nil
}

func (m *MockConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443} }
func (m *MockConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345} }

func (m *MockConn) SetDeadline(t time.Time) error      { return nil }
func (m *MockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestSessionWithMockConn(t *testing.T) {
	mock := &MockConn{}
	sess := NewSession(mock, "tcp")

	if sess.Conn != mock {
		t.Error("Session should store the connection")
	}

	sess.Close()

	if !mock.Closed {
		t.Error("Close should close the underlying connection")
	}
}

func BenchmarkSessionNextTxSeq(b *testing.B) {
	sess := NewSession(nil, "tcp")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sess.NextTxSeq()
	}
}

func BenchmarkSessionRegisterResolve(b *testing.B) {
	sess := NewSession(nil, "tcp")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		taskID := "task-bench"
		ch := sess.RegisterPendingTask(taskID)
		sess.ResolveTask(taskID, nil)
		<-ch
	}
}
