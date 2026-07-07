package session

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/crypto"
	proto "github.com/Ruby570bocadito/WorldC2/src/go/internal/proto"
	protobuf "google.golang.org/protobuf/proto"
)

// State represents the session state machine.
type State uint32

const (
	StateNew          State = iota // Just connected, awaiting key exchange
	StateKeyExchange              // Performing key exchange
	StateActive                   // Fully established, ready for tasks
	StatePassive                  // Agent in passive/reconnect mode
	StateDisconnected             // Clean disconnect
	StateKilled                   // Forcibly terminated
)

func (s State) String() string {
	switch s {
	case StateNew:
		return "new"
	case StateKeyExchange:
		return "key_exchange"
	case StateActive:
		return "active"
	case StatePassive:
		return "passive"
	case StateDisconnected:
		return "disconnected"
	case StateKilled:
		return "killed"
	default:
		return "unknown"
	}
}

// Session represents an authenticated agent connection.
type Session struct {
	ID           string
	state        State
	stateMu      sync.RWMutex

	// Connection
	Conn         net.Conn

	// Crypto
	KeyPair      *crypto.KeyPair
	EncKey       []byte
	HmacKey      []byte
	SessionToken []byte

	// Sequence numbers (monotonic, anti-replay)
	seqRx        uint32
	seqTx        uint32

	// Metadata (from SessionInit)
	Hostname     string
	OS           string
	Arch         string
	Username     string
	IsAdmin      bool
	PublicIP     net.IP
	LocalIP      net.IP
	MACAddress   string
	AgentID      string
	AgentVersion string
	Transport    string

	// Timing
	Created      time.Time
	LastSeen     time.Time
	LastTaskTime time.Time

	// Channels for async task results
	pendingTasks map[string]chan *proto.TaskResult
	taskMu       sync.RWMutex

	// Cleanup
	onClose      []func()
	done         chan struct{}
	closeOnce    sync.Once
}

// NewSession creates a new session from an incoming connection.
func NewSession(conn net.Conn, transport string) *Session {
	return &Session{
		ID:           generateSessionID(),
		state:        StateNew,
		Conn:         conn,
		Transport:    transport,
		Created:      time.Now(),
		LastSeen:     time.Now(),
		pendingTasks: make(map[string]chan *proto.TaskResult),
		done:         make(chan struct{}),
	}
}

// State returns the current session state.
func (s *Session) State() State {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.state
}

// SetState transitions the session to a new state.
func (s *Session) SetState(newState State) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.state = newState
}

// IsActive returns true if the session is in active state.
func (s *Session) IsActive() bool {
	return s.State() == StateActive
}

// Touch updates LastSeen timestamp.
func (s *Session) Touch() {
	s.LastSeen = time.Now()
}

// IsStale returns true if the session hasn't been seen within the timeout.
func (s *Session) IsStale(timeout time.Duration) bool {
	return time.Since(s.LastSeen) > timeout
}

// NextRxSeq returns the next receive sequence number.
func (s *Session) NextRxSeq() uint32 {
	return atomic.AddUint32(&s.seqRx, 1)
}

// NextTxSeq returns the next transmit sequence number.
func (s *Session) NextTxSeq() uint32 {
	return atomic.AddUint32(&s.seqTx, 1)
}

// RegisterPendingTask registers a pending task for async result handling.
func (s *Session) RegisterPendingTask(taskID string) chan *proto.TaskResult {
	ch := make(chan *proto.TaskResult, 1)
	s.taskMu.Lock()
	s.pendingTasks[taskID] = ch
	s.taskMu.Unlock()
	return ch
}

// ResolveTask resolves a pending task with its result.
func (s *Session) ResolveTask(taskID string, result *proto.TaskResult) {
	s.taskMu.Lock()
	ch, ok := s.pendingTasks[taskID]
	if ok {
		delete(s.pendingTasks, taskID)
	}
	s.taskMu.Unlock()

	if ok {
		ch <- result
		close(ch)
	}
}

// OnClose registers a cleanup function to be called when the session closes.
func (s *Session) OnClose(fn func()) {
	s.onClose = append(s.onClose, fn)
}

// Close shuts down the session and runs cleanup handlers.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		if s.State() == StateDisconnected || s.State() == StateKilled {
			return
		}
		s.SetState(StateDisconnected)

		// Run cleanup handlers
		for _, fn := range s.onClose {
			fn()
		}

		// Close pending task channels safely (non-blocking drain)
		s.taskMu.Lock()
		for _, ch := range s.pendingTasks {
			select {
			case <-ch:
			default:
			}
			close(ch)
		}
		s.pendingTasks = nil
		s.taskMu.Unlock()

		// Close connection
		if s.Conn != nil {
			s.Conn.Close()
		}

		close(s.done)
	})
}

// Done returns a channel that is closed when the session is done.
func (s *Session) Done() <-chan struct{} {
	return s.done
}

// SendEnvelope encrypts and sends a proto message envelope.
func (s *Session) SendEnvelope(msgType proto.EnvelopeType, payload protobuf.Message) error {
	inner := &proto.EnvelopeInner{
		Id:           s.NextTxSeq(),
		Type:         msgType,
		Timestamp:    uint64(time.Now().UnixNano()),
		SessionToken: s.SessionToken,
	}

	switch msgType {
	case proto.EnvelopeType_ENVELOPE_TYPE_TASK:
		if payload != nil {
			if t, ok := payload.(*proto.Task); ok {
				inner.Payload = &proto.EnvelopeInner_Task{Task: t}
			} else {
				return fmt.Errorf("payload type mismatch: expected *proto.Task for TASK envelope")
			}
		}
	case proto.EnvelopeType_ENVELOPE_TYPE_ACK:
		if payload != nil {
			if a, ok := payload.(*proto.Acknowledge); ok {
				inner.Payload = &proto.EnvelopeInner_Ack{Ack: a}
			} else {
				return fmt.Errorf("payload type mismatch: expected *proto.Acknowledge for ACK envelope")
			}
		}
	case proto.EnvelopeType_ENVELOPE_TYPE_ERROR:
		if payload != nil {
			if e, ok := payload.(*proto.Error); ok {
				inner.Payload = &proto.EnvelopeInner_Error{Error: e}
			} else {
				return fmt.Errorf("payload type mismatch: expected *proto.Error for ERROR envelope")
			}
		}
	case proto.EnvelopeType_ENVELOPE_TYPE_HEARTBEAT:
		if payload != nil {
			if h, ok := payload.(*proto.Heartbeat); ok {
				inner.Payload = &proto.EnvelopeInner_Heartbeat{Heartbeat: h}
			} else {
				return fmt.Errorf("payload type mismatch: expected *proto.Heartbeat for HEARTBEAT envelope")
			}
		}
	case proto.EnvelopeType_ENVELOPE_TYPE_DISCONNECT:
		// No payload needed — the type itself is the signal
	case proto.EnvelopeType_ENVELOPE_TYPE_RECONNECT:
		// No payload needed
	default:
		return fmt.Errorf("unsupported envelope type for send: %v", msgType)
	}

	innerBytes, err := protobuf.Marshal(inner)
	if err != nil {
		return fmt.Errorf("marshal inner: %w", err)
	}

	encrypted, err := crypto.Encrypt(s.EncKey, innerBytes)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	envelope := &proto.Envelope{
		Id:           inner.Id,
		Type:         msgType,
		Timestamp:    inner.Timestamp,
		SessionToken: s.SessionToken,
		Nonce:        encrypted[:crypto.NonceSize],
		Ciphertext:   encrypted[crypto.NonceSize:],
	}

	envBytes, err := protobuf.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	// Length-prefixed framing: 4 bytes big-endian length + payload
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(envBytes)))

	if _, err := s.Conn.Write(lengthBuf); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := s.Conn.Write(envBytes); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	return nil
}

// RecvEnvelope reads, decrypts, and parses an incoming envelope.
func (s *Session) RecvEnvelope() (*proto.EnvelopeInner, error) {
	// Read length prefix
	lengthBuf := make([]byte, 4)
	if _, err := readFull(s.Conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf)
	if length > 100*1024*1024 { // 100MB max
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	// Read payload
	envBytes := make([]byte, length)
	if _, err := readFull(s.Conn, envBytes); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	envelope := &proto.Envelope{}
	if err := protobuf.Unmarshal(envBytes, envelope); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	// Reconstruct full encrypted data: nonce + ciphertext
	encrypted := make([]byte, len(envelope.Nonce)+len(envelope.Ciphertext))
	copy(encrypted[:crypto.NonceSize], envelope.Nonce)
	copy(encrypted[crypto.NonceSize:], envelope.Ciphertext)

	decrypted, err := crypto.Decrypt(s.EncKey, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	inner := &proto.EnvelopeInner{}
	if err := protobuf.Unmarshal(decrypted, inner); err != nil {
		return nil, fmt.Errorf("unmarshal inner: %w", err)
	}

	// Verify session token (constant comparison to prevent timing attacks)
	if !hmac.Equal(inner.SessionToken, s.SessionToken) {
		return nil, fmt.Errorf("invalid session token")
	}

	s.NextRxSeq()
	s.Touch()

	return inner, nil
}

// SendRaw sends an unencrypted length-prefixed envelope (used during key exchange).
func (s *Session) SendRaw(env *proto.Envelope) error {
	envBytes, err := protobuf.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(envBytes)))

	if _, err := s.Conn.Write(lengthBuf); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := s.Conn.Write(envBytes); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// RecvRaw reads an unencrypted length-prefixed envelope (used during key exchange).
func (s *Session) RecvRaw() (*proto.EnvelopeInner, error) {
	lengthBuf := make([]byte, 4)
	if _, err := readFull(s.Conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf)
	if length > 100*1024*1024 {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	envBytes := make([]byte, length)
	if _, err := readFull(s.Conn, envBytes); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	envelope := &proto.Envelope{}
	if err := protobuf.Unmarshal(envBytes, envelope); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	// For raw messages, ciphertext IS the inner payload (not encrypted)
	inner := &proto.EnvelopeInner{}
	if err := protobuf.Unmarshal(envelope.Ciphertext, inner); err != nil {
		return nil, fmt.Errorf("unmarshal inner: %w", err)
	}

	s.Touch()
	return inner, nil
}

// readFull reads exactly n bytes from a connection.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, fmt.Errorf("connection closed")
		}
		total += n
	}
	return total, nil
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
