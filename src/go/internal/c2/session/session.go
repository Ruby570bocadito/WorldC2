package session

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
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
	StateKeyExchange               // Performing key exchange
	StateActive                    // Fully established, ready for tasks
	StatePassive                   // Agent in passive/reconnect mode
	StateDisconnected              // Clean disconnect
	StateKilled                    // Forcibly terminated
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

// maxRawMessageSize bounds pre-authentication messages (key exchange,
// session init). These payloads are tiny; a large value here only allows
// unauthenticated memory allocation.
const maxRawMessageSize = 1 << 20 // 1 MiB

// maxEncryptedMessageSize bounds post-authentication envelopes.
const maxEncryptedMessageSize = 100 << 20 // 100 MiB

// Session represents an authenticated agent connection.
type Session struct {
	ID      string
	state   State
	stateMu sync.RWMutex

	// Connection
	Conn net.Conn

	// Crypto
	KeyPair      *crypto.KeyPair
	EncKey       []byte
	HmacKey      []byte
	SessionToken []byte

	// Sequence numbers (monotonic, anti-replay)
	seqRx uint32
	seqTx uint32

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
	Created              time.Time
	lastSeenNanos        atomic.Int64
	LastTaskTime         time.Time
	lastSeenDBUpdateNano atomic.Int64

	// Channels for async task results
	pendingTasks map[string]chan *proto.TaskResult
	taskMu       sync.RWMutex

	// Write serialization: envelope framing (length + payload) must be
	// written atomically or concurrent writers interleave and corrupt the
	// stream.
	writeMu sync.Mutex

	// Cleanup
	onClose   []func()
	done      chan struct{}
	closeOnce sync.Once
}

// NewSession creates a new session from an incoming connection.
func NewSession(conn net.Conn, transport string) *Session {
	s := &Session{
		ID:           generateSessionID(),
		state:        StateNew,
		Conn:         conn,
		Transport:    transport,
		Created:      time.Now(),
		pendingTasks: make(map[string]chan *proto.TaskResult),
		done:         make(chan struct{}),
	}
	s.lastSeenNanos.Store(time.Now().UnixNano())
	return s
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
	s.lastSeenNanos.Store(time.Now().UnixNano())
}

// LastSeenTime returns the last time the session was observed.
func (s *Session) LastSeenTime() time.Time {
	return time.Unix(0, s.lastSeenNanos.Load())
}

// IsStale returns true if the session hasn't been seen within the timeout.
func (s *Session) IsStale(timeout time.Duration) bool {
	return time.Since(s.LastSeenTime()) > timeout
}

// ShouldUpdateDB reports whether enough time has passed since the last
// persisted last_seen update (debounces per-heartbeat DB writes).
func (s *Session) ShouldUpdateDB(minInterval time.Duration) bool {
	now := time.Now().UnixNano()
	last := s.lastSeenDBUpdateNano.Load()
	if last != 0 && now-last < int64(minInterval) {
		return false
	}
	return s.lastSeenDBUpdateNano.CompareAndSwap(last, now)
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
// The channel is removed from the map before sending so Close() can never
// close it concurrently (single-sender guarantee).
func (s *Session) ResolveTask(taskID string, result *proto.TaskResult) {
	s.taskMu.Lock()
	ch, ok := s.pendingTasks[taskID]
	if ok {
		delete(s.pendingTasks, taskID)
	}
	s.taskMu.Unlock()

	if ok {
		select {
		case ch <- result:
		default:
		}
		close(ch)
	}
}

// OnClose registers a cleanup function to be called when the session closes.
func (s *Session) OnClose(fn func()) {
	s.onClose = append(s.onClose, fn)
}

// Close shuts down the session and runs cleanup handlers.
// It is idempotent and unconditional: regardless of the current state it
// releases the connection, resolves pending task channels and signals done.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		// Preserve Killed status if it was set explicitly; otherwise mark
		// the session as cleanly disconnected.
		if s.State() != StateKilled {
			s.SetState(StateDisconnected)
		}

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

	return s.writeFrame(envBytes)
}

// RecvEnvelope reads, decrypts, and parses an incoming envelope.
func (s *Session) RecvEnvelope() (*proto.EnvelopeInner, error) {
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(s.Conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf)
	if length > maxEncryptedMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	envBytes := make([]byte, length)
	if _, err := io.ReadFull(s.Conn, envBytes); err != nil {
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
	return s.writeFrame(envBytes)
}

// RecvRaw reads an unencrypted length-prefixed envelope (used during key exchange).
func (s *Session) RecvRaw() (*proto.EnvelopeInner, error) {
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(s.Conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf)
	if length > maxRawMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	envBytes := make([]byte, length)
	if _, err := io.ReadFull(s.Conn, envBytes); err != nil {
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

// writeFrame writes a length-prefixed frame atomically: length prefix and
// payload are serialized into a single buffer and written with one Write
// call while holding the per-session write lock.
func (s *Session) writeFrame(payload []byte) error {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.Conn.Write(frame); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

func generateSessionID() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// Unrecoverable: silent zero-filled IDs would collide and break
		// session routing. crypto/rand failing means the runtime is broken.
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return fmt.Sprintf("%x", b)
}
