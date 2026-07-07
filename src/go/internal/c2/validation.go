package c2

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// CommandValidator validates and sanitizes commands before execution.
type CommandValidator struct {
	maxLength       int
	allowedPatterns []*regexp.Regexp
	blockedCommands []string
}

// NewCommandValidator creates a command validator with sensible defaults.
func NewCommandValidator() *CommandValidator {
	return &CommandValidator{
		maxLength: 10000,
		blockedCommands: []string{
			"rm -rf /",
			"rm -rf /*",
			":(){:|:&};:",
			"mkfs",
			"dd if=/dev/zero",
			"wget -O- | sh",
			"curl | sh",
			"curl | bash",
			"wget | sh",
			"wget | bash",
		},
	}
}

// Validate checks if a command is safe to execute.
func (v *CommandValidator) Validate(cmd string) (bool, string) {
	if len(cmd) == 0 {
		return false, "empty command"
	}

	if len(cmd) > v.maxLength {
		return false, "command too long"
	}

	// Check for blocked commands
	cmdLower := strings.ToLower(cmd)
	for _, blocked := range v.blockedCommands {
		if strings.Contains(cmdLower, blocked) {
			return false, "blocked command pattern"
		}
	}

	// Check for dangerous patterns (system destruction only)
	dangerousPatterns := []string{
		"rm -rf /",
		"rm -rf /*",
		"rm --no-preserve-root",
	}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(cmdLower, pattern) {
			return false, "dangerous command pattern"
		}
	}

	// Check for pipe-to-shell patterns (curl/wget | sh/bash)
	pipeShellPatterns := []string{
		"curl", "wget",
	}
	shellPatterns := []string{
		"| sh", "| bash", "|sh", "|bash",
		"&& sh", "&& bash", "&&sh", "&&bash",
		"; sh", "; bash", ";sh", ";bash",
	}
	for _, fetcher := range pipeShellPatterns {
		for _, shell := range shellPatterns {
			if strings.Contains(cmdLower, fetcher) && strings.Contains(cmdLower, shell) {
				return false, "pipe-to-shell detected"
			}
		}
	}

	// Check for fork bomb patterns
	if strings.Contains(cmdLower, ":(){") || strings.Contains(cmdLower, "(){:|:") {
		return false, "fork bomb detected"
	}

	return true, ""
}

// ValidatedCommandRequest holds a validated command request.
type ValidatedCommandRequest struct {
	AgentID string
	Command string
	Timeout uint32
}

// ValidateCommandRequest validates a command API request and returns the parsed data.
func ValidateCommandRequest(w http.ResponseWriter, r *http.Request) (*ValidatedCommandRequest, bool) {
	var req struct {
		AgentID string `json:"agent_id"`
		Command string `json:"command"`
		Timeout uint32 `json:"timeout"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, 400)
		return nil, false
	}

	// Validate agent_id
	if req.AgentID == "" {
		http.Error(w, `{"error":"agent_id is required"}`, 400)
		return nil, false
	}

	// Validate command
	if req.Command == "" {
		http.Error(w, `{"error":"command is required"}`, 400)
		return nil, false
	}

	validator := NewCommandValidator()
	valid, reason := validator.Validate(req.Command)
	if !valid {
		http.Error(w, `{"error":"`+reason+`"}`, 400)
		return nil, false
	}

	// Validate timeout (max 5 minutes)
	timeout := req.Timeout
	if timeout > 300 {
		timeout = 300
	}

	return &ValidatedCommandRequest{
		AgentID: req.AgentID,
		Command: req.Command,
		Timeout: timeout,
	}, true
}

// ValidateBroadcastRequest validates a broadcast API request and returns the parsed command.
func ValidateBroadcastRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req struct {
		Command string `json:"command"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, 400)
		return "", false
	}

	if req.Command == "" {
		http.Error(w, `{"error":"command is required"}`, 400)
		return "", false
	}

	validator := NewCommandValidator()
	valid, reason := validator.Validate(req.Command)
	if !valid {
		http.Error(w, `{"error":"`+reason+`"}`, 400)
		return "", false
	}

	return req.Command, true
}
