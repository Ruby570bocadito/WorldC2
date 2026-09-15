package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
)

// handleAudit exposes the append-only audit trail (audit_log table) to
// operators holding the audit:read permission — admin and auditor. Every
// API call, auth failure, task and lifecycle event has been WRITTEN here
// since the first round — but until now there was no read API, so the trail
// was invisible from the console and only reachable by opening the SQLite
// file by hand.
//
// Gate: perm("audit:read") runs before this handler in the route chain.
// That permission belongs to admin and auditor by design (rbac.go since the
// early rounds): reviewing the trail is the auditor's whole job, while a
// viewer or plain operator must not get the usernames and IPs the detail
// field carries.
//
// Parameters:
//   - ?limit=1..500 — page size (default 500; the DB clamps anyway).
//   - ?action=NAME  — exact event-type filter (e.g. auth_failed), capped
//     to 64 chars so a hostile query string cannot grow the SQL argument
//     without bound (the value is only ever bound as a parameter; the cap
//     keeps responses and logs tidy).
func (r *Router) handleAudit(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}

	q := req.URL.Query()

	limit := db.MaxAuditPage
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > db.MaxAuditPage {
			http.Error(w, `{"error":"limit must be an integer between 1 and 500"}`, 400)
			return
		}
		limit = n
	}

	action := q.Get("action")
	if len(action) > 64 {
		http.Error(w, `{"error":"action filter must be 64 characters or fewer"}`, 400)
		return
	}

	entries, err := r.server.DB().ListAuditEntries(limit, action)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, 500)
		return
	}

	// Encode an empty JSON array, not null — the console renders
	// entries.length and a bare null would read as an error.
	out := make([]AuditEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, AuditEntry{
			ID:      e.ID,
			Action:  e.Action,
			Detail:  e.Detail,
			Created: e.Created,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// AuditEntry is the JSON shape of one audit row. Field names are lowercase
// to match the console-side conventions (files, notes, credentials); the
// Created encoding matches time.Time's RFC3339 JSON output exactly.
type AuditEntry struct {
	ID      int       `json:"id"`
	Action  string    `json:"action"`
	Detail  string    `json:"detail"`
	Created time.Time `json:"created"`
}
