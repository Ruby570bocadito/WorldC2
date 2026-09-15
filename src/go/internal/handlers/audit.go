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
//   - ?user=NAME    — exact operator filter (r18). Attributability is the
//     point: since this same round every authenticated request writes its
//     real operator_id, so "what did THIS account do" is a query, not a
//     text search. Unknown usernames answer an empty array (no existence
//     oracle), and the cap mirrors ?action=.
//   - ?before_id=N  — cursor pagination (r19): only rows with id < N are
//     returned. audit_log.id is a monotonic AUTOINCREMENT primary key, so
//     the cursor is a plain integer — no timestamp-format traps, no
//     composite tiebreaker (ids cannot collide). The console walks the
//     trail with it ("Load more"); the response stays a bare JSON array
//     so every existing consumer keeps parsing untouched.
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

	user := q.Get("user")
	if len(user) > 64 {
		http.Error(w, `{"error":"user filter must be 64 characters or fewer"}`, 400)
		return
	}

	// Cursor: strict integer. An absent OR zero cursor means "first
	// page" (the DB layer treats beforeID <= 0 as no filter — 0 is
	// also what a client passes to restart the walk). Negatives,
	// float strings and overflow-scale numbers are a malformed cursor
	// and answer 400 — the entry boundary stays loud, the SQL never
	// sees anything but a bound int64 parameter.
	var beforeID int64
	if raw := q.Get("before_id"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			http.Error(w, `{"error":"before_id must be a non-negative integer"}`, 400)
			return
		}
		beforeID = n
	}

	entries, err := r.server.DB().ListAuditEntriesBefore(limit, action, user, beforeID)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, 500)
		return
	}

	// Encode an empty JSON array, not null — the console renders
	// entries.length and a bare null would read as an error.
	out := make([]AuditEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, AuditEntry{
			ID:       e.ID,
			Action:   e.Action,
			Detail:   e.Detail,
			Operator: e.Operator,
			Created:  e.Created,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// AuditEntry is the JSON shape of one audit row. Field names are lowercase
// to match the console-side conventions (files, notes, credentials); the
// Created encoding matches time.Time's RFC3339 JSON output exactly. Operator
// is the attributed account ("" for system events — task lifecycle etc.).
type AuditEntry struct {
	ID       int       `json:"id"`
	Action   string    `json:"action"`
	Detail   string    `json:"detail"`
	Operator string    `json:"operator"`
	Created  time.Time `json:"created"`
}
