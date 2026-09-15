package db

import (
	"fmt"
	"path/filepath"
	"testing"
)

// TestAuditRetentionPrune pins the round-18 retention contract: the pruner
// removes only rows older than the configured window, reports exactly how
// many rows it removed, and days <= 0 is a documented no-op (retention
// disabled — the historical never-delete behaviour).
func TestAuditRetentionPrune(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	// Seed: three old rows (40/35/31 days old) and two fresh ones. The
	// timestamp column is written directly in the same UTC text format
	// SQLite's CURRENT_TIMESTAMP produces, so the pruner's datetime
	// comparison sees exactly what production rows look like.
	for _, age := range []int{40, 35, 31, 0, 0} {
		ts := "datetime('now'"
		if age > 0 {
			ts += fmt.Sprintf(", '-%d days'", age)
		}
		ts += ")"
		if _, err := d.conn.Exec(
			`INSERT INTO audit_log (operator_id, action, detail, timestamp) VALUES (0, 'api_call', 'seed', ` + ts + `)`,
		); err != nil {
			t.Fatalf("seed row age=%d: %v", age, err)
		}
	}

	n, err := d.CountAuditEntries()
	if err != nil || n != 5 {
		t.Fatalf("seed failed: n=%d err=%v", n, err)
	}

	// Disabled retention (0 and negative): strict no-op.
	for _, days := range []int{0, -7} {
		removed, err := d.PruneAuditOlderThan(days)
		if err != nil {
			t.Fatalf("PruneAuditOlderThan(%d): %v", days, err)
		}
		if removed != 0 {
			t.Fatalf("days=%d removed %d rows, want 0 (disabled)", days, removed)
		}
	}
	if n, _ := d.CountAuditEntries(); n != 5 {
		t.Fatalf("disabled retention changed the trail: %d rows remain", n)
	}

	// 30-day window: exactly the three old rows go; the fresh pair stays.
	removed, err := d.PruneAuditOlderThan(30)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 3 {
		t.Fatalf("removed %d rows, want 3", removed)
	}
	if n, _ := d.CountAuditEntries(); n != 2 {
		t.Fatalf("%d rows remain, want 2", n)
	}

	// Idempotent: a second pass over the same window removes nothing.
	if removed, _ := d.PruneAuditOlderThan(30); removed != 0 {
		t.Fatalf("second pass removed %d rows, want 0", removed)
	}
}

// TestAuditOperatorAttribution pins the round-18 attribution contract at the
// DB layer: rows written with a real operator_id resolve the username via
// the JOIN; rows with operator_id 0 read as system (""), and a user filter
// returns only that account's rows — never the system ones.
func TestAuditOperatorAttribution(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "attrib.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	if err := d.CreateOperator("dana", "dana-pass-123", "admin"); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	id, err := d.OperatorIDByUsername("dana")
	if err != nil || id == 0 {
		t.Fatalf("resolve dana: id=%d err=%v", id, err)
	}
	if _, err := d.OperatorIDByUsername("nobody-here"); err != nil {
		t.Fatalf("unknown username must be (0, nil), got %v", err)
	}

	if err := d.LogAction(id, "auth_success", "dana logged in"); err != nil {
		t.Fatalf("log attributed: %v", err)
	}
	if err := d.LogAction(0, "task", "srv-01: whoami"); err != nil {
		t.Fatalf("log system: %v", err)
	}
	if err := d.LogAction(id, "api_call", "GET /api/sessions from 127.0.0.1 by dana"); err != nil {
		t.Fatalf("log second attributed: %v", err)
	}

	// Unfiltered: newest first, operator resolved on attributed rows.
	all, err := d.ListAuditEntries(10, "", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d rows, want 3", len(all))
	}
	if all[0].Action != "api_call" || all[0].Operator != "dana" {
		t.Fatalf("newest row mismatch: %+v", all[0])
	}
	if all[1].Operator != "" {
		t.Fatalf("system row must resolve operator \"\", got %q", all[1].Operator)
	}

	// user filter: only dana's two rows, system row excluded.
	onlyDana, err := d.ListAuditEntries(10, "", "dana")
	if err != nil {
		t.Fatalf("list dana: %v", err)
	}
	if len(onlyDana) != 2 {
		t.Fatalf("user filter returned %d rows, want 2", len(onlyDana))
	}
	for _, r := range onlyDana {
		if r.Operator != "dana" {
			t.Fatalf("user filter leaked row of %q", r.Operator)
		}
	}

	// action+user combined: intersection, not union.
	rows, err := d.ListAuditEntries(10, "api_call", "dana")
	if err != nil || len(rows) != 1 || rows[0].Action != "api_call" {
		t.Fatalf("combined filter: %d rows err=%v %+v", len(rows), err, rows)
	}

	// Unknown user: empty result, no error.
	ghost, err := d.ListAuditEntries(10, "", "ghost")
	if err != nil || len(ghost) != 0 {
		t.Fatalf("ghost user: %d rows err=%v", len(ghost), err)
	}
}
