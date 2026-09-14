package c2

import (
	"path/filepath"
	"testing"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
)

// TestDeleteSessionUnknownIDNoRows documents the db-level contract used by
// PurgeSession: deleting an unknown session id must NOT error (sql returns
// 0 rows affected), so the server layer is responsible for the 404 semantics
// by checking GetSession first. The DB stays a dumb storage layer; this test
// pins the behavior so a driver change cannot silently flip it.
func TestDeleteSessionUnknownIDNoRows(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "nosuch.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	if err := database.DeleteSession("sess-does-not-exist"); err != nil {
		t.Fatalf("DeleteSession on unknown id must be a no-op, got: %v", err)
	}

	// GetSession, in contrast, reports the missing row (sql.ErrNoRows via
	// QueryRow.Scan) — this is the signal PurgeSession turns into 404.
	if _, err := database.GetSession("sess-does-not-exist"); err == nil {
		t.Fatal("GetSession on unknown id must return an error (sql.ErrNoRows)")
	}
}
