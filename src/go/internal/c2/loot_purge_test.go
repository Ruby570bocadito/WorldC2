package c2

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
)

// TestDeleteSessionWithPersistedLoot is the regression test for the round 5
// finding: file_records carries a foreign key to sessions(id) and the
// database runs with PRAGMA foreign_keys=ON, so DeleteSession must clear the
// loot rows in the same transaction or the whole delete fails with
// FOREIGN KEY constraint failed.
func TestDeleteSessionWithPersistedLoot(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "fk.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	// file_records.session_id references sessions(id) with FK enforcement:
	// the session row must exist before storing loot for it.
	if err := database.UpsertSession(&db.SessionRecord{ID: "sess-fk", State: "active"}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	dir := t.TempDir()
	fm := NewFileManager(dir)
	fm.SetDB(database)

	if _, err := fm.Store("sess-fk", "loot.txt", "credentials", []byte("data")); err != nil {
		t.Fatalf("store: %v", err)
	}

	// The actual regression: deleting a session that owns persisted loot
	// must succeed instead of tripping the FK constraint.
	if err := database.DeleteSession("sess-fk"); err != nil {
		t.Fatalf("DeleteSession with persisted loot failed: %v", err)
	}

	records, err := database.ListFileRecords()
	if err != nil {
		t.Fatalf("list file records: %v", err)
	}
	for _, rec := range records {
		if rec.SessionID == "sess-fk" {
			t.Fatalf("loot record for deleted session survived: %s", rec.ID)
		}
	}
}

// TestDeleteFileRecordUnknownID checks the db layer distinguishes an unknown
// id (sql.ErrNoRows) from a real failure.
func TestDeleteFileRecordUnknownID(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "del.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	if err := database.UpsertSession(&db.SessionRecord{ID: "s", State: "active"}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := database.DeleteFileRecord("file-missing"); err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows for unknown id, got: %v", err)
	}
}

// TestFileManagerDeletePurgesEverywhere covers the loot purge path: the blob
// on disk, the current-run listing and the persisted row all disappear, and
// a second Delete reports the record as unknown.
func TestFileManagerDeletePurgesEverywhere(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "purge.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	if err := database.UpsertSession(&db.SessionRecord{ID: "sess-p", State: "active"}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	dir := t.TempDir()
	fm := NewFileManager(dir)
	fm.SetDB(database)

	rec, err := fm.Store("sess-p", "purge-me.txt", "credentials", []byte("SECRETO"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	if err := fm.Delete(rec.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := os.Stat(rec.Path); !os.IsNotExist(err) {
		t.Fatalf("loot blob survived on disk: %v", err)
	}
	if len(fm.List()) != 0 {
		t.Fatalf("in-memory listing still holds %d records", len(fm.List()))
	}
	if persisted, err := database.ListFileRecords(); err != nil || len(persisted) != 0 {
		t.Fatalf("persisted rows survived: %v (n=%d)", err, len(persisted))
	}

	// Second delete must report unknown, not crash.
	if err := fm.Delete(rec.ID); err == nil {
		t.Fatal("deleting an already-purged id unexpectedly succeeded")
	}
}

// TestFileManagerPurgeAllSweepsEverywhere covers the bulk purge: records from
// the current run AND persisted rows from previous runs (which List fuses)
// all disappear — blobs on disk, in-memory listing and file_records rows.
func TestFileManagerPurgeAllSweepsEverywhere(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "purgeall.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	if err := database.UpsertSession(&db.SessionRecord{ID: "sess-all", State: "active"}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	dir := t.TempDir()
	fm := NewFileManager(dir)
	fm.SetDB(database)

	// Two blobs from this run...
	r1, err := fm.Store("sess-all", "one.txt", "credentials", []byte("ONE"))
	if err != nil {
		t.Fatalf("store 1: %v", err)
	}
	r2, err := fm.Store("sess-all", "two.txt", "screenshots", []byte("TWO"))
	if err != nil {
		t.Fatalf("store 2: %v", err)
	}
	// ...and one row simulating a previous run (only in file_records).
	legacy := &db.FileRecord{
		ID: "file-legacy", SessionID: "sess-all", Filename: "legacy.txt",
		Module: "credentials", Size: 6, Path: filepath.Join(dir, "legacy.txt"),
	}
	if err := database.InsertFileRecord(legacy); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if len(fm.List()) != 3 {
		t.Fatalf("precondition: listing should fuse 3 records, got %d", len(fm.List()))
	}

	purged, err := fm.PurgeAll()
	if err != nil {
		t.Fatalf("purge all: %v", err)
	}
	if purged != 3 {
		t.Fatalf("purged %d records, want 3", purged)
	}

	if len(fm.List()) != 0 {
		t.Fatalf("listing still holds %d records after PurgeAll", len(fm.List()))
	}
	for _, rec := range []*FileRecord{r1, r2} {
		if _, err := os.Stat(rec.Path); !os.IsNotExist(err) {
			t.Fatalf("blob survived on disk: %s (%v)", rec.Path, err)
		}
	}
	if persisted, err := database.ListFileRecords(); err != nil || len(persisted) != 0 {
		t.Fatalf("persisted rows survived: %v (n=%d)", err, len(persisted))
	}

	// Idempotent: a second sweep on an empty board purges nothing, no error.
	if n, err := fm.PurgeAll(); err != nil || n != 0 {
		t.Fatalf("second purge: n=%d err=%v, want 0/nil", n, err)
	}
}

// TestFileManagerDeleteForeignPathKeepsBlob verifies the containment guard:
// when a record's stored path escapes the loot base dir (tampered row), the
// records are dropped but the foreign file is never touched.
func TestFileManagerDeleteForeignPathKeepsBlob(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "foreign.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	if err := database.UpsertSession(&db.SessionRecord{ID: "sess-x", State: "active"}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// Foreign file planted outside the loot dir.
	foreignDir := t.TempDir()
	foreignPath := filepath.Join(foreignDir, "innocent.txt")
	if err := os.WriteFile(foreignPath, []byte("keep me"), 0600); err != nil {
		t.Fatalf("seed foreign file: %v", err)
	}

	fm := NewFileManager(t.TempDir())
	fm.SetDB(database)

	// Plant a tampered record directly in the DB.
	tampered := &db.FileRecord{
		ID: "file-tampered", SessionID: "sess-x", Filename: "innocent.txt",
		Module: "evil", Size: 7, Path: foreignPath,
	}
	if err := database.InsertFileRecord(tampered); err != nil {
		t.Fatalf("seed tampered row: %v", err)
	}

	if err := fm.Delete("file-tampered"); err != nil {
		t.Fatalf("delete tampered record: %v", err)
	}

	data, err := os.ReadFile(foreignPath)
	if err != nil || string(data) != "keep me" {
		t.Fatalf("foreign file was touched: data=%q err=%v", data, err)
	}
	if persisted, _ := database.ListFileRecords(); len(persisted) != 0 {
		t.Fatal("tampered row survived the purge")
	}
}
