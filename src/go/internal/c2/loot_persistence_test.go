package c2

import (
	"path/filepath"
	"testing"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
)

func TestLootListingPersistsAcrossManagerInstances(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "loot.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	// file_records.session_id references sessions(id) with FK enforcement:
	// the session row must exist before storing loot for it.
	if err := database.UpsertSession(&db.SessionRecord{ID: "sess-1", State: "active"}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	dir := t.TempDir()
	fm := NewFileManager(dir)
	fm.SetDB(database)

	rec, err := fm.Store("sess-1", "secrets.txt", "credentials", []byte("PASSWORD=abc"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if len(fm.List()) != 1 {
		t.Fatalf("expected 1 record in listing, got %d", len(fm.List()))
	}

	// Simulate a server restart: fresh manager (empty in-memory), same DB.
	fm2 := NewFileManager(dir)
	fm2.SetDB(database)

	list := fm2.List()
	if len(list) != 1 {
		t.Fatalf("persisted listing must survive restart, got %d records", len(list))
	}
	if list[0].ID != rec.ID || list[0].Filename != "secrets.txt" || list[0].SessionID != "sess-1" {
		t.Fatalf("persisted record mismatch: %+v", list[0])
	}

	// Get (and therefore Read) resolves records from previous runs via DB.
	got, err := fm2.Get(rec.ID)
	if err != nil || got.ID != rec.ID {
		t.Fatalf("Get after restart: rec=%+v err=%v", got, err)
	}
	data, meta, err := fm2.Read(rec.ID)
	if err != nil || meta == nil || string(data) != "PASSWORD=abc" {
		t.Fatalf("Read after restart: err=%v meta=%+v data=%q", err, meta, data)
	}

	// Without a DB handle, the fresh manager must not see old records
	// (nil-safety of the optional layer).
	fm3 := NewFileManager(dir)
	if n := len(fm3.List()); n != 0 {
		t.Fatalf("manager without DB must not list persisted rows, got %d", n)
	}
}

func TestSessionRecordObservabilityFields(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	rec := &db.SessionRecord{
		ID: "sess-x", AgentID: "agent-x", Hostname: "host-x", OS: "linux",
		Arch: "amd64", Username: "op", IsAdmin: true, State: "active",
		AgentVersion: "2.0.0", Transport: "http", Privilege: "admin",
		Fingerprint: "aa:bb:cc",
	}
	if err := database.UpsertSession(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := database.GetSession("sess-x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AgentVersion != "2.0.0" || got.Transport != "http" || got.Privilege != "admin" || got.Fingerprint != "aa:bb:cc" {
		t.Fatalf("observability fields lost: %+v", got)
	}

	// A later upsert with an EMPTY fingerprint must not clobber the stored
	// one (mTLS pinning survives plaintext reconnects of the same row id).
	rec.Fingerprint = ""
	if err := database.UpsertSession(rec); err != nil {
		t.Fatalf("upsert2: %v", err)
	}
	got2, _ := database.GetSession("sess-x")
	if got2.Fingerprint != "aa:bb:cc" {
		t.Fatalf("fingerprint clobbered by empty value: %q", got2.Fingerprint)
	}

	if got2.Privilege != "admin" {
		t.Fatalf("privilege mismatch: %q", got2.Privilege)
	}
}
