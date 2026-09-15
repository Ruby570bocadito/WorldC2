package c2

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
)

func newVaultForTest(t *testing.T) (*CredentialVault, *db.DB) {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return NewCredentialVault(database), database
}

// Round 15: Add surfaces persistence errors instead of logging them and
// handing back an ID for a row that never existed.
func TestVaultAddPersistsAndReturnsUsableID(t *testing.T) {
	v, database := newVaultForTest(t)

	id, err := v.Add(Credential{Username: "svc-backup", Password: "P@ss", Host: "dc01.corp"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !strings.HasPrefix(id, "cred-") {
		t.Fatalf("id %q must carry the cred- prefix", id)
	}

	// The returned ID must resolve through the DB (the vault's only storage).
	recs, err := database.ListCredentials()
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != id {
		t.Fatalf("expected the stored row under %q, got %+v", id, recs)
	}
}

// The pre-round-15 ID (cred-<UnixNano>) was predictable and collision-prone
// for the most sensitive loot in the vault. A burst of adds must yield
// unique, non-time-derived IDs.
func TestVaultAddIDsAreUniqueUnderBurst(t *testing.T) {
	v, _ := newVaultForTest(t)

	seen := make(map[string]bool, 200)
	for i := 0; i < 200; i++ {
		id, err := v.Add(Credential{Username: "u"})
		if err != nil {
			t.Fatalf("Add #%d: %v", i, err)
		}
		if seen[id] {
			t.Fatalf("duplicate credential id %q in a 200-add burst", id)
		}
		seen[id] = true
	}
}

// DELETE /api/vault backs Vault.Delete: the row disappears from listings
// and the second delete reports not-found (404 territory, not silent success).
func TestVaultDeleteRemovesRow(t *testing.T) {
	v, _ := newVaultForTest(t)

	id, err := v.Add(Credential{Username: "admin", Domain: "CORP"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(v.List()) != 1 {
		t.Fatalf("expected 1 credential before delete, got %d", len(v.List()))
	}

	deleted, err := v.Delete(id)
	if err != nil || !deleted {
		t.Fatalf("Delete: deleted=%v err=%v", deleted, err)
	}
	if got := v.List(); len(got) != 0 {
		t.Fatalf("vault must be empty after delete, got %d rows", len(got))
	}

	deleted, err = v.Delete(id)
	if err != nil {
		t.Fatalf("second Delete errored: %v", err)
	}
	if deleted {
		t.Fatalf("deleting an already-deleted id must report not-found, got deleted=true")
	}
}
