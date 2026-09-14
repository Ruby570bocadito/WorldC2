package db

import (
	"path/filepath"
	"testing"
)

func TestWebhookPersistenceRoundtrip(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "webhooks.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	// Empty listing on a fresh database.
	recs, err := d.ListWebhooks()
	if err != nil {
		t.Fatalf("list fresh: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected 0 webhooks on fresh DB, got %d", len(recs))
	}

	orig := &WebhookRecord{
		ID:        "wh-abc123",
		URL:       "https://siem.example.com/hook",
		Headers:   map[string]string{"Authorization": "Bearer tok", "X-Scope": "lab"},
		TimeoutMS: 5000,
		Events:    []string{"session.new", "task.result"},
	}
	if err := d.SaveWebhook(orig); err != nil {
		t.Fatalf("save: %v", err)
	}

	recs, err = d.ListWebhooks()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(recs))
	}
	got := recs[0]
	if got.ID != orig.ID || got.URL != orig.URL || got.TimeoutMS != 5000 {
		t.Errorf("scalar fields mismatch: %+v", got)
	}
	if len(got.Headers) != 2 || got.Headers["Authorization"] != "Bearer tok" {
		t.Errorf("headers not roundtripped: %+v", got.Headers)
	}
	if len(got.Events) != 2 || got.Events[0] != "session.new" {
		t.Errorf("events not roundtripped: %+v", got.Events)
	}

	// Upsert with the same ID replaces instead of duplicating.
	orig.URL = "https://siem.example.com/hook2"
	orig.Headers = nil
	orig.Events = nil
	if err := d.SaveWebhook(orig); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	recs, _ = d.ListWebhooks()
	if len(recs) != 1 || recs[0].URL != "https://siem.example.com/hook2" {
		t.Fatalf("upsert did not replace: %+v", recs)
	}
	if recs[0].Headers != nil {
		t.Errorf("nil headers must stay nil, got %+v", recs[0].Headers)
	}

	// Delete: existing id reports true, unknown id false.
	if ok, err := d.DeleteWebhook("wh-abc123"); err != nil || !ok {
		t.Fatalf("delete existing: ok=%v err=%v", ok, err)
	}
	if ok, err := d.DeleteWebhook("wh-abc123"); err != nil || ok {
		t.Fatalf("delete missing: ok=%v err=%v", ok, err)
	}
	recs, _ = d.ListWebhooks()
	if len(recs) != 0 {
		t.Fatalf("expected empty after delete, got %d", len(recs))
	}
}
