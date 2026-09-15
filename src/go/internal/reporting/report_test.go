package reporting

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sampleReport builds a small but complete report for generator tests.
func sampleReport() *EngagementReport {
	return &EngagementReport{
		Title: "WORLDC2 C2 Engagement Report", Operator: "tester",
		StartDate: time.Now().Add(-24 * time.Hour), EndDate: time.Now(),
		Sessions: []SessionReport{{
			ID: "s-1", AgentID: "agent-abc", Hostname: "dc01", OS: "windows",
			Arch: "amd64", Username: "svc", State: "active", TaskCount: 2,
		}},
		Credentials: []CredentialReport{{
			Username: "svc", Password: "hunter2", Domain: "CORP",
			Host: "dc01", Service: "ldap", Captured: time.Now(),
		}},
		Tasks: []TaskReport{{
			ID: "t-1", SessionID: "s-1", Command: "whoami", Output: "corp\\svc",
			Success: true, IssuedAt: time.Now(),
		}},
		Summary: ReportSummary{TotalSessions: 1, ActiveSessions: 1, TotalCredentials: 1, UniqueOS: map[string]int{"windows": 1}, UniqueHosts: 1},
	}
}

// TestGenerateJSON pins the round-14 generator: valid JSON on disk that
// round-trips into the report struct (the API advertised format=json since
// its first day, but round 13 and earlier silently produced text bytes).
func TestGenerateJSON(t *testing.T) {
	dir := t.TempDir()
	rg := NewReportGenerator(dir)

	path, err := rg.GenerateJSON(sampleReport())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if filepath.Ext(path) != ".json" || filepath.Dir(path) != dir {
		t.Errorf("unexpected path %q", path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var back EngagementReport
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("output is not valid JSON: %v\nhead: %.200s", err, raw)
	}
	if back.Summary.TotalSessions != 1 || len(back.Sessions) != 1 || back.Sessions[0].Hostname != "dc01" {
		t.Errorf("round-trip mismatch: %+v", back)
	}
	if back.Credentials[0].Password != "hunter2" {
		t.Errorf("credential payload lost: %+v", back.Credentials[0])
	}
}

// TestGenerateTextAndCSV sanity-checks the two pre-existing generators so
// the format switch in the handler is covered on all three branches.
func TestGenerateTextAndCSV(t *testing.T) {
	dir := t.TempDir()
	rg := NewReportGenerator(dir)

	txtPath, err := rg.GenerateText(sampleReport())
	if err != nil {
		t.Fatalf("text: %v", err)
	}
	raw, _ := os.ReadFile(txtPath)
	s := string(raw)
	if !strings.Contains(s, "ENGAGEMENT REPORT") || !strings.Contains(s, "hunter2") {
		t.Errorf("text report missing expected sections:\n%.300s", s)
	}

	csvPath, err := rg.GenerateCSV(sampleReport())
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	raw, _ = os.ReadFile(csvPath)
	if !strings.Contains(string(raw), "svc,hunter2,CORP,dc01,ldap") {
		t.Errorf("csv report missing credential row:\n%.300s", raw)
	}
}
