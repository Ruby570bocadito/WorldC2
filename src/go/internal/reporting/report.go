package reporting

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReportGenerator creates engagement reports in various formats.
type ReportGenerator struct {
	reportDir string
}

// NewReportGenerator creates a new report generator.
func NewReportGenerator(reportDir string) *ReportGenerator {
	os.MkdirAll(reportDir, 0755)
	return &ReportGenerator{reportDir: reportDir}
}

// EngagementReport contains all data for an engagement report.
type EngagementReport struct {
	Title       string
	Operator    string
	StartDate   time.Time
	EndDate     time.Time
	Sessions    []SessionReport
	Credentials []CredentialReport
	Tasks       []TaskReport
	Summary     ReportSummary
}

// SessionReport contains session data for reporting.
type SessionReport struct {
	ID        string
	AgentID   string
	Hostname  string
	OS        string
	Arch      string
	Username  string
	IsAdmin   bool
	PublicIP  string
	FirstSeen time.Time
	LastSeen  time.Time
	State     string
	TaskCount int
}

// CredentialReport contains credential data for reporting.
type CredentialReport struct {
	Username string
	Password string
	Domain   string
	Host     string
	Service  string
	Source   string
	Captured time.Time
}

// TaskReport contains task data for reporting.
type TaskReport struct {
	ID        string
	SessionID string
	Command   string
	Output    string
	Success   bool
	IssuedAt  time.Time
}

// ReportSummary contains aggregate statistics.
type ReportSummary struct {
	TotalSessions    int
	ActiveSessions   int
	TotalTasks       int
	SuccessfulTasks  int
	TotalCredentials int
	UniqueHosts      int
	UniqueOS         map[string]int
}

// GenerateCSV creates a CSV report of the engagement.
func (rg *ReportGenerator) GenerateCSV(report *EngagementReport) (string, error) {
	filename := fmt.Sprintf("engagement_%s.csv", time.Now().Format("20060102_150405"))
	path := filepath.Join(rg.reportDir, filename)

	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create CSV: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Summary section
	w.Write([]string{"WORLDC2 C2 - Engagement Report"})
	w.Write([]string{"Generated", time.Now().Format("2006-01-02 15:04:05")})
	w.Write([]string{"Operator", report.Operator})
	w.Write([]string{})

	// Sessions summary
	w.Write([]string{"=== SESSIONS ==="})
	w.Write([]string{"ID", "AgentID", "Hostname", "OS", "User", "Admin", "IP", "First Seen", "Last Seen", "State", "Tasks"})
	for _, s := range report.Sessions {
		w.Write([]string{
			s.ID, s.AgentID, s.Hostname, s.OS, s.Username,
			fmt.Sprintf("%v", s.IsAdmin), s.PublicIP,
			s.FirstSeen.Format("2006-01-02 15:04"), s.LastSeen.Format("2006-01-02 15:04"),
			s.State, fmt.Sprintf("%d", s.TaskCount),
		})
	}
	w.Write([]string{})

	// Credentials
	w.Write([]string{"=== CREDENTIALS ==="})
	w.Write([]string{"Username", "Password", "Domain", "Host", "Service", "Source", "Captured"})
	for _, c := range report.Credentials {
		w.Write([]string{
			c.Username, c.Password, c.Domain, c.Host, c.Service, c.Source,
			c.Captured.Format("2006-01-02 15:04"),
		})
	}
	w.Write([]string{})

	// Tasks
	w.Write([]string{"=== TASKS ==="})
	w.Write([]string{"ID", "Session", "Command", "Success", "Issued"})
	for _, t := range report.Tasks {
		w.Write([]string{
			t.ID, t.SessionID, t.Command,
			fmt.Sprintf("%v", t.Success), t.IssuedAt.Format("2006-01-02 15:04"),
		})
	}

	return path, nil
}

// GenerateText creates a human-readable text report.
func (rg *ReportGenerator) GenerateText(report *EngagementReport) (string, error) {
	filename := fmt.Sprintf("engagement_%s.txt", time.Now().Format("20060102_150405"))
	path := filepath.Join(rg.reportDir, filename)

	var sb strings.Builder

	sb.WriteString("══════════════════════════════════════════════\n")
	sb.WriteString("         WORLDC2 C2 - ENGAGEMENT REPORT\n")
	sb.WriteString("══════════════════════════════════════════════\n\n")
	sb.WriteString(fmt.Sprintf("Generated:  %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Operator:   %s\n", report.Operator))
	sb.WriteString(fmt.Sprintf("Period:     %s to %s\n\n",
		report.StartDate.Format("2006-01-02"), report.EndDate.Format("2006-01-02")))

	sb.WriteString("─── SUMMARY ───\n")
	sb.WriteString(fmt.Sprintf("Total Sessions:     %d\n", report.Summary.TotalSessions))
	sb.WriteString(fmt.Sprintf("Active Sessions:    %d\n", report.Summary.ActiveSessions))
	sb.WriteString(fmt.Sprintf("Total Tasks:        %d\n", report.Summary.TotalTasks))
	sb.WriteString(fmt.Sprintf("Successful Tasks:   %d\n", report.Summary.SuccessfulTasks))
	sb.WriteString(fmt.Sprintf("Credentials:        %d\n", report.Summary.TotalCredentials))
	sb.WriteString(fmt.Sprintf("Unique Hosts:       %d\n", report.Summary.UniqueHosts))
	sb.WriteString(fmt.Sprintf("Operating Systems:  %v\n\n", report.Summary.UniqueOS))

	sb.WriteString("─── SESSIONS ───\n")
	for _, s := range report.Sessions {
		admin := ""
		if s.IsAdmin {
			admin = " [ADMIN]"
		}
		sb.WriteString(fmt.Sprintf("  %s | %s | %s/%s | %s%s | %s\n",
			s.AgentID, s.Hostname, s.OS, s.Arch, s.Username, admin, s.PublicIP))
	}

	sb.WriteString("\n─── CREDENTIALS ───\n")
	for _, c := range report.Credentials {
		sb.WriteString(fmt.Sprintf("  %s\\%s : %s (%s/%s)\n",
			c.Domain, c.Username, c.Password, c.Host, c.Service))
	}

	sb.WriteString("\n─── RECENT TASKS ───\n")
	for _, t := range report.Tasks {
		status := "✓"
		if !t.Success {
			status = "✗"
		}
		sb.WriteString(fmt.Sprintf("  %s %s | %s\n", status, t.Command[:min(len(t.Command), 50)], t.SessionID[:8]))
	}

	sb.WriteString("\n══════════════════════════════════════════════\n")
	sb.WriteString("              END OF REPORT\n")
	sb.WriteString("══════════════════════════════════════════════\n")

	os.WriteFile(path, []byte(sb.String()), 0644)
	return path, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
