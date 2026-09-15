package handlers

import (
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/version"
)

// handleMetrics exposes operational telemetry in the Prometheus text
// exposition format (version 0.0.4). It is operational telemetry only:
// counters and gauges, no credential material, no session identifiers,
// no hostnames — the same discipline /api/status already follows (a
// leaked metrics scrape must not leak engagement data).
//
// Gate: perm("sessions:list"), the same privilege /api/status uses. An
// auditor or viewer can read dashboards; only unauthenticated callers
// are excluded (auth middleware runs first in the chain).
//
// Counts that need a query (sessions, tasks, credentials) are computed
// per scrape: a Prometheus default interval of 15-30s makes the cost
// negligible, and it avoids a background cache that could go stale or
// drift from the database.
func (r *Router) handleMetrics(w http.ResponseWriter, req *http.Request) {
	m := newMetricsBuilder()

	// Build identity: exactly one labeled sample, value always 1 — the
	// information lives in the labels (version / commit / go version),
	// which is how prometheus_model expects constant-ish dimensions. The
	// identity is already behind the sessions:list gate like every other
	// gauge here: it tells an authenticated operator WHICH build they are
	// looking at, nothing more (no runtime secrets, no host data).
	m.labeledGauge("worldc2_build_info", 1,
		"Build identity of this server binary (labels: version, commit, go_version).",
		[]metricsLabel{
			{"version", version.Version},
			{"commit", version.Commit},
			{"go_version", runtime.Version()},
		})

	// Server lifecycle.
	m.gauge("worldc2_uptime_seconds", r.server.UptimeSeconds(),
		"Seconds since the server process started.")
	m.gauge("worldc2_listeners", r.server.ListenerCount(),
		"Currently open C2 listeners (HTTP, WebRTC, mTLS...).")

	// Sessions: active from the in-memory tracker, total from the
	// database (every row, including killed/historical records).
	m.gauge("worldc2_sessions_active", r.server.ActiveSessions(),
		"Sessions whose agent currently has a live transport connection.")
	total, terr := r.server.DB().ListAllSessions()
	if terr == nil {
		m.gauge("worldc2_sessions_total", len(total),
			"Every session row in the database (active, inactive and killed).")
	} else {
		m.gauge("worldc2_sessions_query_errors_total", 1,
			"Set to 1 when the last sessions count query failed.")
	}

	// Tasks: a plain COUNT(*) — walking GetSessionTasks per session to
	// count them in Go would scale with task volume for no benefit.
	if n, err := r.server.DB().CountTasks(); err == nil {
		m.gauge("worldc2_tasks_total", n,
			"Task records persisted across all sessions.")
	}

	// Vault and loot.
	m.gauge("worldc2_vault_credentials", r.server.Vault().Count(),
		"Credential records in the vault (counts only — no material).")
	m.gauge("worldc2_files_stored", len(r.server.Files().List()),
		"Loot file records currently listed by the file manager.")

	// Webhooks: configured destinations plus the delivery ledger the
	// round-15 forwarder keeps in memory.
	webhooks, werr := r.server.DB().ListWebhooks()
	if werr == nil {
		m.gauge("worldc2_webhooks_configured", len(webhooks),
			"SIEM webhook destinations registered.")
	}
	var delivered, failed int64
	for _, st := range r.server.SIEM().Stats() {
		delivered += st.Delivered
		failed += st.Failed
	}
	m.gauge("worldc2_webhooks_delivered_total", delivered,
		"Successful webhook deliveries since process start (in-memory ledger).")
	m.gauge("worldc2_webhooks_failed_total", failed,
		"Failed webhook delivery attempts since process start (in-memory ledger).")

	// Go runtime: standard process_* style gauges under the worldc2_ prefix
	// so no Prometheus client library dependency is introduced.
	m.gauge("worldc2_go_goroutines", runtime.NumGoroutine(),
		"Number of goroutines that currently exist.")
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	m.gauge("worldc2_go_heap_alloc_bytes", mem.HeapAlloc,
		"Bytes of allocated heap objects.")

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(m.render()))
}

// metricsBuilder accumulates Prometheus text-format lines. Each metric is
// emitted with one HELP and one TYPE header followed by its sample, which
// keeps the payload stable and diff-friendly.
type metricsBuilder struct {
	lines []string
}

func newMetricsBuilder() *metricsBuilder {
	return &metricsBuilder{lines: make([]string, 0, 52)}
}

func (mb *metricsBuilder) gauge(name string, value interface{}, help string) {
	mb.lines = append(mb.lines,
		"# HELP "+name+" "+help,
		"# TYPE "+name+" gauge",
		name+" "+formatMetricValue(value),
	)
}

// metricsLabel is one label of a labeled sample.
type metricsLabel struct {
	Name  string
	Value string
}

// labeledGauge emits a single sample with Prometheus label sets:
// \tname{label="value",...} sample. Label values are escaped per the
// exposition format (backslash, double quote and newline), so a commit
// string or injected version can never break out of the quotes — and a
// malformed value degrades to escaped text, never to a broken scrape.
func (mb *metricsBuilder) labeledGauge(name string, value interface{}, help string, labels []metricsLabel) {
	parts := make([]string, 0, len(labels))
	for _, l := range labels {
		parts = append(parts, l.Name+"=\""+escapeLabelValue(l.Value)+"\"")
	}
	sample := name
	if len(parts) > 0 {
		sample = name + "{" + strings.Join(parts, ",") + "}"
	}
	mb.lines = append(mb.lines,
		"# HELP "+name+" "+help,
		"# TYPE "+name+" gauge",
		sample+" "+formatMetricValue(value),
	)
}

// escapeLabelValue applies the Prometheus text-format escaping rules for
// label values: backslash first (so later escapes stay literal), then
// double quotes, then newlines.
func escapeLabelValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

func (mb *metricsBuilder) render() string {
	return strings.Join(mb.lines, "\n") + "\n"
}

// formatMetricValue renders integers and int64 without a decimal point —
// strconv.FormatFloat for an int would print "1e+06" style values that
// some scrapers mis-handle on gauges.
func formatMetricValue(v interface{}) string {
	switch n := v.(type) {
	case int:
		return strconv.Itoa(n)
	case int64:
		return strconv.FormatInt(n, 10)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// parseDaysWindow is the shared strict parser for the ?days=N window used
// by the report (round 15) and now by /api/sessions and /api/files. It
// returns the cutoff (now - N*24h) and writes the 400 itself on invalid
// input; ok=false means the caller must stop. The 1..90 cap keeps the
// "full history" pull an explicit decision and rejects absurd or
// overflow-prone values (a huge integer would otherwise flow into
// time.Duration arithmetic).
func parseDaysWindow(w http.ResponseWriter, req *http.Request) (time.Time, bool) {
	raw := req.URL.Query().Get("days")
	if raw == "" {
		return time.Time{}, true // no window requested — full history
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 90 {
		http.Error(w, `{"error":"days must be an integer between 1 and 90"}`, 400)
		return time.Time{}, false
	}
	return time.Now().Add(-time.Duration(n) * 24 * time.Hour), true
}
