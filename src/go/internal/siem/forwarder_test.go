package siem

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// receivedEvent mirrors what the test receiver captures per POST.
type receivedEvent struct {
	EventType string                 `json:"event_type"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
}

// testReceiver is a local HTTP endpoint standing in for a SIEM. Every POST
// is decoded and pushed onto a channel so tests can await real deliveries
// (no sleeps: the select below bounds the wait).
type testReceiver struct {
	srv  *httptest.Server
	mu   sync.Mutex
	urls []string
	got  chan receivedEvent
	hdrs chan http.Header
	fail bool // when true, answer 500 to exercise the failure path
}

func newTestReceiver(t *testing.T) *testReceiver {
	t.Helper()
	r := &testReceiver{got: make(chan receivedEvent, 8), hdrs: make(chan http.Header, 8)}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var ev receivedEvent
		if err := json.NewDecoder(req.Body).Decode(&ev); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.urls = append(r.urls, req.URL.Path)
		fail := r.fail
		r.mu.Unlock()
		if fail {
			http.Error(w, "synthetic failure", http.StatusInternalServerError)
			return
		}
		r.got <- ev
		r.hdrs <- req.Header.Clone()
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// waitFor receives the next delivered event (and its headers), failing the
// test if nothing arrives within two seconds.
func (r *testReceiver) waitFor(t *testing.T) (receivedEvent, http.Header) {
	t.Helper()
	select {
	case ev := <-r.got:
		h := <-r.hdrs
		return ev, h
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for webhook delivery")
		return receivedEvent{}, nil
	}
}

// assertNoDelivery proves nothing arrives during a short window (used for
// the event-filter path: an event that does not match must not be posted).
func (r *testReceiver) assertNoDelivery(t *testing.T) {
	t.Helper()
	select {
	case ev := <-r.got:
		t.Fatalf("unexpected delivery: %+v", ev)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestForwarderDeliversRealPOST is the round-14 E2E: an event queued via
// Forward must come out as a JSON POST on the wire, carrying the custom
// headers configured for the destination.
func TestForwarderDeliversRealPOST(t *testing.T) {
	rx := newTestReceiver(t)
	sf := NewSIEMForwarder(16)
	defer sf.Stop()

	sf.AddWebhook(WebhookConfig{
		ID:      "wh-test",
		URL:     rx.srv.URL + "/ingest",
		Headers: map[string]string{"X-SIEM-Token": "secret-token"},
		Timeout: 3 * time.Second,
	})

	sf.Forward(SIEMEvent{EventType: "session_established", Source: "test", Data: map[string]interface{}{"host": "dc01"}})

	ev, hdr := rx.waitFor(t)
	if ev.EventType != "session_established" || ev.Data["host"] != "dc01" {
		t.Fatalf("delivered payload = %+v", ev)
	}
	if hdr.Get("X-SIEM-Token") != "secret-token" {
		t.Errorf("custom header lost: %v", hdr)
	}
	if hdr.Get("Content-Type") != "application/json" {
		t.Errorf("content-type = %q", hdr.Get("Content-Type"))
	}
}

// TestForwarderEventFilter pins the contains() gate: a webhook subscribed to
// task_result must NOT receive session_error events, and must receive the
// ones it subscribed to.
func TestForwarderEventFilter(t *testing.T) {
	rx := newTestReceiver(t)
	sf := NewSIEMForwarder(16)
	defer sf.Stop()

	sf.AddWebhook(WebhookConfig{ID: "wh-filter", URL: rx.srv.URL, Timeout: 3 * time.Second, Events: []string{"task_result"}})

	sf.Forward(SIEMEvent{EventType: "session_error", Source: "test"})
	rx.assertNoDelivery(t)

	sf.Forward(SIEMEvent{EventType: "task_result", Source: "test"})
	if ev, _ := rx.waitFor(t); ev.EventType != "task_result" {
		t.Fatalf("delivered %q, want task_result", ev.EventType)
	}
}

// TestForwarderRejectsServerError checks the failure path: a 500 from the
// destination is surfaced as an error (logged), not silently treated as a
// successful delivery — and the forwarder stays healthy for later events.
func TestForwarderRejectsServerError(t *testing.T) {
	rx := newTestReceiver(t)
	sf := NewSIEMForwarder(16)
	defer sf.Stop()

	rx.mu.Lock()
	rx.fail = true
	rx.mu.Unlock()

	sf.AddWebhook(WebhookConfig{ID: "wh-fail", URL: rx.srv.URL, Timeout: 3 * time.Second})
	sf.Forward(SIEMEvent{EventType: "operator_login", Source: "test"})

	// The receiver answers 500; give the forwarder a moment, then prove the
	// queue still works by flipping the receiver to 200 and expecting a hit.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		rx.mu.Lock()
		saw := len(rx.urls)
		rx.mu.Unlock()
		if saw > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	rx.mu.Lock()
	rx.fail = false
	rx.mu.Unlock()

	sf.Forward(SIEMEvent{EventType: "operator_login", Source: "test"})
	if ev, _ := rx.waitFor(t); ev.EventType != "operator_login" {
		t.Fatalf("post-failure delivery = %+v", ev)
	}
}

// statsFor reads the ledger for one destination with a bounded wait: the
// delivery goroutine records the outcome after the receiver already saw the
// POST, so the first read can legitimately lag the wire.
func statsFor(t *testing.T, sf *SIEMForwarder, id string, want int64) WebhookStats {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s := sf.Stats()[id]; s.Delivered+s.Failed >= want {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("stats for %s never reached %d recorded attempts", id, want)
	return WebhookStats{}
}

// TestForwarderStatsLedger pins the round-15 delivery ledger: an accepted
// POST counts as Delivered with last_status "ok", a 500 counts as Failed
// with a capped error status, and RemoveWebhook drops the entry (no ledger
// growth for dead destinations).
func TestForwarderStatsLedger(t *testing.T) {
	rx := newTestReceiver(t)
	sf := NewSIEMForwarder(16)
	defer sf.Stop()

	sf.AddWebhook(WebhookConfig{ID: "wh-stats", URL: rx.srv.URL, Timeout: 3 * time.Second})

	// A destination that has never been attempted carries zero values.
	zero := sf.Stats()["wh-stats"]
	if zero.Delivered != 0 || zero.Failed != 0 || zero.LastDelivery != "" || zero.LastStatus != "" {
		t.Fatalf("fresh webhook must carry zero stats, got %+v", zero)
	}

	sf.Forward(SIEMEvent{EventType: "operator_login", Source: "test"})
	rx.waitFor(t)
	s := statsFor(t, sf, "wh-stats", 1)
	if s.Delivered != 1 || s.Failed != 0 {
		t.Fatalf("after one ok delivery: %+v", s)
	}
	if s.LastStatus != "ok" || s.LastDelivery == "" {
		t.Fatalf("ok delivery must stamp status/delivery: %+v", s)
	}

	rx.mu.Lock()
	rx.fail = true
	rx.mu.Unlock()
	sf.Forward(SIEMEvent{EventType: "operator_login", Source: "test"})
	s = statsFor(t, sf, "wh-stats", 2)
	if s.Failed != 1 {
		t.Fatalf("after one failed delivery: %+v", s)
	}
	if len(s.LastStatus) > maxLastStatusLen || !strings.HasPrefix(s.LastStatus, "error:") {
		t.Fatalf("failed delivery must carry a capped error status: %+v", s)
	}

	if !sf.RemoveWebhook("wh-stats") {
		t.Fatalf("RemoveWebhook reported miss for a live destination")
	}
	if s, ok := sf.Stats()["wh-stats"]; ok {
		t.Fatalf("ledger must go with the destination, got %+v", s)
	}
}
