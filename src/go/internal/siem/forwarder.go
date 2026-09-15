package siem

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// WebhookConfig holds webhook notification settings.
type WebhookConfig struct {
	ID      string // stable identifier (persisted in the webhooks table)
	URL     string
	Headers map[string]string
	Timeout time.Duration
	Events  []string // Event types to forward
}

// WebhookStats is the per-destination delivery ledger exposed by
// GET /api/webhooks since round 15. Before it, an operator had no way to
// tell whether a webhook was firing: a wrong URL or a blocked egress just
// logged to the server console and the event was silently lost.
// LastStatus caps the failure text so a huge error body can't inflate the
// API response.
type WebhookStats struct {
	Delivered    int64  `json:"delivered"`
	Failed       int64  `json:"failed"`
	LastDelivery string `json:"last_delivery"` // RFC3339, "" if never attempted
	LastStatus   string `json:"last_status"`   // "ok" or "error: ..." (capped)
}

const maxLastStatusLen = 200

// SIEMForwarder forwards events to external SIEM systems.
type SIEMForwarder struct {
	mu       sync.Mutex
	webhooks []WebhookConfig
	stats    map[string]*WebhookStats
	queue    chan SIEMEvent
	quit     chan struct{}
	wg       sync.WaitGroup
}

// SIEMEvent represents an event to forward.
type SIEMEvent struct {
	Timestamp string                 `json:"timestamp"`
	EventType string                 `json:"event_type"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
}

// NewSIEMForwarder creates a new SIEM forwarder.
func NewSIEMForwarder(bufferSize int) *SIEMForwarder {
	sf := &SIEMForwarder{
		queue: make(chan SIEMEvent, bufferSize),
		quit:  make(chan struct{}),
		stats: make(map[string]*WebhookStats),
	}

	// Start background forwarder
	sf.wg.Add(1)
	go sf.forwardLoop()

	return sf
}

// AddWebhook adds a webhook destination.
func (sf *SIEMForwarder) AddWebhook(cfg WebhookConfig) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	sf.webhooks = append(sf.webhooks, cfg)
	if sf.stats == nil {
		sf.stats = make(map[string]*WebhookStats)
	}
	sf.stats[cfg.ID] = &WebhookStats{}
}

// ListWebhooks returns a copy of the registered webhook destinations. It backs
// GET /api/webhooks so the response matches the OpenAPI contract ("List of
// webhooks") instead of a placeholder status object.
func (sf *SIEMForwarder) ListWebhooks() []WebhookConfig {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	out := make([]WebhookConfig, len(sf.webhooks))
	copy(out, sf.webhooks)
	return out
}

// Stats returns a copy of the per-webhook delivery ledger. Destinations
// never attempted (no matching event since start) carry zero values.
func (sf *SIEMForwarder) Stats() map[string]WebhookStats {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	out := make(map[string]WebhookStats, len(sf.stats))
	for id, s := range sf.stats {
		out[id] = *s
	}
	return out
}

// recordResult folds a delivery attempt into the destination's ledger.
func (sf *SIEMForwarder) recordResult(id string, err error) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	s, ok := sf.stats[id]
	if !ok {
		// Delivery for a destination removed mid-flight: keep the outcome
		// off the ledger instead of re-creating an entry for a dead ID.
		return
	}
	if err != nil {
		s.Failed++
		s.LastStatus = "error: " + err.Error()
		if len(s.LastStatus) > maxLastStatusLen {
			s.LastStatus = s.LastStatus[:maxLastStatusLen]
		}
	} else {
		s.Delivered++
		s.LastStatus = "ok"
	}
	s.LastDelivery = time.Now().UTC().Format(time.RFC3339)
}

// RemoveWebhook deletes the webhook with the given ID. It returns false when
// no webhook matches, so DELETE /api/webhooks can answer 404 precisely.
// The delivery ledger goes with the destination: keeping stats for a
// deleted ID would leak memory and resurrect stale counters if the ID was
// ever reused.
func (sf *SIEMForwarder) RemoveWebhook(id string) bool {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	for i, wh := range sf.webhooks {
		if wh.ID == id {
			sf.webhooks = append(sf.webhooks[:i], sf.webhooks[i+1:]...)
			delete(sf.stats, id)
			return true
		}
	}
	return false
}

// Forward queues an event for forwarding.
func (sf *SIEMForwarder) Forward(event SIEMEvent) {
	event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	select {
	case sf.queue <- event:
	default:
		log.Printf("[SIEM] Event queue full, dropping event: %s", event.EventType)
	}
}

// forwardLoop processes queued events.
func (sf *SIEMForwarder) forwardLoop() {
	defer sf.wg.Done()

	for {
		select {
		case event := <-sf.queue:
			sf.sendEvent(event)
		case <-sf.quit:
			// Drain queue before exiting
			for len(sf.queue) > 0 {
				event := <-sf.queue
				sf.sendEvent(event)
			}
			return
		}
	}
}

// sendEvent sends an event to all configured webhooks.
func (sf *SIEMForwarder) sendEvent(event SIEMEvent) {
	sf.mu.Lock()
	webhooks := make([]WebhookConfig, len(sf.webhooks))
	copy(webhooks, sf.webhooks)
	sf.mu.Unlock()

	for _, wh := range webhooks {
		// Check if event type should be forwarded
		if len(wh.Events) > 0 && !contains(wh.Events, event.EventType) {
			continue
		}

		go func(wh WebhookConfig) {
			err := sf.sendToWebhook(wh, event)
			if err != nil {
				log.Printf("[SIEM] Failed to send to webhook %s: %v", wh.URL, err)
			}
			sf.recordResult(wh.ID, err)
		}(wh)
	}
}

// sendToWebhook sends an event to a single webhook.
func (sf *SIEMForwarder) sendToWebhook(wh WebhookConfig, event SIEMEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	timeout := wh.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	req, err := http.NewRequest("POST", wh.URL, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range wh.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Stop gracefully shuts down the forwarder.
func (sf *SIEMForwarder) Stop() {
	close(sf.quit)
	sf.wg.Wait()
}

// TestDelivery sends one synthetic event to the webhook with the given ID
// SYNCHRONOUSLY and reports the outcome. It backs POST /api/webhooks/test:
// before it, an operator configuring a destination had to wait for a real
// session event (or fire a real task) to learn the URL was wrong — a test
// button needs an immediate, honest answer.
//
// The attempt folds into the same per-destination ledger the automatic
// path uses (recordResult), so the "Test" click shows up in the stats the
// console already renders. The synthetic event carries no engagement
// data — only the event type, the source and the destination ID.
//
// The event type "webhook_test" deliberately bypasses the destination's
// Events subscription: the whole point is to prove reachability, and a
// destination subscribed only to session_error would otherwise be
// untestable. Automatic forwarding keeps honouring the subscription.
//
// Returns (found=false) when no webhook matches the ID — the handler maps
// that to 404; delivery errors are the RESULT of the test, not a handler
// failure, so they come back as (found, err) and land in the 200 body.
func (sf *SIEMForwarder) TestDelivery(id string) (found bool, err error) {
	sf.mu.Lock()
	var wh *WebhookConfig
	for i := range sf.webhooks {
		if sf.webhooks[i].ID == id {
			wh = &sf.webhooks[i]
			break
		}
	}
	if wh == nil {
		sf.mu.Unlock()
		return false, nil
	}
	cfg := *wh
	sf.mu.Unlock()

	event := SIEMEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EventType: "webhook_test",
		Source:    "c2_server",
		Data: map[string]interface{}{
			"webhook_id": cfg.ID,
			"note":       "manual test delivery from the WORLDC2 console",
		},
	}
	err = sf.sendToWebhook(cfg, event)
	sf.recordResult(cfg.ID, err)
	return true, err
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
