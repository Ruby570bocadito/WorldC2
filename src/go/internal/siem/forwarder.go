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
	URL       string
	Headers   map[string]string
	Timeout   time.Duration
	Events    []string // Event types to forward
}

// SIEMForwarder forwards events to external SIEM systems.
type SIEMForwarder struct {
	mu        sync.Mutex
	webhooks  []WebhookConfig
	queue     chan SIEMEvent
	quit      chan struct{}
	wg        sync.WaitGroup
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
			if err := sf.sendToWebhook(wh, event); err != nil {
				log.Printf("[SIEM] Failed to send to webhook %s: %v", wh.URL, err)
			}
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

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
