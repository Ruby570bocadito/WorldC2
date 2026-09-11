package agent

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/transport"
)

// TestDNSRoundtrip exercises the agent DNS client against a real DNSListener
// over UDP loopback: upstream data must arrive and downstream data must be
// delivered through the polling read.
func TestDNSRoundtrip(t *testing.T) {
	ln, err := transport.NewDNSListener("127.0.0.1:0", []string{"c2.example.com"}, nil)
	if err != nil {
		t.Fatalf("dns listener: %v", err)
	}
	ln.Start()
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				conn.Write(buf[:n]) // echo
			}
			if err != nil {
				return
			}
		}
	}()

	conn, err := dialDNS(ln.Addr().String(), "c2.example.com")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("ping-over-dns")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The DNS protocol piggybacks responses on polled queries; the first
	// Read may see an empty answer while the echo lands in the server's
	// down-queue, so give it a few attempts.
	deadline := time.Now().Add(10 * time.Second)
	got := make([]byte, len(payload))
	ok := false
	for time.Now().Before(deadline) {
		n, err := conn.Read(got)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if n == len(payload) && bytes.Equal(got, payload) {
			ok = true
			break
		}
	}
	if !ok {
		t.Fatalf("echo mismatch after retries: got %q", got)
	}

	// Drain: the Accept goroutine finishes when the listener closes.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	_ = io.Discard
}

// TestDNSFramedReadNoByteLoss reproduces the C2 framing over the DNS tunnel:
// the server side reads 4-byte length prefixes with io.ReadFull while each
// up-queue entry can carry ~150 bytes. Any byte dropped by a partial read
// corrupts the stream, so the framed payload must survive intact — including
// empty poll entries queued before the data.
func TestDNSFramedReadNoByteLoss(t *testing.T) {
	ln, err := transport.NewDNSListener("127.0.0.1:0", []string{"c2.example.com"}, nil)
	if err != nil {
		t.Fatalf("dns listener: %v", err)
	}
	ln.Start()
	defer ln.Close()

	received := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
		payload := make([]byte, n)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		received <- payload
	}()

	conn, err := dialDNS(ln.Addr().String(), "c2.example.com")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Interleave empty polls (idle reads) before the real payload: they
	// queue empty up-queue entries that must be skipped, never surfaced.
	for i := 0; i < 3; i++ {
		if _, err := conn.Write([]byte{}); err != nil {
			t.Fatalf("poll write: %v", err)
		}
	}

	payload := make([]byte, 600)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	frame := make([]byte, 4+len(payload))
	frame[0] = byte(len(payload) >> 24)
	frame[1] = byte(len(payload) >> 16)
	frame[2] = byte(len(payload) >> 8)
	frame[3] = byte(len(payload))
	copy(frame[4:], payload)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("frame write: %v", err)
	}

	select {
	case got := <-received:
		if !bytes.Equal(got, payload) {
			t.Fatalf("framed payload corrupted: got %d bytes, want %d", len(got), len(payload))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for framed payload")
	}
}
