package transport

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// startTestHTTPListener boots a plain-HTTP listener on a loopback port and
// returns the listener plus its base URL. The echo handler mimics the real
// admission flow: protocol peek with a 3s deadline, then a raw byte echo so
// the framing and partial-read paths are exercised in both directions.
func startTestHTTPListener(t *testing.T) (*HTTPListener, string) {
	t.Helper()

	ln := NewHTTPListener("127.0.0.1:0")
	if err := ln.Start(); err != nil {
		t.Fatalf("listener start: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Admission peek exactly like c2.Server.handleConnection.
		peek := make([]byte, 4)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(conn, peek); err != nil {
			return
		}
		conn.SetReadDeadline(time.Time{})

		// Echo the peeked bytes back first — the client expects the full
		// frame it sent (the real server re-injects via peekConn).
		if _, err := conn.Write(peek); err != nil {
			return
		}

		buf := make([]byte, 32*1024)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	return ln, "http://" + ln.Addr().String()
}

func buildFrame(payload []byte) []byte {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	return frame
}

func readFrame(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var prefix [4]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatalf("read frame length: %v", err)
	}
	payload := make([]byte, binary.BigEndian.Uint32(prefix[:]))
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read frame body: %v", err)
	}
	return payload
}

// TestHTTPRoundtripAndFraming drives the full path — registration, framed
// writes, io.ReadFull semantics across partial reads — with the admission
// peek (deadline + re-injection) in the loop.
func TestHTTPRoundtripAndFraming(t *testing.T) {
	_, baseURL := startTestHTTPListener(t)

	client, err := DialHTTP(baseURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	client.SetDeadline(time.Now().Add(20 * time.Second))

	payload := []byte("hello worldc2 http long-poll transport")
	if _, err := client.Write(buildFrame(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := readFrame(t, client); string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q", got)
	}

	// Second exchange through the same session (X-Session-ID continuity).
	if _, err := client.Write(buildFrame([]byte("second frame"))); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if got := readFrame(t, client); string(got) != "second frame" {
		t.Fatalf("echo 2 mismatch: got %q", got)
	}
}

// TestHTTPLargeFrame pushes a multi-megabyte frame in both directions to
// force the leftover/surplus stashing on every buffer boundary — the exact
// data-loss bug the round-1 audit found in the old httpConn.Read.
func TestHTTPLargeFrame(t *testing.T) {
	_, baseURL := startTestHTTPListener(t)

	client, err := DialHTTP(baseURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(60 * time.Second))

	payload := make([]byte, 3<<20) // 3 MiB
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	if _, err := client.Write(buildFrame(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readFrame(t, client)
	if len(got) != len(payload) {
		t.Fatalf("echo length: got %d, want %d", len(got), len(payload))
	}
	for i := range got {
		if got[i] != payload[i] {
			t.Fatalf("echo corrupt at byte %d: got %d want %d", i, got[i], payload[i])
		}
	}
}

// TestHTTPConcurrentReadWrite keeps a long-poll Read parked while Writes
// proceed — regression test for the round-1 mutual deadlock where Read held
// the connection mutex that Write needed.
func TestHTTPConcurrentReadWrite(t *testing.T) {
	_, baseURL := startTestHTTPListener(t)

	client, err := DialHTTP(baseURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(30 * time.Second))

	const frames = 12
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// Writer: fire frames while the reader is parked in a long-poll.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < frames; i++ {
			if _, err := client.Write(buildFrame([]byte("frame"))); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Reader: read every echoed frame with small buffers (partial reads).
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 7)
		want := 5 * frames // len("frame")
		read := 0
		for read < want {
			n, err := client.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			read += n
		}
	}()

	wg.Wait()
	select {
	case err := <-errCh:
		t.Fatalf("concurrent read/write failed: %v", err)
	default:
	}
}

// TestHTTPServerDeadlines checks the server-side net.Conn deadline contract
// the admission peek depends on: expired deadline errors immediately, a
// cleared deadline unblocks the wait.
func TestHTTPServerDeadlines(t *testing.T) {
	ln := NewHTTPListener("127.0.0.1:0")
	if err := ln.Start(); err != nil {
		t.Fatalf("listener start: %v", err)
	}
	defer ln.Close()

	// Keeps the server-side session alive until the client has read the
	// response — a premature Close would delete the session and 404 the
	// client's next poll (close semantics: pending output is dropped).
	servingDone := make(chan struct{})
	defer close(servingDone)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Expired deadline must fail fast, not park.
		conn.SetReadDeadline(time.Now().Add(-time.Second))
		if _, err := conn.Read(make([]byte, 4)); err == nil {
			t.Error("read with expired deadline returned nil error")
			return
		}

		// Cleared deadline: the wait resumes and delivery works.
		conn.SetReadDeadline(time.Time{})
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Errorf("read after deadline reset: %v", err)
			return
		}
		if _, err := conn.Write([]byte("ok")); err != nil {
			t.Errorf("write: %v", err)
			return
		}
		<-servingDone
	}()

	client, err := DialHTTP("http://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := client.Write(buildFrame([]byte("ping"))); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("got %q, want %q", got, "ok")
	}
}

// TestHTTPSessionClose verifies the teardown path: when the server closes a
// session the client learns it promptly (410 → net.ErrClosed) instead of
// hanging, and unknown sessions are rejected with 404.
func TestHTTPSessionClose(t *testing.T) {
	ln, baseURL := startTestHTTPListener(t)

	client, err := DialHTTP(baseURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Grab the server-side conn for this session and drop it, exactly like
	// a killed session or the max_sessions admission guard would.
	hc := client.(*HTTPClientConn)
	ln.mu.RLock()
	serverConn := ln.sessions[hc.SessionID()]
	ln.mu.RUnlock()
	if serverConn == nil {
		t.Fatalf("server lost the session %s", hc.SessionID())
	}
	serverConn.Close()

	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := client.Read(make([]byte, 16)); err == nil {
		t.Fatal("read on closed session returned nil error")
	}
	client.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := client.Write([]byte("x")); err == nil {
		t.Fatal("write on closed session returned nil error")
	}
}

// TestHTTPBadRequests pins the wire guards: registration with a non-empty
// body is rejected, and unknown session ids answer 404.
func TestHTTPBadRequests(t *testing.T) {
	_, baseURL := startTestHTTPListener(t)

	resp, err := http.Post(baseURL+"/register", "application/octet-stream", strings.NewReader("data"))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("register with body: got %d, want 400", resp.StatusCode)
	}

	resp, err = http.Post(baseURL+"/poll", "application/octet-stream", nil)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("poll without session: got %d, want 404", resp.StatusCode)
	}
}

// The listener-internal session map is accessed directly by the close test
// (same package); no extra helper is needed.
func TestHTTPClientDeadline(t *testing.T) {
	_, baseURL := startTestHTTPListener(t)

	client, err := DialHTTP(baseURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// An expired read deadline must error immediately, not park in a poll.
	start := time.Now()
	client.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := client.Read(make([]byte, 8)); err == nil {
		t.Fatal("client read with expired deadline returned nil error")
	} else if time.Since(start) > 2*time.Second {
		t.Fatalf("client read with expired deadline took %v", time.Since(start))
	}
}
