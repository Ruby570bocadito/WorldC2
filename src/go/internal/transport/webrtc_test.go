package transport

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// TestWebRTCRoundtrip exercises the full path: signaling endpoint, ICE over
// loopback, data channel open/detach and the net.Conn adapter, in both
// directions.
func TestWebRTCRoundtrip(t *testing.T) {
	ln, err := NewWebRTCListener("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// Echo server over the accepted data channel.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	client, err := DialWebRTC(addr, false)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	client.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("hello webrtc C2 transport")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}

	if client.LocalAddr() == nil || client.RemoteAddr() == nil {
		t.Fatal("addrs must not be nil")
	}
	if client.LocalAddr().Network() != "webrtc" {
		t.Fatalf("network = %q, want webrtc", client.LocalAddr().Network())
	}
}

func TestWebRTCListenerAcceptAfterClose(t *testing.T) {
	ln, err := NewWebRTCListener("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	ln.Close()

	if _, err := ln.Accept(); err == nil {
		t.Fatal("Accept after Close must fail")
	}
}

var _ net.Conn = (*WebRTCConn)(nil)
