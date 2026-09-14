package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Ruby570bocadito/WorldC2/src/go/internal/auth"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/c2"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/config"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/db"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/handlers"
	"github.com/Ruby570bocadito/WorldC2/src/go/internal/siem"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	host := flag.String("host", "", "Override server host")
	port := flag.Int("port", 0, "Override C2 port")
	apiPort := flag.Int("api-port", 0, "Override API port")
	noTLS := flag.Bool("no-tls", false, "Disable TLS")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *host != "" {
		cfg.Server.Host = *host
	}
	if *port != 0 {
		if *port < 1 || *port > 65535 {
			log.Fatalf("Invalid port %d: must be 1-65535", *port)
		}
		cfg.Server.Port = uint16(*port)
	}
	if *apiPort != 0 {
		if *apiPort < 1 || *apiPort > 65535 {
			log.Fatalf("Invalid api-port %d: must be 1-65535", *apiPort)
		}
		cfg.API.Port = uint16(*apiPort)
	}
	if *noTLS {
		cfg.TLS.Enabled = false
	}

	// Open database. Setting WORLDC2_MASTER_KEY enables at-rest encryption
	// (AES-256-GCM) for sensitive columns such as vault passwords and
	// operator notes. Any non-empty passphrase works — the encryptor
	// derives a 256-bit key from it. Losing the key makes stored secrets
	// unrecoverable by design.
	var masterKey []byte
	if mk := os.Getenv("WORLDC2_MASTER_KEY"); mk != "" {
		masterKey = []byte(mk)
		log.Println("[DB] WORLDC2_MASTER_KEY is set — at-rest encryption enabled (AES-256-GCM)")
	}
	database, err := db.OpenWithEncryption(cfg.Database.DSN, masterKey)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()

	// Create operators from config (with pre-hashed passwords)
	for _, op := range cfg.Operators {
		if op.Password != "" {
			// Password is already bcrypt hashed in config
			role := op.Role
			if role == "" {
				role = "operator"
			}
			if !auth.IsValidRole(role) {
				// A typo'd role would create an operator that
				// authenticates but fails every RBAC check.
				log.Printf("[AUTH] Operator %q: unknown role %q (valid: admin, operator, viewer, auditor) — skipped", op.Username, op.Role)
				continue
			}
			if err := database.CreateOperatorWithHash(op.Username, op.Password, role); err != nil {
				log.Printf("[AUTH] Operator %q: %v", op.Username, err)
			}
		}
	}

	// Fallback: create a bootstrap admin if the config defines none. A
	// predictable admin/admin default would be a critical exposure, so a
	// random password is generated and printed exactly once.
	if len(cfg.Operators) == 0 {
		bootPass, err := generateBootstrapPassword()
		if err != nil {
			log.Fatalf("Failed to generate bootstrap password: %v", err)
		}
		if err := database.CreateOperator("admin", bootPass, "admin"); err != nil {
			log.Printf("[AUTH] Bootstrap admin: %v", err)
		} else {
			log.Printf("[AUTH] No operators configured — created bootstrap user 'admin' with password: %s", bootPass)
			log.Printf("[AUTH] Store this password now; it will not be shown again.")
		}
	}

	// Create and start server
	server := c2.New(cfg, database)

	// Re-hydrate persisted SIEM webhook destinations (migration 9) into the
	// forwarder so webhook delivery survives server restarts. Order is safe:
	// the forwarder only delivers when events fire, never during hydration.
	if webhooks, err := database.ListWebhooks(); err != nil {
		log.Printf("[SIEM] hydrate webhooks: %v", err)
	} else {
		for _, wr := range webhooks {
			server.SIEM().AddWebhook(siem.WebhookConfig{
				ID:      wr.ID,
				URL:     wr.URL,
				Headers: wr.Headers,
				Timeout: time.Duration(wr.TimeoutMS) * time.Millisecond,
				Events:  wr.Events,
			})
		}
		if len(webhooks) > 0 {
			log.Printf("[SIEM] hydrated %d persisted webhook(s)", len(webhooks))
		}
	}

	// Wire up REST API handlers (separate package to avoid circular imports)
	router := handlers.NewRouter(server, cfg.Server.TrustedProxies)
	server.SetAPIMux(router.Setup())

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	fmt.Printf(`
╔══════════════════════════════════════════════╗
║              WORLDC2 C2 Framework                ║
║         Command & Control Server             ║
╠══════════════════════════════════════════════╣
║  C2 Port:  %-33d ║
║  API Port: %-33d ║
║  TLS:      %-33v ║
║  Sessions: %-33d ║
╚══════════════════════════════════════════════╝

C2 API:   http://localhost:%d/api/health
REST API: http://localhost:%d/api/sessions
`, cfg.Server.Port, cfg.API.Port, cfg.TLS.Enabled, 0,
		cfg.API.Port, cfg.API.Port)

	log.Printf("[C2] Server ready")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[C2] Shutdown signal received")
	server.Stop()
}

// generateBootstrapPassword creates a random 20-char URL-safe password.
func generateBootstrapPassword() (string, error) {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
