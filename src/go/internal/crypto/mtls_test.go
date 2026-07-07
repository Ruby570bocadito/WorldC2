package crypto

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	cert, key, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}
	if cert == nil {
		t.Fatal("GenerateCA() returned nil cert")
	}
	if key == nil {
		t.Fatal("GenerateCA() returned nil key")
	}
	if !cert.IsCA {
		t.Error("GenerateCA() cert is not a CA")
	}
	if cert.Subject.CommonName != "WORLDC2 C2 CA" {
		t.Errorf("GenerateCA() CN = %q, want %q", cert.Subject.CommonName, "WORLDC2 C2 CA")
	}
}

func TestGenerateServerCert(t *testing.T) {
	caCert, caKey, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	serverCert, err := GenerateServerCert(caCert, caKey, "localhost")
	if err != nil {
		t.Fatalf("GenerateServerCert() error = %v", err)
	}
	if serverCert == nil {
		t.Fatal("GenerateServerCert() returned nil")
	}
	if len(serverCert.Certificate) == 0 {
		t.Fatal("GenerateServerCert() has no certificates")
	}

	// Verify the cert is signed by our CA
	parsedCert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	opts := x509.VerifyOptions{Roots: x509.NewCertPool()}
	opts.Roots.AddCert(caCert)
	if _, err := parsedCert.Verify(opts); err != nil {
		t.Errorf("Server cert verification failed: %v", err)
	}
}

func TestGenerateAgentCert(t *testing.T) {
	caCert, caKey, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	agentCert, err := GenerateAgentCert(caCert, caKey, "agent-test-001")
	if err != nil {
		t.Fatalf("GenerateAgentCert() error = %v", err)
	}
	if agentCert == nil {
		t.Fatal("GenerateAgentCert() returned nil")
	}

	// Verify the cert is signed by our CA
	parsedCert, err := x509.ParseCertificate(agentCert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if parsedCert.Subject.CommonName != "agent-test-001" {
		t.Errorf("Agent cert CN = %q, want %q", parsedCert.Subject.CommonName, "agent-test-001")
	}

	opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		CurrentTime:   parsedCert.NotBefore.Add(time.Hour),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	opts.Roots.AddCert(caCert)
	if _, err := parsedCert.Verify(opts); err != nil {
		t.Errorf("Agent cert verification failed: %v", err)
	}
}

func TestNewMTLSServerConfig(t *testing.T) {
	caCert, caKey, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	serverCert, err := GenerateServerCert(caCert, caKey, "localhost")
	if err != nil {
		t.Fatalf("GenerateServerCert() error = %v", err)
	}

	tlsConfig := NewMTLSServerConfig(*serverCert, caCert)
	if tlsConfig == nil {
		t.Fatal("NewMTLSServerConfig() returned nil")
	}
	if tlsConfig.ClientAuth != 4 { // tls.RequireAndVerifyClientCert
		t.Errorf("ClientAuth = %v, want %v", tlsConfig.ClientAuth, 4)
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1", len(tlsConfig.Certificates))
	}
}

func TestNewMTLSClientConfig(t *testing.T) {
	caCert, caKey, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	agentCert, err := GenerateAgentCert(caCert, caKey, "agent-001")
	if err != nil {
		t.Fatalf("GenerateAgentCert() error = %v", err)
	}

	tlsConfig := NewMTLSClientConfig(*agentCert, caCert, "localhost")
	if tlsConfig == nil {
		t.Fatal("NewMTLSClientConfig() returned nil")
	}
	if tlsConfig.ServerName != "localhost" {
		t.Errorf("ServerName = %q, want %q", tlsConfig.ServerName, "localhost")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1", len(tlsConfig.Certificates))
	}
}

func TestExportPEM(t *testing.T) {
	caCert, caKey, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	certPEM, keyPEM, err := ExportPEM(caCert, caKey)
	if err != nil {
		t.Fatalf("ExportPEM() error = %v", err)
	}
	if len(certPEM) == 0 {
		t.Error("ExportPEM() returned empty cert PEM")
	}
	if len(keyPEM) == 0 {
		t.Error("ExportPEM() returned empty key PEM")
	}
}
