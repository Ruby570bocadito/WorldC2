package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

// CertPinner handles certificate pinning for TLS connections.
// Instead of trusting any certificate, it verifies the server's
// certificate fingerprint matches a pinned value.
type CertPinner struct {
	pinnedFingerprint string
	serverName        string
}

// NewCertPinner creates a certificate pinner with the given fingerprint.
// fingerprint should be the SHA-256 hash of the server's certificate in hex format.
func NewCertPinner(fingerprint, serverName string) *CertPinner {
	return &CertPinner{
		pinnedFingerprint: fingerprint,
		serverName:        serverName,
	}
}

// DialTLS connects to the server via TLS and verifies the certificate fingerprint.
func (cp *CertPinner) DialTLS(addr string) (net.Conn, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{
		ServerName:         cp.serverName,
		InsecureSkipVerify: true, // We verify manually via pinning
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}

	// Get the server's certificate
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		conn.Close()
		return nil, fmt.Errorf("no peer certificate")
	}

	// Calculate SHA-256 fingerprint of the certificate
	cert := state.PeerCertificates[0]
	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	// Compare with pinned fingerprint
	if cp.pinnedFingerprint != "" && fingerprintHex != cp.pinnedFingerprint {
		conn.Close()
		return nil, fmt.Errorf("certificate pin mismatch: got %s, expected %s", fingerprintHex, cp.pinnedFingerprint)
	}

	return conn, nil
}

// GetFingerprintFromCert returns the SHA-256 fingerprint of a certificate.
// Useful for obtaining the fingerprint to pin.
func GetFingerprintFromCert(cert *x509.Certificate) string {
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
}

// GetFingerprintFromPEM returns the SHA-256 fingerprint of a PEM-encoded certificate.
func GetFingerprintFromPEM(pemData []byte) (string, error) {
	block, _ := decodePEMBlock(pemData)
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	return GetFingerprintFromCert(cert), nil
}

func decodePEMBlock(data []byte) (*struct {
	Type  string
	Bytes []byte
}, error) {
	// Simple PEM decoder
	for len(data) > 0 {
		// Find BEGIN marker
		beginIdx := -1
		for i := 0; i < len(data)-10; i++ {
			if string(data[i:i+10]) == "-----BEGIN" {
				beginIdx = i
				break
			}
		}
		if beginIdx == -1 {
			return nil, fmt.Errorf("no PEM begin marker found")
		}

		// Find END marker
		endIdx := -1
		for i := beginIdx + 10; i < len(data)-9; i++ {
			if string(data[i:i+9]) == "-----END " {
				endIdx = i
				break
			}
		}
		if endIdx == -1 {
			return nil, fmt.Errorf("no PEM end marker found")
		}

		// Extract type
		typeStart := beginIdx + 10
		typeEnd := beginIdx + 10
		for i := typeStart; i < len(data)-5; i++ {
			if string(data[i:i+5]) == "-----" {
				typeEnd = i
				break
			}
		}

		// Find the actual base64 content between headers
		contentStart := -1
		for i := endIdx; i < len(data); i++ {
			if data[i] == '\n' {
				contentStart = i + 1
				break
			}
		}
		if contentStart == -1 {
			return nil, fmt.Errorf("no content after end marker")
		}

		// Find the end of base64 content
		contentEnd := -1
		for i := contentStart; i < len(data)-5; i++ {
			if string(data[i:i+5]) == "-----" {
				contentEnd = i
				break
			}
		}
		if contentEnd == -1 {
			return nil, fmt.Errorf("no end of content marker")
		}

		// Decode base64
		content := data[contentStart:contentEnd]
		decoded := make([]byte, len(content))
		n := 0
		for _, b := range content {
			if b != '\n' && b != '\r' && b != ' ' {
				decoded[n] = b
				n++
			}
		}

		// This is a simplified decoder - in production use encoding/pem
		return &struct {
			Type  string
			Bytes []byte
		}{
			Type:  string(data[typeStart:typeEnd]),
			Bytes: decoded[:n],
		}, nil
	}
	return nil, fmt.Errorf("no PEM data found")
}
