package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize is the size of X25519 keys.
	KeySize = 32
	// NonceSize is the size of XChaCha20 nonces.
	NonceSize = chacha20poly1305.NonceSizeX
	// TagSize is the size of the Poly1305 authentication tag.
	TagSize = 16
	// SessionKeySize is the derived session key size.
	SessionKeySize = chacha20poly1305.KeySize
	// TokenSize is the size of the HMAC-based session token.
	TokenSize = 24
)

// KeyPair represents an X25519 key pair.
type KeyPair struct {
	PublicKey  [KeySize]byte
	PrivateKey [KeySize]byte
}

// GenerateKeyPair creates a new X25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := io.ReadFull(rand.Reader, kp.PrivateKey[:]); err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	curve25519.ScalarBaseMult(&kp.PublicKey, &kp.PrivateKey)
	return kp, nil
}

// KeyPairFromPrivate creates a key pair from an existing private key.
func KeyPairFromPrivate(private []byte) (*KeyPair, error) {
	if len(private) != KeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(private))
	}
	kp := &KeyPair{}
	copy(kp.PrivateKey[:], private)
	curve25519.ScalarBaseMult(&kp.PublicKey, &kp.PrivateKey)
	return kp, nil
}

// DeriveSharedSecret performs X25519 key exchange and derives session keys.
func DeriveSharedSecret(privateKey *[KeySize]byte, peerPublic *[KeySize]byte) ([]byte, error) {
	shared, err := curve25519.X25519(privateKey[:], peerPublic[:])
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}
	return shared, nil
}

// DeriveSessionKeys derives encryption and authentication keys from a shared secret.
// Returns (encryptionKey, hmacKey, sessionToken).
func DeriveSessionKeys(sharedSecret []byte, salt []byte) ([]byte, []byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
	}

	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, []byte("ctrlworldc2-session-keys"))

	encKey := make([]byte, SessionKeySize)
	hmacKey := make([]byte, 32)
	token := make([]byte, TokenSize)

	if _, err := io.ReadFull(hkdfReader, encKey); err != nil {
		return nil, nil, nil, fmt.Errorf("derive enc key: %w", err)
	}
	if _, err := io.ReadFull(hkdfReader, hmacKey); err != nil {
		return nil, nil, nil, fmt.Errorf("derive hmac key: %w", err)
	}
	if _, err := io.ReadFull(hkdfReader, token); err != nil {
		return nil, nil, nil, fmt.Errorf("derive token: %w", err)
	}

	return encKey, hmacKey, token, nil
}

// Encrypt encrypts plaintext using XChaCha20-Poly1305 with a random nonce.
// Returns nonce + ciphertext.
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	// Prepend nonce to ciphertext: nonce(24) + ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:NonceSize], nonce)
	copy(result[NonceSize:], ciphertext)

	return result, nil
}

// Decrypt decrypts ciphertext using XChaCha20-Poly1305.
// ciphertext must be: nonce(24) + encrypted_data.
func Decrypt(key []byte, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}

	if len(data) < NonceSize+TagSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(data))
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// GenerateSessionToken creates a unique session token using HMAC-SHA256.
func GenerateSessionToken(hmacKey []byte, counter uint32) []byte {
	mac := hmac.New(sha256.New, hmacKey)
	binary.Write(mac, binary.BigEndian, counter)
	return mac.Sum(nil)[:TokenSize]
}

// VerifySessionToken verifies a session token.
func VerifySessionToken(hmacKey []byte, token []byte, counter uint32) bool {
	expected := GenerateSessionToken(hmacKey, counter)
	return hmac.Equal(expected, token)
}

// GenerateSalt creates a random salt for key derivation.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}
