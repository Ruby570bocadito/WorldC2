package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Ciphertext formats handled by Encryptor:
//
//   legacy (pre-v2): base64( nonce || GCM(sha256(masterKey), plaintext) )
//   v2 (current):    "v2." + base64( nonce || GCM(pbkdf2Key, plaintext) )
//
// The legacy key was sha256(masterKey) with no stretching: a weak operator
// key fell to GPU brute force at ~10^9 guesses/s per card. The v2 key is
// PBKDF2-HMAC-SHA256(masterKey, per-database salt, 600000 iterations) —
// OWASP 2023 guidance for PBKDF2-SHA256 — which cuts that to ~10^3/s.
// Legacy ciphertexts remain readable (backward compatibility with databases
// written before this change); every NEW encryption goes out in v2 format.

// kdfIterations is the PBKDF2 work factor. One-time cost at server start
// (the key is derived once, then reused for every column encryption).
const kdfIterations = 600000

// v2Prefix marks ciphertext produced with the stretched key.
const v2Prefix = "v2."

// Encryptor provides AES-256-GCM encryption for sensitive database fields.
type Encryptor struct {
	// gcm is the LEGACY cipher (sha256(masterKey)); kept for reading old
	// ciphertext. nil when constructed without a master key.
	gcm cipher.AEAD

	// gcmV2 is the stretched cipher (PBKDF2); every Encrypt uses it when
	// present. nil in legacy-only mode (NewEncryptor direct construction).
	gcmV2 cipher.AEAD
}

func newGCMFromKey(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return gcm, nil
}

// deriveLegacyKey reproduces the pre-v2 key derivation: bare sha256.
func deriveLegacyKey(masterKey []byte) []byte {
	hash := sha256.Sum256(masterKey)
	return hash[:]
}

// deriveV2Key stretches the master key with PBKDF2-HMAC-SHA256 using the
// per-database salt persisted in _kdf_meta.
func deriveV2Key(masterKey, salt []byte) []byte {
	return pbkdf2.Key(masterKey, salt, kdfIterations, 32, sha256.New)
}

// NewEncryptor creates a LEGACY encryptor from a master key (any length,
// hashed to 256-bit). Preserved for backward compatibility and tests;
// OpenWithEncryption uses NewEncryptorV2, which also reads legacy values.
func NewEncryptor(masterKey []byte) (*Encryptor, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("master key is required")
	}
	gcm, err := newGCMFromKey(deriveLegacyKey(masterKey))
	if err != nil {
		return nil, err
	}
	return &Encryptor{gcm: gcm}, nil
}

// NewEncryptorV2 creates an encryptor that WRITES v2 (PBKDF2-stretched)
// ciphertext and READS both v2 and legacy formats. salt must be the
// per-database salt persisted in _kdf_meta (see ensureKDFSalt).
func NewEncryptorV2(masterKey, salt []byte) (*Encryptor, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("master key is required")
	}
	if len(salt) == 0 {
		return nil, fmt.Errorf("kdf salt is required")
	}
	gcmLegacy, err := newGCMFromKey(deriveLegacyKey(masterKey))
	if err != nil {
		return nil, err
	}
	gcmV2, err := newGCMFromKey(deriveV2Key(masterKey, salt))
	if err != nil {
		return nil, err
	}
	return &Encryptor{gcm: gcmLegacy, gcmV2: gcmV2}, nil
}

// Encrypt encrypts plaintext (v2 format when available) and returns the
// base64-encoded ciphertext with nonce prepended.
func (e *Encryptor) Encrypt(plaintext []byte) (string, error) {
	gcm := e.gcm
	var prefixed string
	if e.gcmV2 != nil {
		gcm = e.gcmV2
		prefixed = v2Prefix
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return prefixed + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext (v2 or legacy format).
func (e *Encryptor) Decrypt(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)

	gcm := e.gcm
	if strings.HasPrefix(encoded, v2Prefix) {
		if e.gcmV2 == nil {
			return nil, fmt.Errorf("v2 ciphertext requires the kdf salt (legacy-only encryptor)")
		}
		gcm = e.gcmV2
		encoded = strings.TrimPrefix(encoded, v2Prefix)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns base64-encoded ciphertext.
func (e *Encryptor) EncryptString(plaintext string) (string, error) {
	return e.Encrypt([]byte(plaintext))
}

// DecryptString decrypts a base64-encoded ciphertext and returns the plaintext string.
func (e *Encryptor) DecryptString(encoded string) (string, error) {
	plaintext, err := e.Decrypt(encoded)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// ensureKDFSalt returns the per-database KDF salt, creating and persisting a
// random one on first use. The salt is stored in the _kdf_meta table
// (migration 10) so the derived key is stable across server restarts — the
// same database always decrypts with the same key as long as the master key
// (WORLDC2_MASTER_KEY) is unchanged.
func (d *DB) ensureKDFSalt() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var saltB64 string
	err := d.conn.QueryRow(`SELECT value FROM _kdf_meta WHERE key = 'kdf_salt'`).Scan(&saltB64)
	switch {
	case err == nil:
		salt, err := base64.StdEncoding.DecodeString(saltB64)
		if err != nil || len(salt) < 16 {
			return nil, fmt.Errorf("corrupt kdf salt in database")
		}
		return salt, nil

	case err == sql.ErrNoRows:
		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, fmt.Errorf("generate kdf salt: %w", err)
		}
		saltB64 := base64.StdEncoding.EncodeToString(salt)
		if _, err := d.conn.Exec(`INSERT INTO _kdf_meta (key, value) VALUES ('kdf_salt', ?)`, saltB64); err != nil {
			return nil, fmt.Errorf("persist kdf salt: %w", err)
		}
		return salt, nil

	default:
		return nil, fmt.Errorf("read kdf salt: %w", err)
	}
}

// reencryptLegacyColumns migrates at-rest ciphertext written before the KDF
// upgrade (bare sha256 key, no "v2." prefix) to the v2 format, so databases
// converge to a single ciphertext generation instead of staying mixed
// forever. Runs once at OpenWithEncryption when a master key is configured.
//
// Rows that fail to decrypt (plaintext rows from databases that previously
// ran without a master key, or tampered values) are skipped in place: the
// regular read path keeps applying the same semantics it always had.
func (d *DB) reencryptLegacyColumns() {
	if d.enc == nil || d.enc.gcmV2 == nil {
		return
	}

	specs := []struct {
		table, pk, col string
	}{
		{"server_secrets", "key", "value"},
		{"credentials", "id", "password"},
		{"credentials", "id", "notes"},
	}

	reencrypted := 0
	for _, s := range specs {
		d.mu.Lock()
		rows, err := d.conn.Query(`SELECT ` + s.pk + `, ` + s.col + ` FROM ` + s.table + ` WHERE ` + s.col + ` IS NOT NULL AND ` + s.col + ` != '' AND ` + s.col + ` NOT LIKE 'v2.%'`)
		if err != nil {
			d.mu.Unlock()
			log.Printf("[DB] reencrypt scan %s.%s: %v", s.table, s.col, err)
			continue
		}

		type pending struct{ pk, plain string }
		var batch []pending
		for rows.Next() {
			var pk, val string
			if err := rows.Scan(&pk, &val); err != nil {
				continue
			}
			plain, err := d.enc.DecryptString(val)
			if err != nil {
				// Not ours (plaintext or foreign ciphertext): leave as-is.
				continue
			}
			batch = append(batch, pending{pk: pk, plain: plain})
		}
		rows.Close()

		for _, item := range batch {
			ct, err := d.enc.EncryptString(item.plain)
			if err != nil {
				log.Printf("[DB] reencrypt %s.%s/%s: %v", s.table, s.col, item.pk, err)
				continue
			}
			if _, err := d.conn.Exec(`UPDATE `+s.table+` SET `+s.col+`=? WHERE `+s.pk+`=?`, ct, item.pk); err != nil {
				log.Printf("[DB] reencrypt update %s.%s/%s: %v", s.table, s.col, item.pk, err)
				continue
			}
			reencrypted++
		}
		d.mu.Unlock()
	}

	if reencrypted > 0 {
		log.Printf("[DB] re-encrypted %d legacy column value(s) to v2 format", reencrypted)
	}
}
