package db

import (
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptorEncryptDecrypt(t *testing.T) {
	key := []byte("test-master-key-for-encryption")
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	plaintext := []byte("sensitive data: password123")
	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypt() returned empty string")
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypt() = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestEncryptorEncryptDecryptString(t *testing.T) {
	key := []byte("another-test-key")
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	plaintext := "my-secret-password"
	encrypted, err := enc.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}
	if encrypted == "" {
		t.Fatal("EncryptString() returned empty string")
	}

	decrypted, err := enc.DecryptString(encrypted)
	if err != nil {
		t.Fatalf("DecryptString() error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("DecryptString() = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptorDifferentKeys(t *testing.T) {
	key1 := []byte("key-one")
	key2 := []byte("key-two")

	enc1, _ := NewEncryptor(key1)
	enc2, _ := NewEncryptor(key2)

	plaintext := "secret data"
	encrypted, _ := enc1.EncryptString(plaintext)

	// Decrypting with wrong key should fail
	_, err := enc2.DecryptString(encrypted)
	if err == nil {
		t.Error("DecryptString() with wrong key should fail")
	}
}

func TestEncryptorEmptyKey(t *testing.T) {
	_, err := NewEncryptor([]byte{})
	if err == nil {
		t.Error("NewEncryptor() with empty key should fail")
	}
}

func TestEncryptorDeterministicDecryption(t *testing.T) {
	key := []byte("test-key")
	enc, _ := NewEncryptor(key)

	plaintext := "same data"
	enc1, _ := enc.EncryptString(plaintext)
	enc2, _ := enc.EncryptString(plaintext)

	// Each encryption should produce different ciphertext (random nonce)
	if enc1 == enc2 {
		t.Error("EncryptString() produced same ciphertext for same plaintext (nonce not random)")
	}

	// But both should decrypt to the same plaintext
	dec1, _ := enc.DecryptString(enc1)
	dec2, _ := enc.DecryptString(enc2)

	if dec1 != dec2 || dec1 != plaintext {
		t.Errorf("Decryption mismatch: %q, %q, want %q", dec1, dec2, plaintext)
	}
}

func TestEncryptorV2RoundtripAndLegacyCompat(t *testing.T) {
	master := []byte("operator-master-key-2026")
	salt := make([]byte, 32)
	rand.Read(salt)

	v2, err := NewEncryptorV2(master, salt)
	if err != nil {
		t.Fatalf("NewEncryptorV2: %v", err)
	}

	// v2 ciphertext carries the version prefix and roundtrips.
	ct, err := v2.EncryptString("cred-password")
	if err != nil {
		t.Fatalf("v2 encrypt: %v", err)
	}
	if !strings.HasPrefix(ct, v2Prefix) {
		t.Fatalf("v2 ciphertext must carry %q prefix, got %.4s...", v2Prefix, ct)
	}
	if pt, err := v2.DecryptString(ct); err != nil || pt != "cred-password" {
		t.Fatalf("v2 roundtrip failed: pt=%q err=%v", pt, err)
	}

	// Legacy ciphertext (written by an older server) still decrypts through
	// the v2 encryptor.
	legacy, _ := NewEncryptor(master)
	oldCT, _ := legacy.EncryptString("old-stored-password")
	if strings.HasPrefix(oldCT, v2Prefix) {
		t.Fatal("legacy ciphertext must not carry the v2 prefix")
	}
	if pt, err := v2.DecryptString(oldCT); err != nil || pt != "old-stored-password" {
		t.Fatalf("legacy compat failed: pt=%q err=%v", pt, err)
	}

	// A different master key cannot read the v2 ciphertext.
	otherSalt := append([]byte{}, salt...)
	other, _ := NewEncryptorV2([]byte("wrong-key"), otherSalt)
	if _, err := other.DecryptString(ct); err == nil {
		t.Fatal("v2 ciphertext must not decrypt with the wrong master key")
	}

	// A different salt (as if the DB row were swapped) also fails.
	otherSalt[0] ^= 0xFF
	other2, _ := NewEncryptorV2(master, otherSalt)
	if _, err := other2.DecryptString(ct); err == nil {
		t.Fatal("v2 ciphertext must not decrypt under a different salt")
	}

	// Legacy-only encryptor refuses v2 ciphertext with a clear error.
	if _, err := legacy.DecryptString(ct); err == nil {
		t.Fatal("legacy-only encryptor must refuse v2 ciphertext")
	}
}

func TestEnsureKDFSaltStableAcrossReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kdf.db")

	d1, err := Open(path)
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	salt1, err := d1.ensureKDFSalt()
	if err != nil {
		t.Fatalf("salt1: %v", err)
	}
	d1.Close()

	d2, err := Open(path)
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	defer d2.Close()
	salt2, err := d2.ensureKDFSalt()
	if err != nil {
		t.Fatalf("salt2: %v", err)
	}

	if string(salt1) != string(salt2) {
		t.Fatal("KDF salt must be stable across database reopens")
	}
	if len(salt1) != 32 {
		t.Fatalf("salt size = %d, want 32", len(salt1))
	}
}

func TestOpenWithEncryptionV2Format(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enc.db")
	master := []byte("WORLDC2_MASTER_KEY-value")

	d, err := OpenWithEncryption(path, master)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	// Stored credential data must land on disk in v2 format.
	if err := d.AddCredential(&CredentialRecord{
		ID: "cred-1", Username: "svc-backup", Password: "P@ss", Host: "dc01",
	}); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	var stored string
	if err := d.conn.QueryRow(`SELECT password FROM credentials WHERE id='cred-1'`).Scan(&stored); err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if !strings.HasPrefix(stored, v2Prefix) {
		t.Fatalf("at-rest ciphertext must be v2, got %.3s...", stored)
	}

	// ...and must decrypt back through the normal read path.
	creds, err := d.ListCredentials()
	if err != nil || len(creds) != 1 {
		t.Fatalf("list credentials: n=%d err=%v", len(creds), err)
	}
	if creds[0].Password != "P@ss" {
		t.Fatalf("roundtrip mismatch: %q", creds[0].Password)
	}

	// A legacy database (ciphertext written with the sha256 key) stays
	// readable through the new open path.
	legacy, _ := NewEncryptor(master)
	oldCT, _ := legacy.EncryptString("legacy-P@ss")
	d.conn.Exec(`UPDATE credentials SET password=? WHERE id='cred-1'`, oldCT)
	creds2, err := d.ListCredentials()
	if err != nil {
		t.Fatalf("legacy read through new handle: %v", err)
	}
	if creds2[0].Password != "legacy-P@ss" {
		t.Fatalf("legacy value mismatch: %q", creds2[0].Password)
	}
}
