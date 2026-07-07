package db

import (
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
