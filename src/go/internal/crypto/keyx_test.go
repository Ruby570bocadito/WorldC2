package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if len(kp.PublicKey) != KeySize {
		t.Errorf("PublicKey size = %d, want %d", len(kp.PublicKey), KeySize)
	}
	if len(kp.PrivateKey) != KeySize {
		t.Errorf("PrivateKey size = %d, want %d", len(kp.PrivateKey), KeySize)
	}
}

func TestKeyPairFromPrivate(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, err := KeyPairFromPrivate(kp1.PrivateKey[:])
	if err != nil {
		t.Fatalf("KeyPairFromPrivate() error = %v", err)
	}
	if !bytes.Equal(kp1.PublicKey[:], kp2.PublicKey[:]) {
		t.Error("Public keys don't match")
	}
}

func TestDeriveSharedSecret(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	shared1, err := DeriveSharedSecret(&kp1.PrivateKey, &kp2.PublicKey)
	if err != nil {
		t.Fatalf("DeriveSharedSecret() error = %v", err)
	}

	shared2, err := DeriveSharedSecret(&kp2.PrivateKey, &kp1.PublicKey)
	if err != nil {
		t.Fatalf("DeriveSharedSecret() error = %v", err)
	}

	if !bytes.Equal(shared1, shared2) {
		t.Error("Shared secrets don't match")
	}
}

func TestDeriveSessionKeys(t *testing.T) {
	shared := make([]byte, 32)
	salt := make([]byte, 32)

	encKey, hmacKey, token, err := DeriveSessionKeys(shared, salt)
	if err != nil {
		t.Fatalf("DeriveSessionKeys() error = %v", err)
	}

	if len(encKey) != SessionKeySize {
		t.Errorf("encKey size = %d, want %d", len(encKey), SessionKeySize)
	}
	if len(hmacKey) != 32 {
		t.Errorf("hmacKey size = %d, want 32", len(hmacKey))
	}
	if len(token) != TokenSize {
		t.Errorf("token size = %d, want %d", len(token), TokenSize)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("Hello, WORLDC2 C2!")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := []byte("wrongkeywrongkeywrongkeywrongkey")

	plaintext := []byte("secret message")
	ciphertext, _ := Encrypt(key1, plaintext)

	_, err := Decrypt(key2, ciphertext)
	if err == nil {
		t.Error("Decrypt() should fail with wrong key")
	}
}

func TestSessionToken(t *testing.T) {
	hmacKey := make([]byte, 32)

	token := GenerateSessionToken(hmacKey, 1)
	if len(token) != TokenSize {
		t.Errorf("Token size = %d, want %d", len(token), TokenSize)
	}

	if !VerifySessionToken(hmacKey, token, 1) {
		t.Error("VerifySessionToken() should return true for valid token")
	}

	if VerifySessionToken(hmacKey, token, 2) {
		t.Error("VerifySessionToken() should return false for wrong counter")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}
	if len(salt1) != 32 {
		t.Errorf("Salt size = %d, want 32", len(salt1))
	}

	salt2, _ := GenerateSalt()
	if bytes.Equal(salt1, salt2) {
		t.Error("Salts should be unique")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, 32)
	plaintext := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(key, plaintext)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, 32)
	plaintext := make([]byte, 1024)
	ciphertext, _ := Encrypt(key, plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(key, ciphertext)
	}
}
