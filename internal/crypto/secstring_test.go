package crypto

import (
	"bytes"
	"testing"
)

func TestSecureStringCleansUp(t *testing.T) {
	data := []byte("super-secret-passphrase-12345")
	s, cleanup := SecureString(data)

	if s != "super-secret-passphrase-12345" {
		t.Fatalf("SecureString returned wrong value: got %q, want %q", s, "super-secret-passphrase-12345")
	}

	cleanup()

	for i, b := range data {
		if b != 0 {
			t.Fatalf("original data not zeroed at index %d: got byte %d", i, b)
		}
	}
}

func TestSecureStringScrypt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scrypt test in short mode")
	}

	passphrase := []byte("test-passphrase-for-scrypt-roundtrip")
	plaintext := []byte("hello, secure string world!")

	ct, err := EncryptWithPassphrase(plaintext, passphrase, 4)
	if err != nil {
		t.Fatalf("EncryptWithPassphrase failed: %v", err)
	}

	// Original passphrase was wiped — create a fresh copy for decryption.
	passphrase2 := []byte("test-passphrase-for-scrypt-roundtrip")
	pt, err := DecryptWithPassphrase(ct, passphrase2)
	if err != nil {
		t.Fatalf("DecryptWithPassphrase failed: %v", err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", string(pt), string(plaintext))
	}
}

func TestSecureStringEmpty(t *testing.T) {
	s, cleanup := SecureString(nil)
	if s != "" {
		t.Fatalf("expected empty string for nil input, got %q", s)
	}
	cleanup()

	s, cleanup = SecureString([]byte{})
	if s != "" {
		t.Fatalf("expected empty string for empty slice, got %q", s)
	}
	cleanup()
}
