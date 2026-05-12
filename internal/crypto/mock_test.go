package crypto

import (
	"bytes"
	"errors"
	"testing"

	"filippo.io/age"
)

// MockCrypto provides a mock implementation of crypto operations for testing
type MockCrypto struct {
	EncryptFunc               func([]byte, *age.X25519Recipient) ([]byte, error)
	EncryptWithRecipientsFunc func([]byte, ...*age.X25519Recipient) ([]byte, error)
	DecryptFunc               func([]byte, *age.X25519Identity) ([]byte, error)
	EncryptWithPassphraseFunc func([]byte, []byte, int) ([]byte, error)
	DecryptWithPassphraseFunc func([]byte, []byte) ([]byte, error)
}

// NewMockCrypto creates a new MockCrypto with sensible defaults
func NewMockCrypto() *MockCrypto {
	return &MockCrypto{
		EncryptFunc: func(plaintext []byte, recipient *age.X25519Recipient) ([]byte, error) {
			return []byte("encrypted:" + string(plaintext)), nil
		},
		EncryptWithRecipientsFunc: func(plaintext []byte, recipients ...*age.X25519Recipient) ([]byte, error) {
			return []byte("encrypted:" + string(plaintext)), nil
		},
		DecryptFunc: func(ciphertext []byte, identity *age.X25519Identity) ([]byte, error) {
			if bytes.HasPrefix(ciphertext, []byte("encrypted:")) {
				return bytes.TrimPrefix(ciphertext, []byte("encrypted:")), nil
			}
			return nil, ErrDecryptionFailed
		},
		EncryptWithPassphraseFunc: func(plaintext []byte, passphrase []byte, _ int) ([]byte, error) {
			return []byte("passphrase_encrypted:" + string(plaintext)), nil
		},
		DecryptWithPassphraseFunc: func(ciphertext []byte, passphrase []byte) ([]byte, error) {
			if bytes.HasPrefix(ciphertext, []byte("passphrase_encrypted:")) {
				return bytes.TrimPrefix(ciphertext, []byte("passphrase_encrypted:")), nil
			}
			return nil, ErrDecryptionFailed
		},
	}
}

func (m *MockCrypto) Encrypt(plaintext []byte, recipient *age.X25519Recipient) ([]byte, error) {
	return m.EncryptFunc(plaintext, recipient)
}

func (m *MockCrypto) EncryptWithRecipients(plaintext []byte, recipients ...*age.X25519Recipient) ([]byte, error) {
	return m.EncryptWithRecipientsFunc(plaintext, recipients...)
}

func (m *MockCrypto) Decrypt(ciphertext []byte, identity *age.X25519Identity) ([]byte, error) {
	return m.DecryptFunc(ciphertext, identity)
}

func (m *MockCrypto) EncryptWithPassphrase(plaintext []byte, passphrase []byte, workFactor int) ([]byte, error) {
	return m.EncryptWithPassphraseFunc(plaintext, passphrase, workFactor)
}

func (m *MockCrypto) DecryptWithPassphrase(ciphertext []byte, passphrase []byte) ([]byte, error) {
	return m.DecryptWithPassphraseFunc(ciphertext, passphrase)
}

func TestMockCryptoEncryptDecrypt(t *testing.T) {
	mock := NewMockCrypto()
	identity, _ := age.GenerateX25519Identity()

	plaintext := []byte("test data")
	ciphertext, err := mock.Encrypt(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := mock.Decrypt(ciphertext, identity)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestMockCryptoEncryptWithRecipients(t *testing.T) {
	mock := NewMockCrypto()
	identity1, _ := age.GenerateX25519Identity()
	identity2, _ := age.GenerateX25519Identity()

	plaintext := []byte("test data")
	recipients := []*age.X25519Recipient{
		identity1.Recipient(),
		identity2.Recipient(),
	}

	ciphertext, err := mock.EncryptWithRecipients(plaintext, recipients...)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := mock.Decrypt(ciphertext, identity1)
	if err != nil {
		t.Fatalf("decrypt with identity1: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted mismatch with identity1")
	}

	decrypted, err = mock.Decrypt(ciphertext, identity2)
	if err != nil {
		t.Fatalf("decrypt with identity2: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted mismatch with identity2")
	}
}

func TestMockCryptoDecryptFailure(t *testing.T) {
	mock := NewMockCrypto()
	identity, _ := age.GenerateX25519Identity()

	// Try to decrypt invalid ciphertext
	_, err := mock.Decrypt([]byte("invalid ciphertext"), identity)
	if err == nil {
		t.Error("expected error for invalid ciphertext")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestMockCryptoEncryptWithPassphrase(t *testing.T) {
	mock := NewMockCrypto()

	plaintext := []byte("secret data")
	passphrase := []byte("my passphrase")

	ciphertext, err := mock.EncryptWithPassphrase(plaintext, passphrase, 0)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := mock.DecryptWithPassphrase(ciphertext, passphrase)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestMockCryptoDecryptWithPassphraseFailure(t *testing.T) {
	mock := NewMockCrypto()

	// Try to decrypt invalid ciphertext
	_, err := mock.DecryptWithPassphrase([]byte("invalid"), []byte("passphrase"))
	if err == nil {
		t.Error("expected error for invalid ciphertext")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestMockCryptoCustomBehavior(t *testing.T) {
	mock := NewMockCrypto()
	identity, _ := age.GenerateX25519Identity()

	// Override default behavior
	customErr := errors.New("custom error")
	mock.EncryptFunc = func([]byte, *age.X25519Recipient) ([]byte, error) {
		return nil, customErr
	}

	_, err := mock.Encrypt([]byte("test"), identity.Recipient())
	if !errors.Is(err, customErr) {
		t.Errorf("expected custom error, got %v", err)
	}
}

func TestMockCryptoNilRecipient(t *testing.T) {
	mock := NewMockCrypto()

	// Override to handle nil recipient
	mock.EncryptFunc = func(plaintext []byte, recipient *age.X25519Recipient) ([]byte, error) {
		if recipient == nil {
			return nil, ErrNilRecipient
		}
		return []byte("encrypted:" + string(plaintext)), nil
	}

	_, err := mock.Encrypt([]byte("test"), nil)
	if !errors.Is(err, ErrNilRecipient) {
		t.Errorf("expected ErrNilRecipient, got %v", err)
	}
}

func TestMockCryptoNilIdentity(t *testing.T) {
	mock := NewMockCrypto()

	// Override to handle nil identity
	mock.DecryptFunc = func(ciphertext []byte, identity *age.X25519Identity) ([]byte, error) {
		if identity == nil {
			return nil, ErrNilIdentity
		}
		return bytes.TrimPrefix(ciphertext, []byte("encrypted:")), nil
	}

	_, err := mock.Decrypt([]byte("encrypted:test"), nil)
	if !errors.Is(err, ErrNilIdentity) {
		t.Errorf("expected ErrNilIdentity, got %v", err)
	}
}

func TestMockCryptoEmptyPlaintext(t *testing.T) {
	mock := NewMockCrypto()
	identity, _ := age.GenerateX25519Identity()

	// Override to check empty plaintext
	mock.EncryptFunc = func(plaintext []byte, recipient *age.X25519Recipient) ([]byte, error) {
		if len(plaintext) == 0 {
			return nil, ErrEmptyPlaintext
		}
		return []byte("encrypted:" + string(plaintext)), nil
	}

	_, err := mock.Encrypt([]byte{}, identity.Recipient())
	if !errors.Is(err, ErrEmptyPlaintext) {
		t.Errorf("expected ErrEmptyPlaintext, got %v", err)
	}
}

func TestMockCryptoEmptyCiphertext(t *testing.T) {
	mock := NewMockCrypto()
	identity, _ := age.GenerateX25519Identity()

	// Override to check empty ciphertext
	mock.DecryptFunc = func(ciphertext []byte, identity *age.X25519Identity) ([]byte, error) {
		if len(ciphertext) == 0 {
			return nil, ErrEmptyCiphertext
		}
		return bytes.TrimPrefix(ciphertext, []byte("encrypted:")), nil
	}

	_, err := mock.Decrypt([]byte{}, identity)
	if !errors.Is(err, ErrEmptyCiphertext) {
		t.Errorf("expected ErrEmptyCiphertext, got %v", err)
	}
}

// TestRealCryptoWithMockFallback tests that real crypto works but we can mock it
func TestRealCryptoVsMock(t *testing.T) {
	// Test with real crypto
	identity, _ := age.GenerateX25519Identity()
	plaintext := []byte("test data")

	// Real encryption
	realCiphertext, err := Encrypt(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("real encrypt: %v", err)
	}

	realDecrypted, err := Decrypt(realCiphertext, identity)
	if err != nil {
		t.Fatalf("real decrypt: %v", err)
	}

	if !bytes.Equal(realDecrypted, plaintext) {
		t.Error("real crypto roundtrip failed")
	}

	// Test with mock
	mock := NewMockCrypto()
	mockCiphertext, err := mock.Encrypt(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("mock encrypt: %v", err)
	}

	mockDecrypted, err := mock.Decrypt(mockCiphertext, identity)
	if err != nil {
		t.Fatalf("mock decrypt: %v", err)
	}

	if !bytes.Equal(mockDecrypted, plaintext) {
		t.Error("mock crypto roundtrip failed")
	}

	// The ciphertexts should be different
	if bytes.Equal(realCiphertext, mockCiphertext) {
		t.Error("real and mock ciphertexts should differ")
	}
}
