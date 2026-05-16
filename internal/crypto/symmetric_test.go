package crypto

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestEncryptDecryptWithKeyRoundTrip(t *testing.T) {
	key := make([]byte, Argon2idKeyLen)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("hello, world! this is a secret message.")

	ciphertext, err := EncryptWithKey(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptWithKey() error = %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	if len(ciphertext) <= 24 {
		t.Fatal("ciphertext too short to contain nonce")
	}

	decrypted, err := DecryptWithKey(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptWithKey() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptWithKeyWrongKey(t *testing.T) {
	key := make([]byte, Argon2idKeyLen)
	for i := range key {
		key[i] = byte(i)
	}
	wrongKey := make([]byte, Argon2idKeyLen)
	for i := range wrongKey {
		wrongKey[i] = byte(i + 1)
	}

	plaintext := []byte("secret message")
	ciphertext, err := EncryptWithKey(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptWithKey() error = %v", err)
	}

	_, err = DecryptWithKey(ciphertext, wrongKey)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestEncryptDecryptWithKeyWrongSize(t *testing.T) {
	plaintext := []byte("test")
	shortKey := make([]byte, 16)

	_, err := EncryptWithKey(plaintext, shortKey)
	if err == nil {
		t.Fatal("expected error for short key")
	}

	_, err = DecryptWithKey([]byte("ciphertext"), shortKey)
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestEncryptDecryptWithKeyEmpty(t *testing.T) {
	key := make([]byte, Argon2idKeyLen)

	_, err := EncryptWithKey([]byte{}, key)
	if !errors.Is(err, ErrEmptyPlaintext) {
		t.Fatalf("expected ErrEmptyPlaintext, got: %v", err)
	}

	_, err = DecryptWithKey([]byte{}, key)
	if !errors.Is(err, ErrEmptyCiphertext) {
		t.Fatalf("expected ErrEmptyCiphertext, got: %v", err)
	}
}

func TestArgon2idRecipientIdentityRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		plaintext  []byte
	}{
		{"simple", "correct horse battery staple", []byte("secret data")},
		{"empty data", "passphrase", []byte("a")},
		{"binary data", "p@$$w0rd!", []byte{0x00, 0x01, 0xFF, 0xFE}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recipient := NewArgon2idRecipient(tt.passphrase, Argon2idParams{})
			identity := NewArgon2idIdentity(tt.passphrase)

			var buf bytes.Buffer
			w, err := age.Encrypt(&buf, recipient)
			if err != nil {
				t.Fatalf("age.Encrypt() error = %v", err)
			}
			if _, err := w.Write(tt.plaintext); err != nil {
				t.Fatalf("write plaintext: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("close encryptor: %v", err)
			}

			ciphertext := buf.Bytes()

			if !strings.Contains(string(ciphertext), "-> argon2id") {
				t.Fatal("ciphertext does not contain argon2id stanza")
			}

			r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
			if err != nil {
				t.Fatalf("age.Decrypt() error = %v", err)
			}

			decrypted := new(bytes.Buffer)
			if _, err := decrypted.ReadFrom(r); err != nil {
				t.Fatalf("read decrypted: %v", err)
			}

			if !bytes.Equal(decrypted.Bytes(), tt.plaintext) {
				t.Fatalf("decrypted mismatch: got %q, want %q", decrypted.Bytes(), tt.plaintext)
			}
		})
	}
}

func TestArgon2idRecipientWrongPassword(t *testing.T) {
	recipient := NewArgon2idRecipient("correct passphrase", Argon2idParams{})
	wrongIdentity := NewArgon2idIdentity("wrong passphrase")

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		t.Fatalf("age.Encrypt() error = %v", err)
	}
	if _, err := w.Write([]byte("secret")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = age.Decrypt(bytes.NewReader(buf.Bytes()), wrongIdentity)
	if err == nil {
		t.Fatal("expected error decrypting with wrong passphrase")
	}
}

func TestArgon2idRecipientCustomParams(t *testing.T) {
	customParams := Argon2idParams{Time: 2, Memory: 128, Threads: 1}
	passphrase := "custom params test"

	recipient := NewArgon2idRecipient(passphrase, customParams)
	identity := NewArgon2idIdentity(passphrase)

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		t.Fatalf("age.Encrypt() error = %v", err)
	}
	if _, err := w.Write([]byte("test data with custom params")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	r, err := age.Decrypt(bytes.NewReader(buf.Bytes()), identity)
	if err != nil {
		t.Fatalf("age.Decrypt() with custom params error = %v", err)
	}
	plaintext, err := ioReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(plaintext) != "test data with custom params" {
		t.Fatalf("got %q, want %q", string(plaintext), "test data with custom params")
	}
}

func TestEncryptWithPassphraseArgon2idRoundTrip(t *testing.T) {
	plaintext := []byte("secret message encrypted with argon2id passphrase")
	passphrase := []byte("my super secret passphrase")

	ciphertext, err := EncryptWithPassphraseArgon2id(plaintext, passphrase, Argon2idParams{})
	if err != nil {
		t.Fatalf("EncryptWithPassphraseArgon2id() error = %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	if !bytes.Contains(ciphertext, []byte("-> argon2id")) {
		t.Fatal("ciphertext does not contain argon2id stanza")
	}

	decrypted, err := DecryptWithPassphraseArgon2id(ciphertext, []byte("my super secret passphrase"))
	if err != nil {
		t.Fatalf("DecryptWithPassphraseArgon2id() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptWithPassphraseArgon2idWrongPassword(t *testing.T) {
	plaintext := []byte("secret")
	ciphertext, err := EncryptWithPassphraseArgon2id(plaintext, []byte("correct passphrase"), Argon2idParams{})
	if err != nil {
		t.Fatalf("EncryptWithPassphraseArgon2id() error = %v", err)
	}

	_, err = DecryptWithPassphraseArgon2id(ciphertext, []byte("wrong passphrase"))
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestEncryptWithPassphraseArgon2idEmptyInputs(t *testing.T) {
	_, err := EncryptWithPassphraseArgon2id([]byte{}, []byte("pass"), Argon2idParams{})
	if !errors.Is(err, ErrEmptyPlaintext) {
		t.Fatalf("expected ErrEmptyPlaintext, got: %v", err)
	}

	_, err = EncryptWithPassphraseArgon2id([]byte("text"), []byte(""), Argon2idParams{})
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestDecryptWithPassphraseArgon2idEmptyInputs(t *testing.T) {
	_, err := DecryptWithPassphraseArgon2id([]byte{}, []byte("pass"))
	if !errors.Is(err, ErrEmptyCiphertext) {
		t.Fatalf("expected ErrEmptyCiphertext, got: %v", err)
	}

	_, err = DecryptWithPassphraseArgon2id([]byte("data"), []byte(""))
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestArgon2idIdentityRejectsWrongStanzaType(t *testing.T) {
	// Create a stanza that is NOT argon2id type
	identity := NewArgon2idIdentity("passphrase")
	_, err := identity.Unwrap([]*age.Stanza{
		{Type: "scrypt", Args: []string{"salt"}, Body: []byte("body")},
	})
	if err == nil {
		t.Fatal("expected error for non-argon2id stanza")
	}
}

func TestSaveLoadIdentityWithArgon2id(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error = %v", err)
	}

	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "identity.age"
	passphrase := []byte("test passphrase for argon2id identity")

	if err = SaveIdentityWithArgon2id(identity, path, passphrase, Argon2idParams{}); err != nil {
		t.Fatalf("SaveIdentityWithArgon2id() error = %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved identity: %v", err)
	}
	if strings.Contains(string(raw), identity.String()) {
		t.Fatal("saved file contains plaintext private key")
	}
	if !strings.Contains(string(raw), "-> argon2id") {
		t.Fatal("saved file does not contain argon2id stanza")
	}

	loaded, err := LoadIdentityWithArgon2id(path, []byte("test passphrase for argon2id identity"))
	if err != nil {
		t.Fatalf("LoadIdentityWithArgon2id() error = %v", err)
	}
	if loaded.String() != identity.String() {
		t.Fatalf("loaded identity mismatch: got %q, want %q", loaded.String(), identity.String())
	}
}

func TestSaveLoadIdentityWithArgon2idWrongPassphrase(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error = %v", err)
	}

	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "identity.age"

	if err = SaveIdentityWithArgon2id(identity, path, []byte("correct passphrase"), Argon2idParams{}); err != nil {
		t.Fatalf("SaveIdentityWithArgon2id() error = %v", err)
	}

	_, err = LoadIdentityWithArgon2id(path, []byte("wrong passphrase"))
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestDetectEncryptedIdentityFormat(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{"argon2id", "-> argon2id t=1,m=64,p=1\n", "argon2id"},
		{"scrypt", "-> scrypt AAAA\n", "scrypt"},
		{"unknown", "-> unknown type\n", ""},
		{"empty", "", ""},
		{"random data", "some random data\n", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectEncryptedIdentityFormat([]byte(tt.data))
			if got != tt.expected {
				t.Errorf("DetectEncryptedIdentityFormat() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestParseArgon2idParams(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Argon2idParams
		wantErr bool
	}{
		{"full params", "t=3,m=65536,p=4", Argon2idParams{Time: 3, Memory: 65536, Threads: 4}, false},
		{"minimal", "t=1,m=64,p=1", Argon2idParams{Time: 1, Memory: 64, Threads: 1}, false},
		{"large values", "t=10,m=1048576,p=8", Argon2idParams{Time: 10, Memory: 1048576, Threads: 8}, false},
		{"incomplete missing threads", "t=3,m=65536", Argon2idParams{}, true},
		{"invalid format no equals", "t3", Argon2idParams{}, true},
		{"non-numeric value", "t=abc,m=64,p=1", Argon2idParams{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseArgon2idParams(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Time != tt.want.Time || got.Memory != tt.want.Memory || got.Threads != tt.want.Threads {
				t.Errorf("parseArgon2idParams(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLargeDataEncryptionWithArgon2id(t *testing.T) {
	passphrase := "test passphrase"
	recipient := NewArgon2idRecipient(passphrase, Argon2idParams{})
	identity := NewArgon2idIdentity(passphrase)

	// 1 MB of data
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		t.Fatalf("age.Encrypt() error = %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	r, err := age.Decrypt(bytes.NewReader(buf.Bytes()), identity)
	if err != nil {
		t.Fatalf("age.Decrypt() error = %v", err)
	}
	decrypted, err := ioReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("large data roundtrip mismatch")
	}
}

// Helper that matches io.ReadAll signature for Go <1.26 compatibility.
func ioReadAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
