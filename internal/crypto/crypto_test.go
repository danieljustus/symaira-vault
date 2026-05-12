package crypto

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	plaintext := []byte("s3cr3t payload")
	ciphertext, err := Encrypt(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytesEqual(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	got, err := Decrypt(ciphertext, identity)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytesEqual(got, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plaintext)
	}
}

func TestEncryptWithMultipleRecipients(t *testing.T) {
	identity1, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity 1: %v", err)
	}
	identity2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity 2: %v", err)
	}
	identity3, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity 3: %v", err)
	}

	plaintext := []byte("shared secret message")
	recipients := []*age.X25519Recipient{
		identity1.Recipient(),
		identity2.Recipient(),
		identity3.Recipient(),
	}

	ciphertext, err := EncryptWithRecipients(plaintext, recipients...)
	if err != nil {
		t.Fatalf("encrypt with recipients: %v", err)
	}

	tests := []struct {
		identity *age.X25519Identity
		name     string
	}{
		{name: "identity1", identity: identity1},
		{name: "identity2", identity: identity2},
		{name: "identity3", identity: identity3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decrypt(ciphertext, tt.identity)
			if err != nil {
				t.Fatalf("decrypt with %s: %v", tt.name, err)
			}
			if !bytesEqual(got, plaintext) {
				t.Fatalf("decrypt mismatch with %s: got %q want %q", tt.name, got, plaintext)
			}
		})
	}
}

func TestEncryptWithNoRecipients(t *testing.T) {
	plaintext := []byte("test data")
	_, err := EncryptWithRecipients(plaintext)
	if !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("expected ErrNoRecipients, got: %v", err)
	}
}

func TestEncryptWithNilRecipient(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	plaintext := []byte("test data")
	recipients := []*age.X25519Recipient{identity.Recipient(), nil}

	_, err = EncryptWithRecipients(plaintext, recipients...)
	if err == nil {
		t.Fatal("expected error for nil recipient")
	}
	if !strings.Contains(err.Error(), "index 1") {
		t.Fatalf("expected error to mention index 1, got: %v", err)
	}
}

func TestDecryptWithWrongIdentity(t *testing.T) {
	identity1, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity 1: %v", err)
	}
	identity2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity 2: %v", err)
	}

	plaintext := []byte("secret")
	ciphertext, err := Encrypt(plaintext, identity1.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = Decrypt(ciphertext, identity2)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong identity")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestEncryptDecryptEmptyPlaintext(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	_, err = Encrypt([]byte{}, identity.Recipient())
	if !errors.Is(err, ErrEmptyPlaintext) {
		t.Fatalf("expected ErrEmptyPlaintext, got: %v", err)
	}
}

func TestDecryptEmptyCiphertext(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	_, err = Decrypt([]byte{}, identity)
	if !errors.Is(err, ErrEmptyCiphertext) {
		t.Fatalf("expected ErrEmptyCiphertext, got: %v", err)
	}
}

func TestEncryptDecryptNilRecipient(t *testing.T) {
	_, err := Encrypt([]byte("test"), nil)
	if !errors.Is(err, ErrNilRecipient) {
		t.Fatalf("expected ErrNilRecipient, got: %v", err)
	}
}

func TestDecryptNilIdentity(t *testing.T) {
	_, err := Decrypt([]byte("test"), nil)
	if !errors.Is(err, ErrNilIdentity) {
		t.Fatalf("expected ErrNilIdentity, got: %v", err)
	}
}

func TestGenerateIdentityCreatesValidX25519Identity(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	if identity == nil {
		t.Fatal("identity is nil")
	}
	if !strings.HasPrefix(identity.String(), "AGE-SECRET-KEY-") {
		t.Fatalf("unexpected secret key format: %q", identity.String())
	}
	if got := identity.Recipient().String(); !strings.HasPrefix(got, "age1") {
		t.Fatalf("unexpected recipient format: %q", got)
	}
	parsed, err := age.ParseX25519Identity(identity.String())
	if err != nil {
		t.Fatalf("parse generated identity: %v", err)
	}
	if parsed.String() != identity.String() {
		t.Fatalf("parsed identity mismatch: got %q want %q", parsed.String(), identity.String())
	}
}

func TestGenerateIdentityString(t *testing.T) {
	identityStr, err := GenerateIdentityString()
	if err != nil {
		t.Fatalf("generate identity string: %v", err)
	}
	if !strings.HasPrefix(identityStr, "AGE-SECRET-KEY-") {
		t.Fatalf("unexpected format: %q", identityStr)
	}

	parsed, err := age.ParseX25519Identity(identityStr)
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	if parsed.String() != identityStr {
		t.Fatalf("parsed mismatch: got %q want %q", parsed.String(), identityStr)
	}
}

func TestSaveLoadIdentityWithPassphrase(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "identity.age"
	passphrase := []byte("correct horse battery staple")

	if err = SaveIdentity(identity, path, passphrase, 0); err != nil {
		t.Fatalf("save identity: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved identity: %v", err)
	}
	if strings.Contains(string(raw), identity.String()) {
		t.Fatal("saved file contains plaintext private key")
	}
	if strings.Contains(string(raw), "AGE-SECRET-KEY-") {
		t.Fatal("saved file contains secret key material in plaintext")
	}

	passphrase = []byte("correct horse battery staple")
	loaded, err := LoadIdentity(path, passphrase)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	if loaded.String() != identity.String() {
		t.Fatalf("loaded identity mismatch: got %q want %q", loaded.String(), identity.String())
	}
}

func TestSaveIdentityNilIdentity(t *testing.T) {
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "identity.age"

	err := SaveIdentity(nil, path, []byte("passphrase"), 0)
	if !errors.Is(err, ErrNilIdentity) {
		t.Fatalf("expected ErrNilIdentity, got: %v", err)
	}
}

func TestSaveIdentityEmptyPassphrase(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "identity.age"

	err = SaveIdentity(identity, path, []byte(""), 0)
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestLoadIdentityWrongPassphrase(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "identity.age"

	if err = SaveIdentity(identity, path, []byte("correct passphrase"), 0); err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}

	_, err = LoadIdentity(path, []byte("wrong passphrase"))
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestLoadIdentityEmptyPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "identity.age"

	_, err := LoadIdentity(path, []byte(""))
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestLoadIdentityNonExistentFile(t *testing.T) {
	_, err := LoadIdentity("/nonexistent/path/identity.age", []byte("passphrase"))
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestEncryptDecryptWithPassphrase(t *testing.T) {
	plaintext := []byte("secret message encrypted with passphrase")
	passphrase := []byte("my super secret passphrase")

	ciphertext, err := EncryptWithPassphrase(plaintext, passphrase, 0)
	if err != nil {
		t.Fatalf("encrypt with passphrase: %v", err)
	}

	if bytesEqual(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	passphrase = []byte("my super secret passphrase")
	decrypted, err := DecryptWithPassphrase(ciphertext, passphrase)
	if err != nil {
		t.Fatalf("decrypt with passphrase: %v", err)
	}

	if !bytesEqual(decrypted, plaintext) {
		t.Fatalf("decrypted mismatch: got %q want %q", decrypted, plaintext)
	}
}

func TestDecryptWithPassphraseWrongPassword(t *testing.T) {
	plaintext := []byte("secret message")
	passphrase := []byte("correct passphrase")
	wrongPassphrase := []byte("wrong passphrase")

	ciphertext, err := EncryptWithPassphrase(plaintext, passphrase, 0)
	if err != nil {
		t.Fatalf("encrypt with passphrase: %v", err)
	}

	_, err = DecryptWithPassphrase(ciphertext, wrongPassphrase)
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestEncryptWithPassphraseEmptyPlaintext(t *testing.T) {
	_, err := EncryptWithPassphrase([]byte{}, []byte("passphrase"), 0)
	if !errors.Is(err, ErrEmptyPlaintext) {
		t.Fatalf("expected ErrEmptyPlaintext, got: %v", err)
	}
}

func TestEncryptWithPassphraseEmptyPassphrase(t *testing.T) {
	_, err := EncryptWithPassphrase([]byte("test"), []byte(""), 0)
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestDecryptWithPassphraseEmptyCiphertext(t *testing.T) {
	_, err := DecryptWithPassphrase([]byte{}, []byte("passphrase"))
	if !errors.Is(err, ErrEmptyCiphertext) {
		t.Fatalf("expected ErrEmptyCiphertext, got: %v", err)
	}
}

func TestDecryptWithPassphraseEmptyPassphrase(t *testing.T) {
	_, err := DecryptWithPassphrase([]byte("encrypted"), []byte(""))
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestValidateRecipient(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	recipientStr := identity.Recipient().String()

	tests := []struct {
		name        string
		recipient   string
		expectError bool
	}{
		{"valid recipient", recipientStr, false},
		{"empty string", "", true},
		{"invalid prefix", "invalid1recipient", true},
		{"invalid bech32", "age1invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recipient, err := ValidateRecipient(tt.recipient)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error")
				}
				if !errors.Is(err, ErrInvalidKeyFormat) && err.Error() != "recipient string is empty" {
					t.Fatalf("expected ErrInvalidKeyFormat or empty error, got: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if recipient == nil {
					t.Fatal("recipient is nil")
				}
				if recipient.String() != tt.recipient {
					t.Fatalf("recipient mismatch: got %q want %q", recipient.String(), tt.recipient)
				}
			}
		})
	}
}

func TestValidateIdentity(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	identityStr := identity.String()

	tests := []struct {
		name        string
		identity    string
		expectError bool
	}{
		{"valid identity", identityStr, false},
		{"empty string", "", true},
		{"invalid prefix", "INVALID-SECRET-KEY-1xyz", true},
		{"invalid bech32", "AGE-SECRET-KEY-1invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ValidateIdentity(tt.identity)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error")
				}
				if !errors.Is(err, ErrInvalidKeyFormat) && err.Error() != "identity string is empty" {
					t.Fatalf("expected ErrInvalidKeyFormat or empty error, got: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if parsed == nil {
					t.Fatal("identity is nil")
				}
				if parsed.String() != tt.identity {
					t.Fatalf("identity mismatch: got %q want %q", parsed.String(), tt.identity)
				}
			}
		})
	}
}

func TestIsValidRecipient(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	if !IsValidRecipient(identity.Recipient().String()) {
		t.Fatal("expected valid recipient to return true")
	}
	if IsValidRecipient("invalid") {
		t.Fatal("expected invalid recipient to return false")
	}
	if IsValidRecipient("") {
		t.Fatal("expected empty string to return false")
	}
}

func TestIsValidIdentity(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	if !IsValidIdentity(identity.String()) {
		t.Fatal("expected valid identity to return true")
	}
	if IsValidIdentity("invalid") {
		t.Fatal("expected invalid identity to return false")
	}
	if IsValidIdentity("") {
		t.Fatal("expected empty string to return false")
	}
}

func TestRecipientsToStrings(t *testing.T) {
	identity1, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity 1: %v", err)
	}
	identity2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity 2: %v", err)
	}

	recipients := []*age.X25519Recipient{
		identity1.Recipient(),
		identity2.Recipient(),
		nil,
	}

	strs := RecipientsToStrings(recipients)
	if len(strs) != 3 {
		t.Fatalf("expected 3 strings, got %d", len(strs))
	}
	if strs[0] != identity1.Recipient().String() {
		t.Fatalf("recipient 1 mismatch")
	}
	if strs[1] != identity2.Recipient().String() {
		t.Fatalf("recipient 2 mismatch")
	}
	if strs[2] != "" {
		t.Fatalf("expected empty string for nil recipient")
	}
}

func TestParseRecipients(t *testing.T) {
	identity1, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity 1: %v", err)
	}
	identity2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity 2: %v", err)
	}

	validStrs := []string{
		identity1.Recipient().String(),
		identity2.Recipient().String(),
	}

	recipients, err := ParseRecipients(validStrs)
	if err != nil {
		t.Fatalf("parse valid recipients: %v", err)
	}
	if len(recipients) != 2 {
		t.Fatalf("expected 2 recipients, got %d", len(recipients))
	}

	_, err = ParseRecipients([]string{})
	if !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("expected ErrNoRecipients, got: %v", err)
	}

	_, err = ParseRecipients([]string{"invalid"})
	if err == nil {
		t.Fatal("expected error for invalid recipient")
	}
}

func TestIdentityExists(t *testing.T) {
	dir := t.TempDir()
	existingPath := dir + string(os.PathSeparator) + "existing.age"
	nonExistingPath := dir + string(os.PathSeparator) + "nonexisting.age"

	if err := os.WriteFile(existingPath, []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if !IdentityExists(existingPath) {
		t.Fatal("expected existing file to return true")
	}
	if IdentityExists(nonExistingPath) {
		t.Fatal("expected non-existing file to return false")
	}
}

func TestGetRecipientFromIdentity(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	recipient, err := GetRecipientFromIdentity(identity)
	if err != nil {
		t.Fatalf("get recipient: %v", err)
	}
	if recipient == nil {
		t.Fatal("recipient is nil")
	}
	if recipient.String() != identity.Recipient().String() {
		t.Fatalf("recipient mismatch")
	}

	_, err = GetRecipientFromIdentity(nil)
	if !errors.Is(err, ErrNilIdentity) {
		t.Fatalf("expected ErrNilIdentity, got: %v", err)
	}
}

func TestLargePlaintextEncryption(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	// Test with 1MB of data
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := Encrypt(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt large data: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, identity)
	if err != nil {
		t.Fatalf("decrypt large data: %v", err)
	}

	if !bytesEqual(decrypted, plaintext) {
		t.Fatal("large data roundtrip mismatch")
	}
}

func TestBinaryDataEncryption(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	// Test with binary data containing all byte values
	plaintext := make([]byte, 256)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	ciphertext, err := Encrypt(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt binary data: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, identity)
	if err != nil {
		t.Fatalf("decrypt binary data: %v", err)
	}

	if !bytesEqual(decrypted, plaintext) {
		t.Fatal("binary data roundtrip mismatch")
	}
}

func TestGenerateTOTP(t *testing.T) {
	code, err := GenerateTOTP("JBSWY3DPEHPK3PXP", "SHA1", 6, 30)
	if err != nil {
		t.Fatalf("GenerateTOTP() error = %v", err)
	}
	if code == nil {
		t.Fatal("GenerateTOTP() returned nil")
	}
	if len(code.Code) != 6 {
		t.Errorf("code length = %d, want 6", len(code.Code))
	}
	if code.Period != 30 {
		t.Errorf("Period = %d, want 30", code.Period)
	}
	if code.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
}

func TestGenerateTOTPDifferentAlgorithms(t *testing.T) {
	for _, algo := range []string{"SHA1", "SHA256", "SHA512"} {
		t.Run(algo, func(t *testing.T) {
			code, err := GenerateTOTP("JBSWY3DPEHPK3PXP", algo, 6, 30)
			if err != nil {
				t.Fatalf("GenerateTOTP(%s) error = %v", algo, err)
			}
			if len(code.Code) != 6 {
				t.Errorf("code length = %d, want 6", len(code.Code))
			}
		})
	}
}

func TestGenerateTOTPDifferentDigits(t *testing.T) {
	// 7 digits is not valid per RFC 6238 (only 6 and 8 are allowed)
	for _, digits := range []int{6, 8} {
		t.Run(fmt.Sprintf("%d digits", digits), func(t *testing.T) {
			code, err := GenerateTOTP("JBSWY3DPEHPK3PXP", "SHA1", digits, 30)
			if err != nil {
				t.Fatalf("GenerateTOTP(%d digits) error = %v", digits, err)
			}
			if len(code.Code) != digits {
				t.Errorf("code length = %d, want %d", len(code.Code), digits)
			}
		})
	}
}

func TestGenerateTOTPInvalidSecret(t *testing.T) {
	_, err := GenerateTOTP("invalid!@#$", "SHA1", 6, 30)
	if err == nil {
		t.Error("expected error for invalid secret")
	}
}

func TestPower10(t *testing.T) {
	tests := []struct {
		n     int
		value int
	}{
		{0, 1},
		{1, 10},
		{2, 100},
		{3, 1000},
		{6, 1000000},
		{10, 10000000000},
	}
	for _, tt := range tests {
		got := power10(tt.n)
		if got != tt.value {
			t.Errorf("power10(%d) = %d, want %d", tt.n, got, tt.value)
		}
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
