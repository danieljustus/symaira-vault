// Package crypto provides age-based encryption functionality for OpenPass.
// It supports encryption with X25519 recipients, passphrase-based encryption,
// and multi-recipient encryption for sharing vault entries.
package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"unsafe"

	"filippo.io/age"
)

// Common errors for crypto operations
var (
	ErrNilRecipient     = errors.New("recipient is nil")
	ErrNilIdentity      = errors.New("identity is nil")
	ErrNoRecipients     = errors.New("no recipients provided")
	ErrInvalidKeyFormat = errors.New("invalid key format")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrEmptyPlaintext   = errors.New("plaintext is empty")
	ErrEmptyCiphertext  = errors.New("ciphertext is empty")
)

// wipeSink is a package-level variable used to prevent the compiler from
// optimizing away the memory clearing in Wipe(). By storing a pointer to
// the buffer in a variable the compiler cannot prove is unused, we force
// the compiler to emit the zeroing stores.
//
// Use atomic.Uintptr to avoid data-race reports when Wipe is called from
// multiple goroutines (e.g. concurrent vault search).
var wipeSink atomic.Uintptr

// Encrypt encrypts plaintext for a single recipient.
// Returns the encrypted ciphertext or an error if encryption fails.
func Encrypt(plaintext []byte, recipient *age.X25519Recipient) ([]byte, error) {
	if recipient == nil {
		return nil, ErrNilRecipient
	}
	return EncryptWithRecipients(plaintext, recipient)
}

// EncryptWithRecipients encrypts plaintext for multiple recipients.
// All provided recipients will be able to decrypt the resulting ciphertext.
// Returns an error if no recipients are provided or if any recipient is nil.
func EncryptWithRecipients(plaintext []byte, recipients ...*age.X25519Recipient) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrEmptyPlaintext
	}

	if len(recipients) == 0 {
		return nil, ErrNoRecipients
	}

	// Convert X25519Recipient slice to age.Recipient interface slice
	ageRecipients := make([]age.Recipient, 0, len(recipients))
	for i, r := range recipients {
		if r == nil {
			return nil, fmt.Errorf("recipient at index %d is nil", i)
		}
		ageRecipients = append(ageRecipients, r)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, ageRecipients...)
	if err != nil {
		return nil, fmt.Errorf("create encryptor: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("write plaintext: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close encryptor: %w", err)
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts ciphertext using the provided identity.
// Returns the decrypted plaintext or an error if decryption fails.
func Decrypt(ciphertext []byte, identity *age.X25519Identity) ([]byte, error) {
	if identity == nil {
		return nil, ErrNilIdentity
	}

	if len(ciphertext) == 0 {
		return nil, ErrEmptyCiphertext
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read decrypted data: %w", err)
	}

	return plaintext, nil
}

// Wipe overwrites the contents of buf with zeros to prevent sensitive data
// from remaining in memory after use. Call with defer after allocating buffers
// that hold passphrases, identity bytes, or decrypted entry fields.
//
// Wipe uses unsafe.Pointer to force the compiler to emit the zeroing stores.
// The pointer is stored in a package-level sink variable that the compiler
// cannot prove is unused, preventing dead-store elimination.
//
// Note: This is a best-effort measure. Go's garbage collector may have
// copied the data, and the OS may have swapped it to disk. For stronger
// guarantees, consider github.com/awnumar/memguard.
func Wipe(buf []byte) {
	if len(buf) == 0 {
		return
	}
	// Force compiler to keep the buffer alive and emit stores.
	// unsafe.Pointer prevents the compiler from optimizing away the zeroing.
	// #nosec G103 — intentional use of unsafe for secure memory wiping; audited.
	ptr := unsafe.Pointer(&buf[0])
	for i := range buf {
		*(*byte)(unsafe.Add(ptr, i)) = 0
	}
	// Store pointer in sink to prevent dead-store elimination.
	// The compiler cannot prove wipeSink is never read.
	wipeSink.Store(uintptr(ptr))
	// Ensure buf is not optimized away before the loop completes.
	runtime.KeepAlive(buf)
}

// EncryptWithPassphrase encrypts plaintext using a passphrase.
// The passphrase is used to derive a scrypt-based recipient.
// This is useful for encrypting data that should be decryptable with a password.
// workFactor controls the scrypt KDF cost (N = 1<<workFactor). Pass 0 to use DefaultScryptWorkFactor.
func EncryptWithPassphrase(plaintext []byte, passphrase []byte, workFactor int) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrEmptyPlaintext
	}

	if len(passphrase) == 0 {
		return nil, errors.New("passphrase is empty")
	}

	recipient, err := age.NewScryptRecipient(string(passphrase))
	Wipe(passphrase)
	if err != nil {
		return nil, fmt.Errorf("create scrypt recipient: %w", err)
	}
	recipient.SetWorkFactor(resolveWorkFactor(workFactor))

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("create encryptor: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("write plaintext: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close encryptor: %w", err)
	}

	return buf.Bytes(), nil
}

// DecryptWithPassphrase decrypts ciphertext using a passphrase.
// The passphrase must match the one used during encryption.
func DecryptWithPassphrase(ciphertext []byte, passphrase []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, ErrEmptyCiphertext
	}

	if len(passphrase) == 0 {
		return nil, errors.New("passphrase is empty")
	}

	identity, err := age.NewScryptIdentity(string(passphrase))
	Wipe(passphrase)
	if err != nil {
		return nil, fmt.Errorf("create scrypt identity: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read decrypted data: %w", err)
	}

	return plaintext, nil
}

// ValidateRecipient validates that the given string is a valid age recipient.
// A valid recipient starts with "age1" and contains valid bech32 encoding.
func ValidateRecipient(recipientStr string) (*age.X25519Recipient, error) {
	if recipientStr == "" {
		return nil, errors.New("recipient string is empty")
	}

	if !strings.HasPrefix(recipientStr, "age1") {
		return nil, fmt.Errorf("%w: recipient must start with 'age1'", ErrInvalidKeyFormat)
	}

	recipient, err := age.ParseX25519Recipient(recipientStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKeyFormat, err)
	}

	return recipient, nil
}

// ValidateIdentity validates that the given string is a valid age identity.
// A valid identity starts with "AGE-SECRET-KEY-1" and contains valid bech32 encoding.
func ValidateIdentity(identityStr string) (*age.X25519Identity, error) {
	if identityStr == "" {
		return nil, errors.New("identity string is empty")
	}

	if !strings.HasPrefix(identityStr, "AGE-SECRET-KEY-") {
		return nil, fmt.Errorf("%w: identity must start with 'AGE-SECRET-KEY-'", ErrInvalidKeyFormat)
	}

	identity, err := age.ParseX25519Identity(identityStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKeyFormat, err)
	}

	return identity, nil
}

// IsValidRecipient checks if the given string is a valid age recipient without returning the parsed recipient.
func IsValidRecipient(recipientStr string) bool {
	_, err := ValidateRecipient(recipientStr)
	return err == nil
}

// IsValidIdentity checks if the given string is a valid age identity without returning the parsed identity.
func IsValidIdentity(identityStr string) bool {
	_, err := ValidateIdentity(identityStr)
	return err == nil
}

// RecipientsToStrings converts a slice of X25519Recipient to their string representations.
func RecipientsToStrings(recipients []*age.X25519Recipient) []string {
	strs := make([]string, len(recipients))
	for i, r := range recipients {
		if r != nil {
			strs[i] = r.String()
		}
	}
	return strs
}

// ParseRecipients parses a slice of recipient strings into X25519Recipient objects.
// Returns an error if any recipient string is invalid.
func ParseRecipients(recipientStrs []string) ([]*age.X25519Recipient, error) {
	if len(recipientStrs) == 0 {
		return nil, ErrNoRecipients
	}

	recipients := make([]*age.X25519Recipient, 0, len(recipientStrs))
	for i, rs := range recipientStrs {
		recipient, err := ValidateRecipient(rs)
		if err != nil {
			return nil, fmt.Errorf("recipient at index %d: %w", i, err)
		}
		recipients = append(recipients, recipient)
	}

	return recipients, nil
}
