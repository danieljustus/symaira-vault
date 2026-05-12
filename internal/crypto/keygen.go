package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/scrypt"

	"github.com/danieljustus/OpenPass/internal/fileutil"
	"github.com/danieljustus/OpenPass/internal/pathutil"
)

// DefaultScryptWorkFactor is the default scrypt work factor used when no explicit
// value is provided. Higher values increase KDF cost exponentially (N = 1<<workFactor).
const DefaultScryptWorkFactor = 18

// testScryptWorkFactor is an atomic override for tests. When non-zero, it is used
// as the default work factor instead of DefaultScryptWorkFactor. This avoids the
// test slowdown from full-cost scrypt KDF while keeping production paths unaffected.
var testScryptWorkFactor atomic.Int32

// SetTestScryptWorkFactor sets the scrypt work factor for tests. Returns a restore
// function that resets to the previous value. Only effective when workFactor <= 0
// is passed to scrypt-based functions.
func SetTestScryptWorkFactor(wf int) (restore func()) {
	prev := testScryptWorkFactor.Load()
	testScryptWorkFactor.Store(int32(wf))
	return func() { testScryptWorkFactor.Store(prev) }
}

// resolveWorkFactor returns the effective work factor: if wf > 0 it is used directly;
// otherwise the test override is checked, falling back to DefaultScryptWorkFactor.
func resolveWorkFactor(wf int) int {
	if wf > 0 {
		return wf
	}
	if twf := int(testScryptWorkFactor.Load()); twf > 0 {
		return twf
	}
	return DefaultScryptWorkFactor
}

// BenchmarkScryptWorkFactor measures scrypt KDF timing on the current hardware
// by trying progressively higher work factors until the key derivation exceeds
// the target duration.
func BenchmarkScryptWorkFactor(target time.Duration) (int, time.Duration, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return 0, 0, fmt.Errorf("generate salt: %w", err)
	}

	password := []byte("benchmark-password")

	for wf := 1; wf <= 22; wf++ {
		N := 1 << wf
		start := time.Now()
		_, err := scrypt.Key(password, salt, N, 1, 1, 32)
		elapsed := time.Since(start)
		if err != nil {
			return 0, 0, fmt.Errorf("scrypt key at work factor %d: %w", wf, err)
		}
		if elapsed >= target {
			return wf, elapsed, nil
		}
	}

	start := time.Now()
	_, err := scrypt.Key(password, salt, 1<<22, 1, 1, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("scrypt key at max work factor: %w", err)
	}
	return 22, time.Since(start), nil
}

// GenerateIdentity generates a new age X25519 identity.
// Returns the generated identity or an error if generation fails.
func GenerateIdentity() (*age.X25519Identity, error) {
	return age.GenerateX25519Identity()
}

// validateIdentityPath ensures the identity file path doesn't escape expected directories.
func validateIdentityPath(path string) error {
	if pathutil.HasTraversal(path) {
		return errors.New("identity file path escapes expected directory")
	}
	return nil
}

// GenerateIdentityString generates a new age identity and returns it as a string.
func GenerateIdentityString() (string, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	return identity.String(), nil
}

// SaveIdentity encrypts and saves an identity to a file using a passphrase.
// The identity is encrypted with scrypt before being written to disk.
// The file permissions are set to 0o600 (readable/writable by owner only).
// workFactor controls the scrypt KDF cost (N = 1<<workFactor). Pass 0 to use DefaultScryptWorkFactor.
func SaveIdentity(id *age.X25519Identity, path string, passphrase []byte, workFactor int) error {
	if id == nil {
		return ErrNilIdentity
	}

	if len(passphrase) == 0 {
		return errors.New("passphrase is empty")
	}

	if err := validateIdentityPath(path); err != nil {
		return err
	}

	recipient, err := age.NewScryptRecipient(string(passphrase))
	Wipe(passphrase)
	if err != nil {
		return fmt.Errorf("create scrypt recipient: %w", err)
	}
	recipient.SetWorkFactor(resolveWorkFactor(workFactor))

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return fmt.Errorf("create encryptor: %w", err)
	}

	if _, err := w.Write([]byte(id.String())); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("close encryptor: %w", err)
	}

	if err := fileutil.AtomicWriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// LoadIdentity loads and decrypts an identity from a file using a passphrase.
// Returns the decrypted identity or an error if loading/decryption fails.
func LoadIdentity(path string, passphrase []byte) (*age.X25519Identity, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase is empty")
	}

	if err := validateIdentityPath(path); err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(path) //#nosec G304 -- path validated by validateIdentityPath()
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	identity, err := age.NewScryptIdentity(string(passphrase))
	Wipe(passphrase)
	if err != nil {
		return nil, fmt.Errorf("create scrypt identity: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(raw), identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read decrypted data: %w", err)
	}
	defer Wipe(plaintext)

	parsed, err := age.ParseX25519Identity(strings.TrimSpace(string(plaintext)))
	if err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}

	return parsed, nil
}

// IdentityExists checks if an identity file exists at the given path.
func IdentityExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetRecipientFromIdentity extracts the public recipient from an identity.
func GetRecipientFromIdentity(identity *age.X25519Identity) (*age.X25519Recipient, error) {
	if identity == nil {
		return nil, ErrNilIdentity
	}
	return identity.Recipient(), nil
}
