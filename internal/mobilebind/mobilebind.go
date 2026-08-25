// Package mobilebind exposes a minimal, gomobile-compatible API surface for
// mobile clients (iOS/Android).
//
// gomobile bind restricts the types that can cross the FFI boundary:
// - Supported: string, []byte, bool, int, int64, float64, error
// - Unsupported: map[string]any, any, [][]byte, complex structs
//
// All structured payloads (e.g. vault entries, lists) use JSON encoding
// across the bridge per ADR 0006 D2.
package mobilebind

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

// GenerateIdentity generates a new age X25519 identity and returns its secret key string.
func GenerateIdentity() (string, error) {
	id, err := vaultcrypto.GenerateIdentity()
	if err != nil {
		return "", fmt.Errorf("generate identity: %w", err)
	}
	return id.String(), nil
}

// IdentityPublicKey derives the public recipient string (age1...) from a secret identity string.
func IdentityPublicKey(identityStr string) (string, error) {
	id, err := vaultcrypto.ValidateIdentity(strings.TrimSpace(identityStr))
	if err != nil {
		return "", fmt.Errorf("validate identity: %w", err)
	}
	return id.Recipient().String(), nil
}

// PublicKeyFingerprint computes a human-verifiable fingerprint for an age public key string.
func PublicKeyFingerprint(pubkey string) string {
	return vaultcrypto.PublicKeyFingerprint(pubkey)
}

// EncryptWithPublicKey encrypts plaintext using an age recipient public key string.
func EncryptWithPublicKey(recipientStr string, plaintext []byte) ([]byte, error) {
	recipient, err := vaultcrypto.ValidateRecipient(strings.TrimSpace(recipientStr))
	if err != nil {
		return nil, fmt.Errorf("validate recipient: %w", err)
	}
	return vaultcrypto.Encrypt(plaintext, recipient)
}

// DecryptWithIdentity decrypts ciphertext using an age secret identity string.
func DecryptWithIdentity(identityStr string, ciphertext []byte) ([]byte, error) {
	id, err := vaultcrypto.ValidateIdentity(strings.TrimSpace(identityStr))
	if err != nil {
		return nil, fmt.Errorf("validate identity: %w", err)
	}
	return vaultcrypto.Decrypt(ciphertext, id)
}

// EncryptWithPassphrase encrypts plaintext using a passphrase (via age scrypt/argon2id).
func EncryptWithPassphrase(passphrase string, plaintext []byte) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase is empty")
	}
	return vaultcrypto.EncryptWithPassphrase(plaintext, []byte(passphrase), 0)
}

// DecryptWithPassphrase decrypts ciphertext using a passphrase.
func DecryptWithPassphrase(passphrase string, ciphertext []byte) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase is empty")
	}
	return vaultcrypto.DecryptWithPassphrase(ciphertext, []byte(passphrase))
}

// InitVault initializes a new vault structure at vaultDir encrypted with passphrase.
func InitVault(vaultDir string, passphrase string) error {
	if vaultDir == "" {
		return errors.New("vaultDir is empty")
	}
	if passphrase == "" {
		return errors.New("passphrase is empty")
	}
	cfg := &vaultconfig.Config{
		Vault: &vaultconfig.VaultConfig{
			FormatVersion: 2,
		},
	}
	_, err := vault.InitWithPassphrase(vaultDir, []byte(passphrase), cfg)
	return err
}

// OpenVaultWithPassphrase unlocks vaultDir and returns the decrypted master identity string.
func OpenVaultWithPassphrase(vaultDir string, passphrase string) (string, error) {
	if vaultDir == "" {
		return "", errors.New("vaultDir is empty")
	}
	if passphrase == "" {
		return "", errors.New("passphrase is empty")
	}
	v, err := vault.OpenWithPassphrase(vaultDir, []byte(passphrase))
	if err != nil {
		return "", err
	}
	if v.Identity == nil {
		return "", errors.New("vault identity is nil")
	}
	return v.Identity.String(), nil
}

// EntryDataBridge is the JSON-serializable representation of a vault entry.
type EntryDataBridge struct {
	Path        string            `json:"path"`
	Data        map[string]any    `json:"data"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Version     int               `json:"version"`
	UpdatedAt   string            `json:"updated_at,omitempty"`
	UpdatedBy   string            `json:"updated_by,omitempty"`
}

// ReadEntryJSON reads and decrypts an entry from vaultDir, returning it as a JSON string.
func ReadEntryJSON(vaultDir string, entryPath string, identityStr string) (string, error) {
	id, err := vaultcrypto.ValidateIdentity(strings.TrimSpace(identityStr))
	if err != nil {
		return "", fmt.Errorf("validate identity: %w", err)
	}
	v, err := vault.Open(vaultDir, id)
	if err != nil {
		return "", fmt.Errorf("open vault: %w", err)
	}
	entry, err := v.ReadEntry(entryPath)
	if err != nil {
		return "", fmt.Errorf("read entry: %w", err)
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return "", fmt.Errorf("marshal entry: %w", err)
	}
	return string(data), nil
}

// WriteEntryJSON parses entryJSON and writes it encrypted into vaultDir.
func WriteEntryJSON(vaultDir string, entryPath string, entryJSON string, identityStr string) error {
	id, err := vaultcrypto.ValidateIdentity(strings.TrimSpace(identityStr))
	if err != nil {
		return fmt.Errorf("validate identity: %w", err)
	}
	var entry vault.Entry
	if err := json.Unmarshal([]byte(entryJSON), &entry); err != nil {
		return fmt.Errorf("unmarshal entry: %w", err)
	}
	return vault.WriteEntry(vaultDir, entryPath, &entry, id)
}

// ListEntriesJSON lists all entry paths in vaultDir matching prefix, returned as a JSON array of strings.
func ListEntriesJSON(vaultDir string, prefix string, identityStr string) (string, error) {
	id, err := vaultcrypto.ValidateIdentity(strings.TrimSpace(identityStr))
	if err != nil {
		return "", fmt.Errorf("validate identity: %w", err)
	}
	entries, err := vault.List(vaultDir, prefix, id)
	if err != nil {
		return "", fmt.Errorf("list entries: %w", err)
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return "", fmt.Errorf("marshal list: %w", err)
	}
	return string(data), nil
}

// VerifyManifestIntegrity checks the integrity of manifest.age in vaultDir.
func VerifyManifestIntegrity(vaultDir string, identityStr string) (bool, error) {
	id, err := vaultcrypto.ValidateIdentity(strings.TrimSpace(identityStr))
	if err != nil {
		return false, fmt.Errorf("validate identity: %w", err)
	}
	manifestPath := filepath.Join(vaultDir, "manifest.age")
	if _, err := os.Stat(manifestPath); err != nil {
		return false, fmt.Errorf("manifest not found: %w", err)
	}
	res, err := vault.VerifyManifestIntegrity(vaultDir, id)
	if err != nil {
		return false, fmt.Errorf("verify manifest: %w", err)
	}
	return len(res.Tampered) == 0 && len(res.Missing) == 0, nil
}
