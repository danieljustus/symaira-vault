// Package vaultsvc provides a high-level service layer for vault operations.
package vaultsvc

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"filippo.io/age"

	cryptopkg "github.com/danieljustus/OpenPass/internal/crypto"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

// Service defines the high-level vault operations interface.
// Encapsulates the full lifecycle: vault-open → decrypt → operation → encrypt → auto-commit.
type Service interface {
	Vault() *vaultpkg.Vault
	GetField(path, field string) (any, error)
	SetField(path, field string, value any) error
	SetFields(path string, data map[string]any) error
	Delete(path string) error
	List(prefix string) ([]string, error)
	Find(query string, opts vaultpkg.FindOptions) ([]vaultpkg.Match, error)
	GetEntry(path string) (*vaultpkg.Entry, error)
	WriteEntry(path string, entry *vaultpkg.Entry) error
	GetIdentity() *age.X25519Identity
	GetDir() string
}

// vaultService is the concrete implementation of Service.
type vaultService struct {
	vault  *vaultpkg.Vault
	logger *slog.Logger
}

// New creates a new vault service for the given vault.
func New(logger *slog.Logger, v *vaultpkg.Vault) Service {
	return &vaultService{vault: v, logger: logger}
}

// Vault returns the underlying vault instance.
func (s *vaultService) Vault() *vaultpkg.Vault {
	return s.vault
}

// GetField reads an entry and returns the value of the specified field.
// If field is empty, returns the full entry data map.
// Supports path.field syntax for nested field access.
func (s *vaultService) GetField(path, field string) (any, error) {
	entry, err := vaultpkg.ReadEntry(s.vault.Dir, path, s.vault.Identity)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errorspkg.NotFound("entry not found: %s", path)
		}
		return nil, errorspkg.ReadFailed(err, "cannot read entry %s: %v", path, err)
	}

	if field == "" {
		return entry.Data, nil
	}

	value, ok := entry.Data[field]
	if !ok {
		return nil, errorspkg.Wrap(errorspkg.ExitNotFound, errorspkg.ErrFieldNotFound, errorspkg.ErrEntryNotFound, "field not found: %s.%s", path, field)
	}

	return value, nil
}

// SetField sets a single field on an entry, creating the entry if it doesn't exist.
// Uses multi-recipient encryption if recipients are configured.
func (s *vaultService) SetField(path, field string, value any) error {
	data := map[string]any{field: value}
	return s.setEntry(path, data)
}

// SetFields sets multiple fields on an entry, creating the entry if it doesn't exist.
func (s *vaultService) SetFields(path string, data map[string]any) error {
	return s.setEntry(path, data)
}

// setEntry is the internal upsert implementation shared by SetField and SetFields.
func (s *vaultService) setEntry(path string, data map[string]any) error {
	existing, readErr := vaultpkg.ReadEntry(s.vault.Dir, path, s.vault.Identity)
	switch {
	case readErr == nil && existing != nil:
		// Entry exists — merge new data into it
		if _, err := vaultpkg.MergeEntryWithRecipients(s.vault.Dir, path, data, s.vault.Identity); err != nil {
			return errorspkg.WriteFailed(err, "cannot update entry %s: %v", path, err)
		}
	case errors.Is(readErr, os.ErrNotExist):
		// New entry
		entry := &vaultpkg.Entry{
			Data: data,
			Metadata: vaultpkg.EntryMetadata{
				Created: time.Now().UTC(),
				Updated: time.Now().UTC(),
				Version: 0,
			},
		}
		if pwd, ok := data["password"]; ok {
			if pwdStr, ok := pwd.(string); ok && pwdStr != "" {
				strength := cryptopkg.AssessPasswordStrength(pwdStr)
				if strength.Weak {
					entry.AddTag(vaultpkg.TagWeakPassword)
				}
			}
		}
		if err := vaultpkg.WriteEntryWithRecipients(s.vault.Dir, path, entry, s.vault.Identity); err != nil {
			return errorspkg.WriteFailed(err, "cannot create entry %s: %v", path, err)
		}
	default:
		return errorspkg.ReadFailed(readErr, "cannot read entry %s: %v", path, readErr)
	}

	// Auto-commit failure is a warning, not an error.
	if err := s.vault.AutoCommit(fmt.Sprintf("Update %s", path)); err != nil {
		s.warnAutoCommit(err)
	}
	vaultpkg.InvalidateListCache(s.vault.Dir)
	return nil
}

// Delete removes an entry from the vault.
func (s *vaultService) Delete(path string) error {
	if err := vaultpkg.DeleteEntry(s.vault.Dir, path, s.vault.Identity); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errorspkg.NotFound("entry not found: %s", path)
		}
		return errorspkg.WriteFailed(err, "cannot delete entry %s: %v", path, err)
	}

	// Auto-commit failure is a warning, not an error.
	if err := s.vault.AutoCommit(fmt.Sprintf("Delete %s", path)); err != nil {
		s.warnAutoCommit(err)
	}
	vaultpkg.InvalidateListCache(s.vault.Dir)
	return nil
}

// List returns all entry paths, optionally filtered by prefix.
func (s *vaultService) List(prefix string) ([]string, error) {
	entries, err := vaultpkg.List(s.vault.Dir, prefix)
	if err != nil {
		return nil, errorspkg.ReadFailed(err, "cannot list entries: %v", err)
	}
	return entries, nil
}

// Find searches for entries matching the given query.
func (s *vaultService) Find(query string, opts vaultpkg.FindOptions) ([]vaultpkg.Match, error) {
	matches, err := vaultpkg.FindWithOptions(s.vault.Dir, query, opts)
	if err != nil {
		return nil, errorspkg.ReadFailed(err, "search failed: %v", err)
	}

	return matches, nil
}

// GetEntry returns the full entry for the given path.
func (s *vaultService) GetEntry(path string) (*vaultpkg.Entry, error) {
	entry, err := vaultpkg.ReadEntry(s.vault.Dir, path, s.vault.Identity)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errorspkg.NotFound("entry not found: %s", path)
		}
		return nil, errorspkg.ReadFailed(err, "cannot read entry %s: %v", path, err)
	}
	return entry, nil
}

// WriteEntry writes a complete entry to the vault.
func (s *vaultService) WriteEntry(path string, entry *vaultpkg.Entry) error {
	if err := vaultpkg.WriteEntryWithRecipients(s.vault.Dir, path, entry, s.vault.Identity); err != nil {
		return errorspkg.WriteFailed(err, "cannot write entry %s: %v", path, err)
	}

	// Auto-commit failure is a warning, not an error.
	if err := s.vault.AutoCommit(fmt.Sprintf("Update %s", path)); err != nil {
		s.warnAutoCommit(err)
	}
	vaultpkg.InvalidateListCache(s.vault.Dir)
	return nil
}

// warnAutoCommit logs an auto-commit warning.
func (s *vaultService) warnAutoCommit(err error) {
	s.logger.Warn("auto-commit failed", "error", err)
}

// GetIdentity returns the vault's identity for encryption/decryption operations.
func (s *vaultService) GetIdentity() *age.X25519Identity {
	return s.vault.Identity
}

// GetDir returns the vault directory path.
func (s *vaultService) GetDir() string {
	return s.vault.Dir
}
