package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"filippo.io/age"

	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const MaxFieldLength = 4096

func GetField(v *vaultpkg.Vault, path, field string) (any, error) {
	entry, err := vaultpkg.ReadEntry(v.Dir, path, v.Identity)
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

func SetField(v *vaultpkg.Vault, path, field string, value any) error {
	data := map[string]any{field: value}
	return setEntry(v, path, data, nil)
}

func SetFields(v *vaultpkg.Vault, path string, data map[string]any) error {
	return setEntry(v, path, data, nil)
}

func SetFieldsWithProvenance(v *vaultpkg.Vault, path string, data map[string]any, record vaultpkg.WriteRecord) error {
	return setEntry(v, path, data, &record)
}

func validateFieldLengths(data map[string]any) error {
	for k, v := range data {
		if s, ok := v.(string); ok && len(s) > MaxFieldLength {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("field %q exceeds maximum length of %d characters", k, MaxFieldLength), nil)
		}
		if m, ok := v.(map[string]any); ok {
			if err := validateFieldLengths(m); err != nil {
				return err
			}
		}
	}
	return nil
}

func setEntry(v *vaultpkg.Vault, path string, data map[string]any, provenance *vaultpkg.WriteRecord) error {
	if err := validateFieldLengths(data); err != nil {
		return err
	}
	existing, readErr := vaultpkg.ReadEntry(v.Dir, path, v.Identity)
	field := ""
	if len(data) == 1 {
		for k := range data {
			field = k
			break
		}
	}
	if provenance != nil {
		provenance.Field = field
	}
	switch {
	case readErr == nil && existing != nil:
		if provenance != nil {
			existing.PendingWrite = provenance
		} else {
			existing.PendingWrite = &vaultpkg.WriteRecord{Field: field, Action: "set"}
		}
		if _, err := vaultpkg.MergeEntryWithRecipients(v.Dir, path, data, v.Identity); err != nil {
			return errorspkg.WriteFailed(err, "cannot update entry %s: %v", path, err)
		}
	case errors.Is(readErr, os.ErrNotExist):
		action := "create"
		if provenance != nil && provenance.Action != "" {
			action = provenance.Action
		}
		entry := &vaultpkg.Entry{
			Data: data,
			Metadata: vaultpkg.EntryMetadata{
				Created: time.Now().UTC(),
				Updated: time.Now().UTC(),
				Version: 0,
			},
			PendingWrite: &vaultpkg.WriteRecord{Field: field, Action: action},
		}
		if pwd, ok := data["password"]; ok {
			if pwdStr, ok := pwd.(string); ok && pwdStr != "" {
				strength := cryptopkg.AssessPasswordStrength(pwdStr)
				if strength.Weak {
					entry.AddTag(vaultpkg.TagWeakPassword)
				}
			}
		}
		if err := vaultpkg.WriteEntryWithRecipients(v.Dir, path, entry, v.Identity); err != nil {
			return errorspkg.WriteFailed(err, "cannot create entry %s: %v", path, err)
		}
	default:
		return errorspkg.ReadFailed(readErr, "cannot read entry %s: %v", path, readErr)
	}

	if err := v.AutoCommit(fmt.Sprintf("Update %s", path)); err != nil {
		slog.Default().Warn("auto-commit failed", "error", err)
	}
	vaultpkg.InvalidateListCache(v.Dir)
	return nil
}

// DeleteEntry removes an entry from the vault.
func DeleteEntry(v *vaultpkg.Vault, path string) error {
	if err := vaultpkg.DeleteEntry(v.Dir, path, v.Identity); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errorspkg.NotFound("entry not found: %s", path)
		}
		return errorspkg.WriteFailed(err, "cannot delete entry %s: %v", path, err)
	}

	if err := v.AutoCommit(fmt.Sprintf("Delete %s", path)); err != nil {
		slog.Default().Warn("auto-commit failed", "error", err)
	}
	vaultpkg.InvalidateListCache(v.Dir)
	return nil
}

// ListEntries returns all entry paths, optionally filtered by prefix.
func ListEntries(v *vaultpkg.Vault, prefix string) ([]string, error) {
	entries, err := vaultpkg.List(v.Dir, prefix)
	if err != nil {
		return nil, errorspkg.ReadFailed(err, "cannot list entries: %v", err)
	}
	return entries, nil
}

// FindEntries searches for entries matching the given query.
func FindEntries(v *vaultpkg.Vault, query string, opts vaultpkg.FindOptions) ([]vaultpkg.Match, error) {
	matches, err := vaultpkg.FindWithOptions(v.Dir, query, opts)
	if err != nil {
		return nil, errorspkg.ReadFailed(err, "search failed: %v", err)
	}
	return matches, nil
}

// GetEntry returns the full entry for the given path.
func GetEntry(v *vaultpkg.Vault, path string) (*vaultpkg.Entry, error) {
	entry, err := vaultpkg.ReadEntry(v.Dir, path, v.Identity)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errorspkg.NotFound("entry not found: %s", path)
		}
		return nil, errorspkg.ReadFailed(err, "cannot read entry %s: %v", path, err)
	}
	return entry, nil
}

// WriteEntry writes a complete entry to the vault.
func WriteEntry(v *vaultpkg.Vault, path string, entry *vaultpkg.Entry) error {
	if err := vaultpkg.WriteEntryWithRecipients(v.Dir, path, entry, v.Identity); err != nil {
		return errorspkg.WriteFailed(err, "cannot write entry %s: %v", path, err)
	}

	if err := v.AutoCommit(fmt.Sprintf("Update %s", path)); err != nil {
		slog.Default().Warn("auto-commit failed", "error", err)
	}
	vaultpkg.InvalidateListCache(v.Dir)
	return nil
}

// VaultDir returns the vault directory path.
func VaultDir(v *vaultpkg.Vault) string {
	return v.Dir
}

// VaultIdentity returns the vault's identity for encryption/decryption operations.
func VaultIdentity(v *vaultpkg.Vault) *age.X25519Identity {
	return v.Identity
}
