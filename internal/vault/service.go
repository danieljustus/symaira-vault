package vault

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"filippo.io/age"

	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
)

const MaxFieldLength = 4096

type ListEntryInfo struct {
	Path       string `json:"path"`
	Type       string `json:"type,omitempty"`
	UsageHint  string `json:"usage_hint,omitempty"`
	AutoRotate bool   `json:"auto_rotate,omitempty"`
	HasValue   bool   `json:"has_value,omitempty"`
	FieldCount int    `json:"field_count,omitempty"`
}

type OperationService interface {
	GetField(v *Vault, path, field string) (any, error)
	UpsertEntry(v *Vault, path string, data map[string]any, action string, provenance *WriteRecord) error
	GetEntry(v *Vault, path string) (*Entry, error)
	WriteEntry(v *Vault, path string, entry *Entry) error
	DeleteEntry(v *Vault, path string) error
	ListEntries(v *Vault, prefix string) ([]string, error)
	FindEntries(v *Vault, query string, opts FindOptions) ([]Match, error)
	VaultDir(v *Vault) string
	VaultIdentity(v *Vault) *age.X25519Identity
}

type DefaultOperationService struct{}

type VaultService struct {
	Vault *Vault
	Ops   OperationService
}

func NewVaultService(v *Vault, ops OperationService) *VaultService {
	if ops == nil {
		ops = DefaultOperationService{}
	}
	return &VaultService{Vault: v, Ops: ops}
}

func (s *VaultService) GetField(path, field string) (any, error) {
	return s.Ops.GetField(s.Vault, path, field)
}

func (s *VaultService) UpsertEntry(path string, data map[string]any, action string, provenance *WriteRecord) error {
	return s.Ops.UpsertEntry(s.Vault, path, data, action, provenance)
}

func (s *VaultService) GetEntry(path string) (*Entry, error) {
	return s.Ops.GetEntry(s.Vault, path)
}

func (s *VaultService) WriteEntry(path string, entry *Entry) error {
	return s.Ops.WriteEntry(s.Vault, path, entry)
}

func (s *VaultService) DeleteEntry(path string) error {
	return s.Ops.DeleteEntry(s.Vault, path)
}

func (s *VaultService) ListEntries(prefix string) ([]string, error) {
	return s.Ops.ListEntries(s.Vault, prefix)
}

func (s *VaultService) FindEntries(query string, opts FindOptions) ([]Match, error) {
	return s.Ops.FindEntries(s.Vault, query, opts)
}

func (s *VaultService) VaultDir() string {
	return s.Ops.VaultDir(s.Vault)
}

func (s *VaultService) VaultIdentity() *age.X25519Identity {
	return s.Ops.VaultIdentity(s.Vault)
}

func (DefaultOperationService) GetField(v *Vault, path, field string) (any, error) {
	entry, err := ReadEntry(v.Dir, path, v.Identity)
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

func ValidateFieldLengths(data map[string]any) error {
	for k, v := range data {
		if s, ok := v.(string); ok && len(s) > MaxFieldLength {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("field %q exceeds maximum length of %d characters", k, MaxFieldLength), nil)
		}
		if m, ok := v.(map[string]any); ok {
			if err := ValidateFieldLengths(m); err != nil {
				return err
			}
		}
	}
	return nil
}

func (DefaultOperationService) UpsertEntry(v *Vault, path string, data map[string]any, action string, provenance *WriteRecord) error {
	if err := ValidateFieldLengths(data); err != nil {
		return err
	}

	existing, readErr := ReadEntry(v.Dir, path, v.Identity)
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
			existing.PendingWrite = &WriteRecord{Field: field, Action: action}
		}
		if _, err := MergeEntryWithRecipients(v.Dir, path, data, v.Identity); err != nil {
			return errorspkg.WriteFailed(err, "cannot update entry %s: %v", path, err)
		}
	case errors.Is(readErr, os.ErrNotExist):
		createAction := "create"
		if provenance != nil && provenance.Action != "" {
			createAction = provenance.Action
		} else if action != "" {
			createAction = action
		}
		entry := &Entry{
			Data: data,
			Metadata: EntryMetadata{
				Created: time.Now().UTC(),
				Updated: time.Now().UTC(),
				Version: 0,
			},
			PendingWrite: &WriteRecord{Field: field, Action: createAction},
		}
		if pwd, ok := data["password"]; ok {
			if pwdStr, ok := pwd.(string); ok && pwdStr != "" {
				strength := cryptopkg.AssessPasswordStrength(pwdStr)
				if strength.Weak {
					entry.AddTag(TagWeakPassword)
				}
			}
		}
		if err := WriteEntryWithRecipients(v.Dir, path, entry, v.Identity); err != nil {
			return errorspkg.WriteFailed(err, "cannot create entry %s: %v", path, err)
		}
	default:
		return errorspkg.ReadFailed(readErr, "cannot read entry %s: %v", path, readErr)
	}

	if err := v.AutoCommit(fmt.Sprintf("Update %s", path)); err != nil {
		slog.Default().Warn("auto-commit failed", "error", err)
	}
	InvalidateListCache(v.Dir)
	return nil
}

func (DefaultOperationService) GetEntry(v *Vault, path string) (*Entry, error) {
	entry, err := ReadEntry(v.Dir, path, v.Identity)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errorspkg.NotFound("entry not found: %s", path)
		}
		return nil, errorspkg.ReadFailed(err, "cannot read entry %s: %v", path, err)
	}
	return entry, nil
}

func (DefaultOperationService) WriteEntry(v *Vault, path string, entry *Entry) error {
	if err := WriteEntryWithRecipients(v.Dir, path, entry, v.Identity); err != nil {
		return errorspkg.WriteFailed(err, "cannot write entry %s: %v", path, err)
	}

	if err := v.AutoCommit(fmt.Sprintf("Update %s", path)); err != nil {
		slog.Default().Warn("auto-commit failed", "error", err)
	}
	InvalidateListCache(v.Dir)
	return nil
}

func (DefaultOperationService) DeleteEntry(v *Vault, path string) error {
	if err := vaultDeleteHelper(v.Dir, path, v.Identity); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errorspkg.NotFound("entry not found: %s", path)
		}
		return errorspkg.WriteFailed(err, "cannot delete entry %s: %v", path, err)
	}

	if err := v.AutoCommit(fmt.Sprintf("Delete %s", path)); err != nil {
		slog.Default().Warn("auto-commit failed", "error", err)
	}
	InvalidateListCache(v.Dir)
	return nil
}

func (DefaultOperationService) ListEntries(v *Vault, prefix string) ([]string, error) {
	entries, err := List(v.Dir, prefix, v.Identity)
	if err != nil {
		return nil, errorspkg.ReadFailed(err, "cannot list entries: %v", err)
	}
	return entries, nil
}

func (DefaultOperationService) FindEntries(v *Vault, query string, opts FindOptions) ([]Match, error) {
	matches, err := FindWithOptions(v.Dir, query, opts, v.Identity)
	if err != nil {
		return nil, errorspkg.ReadFailed(err, "search failed: %v", err)
	}
	return matches, nil
}

func (DefaultOperationService) VaultDir(v *Vault) string {
	return v.Dir
}

func (DefaultOperationService) VaultIdentity(v *Vault) *age.X25519Identity {
	return v.Identity
}

func vaultDeleteHelper(vaultDir, path string, identity *age.X25519Identity) error {
	err := DeleteEntry(vaultDir, path, identity)
	if err != nil {
		if os.IsNotExist(err) {
			return os.ErrNotExist
		}
		return err
	}
	return nil
}
