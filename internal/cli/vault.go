package cli

import (
	"filippo.io/age"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

type VaultService struct {
	vaultService *vaultpkg.VaultService
}

func NewVaultService(v *vaultpkg.Vault, ops vaultpkg.OperationService) *VaultService {
	return &VaultService{vaultService: vaultpkg.NewVaultService(v, ops)}
}

func (s *VaultService) GetField(path, field string) (any, error) {
	return s.vaultService.GetField(path, field)
}

func (s *VaultService) SetField(path, field string, value any) error {
	data := map[string]any{field: value}
	return s.vaultService.UpsertEntry(path, data, "set", nil)
}

func (s *VaultService) SetFields(path string, data map[string]any) error {
	return s.vaultService.UpsertEntry(path, data, "set", nil)
}

func (s *VaultService) SetFieldsWithProvenance(path string, data map[string]any, record vaultpkg.WriteRecord) error {
	return s.vaultService.UpsertEntry(path, data, "set", &record)
}

func (s *VaultService) DeleteEntry(path string) error {
	return s.vaultService.DeleteEntry(path)
}

func (s *VaultService) ListEntries(prefix string) ([]string, error) {
	return s.vaultService.ListEntries(prefix)
}

func (s *VaultService) ListEntryInfos(prefix string, configuredWorkers int) ([]vaultpkg.ListEntryInfo, error) {
	return s.vaultService.ListEntryInfos(prefix, configuredWorkers)
}

func (s *VaultService) FindEntries(query string, opts vaultpkg.FindOptions) ([]vaultpkg.Match, error) {
	return s.vaultService.FindEntries(query, opts)
}

func (s *VaultService) GetEntry(path string) (*vaultpkg.Entry, error) {
	return s.vaultService.GetEntry(path)
}

func (s *VaultService) WriteEntry(path string, entry *vaultpkg.Entry) error {
	return s.vaultService.WriteEntry(path, entry)
}

func (s *VaultService) VaultDir() string {
	return s.vaultService.VaultDir()
}

func (s *VaultService) VaultIdentity() *age.X25519Identity {
	return s.vaultService.VaultIdentity()
}
