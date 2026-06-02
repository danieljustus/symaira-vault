package cli

import (
	"filippo.io/age"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var vaultOps vaultpkg.OperationService = vaultpkg.Ops

func GetField(v *vaultpkg.Vault, path, field string) (any, error) {
	return vaultOps.GetField(v, path, field)
}

func SetField(v *vaultpkg.Vault, path, field string, value any) error {
	data := map[string]any{field: value}
	return vaultOps.UpsertEntry(v, path, data, "set", nil)
}

func SetFields(v *vaultpkg.Vault, path string, data map[string]any) error {
	return vaultOps.UpsertEntry(v, path, data, "set", nil)
}

func SetFieldsWithProvenance(v *vaultpkg.Vault, path string, data map[string]any, record vaultpkg.WriteRecord) error {
	return vaultOps.UpsertEntry(v, path, data, "set", &record)
}

func DeleteEntry(v *vaultpkg.Vault, path string) error {
	return vaultOps.DeleteEntry(v, path)
}

func ListEntries(v *vaultpkg.Vault, prefix string) ([]string, error) {
	return vaultOps.ListEntries(v, prefix)
}

func FindEntries(v *vaultpkg.Vault, query string, opts vaultpkg.FindOptions) ([]vaultpkg.Match, error) {
	return vaultOps.FindEntries(v, query, opts)
}

func GetEntry(v *vaultpkg.Vault, path string) (*vaultpkg.Entry, error) {
	return vaultOps.GetEntry(v, path)
}

func WriteEntry(v *vaultpkg.Vault, path string, entry *vaultpkg.Entry) error {
	return vaultOps.WriteEntry(v, path, entry)
}

func VaultDir(v *vaultpkg.Vault) string {
	return vaultOps.VaultDir(v)
}

func VaultIdentity(v *vaultpkg.Vault) *age.X25519Identity {
	return vaultOps.VaultIdentity(v)
}
