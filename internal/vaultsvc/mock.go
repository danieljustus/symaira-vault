package vaultsvc

import (
	"filippo.io/age"

	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

// MockService provides a mock implementation of the Service interface for testing.
// Follows the function-field mock pattern; set any Func field to customize behavior.
type MockService struct {
	VaultFunc                   func() *vaultpkg.Vault
	GetFieldFunc                func(path, field string) (any, error)
	SetFieldFunc                func(path, field string, value any) error
	SetFieldsFunc               func(path string, data map[string]any) error
	SetFieldsWithProvenanceFunc func(path string, data map[string]any, record vaultpkg.WriteRecord) error
	DeleteFunc                  func(path string) error
	ListFunc                    func(prefix string) ([]string, error)
	FindFunc                    func(query string, opts vaultpkg.FindOptions) ([]vaultpkg.Match, error)
	GetEntryFunc                func(path string) (*vaultpkg.Entry, error)
	WriteEntryFunc              func(path string, entry *vaultpkg.Entry) error
	GetIdentityFunc             func() *age.X25519Identity
	GetDirFunc                  func() string
}

// NewMockService creates a MockService with sensible no-op defaults.
func NewMockService() *MockService {
	return &MockService{
		VaultFunc: func() *vaultpkg.Vault {
			return &vaultpkg.Vault{}
		},
		GetFieldFunc: func(path, field string) (any, error) {
			return nil, nil
		},
		SetFieldFunc: func(path, field string, value any) error {
			return nil
		},
		SetFieldsFunc: func(path string, data map[string]any) error {
			return nil
		},
		SetFieldsWithProvenanceFunc: func(path string, data map[string]any, record vaultpkg.WriteRecord) error {
			return nil
		},
		DeleteFunc: func(path string) error {
			return nil
		},
		ListFunc: func(prefix string) ([]string, error) {
			return nil, nil
		},
		FindFunc: func(query string, opts vaultpkg.FindOptions) ([]vaultpkg.Match, error) {
			return nil, nil
		},
		GetEntryFunc: func(path string) (*vaultpkg.Entry, error) {
			return &vaultpkg.Entry{}, nil
		},
		WriteEntryFunc: func(path string, entry *vaultpkg.Entry) error {
			return nil
		},
		GetIdentityFunc: func() *age.X25519Identity {
			return nil
		},
		GetDirFunc: func() string {
			return "/mock/dir"
		},
	}
}

func (m *MockService) Vault() *vaultpkg.Vault {
	return m.VaultFunc()
}

func (m *MockService) GetField(path, field string) (any, error) {
	return m.GetFieldFunc(path, field)
}

func (m *MockService) SetField(path, field string, value any) error {
	return m.SetFieldFunc(path, field, value)
}

func (m *MockService) SetFields(path string, data map[string]any) error {
	return m.SetFieldsFunc(path, data)
}

func (m *MockService) SetFieldsWithProvenance(path string, data map[string]any, record vaultpkg.WriteRecord) error {
	return m.SetFieldsWithProvenanceFunc(path, data, record)
}

func (m *MockService) Delete(path string) error {
	return m.DeleteFunc(path)
}

func (m *MockService) List(prefix string) ([]string, error) {
	return m.ListFunc(prefix)
}

func (m *MockService) Find(query string, opts vaultpkg.FindOptions) ([]vaultpkg.Match, error) {
	return m.FindFunc(query, opts)
}

func (m *MockService) GetEntry(path string) (*vaultpkg.Entry, error) {
	return m.GetEntryFunc(path)
}

func (m *MockService) WriteEntry(path string, entry *vaultpkg.Entry) error {
	return m.WriteEntryFunc(path, entry)
}

func (m *MockService) GetIdentity() *age.X25519Identity {
	return m.GetIdentityFunc()
}

func (m *MockService) GetDir() string {
	return m.GetDirFunc()
}
