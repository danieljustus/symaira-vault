package secrets

import (
	"testing"

	"filippo.io/age"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func newTestVault(t *testing.T) *vaultpkg.Vault {
	t.Helper()

	vaultDir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return &vaultpkg.Vault{Dir: vaultDir, Identity: id}
}

func writeTestEntry(t *testing.T, vault *vaultpkg.Vault, path string, data map[string]any) {
	t.Helper()
	if err := vaultpkg.WriteEntry(vault.Dir, path, &vaultpkg.Entry{Data: data}, vault.Identity); err != nil {
		t.Fatalf("write entry %q: %v", path, err)
	}
}

func TestResolveSecretRef(t *testing.T) {
	vault := newTestVault(t)
	writeTestEntry(t, vault, "work/aws", map[string]any{
		"username": "alice",
		"password": "secret123",
		"profile":  map[string]any{"email": "alice@example.com"},
	})
	writeTestEntry(t, vault, "github.com", map[string]any{
		"token": "ghp_token_value",
	})

	tests := []struct {
		name    string
		ref     string
		want    string
		wantErr bool
	}{
		{
			name:    "path.field syntax with existing entry and field",
			ref:     "work/aws.password",
			want:    "secret123",
			wantErr: false,
		},
		{
			name:    "bare path returns full entry data",
			ref:     "work/aws",
			want:    "map[password:secret123 profile:map[email:alice@example.com] username:alice]",
			wantErr: false,
		},
		{
			name:    "missing entry returns error",
			ref:     "nonexistent.password",
			want:    "",
			wantErr: true,
		},
		{
			name:    "existing entry but missing field returns error",
			ref:     "work/aws.apikey",
			want:    "",
			wantErr: true,
		},
		{
			name:    "dot in path name treated as path, not field split (when field doesn't match)",
			ref:     "github.com",
			want:    "map[token:ghp_token_value]",
			wantErr: false,
		},
		{
			name:    "path with dot where candidate field exists resolves correctly",
			ref:     "github.com.token",
			want:    "ghp_token_value",
			wantErr: false,
		},
		{
			name:    "empty ref",
			ref:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveSecretRef(vault, tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ResolveSecretRef() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveSecretRef() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ResolveSecretRef() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveSecretRef_NestedField(t *testing.T) {
	vault := newTestVault(t)
	writeTestEntry(t, vault, "github", map[string]any{
		"password": "s3cret",
	})

	got, err := ResolveSecretRef(vault, "github.password")
	if err != nil {
		t.Fatalf("ResolveSecretRef() unexpected error: %v", err)
	}
	if got != "s3cret" {
		t.Fatalf("ResolveSecretRef() = %q, want %q", got, "s3cret")
	}
}

func TestResolveSecretRef_ErrorKind(t *testing.T) {
	vault := newTestVault(t)
	writeTestEntry(t, vault, "github", map[string]any{"password": "s3cret"})

	_, err := ResolveSecretRef(vault, "github.apikey")
	if err == nil {
		t.Fatal("expected error for missing field, got nil")
	}
}
