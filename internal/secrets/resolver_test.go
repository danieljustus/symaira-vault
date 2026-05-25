package secrets

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
	vaultsvc "github.com/danieljustus/symaira-vault/internal/vaultsvc"
)

var testPassphrase = []byte("test-passphrase")

func newTestService(t *testing.T) vaultsvc.Service {
	t.Helper()

	vaultDir := t.TempDir()
	cfg := config.Default()

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, testPassphrase, cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	v, err := vaultpkg.OpenWithPassphrase(vaultDir, testPassphrase)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	return vaultsvc.New(slog.Default(), v)
}

func writeTestEntry(t *testing.T, svc vaultsvc.Service, path string, data map[string]any) {
	t.Helper()
	if err := svc.WriteEntry(path, &vaultpkg.Entry{Data: data}); err != nil {
		t.Fatalf("write entry %q: %v", path, err)
	}
}

func TestResolveSecretRef(t *testing.T) {
	svc := newTestService(t)
	writeTestEntry(t, svc, "work/aws", map[string]any{
		"username": "alice",
		"password": "secret123",
		"profile":  map[string]any{"email": "alice@example.com"},
	})
	writeTestEntry(t, svc, "github.com", map[string]any{
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
			got, err := ResolveSecretRef(svc, tt.ref)
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
	svc := newTestService(t)
	writeTestEntry(t, svc, "github", map[string]any{
		"password": "s3cret",
	})

	got, err := ResolveSecretRef(svc, "github.password")
	if err != nil {
		t.Fatalf("ResolveSecretRef() unexpected error: %v", err)
	}
	if got != "s3cret" {
		t.Fatalf("ResolveSecretRef() = %q, want %q", got, "s3cret")
	}
}

func TestResolveSecretRef_ErrorKind(t *testing.T) {
	svc := newTestService(t)
	writeTestEntry(t, svc, "github", map[string]any{"password": "s3cret"})

	_, err := ResolveSecretRef(svc, "github.apikey")
	if err == nil {
		t.Fatal("expected error for missing field, got nil")
	}

	var cliErr *errorspkg.CLIError
	if !errors.As(err, &cliErr) {
		t.Logf("error is not *errorspkg.CLIError: %v", err)
	}
}
