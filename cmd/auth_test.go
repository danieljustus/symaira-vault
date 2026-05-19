package cmd

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	auth "github.com/danieljustus/OpenPass/cmd/auth"
	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/session"
)

type cmdMockBiometricStore struct {
	available bool
}

func (c cmdMockBiometricStore) IsAvailable() bool { return c.available }
func (c cmdMockBiometricStore) Save(context.Context, string, []byte) error {
	return nil
}
func (c cmdMockBiometricStore) Load(context.Context, string) ([]byte, error) {
	return nil, session.ErrBiometricNotConfigured
}
func (c cmdMockBiometricStore) Delete(string) error { return nil }

func TestAuthSetPassphraseUpdatesConfig(t *testing.T) {
	vaultDir, _ := initVault(t)
	defer setupVaultFlag(t, vaultDir)()

	oldStore := session.DefaultBiometricPassphraseStore()
	session.SetBiometricPassphraseStore(cmdMockBiometricStore{})
	t.Cleanup(func() { session.SetBiometricPassphraseStore(oldStore) })

	cfg, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := cfg.SetAuthMethod(configpkg.AuthMethodTouchID); err != nil {
		t.Fatalf("SetAuthMethod() error = %v", err)
	}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("SaveTo() error = %v", err)
	}

	output := captureStdout(func() {
		if err := auth.AuthSetCmd.RunE(auth.AuthSetCmd, []string{"passphrase"}); err != nil {
			t.Fatalf("auth set passphrase error = %v", err)
		}
	})
	if !strings.Contains(output, "passphrase") {
		t.Fatalf("output = %q, want passphrase", output)
	}

	loaded, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("Load() after auth set error = %v", err)
	}
	if got := loaded.EffectiveAuthMethod(); got != configpkg.AuthMethodPassphrase {
		t.Fatalf("auth method = %q, want passphrase", got)
	}
}

func TestAuthStatusJSON(t *testing.T) {
	vaultDir, _ := initVault(t)
	defer setupVaultFlag(t, vaultDir)()

	oldJSON := auth.AuthStatusJSON
	auth.AuthStatusJSON = true
	t.Cleanup(func() { auth.AuthStatusJSON = oldJSON })

	output := captureStdout(func() {
		if err := auth.AuthStatusCmd.RunE(auth.AuthStatusCmd, nil); err != nil {
			t.Fatalf("auth status error = %v", err)
		}
	})
	if !strings.Contains(output, `"method"`) {
		t.Fatalf("output = %q, want JSON status", output)
	}
}
