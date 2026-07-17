package admin

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/config"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStderr := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = origStderr })
	fn()
	w.Close()
	os.Stderr = origStderr
	var buf strings.Builder
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Fatalf("copy stderr: %v", copyErr)
	}
	return buf.String()
}

func TestExport_ConfirmDecline_NoOutput(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "should-not-exist.csv")

	origConfirm := confirmExport
	confirmExport = func(_ string, _ bool) (bool, error) { return false, nil }
	t.Cleanup(func() { confirmExport = origConfirm })

	stderr := captureStderr(t, func() {
		cmd := cli.RootCmd
		cmd.SetArgs([]string{"export", "--format", "csv", "--output", outputPath})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("export: %v", err)
		}
	})

	if _, err := os.Stat(outputPath); err == nil {
		t.Error("output file should not exist after decline")
	}
	if !strings.Contains(stderr, "Export canceled.") {
		t.Errorf("stderr missing cancel message, got: %q", stderr)
	}
}

func TestExport_ConfirmAccept_WithEntries(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := "test-passphrase"
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, []byte(passphrase), config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	origVault := cli.Vault
	cli.Vault = vaultDir
	t.Cleanup(func() { cli.Vault = origVault })
	t.Setenv("SYMVAULT_PASSPHRASE", passphrase)

	v, err := cli.UnlockVault(vaultDir, true)
	if err != nil {
		t.Fatalf("unlock vault: %v", err)
	}
	vs := cli.NewVaultService(v, nil)
	if setErr := vs.SetFields("test/entry", map[string]any{"password": "secret123"}); setErr != nil {
		t.Fatalf("set entry: %v", setErr)
	}

	origConfirm := confirmExport
	confirmExport = func(_ string, _ bool) (bool, error) { return true, nil }
	t.Cleanup(func() { confirmExport = origConfirm })

	outputPath := filepath.Join(t.TempDir(), "export.csv")

	cmd := cli.RootCmd
	cmd.SetArgs([]string{"export", "--format", "csv", "--output", outputPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(data) == 0 {
		t.Error("export produced empty output")
	}
}

func TestExport_YesFlag_SkipsPrompt(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := "test-passphrase"
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, []byte(passphrase), config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	origVault := cli.Vault
	cli.Vault = vaultDir
	t.Cleanup(func() { cli.Vault = origVault })
	t.Setenv("SYMVAULT_PASSPHRASE", passphrase)

	v, err := cli.UnlockVault(vaultDir, true)
	if err != nil {
		t.Fatalf("unlock vault: %v", err)
	}
	vs := cli.NewVaultService(v, nil)
	if setErr := vs.SetFields("test/entry", map[string]any{"password": "secret123"}); setErr != nil {
		t.Fatalf("set entry: %v", setErr)
	}

	var capturedForce bool
	origConfirm := confirmExport
	confirmExport = func(_ string, force bool) (bool, error) {
		capturedForce = force
		return true, nil
	}
	t.Cleanup(func() { confirmExport = origConfirm })

	outputPath := filepath.Join(t.TempDir(), "export.json")

	cmd := cli.RootCmd
	cmd.SetArgs([]string{"export", "--format", "json", "--output", outputPath, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}

	if !capturedForce {
		t.Error("confirmExport should receive force=true when --yes is set")
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(data) == 0 {
		t.Error("export produced empty output")
	}
}
