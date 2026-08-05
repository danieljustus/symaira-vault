package crud

import (
	"bufio"
	"io"
	"os"
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// setupTestVault initializes a temp vault, points the global --vault flag at
// it, and opts into env-passphrase unlocking for the duration of the test —
// the same fixture shape cmd/file and cmd/auth use.
func setupTestVault(t *testing.T) {
	t.Helper()

	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, configpkg.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	t.Cleanup(vaultpkg.FlushManifestUpdates)

	origVault := cli.Vault
	var origChanged bool
	if cli.VaultFlag != nil {
		origChanged = cli.VaultFlag.Changed
	}
	cli.Vault = vaultDir
	if cli.VaultFlag != nil {
		_ = cli.VaultFlag.Value.Set(vaultDir)
		cli.VaultFlag.Changed = true
	}
	t.Cleanup(func() {
		cli.Vault = origVault
		if cli.VaultFlag != nil {
			_ = cli.VaultFlag.Value.Set(origVault)
			cli.VaultFlag.Changed = origChanged
		}
	})

	t.Setenv("SYMVAULT_VAULT", vaultDir)
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
	t.Setenv("SYMVAULT_PASSPHRASE", string(passphrase))
	t.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
}

// withStdin runs fn with os.Stdin replaced by a pipe pre-filled with input.
func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdin = r
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.WriteString(w, input)
		_ = w.Close()
	}()
	defer func() { os.Stdin = oldStdin }()
	fn()
	<-done
}

// setJSONOutput switches the global output format to JSON and restores it on
// cleanup.
func setJSONOutput(t *testing.T) {
	t.Helper()
	orig := cli.OutputFormat
	cli.OutputFormat = "json"
	t.Cleanup(func() { cli.OutputFormat = orig })
}

// addTestEntry writes an entry into the vault via a fresh WithVaultRaw call.
func addTestEntry(t *testing.T, path string, fields map[string]any) {
	t.Helper()
	err := cli.WithVaultRaw(func(_ *vaultpkg.Vault, vs *cli.VaultService) error {
		return vs.SetFieldsWithProvenance(path, fields, vaultpkg.WriteRecord{Action: "test"})
	})
	if err != nil {
		t.Fatalf("seed entry %q: %v", path, err)
	}
}

// entryExists reports whether the seeded "github" entry still exists, without
// failing the test when it does not (unlike getTestEntry, which is for
// read-back asserts).
func entryExists(t *testing.T) bool {
	t.Helper()
	exists := false
	err := cli.WithVaultRaw(func(_ *vaultpkg.Vault, vs *cli.VaultService) error {
		entry, err := vs.GetEntry("github")
		if err == nil && entry != nil {
			exists = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("check entry: %v", err)
	}
	return exists
}

// getTestEntry re-reads an entry from the vault via a fresh WithVaultRaw call.
func getTestEntry(t *testing.T, path string) *vaultpkg.Entry {
	t.Helper()
	var got *vaultpkg.Entry
	err := cli.WithVaultRaw(func(_ *vaultpkg.Vault, vs *cli.VaultService) error {
		entry, err := vs.GetEntry(path)
		if err != nil {
			return err
		}
		got = entry
		return nil
	})
	if err != nil {
		t.Fatalf("read back entry %q: %v", path, err)
	}
	return got
}

// captureStderr runs fn while capturing everything written to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = oldStderr
	var buf strings.Builder
	_, _ = io.Copy(&buf, bufio.NewReader(r))
	_ = r.Close()
	return buf.String()
}

// captureStdout runs fn while capturing everything written to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = oldStdout
	var buf strings.Builder
	_, _ = io.Copy(&buf, bufio.NewReader(r))
	_ = r.Close()
	return buf.String()
}
