//go:build test_headless

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	crud "github.com/danieljustus/symaira-vault/cmd/crud"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
	clipboardapp "github.com/danieljustus/symaira-vault/internal/clipboard"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestScriptingGet_TTYDetection_InProcess(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "tty-test-pass"}}
	_ = vaultpkg.WriteEntry(vaultDir, "tty-entry", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	t.Run("non-TTY prints to stdout", func(t *testing.T) {
		oldIsTerminal := cli.IsTerminalFunc
		cli.IsTerminalFunc = func(int) bool { return false }
		defer func() { cli.IsTerminalFunc = oldIsTerminal }()

		out := execWithStdout("--vault", vaultDir, "get", "tty-entry.password")
		if strings.TrimSpace(out) != "tty-test-pass" {
			t.Errorf("non-TTY stdout = %q, want tty-test-pass", out)
		}
	})

	t.Run("TTY copies to clipboard", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(vaultDir, "config.yaml"), []byte("clipboard:\n  auto_clear_duration: 0\n"), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		clipboardapp.SetClipboard(clipboardapp.NewNullClipboard())
		t.Cleanup(func() { clipboardapp.SetClipboard(nil) })
		crud.GetAutoClearDurationFunc = func() int { return 0 }
		t.Cleanup(func() { crud.GetAutoClearDurationFunc = crud.GetAutoClearDuration })

		oldIsTerminal := cli.IsTerminalFunc
		cli.IsTerminalFunc = func(int) bool { return true }
		defer func() { cli.IsTerminalFunc = oldIsTerminal }()

		var stdout string
		captureStderr(func() {
			stdout = captureStdout(func() {
				rootCmd.SetArgs([]string{"--vault", vaultDir, "get", "tty-entry.password"})
				_ = rootCmd.Execute()
				rootCmd.SetArgs(nil)
			})
		})
		if stdout != "" {
			t.Errorf("TTY stdout = %q, want empty (clipboard mode)", stdout)
		}
	})
}
