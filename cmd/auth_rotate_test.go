package cmd

import (
	"os"
	"strings"
	"testing"

	cli "github.com/danieljustus/OpenPass/internal/cli"
)

func TestAuthRotate_ValidatesLengthBeforeConfirmation(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	defer setupVaultFlag(t, vaultDir)()

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdin = r

	go func() {
		defer w.Close()
		w.Write(passphrase)
		w.Write([]byte("\n"))
		w.Write([]byte("short\n"))
	}()

	cli.RootCmd.SetArgs([]string{"auth", "rotate-passphrase"})
	err = cli.RootCmd.Execute()
	os.Stdin = oldStdin

	if err == nil {
		t.Fatal("expected error for short passphrase")
	}
	if !strings.Contains(err.Error(), "at least 12 characters") {
		t.Fatalf("expected 'at least 12 characters' error, got: %v", err)
	}
}
