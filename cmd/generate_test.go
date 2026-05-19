package cmd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	cli "github.com/danieljustus/OpenPass/internal/cli"
	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/crypto"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func TestGeneratePassword_ValidLengths(t *testing.T) {
	for _, length := range []int{1, 20, 100, 1024, crypto.MaxPasswordLength} {
		t.Run("", func(t *testing.T) {
			password, err := generatePassword(length, false)
			if err != nil {
				t.Fatalf("generatePassword(%d) unexpected error: %v", length, err)
			}
			if len(password) != length {
				t.Errorf("password length = %d, want %d", len(password), length)
			}
		})
	}
}

func TestGeneratePassword_ZeroLength(t *testing.T) {
	_, err := generatePassword(0, false)
	if err == nil {
		t.Fatal("expected error for length=0, got nil")
	}
	if !strings.Contains(err.Error(), "greater than zero") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGeneratePassword_NegativeLength(t *testing.T) {
	_, err := generatePassword(-1, false)
	if err == nil {
		t.Fatal("expected error for length=-1, got nil")
	}
	if !strings.Contains(err.Error(), "greater than zero") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGeneratePassword_ExceedsMaxLength(t *testing.T) {
	_, err := generatePassword(crypto.MaxPasswordLength+1, false)
	if err == nil {
		t.Fatalf("expected error for length=%d, got nil", crypto.MaxPasswordLength+1)
	}
	if !strings.Contains(err.Error(), "at most") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGeneratePassword_WithSymbols(t *testing.T) {
	password, err := generatePassword(50, true)
	if err != nil {
		t.Fatalf("generatePassword(50, true) error: %v", err)
	}
	if len(password) != 50 {
		t.Errorf("password length = %d, want 50", len(password))
	}
}

func TestCmdGenerate_StoreExisting(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	identity, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())
	if err != nil {
		t.Fatalf("init vault: %v", err)
	}

	entry := &vaultpkg.Entry{Data: map[string]any{"password": "oldpass"}}
	if err := vaultpkg.WriteEntry(vaultDir, "existing.password", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	origGenStore := genStore
	origGenLength := genLength
	t.Cleanup(func() { genStore = origGenStore; genLength = origGenLength })

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "generate", "--length", "16", "--store", "existing.password"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	output := captureStdout(func() {
		_ = rootCmd.Execute()
	})

	if !strings.Contains(output, "Password stored at") {
		t.Errorf("generate store existing output: %q", output)
	}
}

func TestCmdGenerate_StoreJSONDoesNotRevealByDefault(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	t.Cleanup(func() {
		genStore = ""
		genReveal = false
		genQuiet = false
		cli.OutputFormat = "text"
	})

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "generate", "--length", "16", "--store", "json.password", "--output", "json"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	output := captureStdout(func() {
		_ = rootCmd.Execute()
	})

	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("generate --store --json output is not valid JSON: %q: %v", output, err)
	}
	if _, ok := result["password"]; ok {
		t.Fatalf("generate --store --json revealed password by default: %#v", result)
	}
	if result["stored"] != true || result["path"] != "json.password" {
		t.Fatalf("unexpected generate JSON result: %#v", result)
	}
}

func TestCmdGenerate_ZeroLength(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	origGenLength := genLength
	t.Cleanup(func() { genLength = origGenLength })

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "generate", "--length", "0"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for zero length password")
	}
}

func TestCmdGenerate_NoStore(t *testing.T) {
	vaultDir := t.TempDir()
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, []byte("testpassphrase"), config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	origGenStore := genStore
	origGenLength := genLength
	t.Cleanup(func() { genStore = origGenStore; genLength = origGenLength })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "generate", "--length", "12"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	output := captureStdout(func() {
		_ = rootCmd.Execute()
	})

	if len(strings.TrimSpace(output)) != 12 {
		t.Errorf("generate output length %d, want 12: %q", len(strings.TrimSpace(output)), output)
	}
}

func TestGenerate_ErrorPaths(t *testing.T) {
	resetVaultState(t)
	t.Run("invalid length", func(t *testing.T) {
		tmpDir := t.TempDir()
		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
		defer func() {
			_ = os.Unsetenv("OPENPASS_VAULT")
			_ = os.Unsetenv("OPENPASS_PASSPHRASE")
		}()

		cfg := config.Default()
		_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

		rootCmd.SetArgs([]string{"--vault", tmpDir, "generate", "--length", "0"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil {
			t.Error("expected error for zero length")
		}
	})
}
