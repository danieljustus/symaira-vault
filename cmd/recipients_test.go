package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/testutil"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	testRecipient1 = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	testRecipient2 = "age1savzx9za5xg4fvwkeq788v50esvs3ccn9sscdxevw2fev9xdyeps8z9z65"
)

func TestRecipientsListCmd_VaultNotInitialized(t *testing.T) {
	resetVaultState(t)
	vaultDir := t.TempDir()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--vault", vaultDir, "recipients", "list"})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for vault not initialized")
	}
	if !strings.Contains(err.Error(), "vault not initialized") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRecipientsAddCmd_VaultNotInitialized(t *testing.T) {
	resetVaultState(t)
	vaultDir := t.TempDir()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--vault", vaultDir, "recipients", "add", testRecipient1})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for vault not initialized")
	}
}

func TestRecipientsRemoveCmd_VaultNotInitialized(t *testing.T) {
	resetVaultState(t)
	vaultDir := t.TempDir()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--vault", vaultDir, "recipients", "remove", testRecipient1})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for vault not initialized")
	}
}

func TestListRecipients_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	recipients, err := rm.ListRecipients()
	if err != nil {
		t.Fatalf("failed to list recipients: %v", err)
	}
	if len(recipients) != 0 {
		t.Errorf("expected 0 recipients, got %d", len(recipients))
	}
}

func TestRecipientsManagerInvalidKey_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	err := rm.AddRecipient("invalid-key")
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestRecipientsManagerRemoveNotFound_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	err := rm.RemoveRecipient("age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err == nil {
		t.Error("expected error for removing non-existent recipient")
	}
}

func TestRecipientsList_WithRecipients_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	if err := rm.AddRecipient(testRecipient1); err != nil {
		t.Fatalf("failed to add recipient: %v", err)
	}
	if err := rm.AddRecipient(testRecipient2); err != nil {
		t.Fatalf("failed to add recipient: %v", err)
	}

	recipients, err := rm.ListRecipients()
	if err != nil {
		t.Fatalf("failed to list recipients: %v", err)
	}
	if len(recipients) != 2 {
		t.Errorf("expected 2 recipients, got %d", len(recipients))
	}

	for _, r := range recipients {
		if !r.Valid {
			t.Errorf("expected recipient to be valid: %s", r.RawString)
		}
	}
}

func TestRecipientsAdd_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	err := rm.AddRecipient(testRecipient1)
	if err != nil {
		t.Fatalf("failed to add recipient: %v", err)
	}

	recipients, err := rm.ListRecipients()
	if err != nil {
		t.Fatalf("failed to list recipients: %v", err)
	}
	if len(recipients) != 1 {
		t.Errorf("expected 1 recipient, got %d", len(recipients))
	}
}

func TestRecipientsAdd_Duplicate_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	if err := rm.AddRecipient(testRecipient1); err != nil {
		t.Fatalf("failed to add recipient: %v", err)
	}

	err := rm.AddRecipient(testRecipient1)
	if err == nil {
		t.Error("expected error for duplicate recipient")
	}
	if !errors.Is(err, vaultpkg.ErrRecipientAlreadyExists) {
		t.Errorf("expected ErrRecipientAlreadyExists, got: %v", err)
	}
}

func TestRecipientsRemove_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	if err := rm.AddRecipient(testRecipient1); err != nil {
		t.Fatalf("failed to add recipient: %v", err)
	}

	err := rm.RemoveRecipient(testRecipient1)
	if err != nil {
		t.Fatalf("failed to remove recipient: %v", err)
	}

	recipients, err := rm.ListRecipients()
	if err != nil {
		t.Fatalf("failed to list recipients: %v", err)
	}
	if len(recipients) != 0 {
		t.Errorf("expected 0 recipients, got %d", len(recipients))
	}
}

func TestMultiUserEncryption_Integration(t *testing.T) {
	vaultDir := t.TempDir()

	identity1 := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity1, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	if err := rm.AddRecipient(testRecipient1); err != nil {
		t.Fatalf("failed to add recipient 1: %v", err)
	}
	if err := rm.AddRecipient(testRecipient2); err != nil {
		t.Fatalf("failed to add recipient 2: %v", err)
	}

	entry := &vaultpkg.Entry{
		Data: map[string]any{
			"password": "shared-secret",
			"username": "shared-user",
		},
	}
	if err := vaultpkg.WriteEntryWithRecipients(vaultDir, "shared-entry", entry, identity1); err != nil {
		t.Fatalf("failed to write entry: %v", err)
	}

	entryPath := filepath.Join(vaultDir, "entries", "shared-entry.age")
	if _, err := os.Stat(entryPath); os.IsNotExist(err) {
		t.Fatal("entry file was not created")
	}

	readEntry, err := vaultpkg.ReadEntry(vaultDir, "shared-entry", identity1)
	if err != nil {
		t.Fatalf("failed to read entry with identity1: %v", err)
	}
	if readEntry.Data["password"] != "shared-secret" {
		t.Errorf("expected password 'shared-secret', got %v", readEntry.Data["password"])
	}

	v := &vaultpkg.Vault{Dir: vaultDir, Identity: identity1}
	recipients, err := v.GetAllRecipientsForEncryption()
	if err != nil {
		t.Fatalf("failed to get recipients: %v", err)
	}

	if len(recipients) != 3 {
		t.Errorf("expected 3 recipients, got %d", len(recipients))
	}
}

func TestRecipientsList_ValidAndInvalid_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	recipientsPath := filepath.Join(vaultDir, "recipients.txt")
	content := testRecipient1 + "\ninvalid-key\n" + testRecipient2 + "\n"
	if err := os.WriteFile(recipientsPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write recipients file: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	recipients, err := rm.ListRecipients()
	if err != nil {
		t.Fatalf("failed to list recipients: %v", err)
	}
	if len(recipients) != 3 {
		t.Errorf("expected 3 recipients, got %d", len(recipients))
	}

	validCount := 0
	invalidCount := 0
	for _, r := range recipients {
		if r.Valid {
			validCount++
		} else {
			invalidCount++
		}
	}
	if validCount != 2 {
		t.Errorf("expected 2 valid recipients, got %d", validCount)
	}
	if invalidCount != 1 {
		t.Errorf("expected 1 invalid recipient, got %d", invalidCount)
	}
}

func TestRecipientsAdd_Multiple_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	if err := rm.AddRecipient(testRecipient1); err != nil {
		t.Fatalf("failed to add recipient 1: %v", err)
	}
	if err := rm.AddRecipient(testRecipient2); err != nil {
		t.Fatalf("failed to add recipient 2: %v", err)
	}

	recipients, err := rm.ListRecipients()
	if err != nil {
		t.Fatalf("failed to list recipients: %v", err)
	}
	if len(recipients) != 2 {
		t.Errorf("expected 2 recipients, got %d", len(recipients))
	}
}

func TestRecipientsRemove_CorrectOne_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	if err := rm.AddRecipient(testRecipient1); err != nil {
		t.Fatalf("failed to add recipient 1: %v", err)
	}
	if err := rm.AddRecipient(testRecipient2); err != nil {
		t.Fatalf("failed to add recipient 2: %v", err)
	}

	err := rm.RemoveRecipient(testRecipient1)
	if err != nil {
		t.Fatalf("failed to remove recipient: %v", err)
	}

	recipients, err := rm.ListRecipients()
	if err != nil {
		t.Fatalf("failed to list recipients: %v", err)
	}
	if len(recipients) != 1 {
		t.Errorf("expected 1 recipient after removal, got %d", len(recipients))
	}

	if len(recipients) != 1 || !strings.Contains(recipients[0].RawString, testRecipient2) {
		t.Errorf("expected only recipient 2 to remain, got: %v", recipients)
	}
}

func TestCmdRecipientsList_WithRecipients(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_VAULT") })

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	if err := rm.AddRecipient(testRecipient1); err != nil {
		t.Fatalf("add recipient: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "recipients", "list"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	output := captureStdout(func() {
		_ = rootCmd.Execute()
	})

	if !strings.Contains(output, "Recipients") {
		t.Errorf("list output missing header: %q", output)
	}
	if !strings.Contains(output, testRecipient1) {
		t.Errorf("list output missing recipient: %q", output)
	}
}

func TestCmdRecipientsAdd_Invalid(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "recipients", "add", "not-a-valid-key"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for invalid recipient key")
	}
	if !strings.Contains(execErr.Error(), "invalid recipient") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestCmdRecipientsAdd_Duplicate(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	if err := rm.AddRecipient(testRecipient1); err != nil {
		t.Fatalf("pre-add recipient: %v", err)
	}

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "recipients", "add", testRecipient1})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for duplicate recipient")
	}
	if !strings.Contains(execErr.Error(), "already exists") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestCmdRecipientsRemove_NotFound(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "recipients", "remove", testRecipient2, "--yes"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for recipient not found")
	}
	if !strings.Contains(execErr.Error(), "not found") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestCmdRecipientsRemove_Cancel(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	origConfirmRemove := confirmRemove
	confirmRemove = false
	t.Cleanup(func() { confirmRemove = origConfirmRemove })

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	_, _ = w.WriteString("n\n")
	_ = w.Close()
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = r.Close()
	})

	rootCmd.SetArgs([]string{"--vault", vaultDir, "recipients", "remove", testRecipient1})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	output := captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr != nil {
		t.Errorf("unexpected error for canceled remove: %v", execErr)
	}
	if !strings.Contains(output, "Canceled") {
		t.Errorf("expected 'Canceled' in output: %q", output)
	}
}

func TestCmdRecipientsRemove_WithYesFlag(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	if err := rm.AddRecipient(testRecipient1); err != nil {
		t.Fatalf("add recipient: %v", err)
	}

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "recipients", "remove", testRecipient1, "--yes"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	output := captureStdout(func() {
		_ = rootCmd.Execute()
	})

	if !strings.Contains(output, "Recipient removed successfully") {
		t.Errorf("expected 'Recipient removed successfully', got: %q", output)
	}
}

func TestCmdRecipientsRemove_InvalidKey(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "recipients", "remove", "not-a-valid-key", "--yes"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for invalid recipient key")
	}
	if !strings.Contains(execErr.Error(), "invalid recipient") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestCmdRecipientsAdd_UnlockError(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	_ = os.Setenv("OPENPASS_PASSPHRASE", "wrong-passphrase")
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "recipients", "add", testRecipient1})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for wrong passphrase")
	}
	if !strings.Contains(execErr.Error(), "open vault") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestCmdRecipientsRemove_UnlockError(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	_ = os.Setenv("OPENPASS_PASSPHRASE", "wrong-passphrase")
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "recipients", "remove", testRecipient1, "--yes"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for wrong passphrase")
	}
	if !strings.Contains(execErr.Error(), "open vault") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestRecipients_ErrorPaths(t *testing.T) {
	resetVaultState(t)
	t.Run("list - uninitialized vault", func(t *testing.T) {
		tmpDir := t.TempDir()
		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

		rootCmd.SetArgs([]string{"--vault", tmpDir, "recipients", "list"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "not initialized") {
			t.Errorf("expected 'not initialized' error, got: %v", err)
		}
	})

	t.Run("add - invalid recipient", func(t *testing.T) {
		tmpDir := t.TempDir()
		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
		defer func() {
			_ = os.Unsetenv("OPENPASS_VAULT")
			_ = os.Unsetenv("OPENPASS_PASSPHRASE")
		}()

		cfg := config.Default()
		_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

		rootCmd.SetArgs([]string{"--vault", tmpDir, "recipients", "add", "invalid-key"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("expected 'invalid' error, got: %v", err)
		}
	})

	t.Run("remove - invalid recipient format", func(t *testing.T) {
		tmpDir := t.TempDir()
		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
		defer func() {
			_ = os.Unsetenv("OPENPASS_VAULT")
			_ = os.Unsetenv("OPENPASS_PASSPHRASE")
		}()

		cfg := config.Default()
		_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

		rootCmd.SetArgs([]string{"--vault", tmpDir, "recipients", "remove", "not-age1-key", "-y"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("expected 'invalid' error, got: %v", err)
		}
	})

	t.Run("remove - recipient not in list", func(t *testing.T) {
		tmpDir := t.TempDir()
		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
		defer func() {
			_ = os.Unsetenv("OPENPASS_VAULT")
			_ = os.Unsetenv("OPENPASS_PASSPHRASE")
		}()

		cfg := config.Default()
		_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

		_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
		identity2, _ := vaultpkg.InitWithPassphrase(tmpDir+"_second", []byte("test2"), cfg)

		rootCmd.SetArgs([]string{"--vault", tmpDir, "recipients", "remove", identity2.Recipient().String(), "-y"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("expected 'not found' error, got: %v", err)
		}
	})
}

func TestRecipients_ListEmpty(t *testing.T) {
	resetVaultState(t)

	tmpDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", tmpDir)
	_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
	defer func() {
		_ = os.Unsetenv("OPENPASS_VAULT")
		_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	}()

	cfg := config.Default()
	_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

	rootCmd.SetArgs([]string{"--vault", tmpDir, "recipients", "list"})
	defer rootCmd.SetArgs(nil)

	output := captureStdout(func() {
		_ = rootCmd.Execute()
	})

	if !strings.Contains(output, "No recipients configured") {
		t.Errorf("expected 'No recipients configured', got: %s", output)
	}
}

func TestRecipients_ListInvalidRecipient(t *testing.T) {
	resetVaultState(t)

	tmpDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", tmpDir)
	_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
	defer func() {
		_ = os.Unsetenv("OPENPASS_VAULT")
		_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	}()

	cfg := config.Default()
	_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

	// Write an invalid recipient directly to recipients.txt
	_ = os.WriteFile(tmpDir+"/recipients.txt", []byte("invalid-key\n"), 0o600)

	rootCmd.SetArgs([]string{"--vault", tmpDir, "recipients", "list"})
	defer rootCmd.SetArgs(nil)

	output := captureStdout(func() {
		_ = rootCmd.Execute()
	})

	if !strings.Contains(output, "invalid key format") {
		t.Errorf("expected output to contain invalid recipient error, got: %s", output)
	}
}

func TestRecipients_AddAlreadyExists(t *testing.T) {
	resetVaultState(t)

	tmpDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", tmpDir)
	_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
	defer func() {
		_ = os.Unsetenv("OPENPASS_VAULT")
		_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	}()

	cfg := config.Default()
	identity, _ := vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)
	recipient := identity.Recipient().String()

	// Add once
	_ = vaultpkg.NewRecipientsManager(tmpDir).AddRecipient(recipient)

	// Try to add again via CLI
	rootCmd.SetArgs([]string{"--vault", tmpDir, "recipients", "add", recipient})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}
}

func TestRecipients_RemoveCancelled(t *testing.T) {
	resetVaultState(t)

	tmpDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", tmpDir)
	_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
	defer func() {
		_ = os.Unsetenv("OPENPASS_VAULT")
		_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	}()

	cfg := config.Default()
	identity, _ := vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)
	recipient := identity.Recipient().String()
	_ = vaultpkg.NewRecipientsManager(tmpDir).AddRecipient(recipient)

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	_, _ = w.WriteString("n\n")
	_ = w.Close()

	rootCmd.SetArgs([]string{"--vault", tmpDir, "recipients", "remove", recipient})
	defer rootCmd.SetArgs(nil)

	_ = rootCmd.Execute()
	os.Stdin = oldStdin
	_ = r.Close()
}
