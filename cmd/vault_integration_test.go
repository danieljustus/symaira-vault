package cmd

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/session"
	"github.com/danieljustus/symaira-vault/internal/testutil"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestVaultInitWithPassphrase_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase-123")

	identity, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())
	if err != nil {
		t.Fatalf("InitWithPassphrase() error = %v", err)
	}
	if identity == nil {
		t.Fatal("InitWithPassphrase() returned nil identity")
	}

	identityPath := vaultDir + "/identity.age"
	configPath := vaultDir + "/config.yaml"
	if _, cmdErr := exec.Command("test", "-f", identityPath).CombinedOutput(); cmdErr != nil {
		t.Errorf("identity.age file not created at %s", identityPath)
	}
	if _, cmdErr := exec.Command("test", "-f", configPath).CombinedOutput(); cmdErr != nil {
		t.Errorf("config.yaml file not created at %s", configPath)
	}

	v, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatalf("OpenWithPassphrase() error = %v", err)
	}
	if v == nil {
		t.Fatal("OpenWithPassphrase() returned nil vault")
	}

	recipient, err := v.GetRecipient()
	if err != nil {
		t.Fatalf("GetRecipient() error = %v", err)
	}
	if recipient == nil {
		t.Fatal("GetRecipient() returned nil recipient")
	}
	if recipient.String() != identity.Recipient().String() {
		t.Errorf("recipient mismatch: got %s, want %s", recipient.String(), identity.Recipient().String())
	}
}

func TestVaultEntryCRUD_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	data := map[string]any{
		"username": "testuser",
		"password": "testpass",
	}
	entry := &vaultpkg.Entry{Data: data}
	if err := vaultpkg.WriteEntry(vaultDir, "github.com/user", entry, identity); err != nil {
		t.Fatalf("WriteEntry() error = %v", err)
	}

	readEntry, err := vaultpkg.ReadEntry(vaultDir, "github.com/user", identity)
	if err != nil {
		t.Fatalf("ReadEntry() error = %v", err)
	}
	if readEntry.Data["username"] != "testuser" {
		t.Errorf("ReadEntry() username = %v, want testuser", readEntry.Data["username"])
	}
	if readEntry.Data["password"] != "testpass" {
		t.Errorf("ReadEntry() password = %v, want testpass", readEntry.Data["password"])
	}

	newData := map[string]any{
		"url":   "https://github.com/user",
		"notes": "merged note",
	}
	mergedEntry, err := vaultpkg.MergeEntry(vaultDir, "github.com/user", newData, identity)
	if err != nil {
		t.Fatalf("MergeEntry() error = %v", err)
	}
	if mergedEntry.Data["username"] != "testuser" {
		t.Errorf("MergeEntry() username = %v, want testuser", mergedEntry.Data["username"])
	}
	if mergedEntry.Data["password"] != "testpass" {
		t.Errorf("MergeEntry() password = %v, want testpass", mergedEntry.Data["password"])
	}
	if mergedEntry.Data["url"] != "https://github.com/user" {
		t.Errorf("MergeEntry() url = %v, want https://github.com/user", mergedEntry.Data["url"])
	}
	if mergedEntry.Data["notes"] != "merged note" {
		t.Errorf("MergeEntry() notes = %v, want merged note", mergedEntry.Data["notes"])
	}

	if delErr := vaultpkg.DeleteEntry(vaultDir, "github.com/user", identity); delErr != nil {
		t.Fatalf("DeleteEntry() error = %v", delErr)
	}

	_, err = vaultpkg.ReadEntry(vaultDir, "github.com/user", identity)
	if err == nil {
		t.Fatal("ReadEntry() after DeleteEntry() should return error, got nil")
	}
}

func TestVaultGitAutoCommit_Integration(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	if out, err := exec.Command("git", "-C", vaultDir, "init").CombinedOutput(); err != nil {
		t.Fatalf("git init error = %v, output: %s", err, out)
	}
	if out, err := exec.Command("git", "-C", vaultDir, "config", "user.email", "test@test.com").CombinedOutput(); err != nil {
		t.Fatalf("git config user.email error = %v, output: %s", err, out)
	}
	if out, err := exec.Command("git", "-C", vaultDir, "config", "user.name", "Test").CombinedOutput(); err != nil {
		t.Fatalf("git config user.name error = %v, output: %s", err, out)
	}

	entry := &vaultpkg.Entry{
		Data: map[string]any{
			"password": "git-test-pass",
		},
	}
	if err := vaultpkg.WriteEntry(vaultDir, "test-entry", entry, identity); err != nil {
		t.Fatalf("WriteEntry() error = %v", err)
	}

	v := &vaultpkg.Vault{Dir: vaultDir, Identity: identity, Config: cfg}
	if err := v.AutoCommit("Add test entry"); err != nil {
		t.Fatalf("AutoCommit() error = %v", err)
	}

	logOut, err := exec.Command("git", "-C", vaultDir, "log", "--oneline", "-1").CombinedOutput()
	if err != nil {
		t.Fatalf("git log error = %v, output: %s", err, logOut)
	}
	if !strings.Contains(string(logOut), "Add test entry") {
		t.Errorf("git log should contain 'Add test entry', got: %s", logOut)
	}
}

func TestVaultSessionCaching_Integration(t *testing.T) {
	probeDir := t.TempDir()
	if err := session.SavePassphrase(probeDir, []byte("probe"), time.Second); err != nil {
		t.Skipf("OS keyring not available in test environment: %v", err)
	}
	// Verify the keyring can also load back what was saved; some CI
	// environments allow writes but reads return ErrNotFound.
	if _, err := session.LoadPassphrase(probeDir); err != nil {
		t.Skipf("OS keyring inconsistent in test environment: %v", err)
	}
	_ = session.ClearSession(probeDir)

	vaultDir := t.TempDir()
	passphrase := []byte("session-test-passphrase")

	if err := session.SavePassphrase(vaultDir, passphrase, 2*time.Second); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	loaded, err := session.LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() immediately after save error = %v", err)
	}
	if string(loaded) != string(passphrase) {
		t.Errorf("LoadPassphrase() = %q, want %q", loaded, passphrase)
	}

	time.Sleep(3 * time.Second)

	_, err = session.LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() after TTL expiry should return error, got nil")
	}

	_ = session.ClearSession(vaultDir)

	_, err = session.LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() after ClearSession() should return error, got nil")
	}
}
