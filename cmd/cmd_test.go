package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/testutil"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func TestExpandVaultDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path tests use unix paths")
	}
	home, _ := os.UserHomeDir()

	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"~", home, false},
		{"~/test", filepath.Join(home, "test"), false},
		{"/absolute/path", "/absolute/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := expandVaultDir(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("expandVaultDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("expandVaultDir() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGeneratePassword(t *testing.T) {
	tests := []struct {
		name       string
		length     int
		useSymbols bool
		wantErr    bool
		wantLen    int
	}{
		{"default length", 20, false, false, 20},
		{"custom length", 32, false, false, 32},
		{"with symbols", 20, true, false, 20},
		{"zero length", 0, false, true, 0},
		{"negative length", -1, false, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generatePassword(tt.length, tt.useSymbols)
			if (err != nil) != tt.wantErr {
				t.Errorf("generatePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.wantLen {
				t.Errorf("generatePassword() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestGeneratePasswordContainsExpectedChars(t *testing.T) {
	password, err := generatePassword(100, false)
	if err != nil {
		t.Fatalf("generatePassword() error = %v", err)
	}

	hasOnlyAlphaNum := true
	for _, c := range password {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			hasOnlyAlphaNum = false
			break
		}
	}
	if !hasOnlyAlphaNum {
		t.Error("password without symbols contains non-alphanumeric characters")
	}

	passwordWithSymbols, _ := generatePassword(100, true)
	hasSymbols := false
	symbols := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, c := range passwordWithSymbols {
		if strings.Contains(symbols, string(c)) {
			hasSymbols = true
			break
		}
	}
	if !hasSymbols {
		t.Error("password with symbols does not contain any symbols")
	}
}

func TestSetVersionInfo(t *testing.T) {
	origVersion := appVersion
	origCommit := appCommit
	origDate := appDate

	SetVersionInfo("1.0.0", "abc123", "2024-01-01")

	if appVersion != "1.0.0" {
		t.Errorf("appVersion = %q, want %q", appVersion, "1.0.0")
	}
	if appCommit != "abc123" {
		t.Errorf("appCommit = %q, want %q", appCommit, "abc123")
	}
	if appDate != "2024-01-01" {
		t.Errorf("appDate = %q, want %q", appDate, "2024-01-01")
	}

	appVersion = origVersion
	appCommit = origCommit
	appDate = origDate
}

func TestVaultPathWithTilde(t *testing.T) {
	origHome := os.Getenv("HOME")
	defer func() { _ = os.Setenv("HOME", origHome) }()

	_ = os.Setenv("HOME", "/custom/home")

	vault = "~/my-vault"
	got, _ := vaultPath()

	home, _ := os.UserHomeDir()
	expected := filepath.Join(home, "my-vault")
	if got != expected {
		t.Errorf("vaultPath() = %q, want %q", got, expected)
	}
}

func TestVaultPathWithAbsolute(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	vault = "/absolute/path"
	got, _ := vaultPath()

	if got != "/absolute/path" {
		t.Errorf("vaultPath() = %q, want %q", got, "/absolute/path")
	}
}

func TestVaultPathWithTildeOnly(t *testing.T) {
	home, _ := os.UserHomeDir()
	vault = "~"
	got, _ := vaultPath()

	expected := home
	if got != expected {
		t.Errorf("vaultPath() = %q, want %q", got, expected)
	}
}

func TestLoadConfigSilent(t *testing.T) {
	_, err := loadConfigSilent("/tmp/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent config")
	}

	vaultDir := t.TempDir()
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	data, _ := yaml.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(vaultDir, "config.yaml"), data, 0o600)

	loaded, err := loadConfigSilent(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if loaded.VaultDir != vaultDir {
		t.Errorf("VaultDir = %q, want %q", loaded.VaultDir, vaultDir)
	}
}

func TestUnlockVaultLocked(t *testing.T) {
	vaultDir := t.TempDir()

	_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	_, err := unlockVault(vaultDir, false)
	if err == nil {
		t.Error("expected error for locked vault")
	}
}

func TestOutputStdioConfig(t *testing.T) {
	err := outputStdioConfig("claude-code", "openpass")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOutputHTTPConfig(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	err := outputHTTPConfig("claude-code", "openpass", true, "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestListRecipients(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

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

func TestRecipientsManagerInvalidKey(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

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

func TestRecipientsManagerRemoveNotFound(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

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

func TestAddEntryToVault(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	entry := &vaultpkg.Entry{
		Data: map[string]any{
			"password": "secret123",
			"username": "user123",
		},
		Metadata: vaultpkg.EntryMetadata{
			Created: time.Now().UTC(),
			Updated: time.Now().UTC(),
			Version: 1,
		},
	}
	err := vaultpkg.WriteEntryWithRecipients(vaultDir, "test-entry", entry, identity)
	if err != nil {
		t.Fatalf("failed to write entry: %v", err)
	}

	readEntry, err := vaultpkg.ReadEntry(vaultDir, "test-entry", identity)
	if err != nil {
		t.Fatalf("failed to read entry: %v", err)
	}
	if readEntry.Data["password"] != "secret123" {
		t.Errorf("expected password 'secret123', got %v", readEntry.Data["password"])
	}
}

func TestExecute(t *testing.T) {
	Execute()
}

func TestTruncatePubkey_Long(t *testing.T) {
	pubkey := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	got := truncatePubkey(pubkey)
	want := "ABCDEFGHIJKLMNOP..."
	if got != want {
		t.Errorf("truncatePubkey(%q) = %q, want %q", pubkey, got, want)
	}
}

func TestTruncatePubkey_Short(t *testing.T) {
	pubkey := "ABCDE"
	got := truncatePubkey(pubkey)
	if got != pubkey {
		t.Errorf("truncatePubkey(%q) = %q, want %q", pubkey, got, pubkey)
	}
}

func TestParseSSHTarget_WithUserAndPath(t *testing.T) {
	user, host, path, err := parseSSHTarget("alice@example.com:~/repos/vault", "")
	if err != nil {
		t.Fatalf("parseSSHTarget error: %v", err)
	}
	if user != "alice" {
		t.Errorf("user = %q, want %q", user, "alice")
	}
	if host != "example.com" {
		t.Errorf("host = %q, want %q", host, "example.com")
	}
	if path != "~/repos/vault" {
		t.Errorf("path = %q, want %q", path, "~/repos/vault")
	}
}

func TestParseSSHTarget_HostOnly(t *testing.T) {
	_, host, path, err := parseSSHTarget("example.com", "")
	if err != nil {
		t.Fatalf("parseSSHTarget error: %v", err)
	}
	if host != "example.com" {
		t.Errorf("host = %q, want %q", host, "example.com")
	}
	if path != "~/openpass-remote.git" {
		t.Errorf("path = %q, want %q", path, "~/openpass-remote.git")
	}
}

func TestParseSSHTarget_Empty(t *testing.T) {
	user, host, path, err := parseSSHTarget("", "")
	_ = user
	_ = host
	_ = path
	if err == nil {
		t.Error("expected error for empty target")
	}
}

func TestBuildSSHURL_WithUser(t *testing.T) {
	url := buildSSHURL("alice", "example.com", "~/vault.git")
	want := "ssh://alice@example.com/~vault.git"
	if url != want {
		t.Errorf("buildSSHURL = %q, want %q", url, want)
	}
}

func TestBuildSSHURL_NoUser(t *testing.T) {
	url := buildSSHURL("", "example.com", "~/vault.git")
	want := "ssh://example.com/~vault.git"
	if url != want {
		t.Errorf("buildSSHURL = %q, want %q", url, want)
	}
}

func TestGetAutoClearDuration_Default(t *testing.T) {
	// No vault configured — should return default of 30.
	dur := getAutoClearDuration()
	if dur <= 0 {
		t.Errorf("getAutoClearDuration() = %d, want positive value", dur)
	}
}
