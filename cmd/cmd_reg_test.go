package cmd

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"

	admin "github.com/danieljustus/OpenPass/cmd/admin"
	mcpcmd "github.com/danieljustus/OpenPass/cmd/mcp"
	cli "github.com/danieljustus/OpenPass/internal/cli"
	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/mcp/serverbootstrap"
	"github.com/danieljustus/OpenPass/internal/testutil"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func TestCommandRegistration(t *testing.T) {
	commands := []string{
		"add",
		"delete",
		"device",
		"dynamic",
		"edit",
		"find",
		"generate",
		"get",
		"git",
		"init",
		"list",
		"lock",
		"mcp-config",
		"migrate",
		"policy",
		"recipients",
		"remote",
		"serve",
		"set",
		"sync",
		"template",
		"unlock",
		"update",
		"version",
	}

	for _, cmd := range commands {
		found := false
		for _, c := range rootCmd.Commands() {
			if c.Name() == cmd {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("command %q not registered in rootCmd", cmd)
		}
	}
}

func TestSubcommandRegistration(t *testing.T) {
	recipientsSubcommands := []string{"list", "add", "remove"}
	for _, sub := range recipientsSubcommands {
		found := false
		for _, c := range recipientsCmd.Commands() {
			if c.Name() == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("recipients subcommand %q not registered", sub)
		}
	}

	updateSubcommands := []string{"check"}
	for _, sub := range updateSubcommands {
		found := false
		for _, c := range admin.UpdateCmd.Commands() {
			if c.Name() == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("update subcommand %q not registered", sub)
		}
	}

	found := false
	for _, c := range rootCmd.Commands() {
		if c.Name() == "git" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("command %q not registered in rootCmd", "git")
	}

	remoteSubcommands := []string{"init", "status"}
	for _, sub := range remoteSubcommands {
		found := false
		for _, c := range remoteCmd.Commands() {
			if c.Name() == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("remote subcommand %q not registered", sub)
		}
	}

	deviceSubcommands := []string{"pair", "join", "accept", "list", "revoke"}
	for _, sub := range deviceSubcommands {
		found := false
		for _, c := range deviceCmd.Commands() {
			if c.Name() == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("device subcommand %q not registered", sub)
		}
	}

	serveSubcommands := []string{"install", "uninstall", "status"}
	for _, sub := range serveSubcommands {
		found := false
		for _, c := range mcpcmd.ServeCmd.Commands() {
			if c.Name() == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("serve subcommand %q not registered", sub)
		}
	}

	migrateSubcommands := []string{"pseudonymize"}
	for _, sub := range migrateSubcommands {
		found := false
		for _, c := range admin.MigrateCmd.Commands() {
			if c.Name() == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("migrate subcommand %q not registered", sub)
		}
	}

	dynamicSubcommands := []string{"generate"}
	for _, sub := range dynamicSubcommands {
		found := false
		for _, c := range dynamicCmd.Commands() {
			if c.Name() == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("dynamic subcommand %q not registered", sub)
		}
	}

	templateSubcommands := []string{"generate"}
	for _, sub := range templateSubcommands {
		found := false
		for _, c := range templateCmd.Commands() {
			if c.Name() == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("template subcommand %q not registered", sub)
		}
	}

	policySubcommands := []string{"validate", "apply", "list", "remove"}
	for _, sub := range policySubcommands {
		found := false
		for _, c := range policyCmd.Commands() {
			if c.Name() == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("policy subcommand %q not registered", sub)
		}
	}
}
func TestGeneratePasswordCoverage(t *testing.T) {
	tests := []struct {
		name       string
		length     int
		useSymbols bool
		wantErr    bool
	}{
		{"length 1", 1, false, false},
		{"length 100", 100, false, false},
		{"length 1 with symbols", 1, true, false},
		{"length 50 with symbols", 50, true, false},
		{"negative length", -1, false, true},
		{"zero length", 0, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generatePassword(tt.length, tt.useSymbols)
			if (err != nil) != tt.wantErr {
				t.Errorf("generatePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.length {
				t.Errorf("generatePassword() len = %d, want %d", len(got), tt.length)
			}
		})
	}
}

func TestUnlockVaultWithEnvVar(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	vault = vaultDir
	if vaultFlag != nil {
		vaultFlag.Changed = false
	}

	_, err := unlockVault(vaultDir, false)
	if err != nil {
		t.Errorf("unlockVault with env var failed: %v", err)
	}
}

func TestUnlockVaultNoPassphrase(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	vault = vaultDir
	if vaultFlag != nil {
		vaultFlag.Changed = false
	}

	_, err := unlockVault(vaultDir, false)
	if err == nil {
		t.Error("expected error when no passphrase available")
	}
}

func TestUnlockVaultWrongPassphrase(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	_ = os.Setenv("OPENPASS_PASSPHRASE", "wrong-passphrase")
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	vault = vaultDir
	if vaultFlag != nil {
		vaultFlag.Changed = false
	}

	_, err := unlockVault(vaultDir, false)
	if err == nil {
		t.Error("expected error for wrong passphrase")
	}
}

func TestVaultPathWithEnvVarOpenPassVault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	origEnv := os.Getenv("OPENPASS_VAULT")
	defer func() { _ = os.Setenv("OPENPASS_VAULT", origEnv) }()

	_ = os.Setenv("OPENPASS_VAULT", "/test/vault")

	origVault := vault
	defer func() { vault = origVault }()
	vault = "~/should-not-be-used"

	path, err := vaultPath()
	if err != nil {
		t.Fatalf("vaultPath() error = %v", err)
	}
	if path != "/test/vault" {
		t.Errorf("vaultPath() = %q, want %q", path, "/test/vault")
	}
}

func TestUnlockVaultSavesToKeyring(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	vault = vaultDir
	if vaultFlag != nil {
		vaultFlag.Changed = false
	}

	v, err := unlockVault(vaultDir, false)
	if err != nil {
		t.Fatalf("unlockVault failed: %v", err)
	}
	if v == nil {
		t.Error("unlockVault returned nil vault")
	}
}

func TestRecipientsCmd_Add_Success(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	_, _ = vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	vault = vaultDir
	if vaultFlag != nil {
		vaultFlag.Changed = false
	}

	recipientsAddCmd.SetArgs([]string{"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"})

	err := recipientsAddCmd.Execute()
	if err != nil {
		t.Errorf("recipients add failed: %v", err)
	}
}

func TestRecipientsCmd_List_WithRecipients(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	_, _ = vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	err := rm.AddRecipient("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")
	if err != nil {
		t.Fatalf("add recipient failed: %v", err)
	}

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	vault = vaultDir
	if vaultFlag != nil {
		vaultFlag.Changed = false
	}

	err = recipientsListCmd.Execute()
	if err != nil {
		t.Errorf("recipients list failed: %v", err)
	}
}

func TestRecipientsCmd_Remove_Success(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	_, _ = vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())

	const testRecipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	err := rm.AddRecipient(testRecipient)
	if err != nil {
		t.Fatalf("add recipient failed: %v", err)
	}

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	vault = vaultDir
	if vaultFlag != nil {
		vaultFlag.Changed = false
	}

	recipientsRemoveCmd.SetArgs([]string{testRecipient, "--yes"})

	err = recipientsRemoveCmd.Execute()
	if err != nil {
		t.Errorf("recipients remove failed: %v", err)
	}
}

func TestGenerateCmd_StoreToExistingEntry(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	identity, _ := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "oldpassword"}}
	_ = vaultpkg.WriteEntry(vaultDir, "existing.pass", entry, identity)

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	vault = vaultDir
	if vaultFlag != nil {
		vaultFlag.Changed = false
	}

	generateCmd.SetArgs([]string{"--store", "existing.pass", "--length", "16"})

	err := generateCmd.Execute()
	if err != nil {
		t.Errorf("generate store to existing failed: %v", err)
	}
}

func TestGenerateCmd_StoreNewEntry(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	_, _ = vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	vault = vaultDir
	if vaultFlag != nil {
		vaultFlag.Changed = false
	}

	generateCmd.SetArgs([]string{"--store", "new.pass", "--length", "16"})

	err := generateCmd.Execute()
	if err != nil {
		t.Errorf("generate store new failed: %v", err)
	}
}

func TestOutputHTTPConfigMCP(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	cfg.MCP = &config.MCPConfig{
		Bind: "0.0.0.0",
		Port: 9090,
	}
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	vault = vaultDir
	if vaultFlag != nil {
		vaultFlag.Changed = false
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "mcp-config", "claude-code", "--http"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestRunHTTPServer(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	v, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())
	if err != nil {
		t.Fatalf("init vault: %v", err)
	}

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	cli.Vault = vaultDir
	cli.VaultFlag.Changed = true

	v2, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatalf("open vault failed: %v", err)
	}
	_ = v

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	vaultDir, _ = cli.VaultPath()
	err = serverbootstrap.RunHTTPServer(ctx, "127.0.0.1", 0, v2, vaultDir, "dev", mcp.New)
	_ = err
	if err != nil {
		t.Errorf("RunHTTPServer unexpected error: %v", err)
	}
}

func TestRunStdioServer(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	_, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())
	if err != nil {
		t.Fatalf("init vault: %v", err)
	}

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	vault = vaultDir
	if vaultFlag != nil {
		vaultFlag.Changed = false
	}

	v2, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatalf("open vault failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = serverbootstrap.RunStdioServer(ctx, v2, "default", mcp.New)
	if err != nil {
		t.Errorf("RunStdioServer unexpected error: %v", err)
	}
}
