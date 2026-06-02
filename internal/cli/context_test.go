package cli

import (
	"context"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/session"
)

// mockSessionManager implements SessionManager for testing.
type mockSessionManager struct {
	loadPassphrase func(vaultDir string) ([]byte, error)
	savePassphrase func(vaultDir string, passphrase []byte, ttl time.Duration) error
	isExpired      func(vaultDir string) bool
	loadBiometric  func(ctx context.Context, vaultDir string) ([]byte, error)
	saveBiometric  func(ctx context.Context, vaultDir string, passphrase []byte) error
	getCacheStatus func() session.CacheStatus
	loadIdentity   func(vaultDir string) (string, error)
	saveIdentity   func(vaultDir string, identity string, ttl time.Duration) error
}

func (m *mockSessionManager) LoadPassphrase(vaultDir string) ([]byte, error) {
	if m.loadPassphrase != nil {
		return m.loadPassphrase(vaultDir)
	}
	return nil, nil
}
func (m *mockSessionManager) SavePassphrase(vaultDir string, passphrase []byte, ttl time.Duration) error {
	if m.savePassphrase != nil {
		return m.savePassphrase(vaultDir, passphrase, ttl)
	}
	return nil
}
func (m *mockSessionManager) IsExpired(vaultDir string) bool {
	if m.isExpired != nil {
		return m.isExpired(vaultDir)
	}
	return false
}
func (m *mockSessionManager) LoadBiometric(ctx context.Context, vaultDir string) ([]byte, error) {
	if m.loadBiometric != nil {
		return m.loadBiometric(ctx, vaultDir)
	}
	return nil, nil
}
func (m *mockSessionManager) SaveBiometric(ctx context.Context, vaultDir string, passphrase []byte) error {
	if m.saveBiometric != nil {
		return m.saveBiometric(ctx, vaultDir, passphrase)
	}
	return nil
}
func (m *mockSessionManager) GetCacheStatus() session.CacheStatus {
	if m.getCacheStatus != nil {
		return m.getCacheStatus()
	}
	return session.CacheStatus{}
}
func (m *mockSessionManager) LoadIdentity(vaultDir string) (string, error) {
	if m.loadIdentity != nil {
		return m.loadIdentity(vaultDir)
	}
	return "", nil
}
func (m *mockSessionManager) SaveIdentity(vaultDir string, identity string, ttl time.Duration) error {
	if m.saveIdentity != nil {
		return m.saveIdentity(vaultDir, identity, ttl)
	}
	return nil
}

func TestNewCLIContext_HasDefaults(t *testing.T) {
	ctx := NewCLIContext()
	if ctx.OutputFormat != "text" {
		t.Errorf("expected OutputFormat 'text', got %q", ctx.OutputFormat)
	}
	if ctx.ColorMode != "auto" {
		t.Errorf("expected ColorMode 'auto', got %q", ctx.ColorMode)
	}
	if ctx.Session == nil {
		t.Error("expected non-nil Session")
	}
	if ctx.OsExit == nil {
		t.Error("expected non-nil OsExit")
	}
}

func TestNewTestContext_ProducesIsolatedState(t *testing.T) {
	ctx1 := NewTestContext()
	ctx1.QuietMode = true
	ctx1.OutputFormat = "json"

	ctx2 := NewTestContext()
	ctx2.QuietMode = false
	ctx2.OutputFormat = "yaml"

	if !ctx1.QuietMode {
		t.Error("ctx1 should have QuietMode=true")
	}
	if ctx2.QuietMode {
		t.Error("ctx2 should have QuietMode=false")
	}
	if ctx1.OutputFormat != "json" {
		t.Errorf("ctx1 OutputFormat = %q, want json", ctx1.OutputFormat)
	}
	if ctx2.OutputFormat != "yaml" {
		t.Errorf("ctx2 OutputFormat = %q, want yaml", ctx2.OutputFormat)
	}
}

func TestSyncFromContext_WritesGlobals(t *testing.T) {
	ctx := NewCLIContext()
	ctx.Vault = "/tmp/test-vault"
	ctx.QuietMode = true
	ctx.OutputFormat = "yaml"
	ctx.NoPipeWarning = true
	ctx.ColorMode = "never"
	ctx.ThemePreset = "dark"

	syncFromContext(ctx)

	if Vault != "/tmp/test-vault" {
		t.Errorf("Vault = %q, want /tmp/test-vault", Vault)
	}
	if !QuietMode {
		t.Error("QuietMode should be true")
	}
	if OutputFormat != "yaml" {
		t.Errorf("OutputFormat = %q, want yaml", OutputFormat)
	}
}

func TestSyncToContext_ReadsGlobals(t *testing.T) {
	Vault = "/tmp/read-back"
	QuietMode = true
	OutputFormat = "json"
	ColorMode = "always"
	ThemePreset = "light"
	NoPipeWarning = false
	Profile = "test-profile"

	ctx := NewCLIContext()
	syncToContext(ctx)

	if ctx.Vault != "/tmp/read-back" {
		t.Errorf("ctx.Vault = %q, want /tmp/read-back", ctx.Vault)
	}
	if !ctx.QuietMode {
		t.Error("ctx.QuietMode should be true")
	}
	if ctx.OutputFormat != "json" {
		t.Errorf("ctx.OutputFormat = %q, want json", ctx.OutputFormat)
	}
	if ctx.Profile != "test-profile" {
		t.Errorf("ctx.Profile = %q, want test-profile", ctx.Profile)
	}
}

func TestExecuteWithContext_SetsActiveContext(t *testing.T) {
	ctx := NewTestContext()
	ctx.OutputFormat = "yaml"

	ExecuteWithContext(ctx)

	if ActiveContext != ctx {
		t.Fatal("ActiveContext not set after ExecuteWithContext")
	}
	if OutputFormat != "yaml" {
		t.Errorf("OutputFormat = %q, want yaml (should sync from context)", OutputFormat)
	}
}

func TestCLIContext_MockSessionManager(t *testing.T) {
	ctx := NewTestContext()
	ctx.Session = &mockSessionManager{
		isExpired: func(vaultDir string) bool { return true },
	}

	if !ctx.Session.IsExpired("/fake") {
		t.Error("expected mock session to report expired")
	}
}
