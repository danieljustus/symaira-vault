package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/testutil"
)

func TestInitCreatesDirectoryAndFiles(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir

	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	for _, path := range []string{
		vaultDir,
		filepath.Join(vaultDir, "config.yaml"),
		filepath.Join(vaultDir, "identity.age"),
		filepath.Join(vaultDir, "entries"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %q to exist: %v", path, err)
		}
	}

	raw, err := os.ReadFile(filepath.Join(vaultDir, "identity.age"))
	if err != nil {
		t.Fatalf("read identity file: %v", err)
	}
	if strings.Contains(string(raw), identity.String()) {
		t.Fatal("identity file should not contain plaintext secret key")
	}

	loaded, err := config.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.VaultDir != vaultDir {
		t.Fatalf("VaultDir = %q, want %q", loaded.VaultDir, vaultDir)
	}
}

func TestOpenLoadsExistingVault(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir

	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	v, err := Open(vaultDir, identity)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if v == nil {
		t.Fatal("Open() returned nil vault")
	}
	if v.Dir != vaultDir {
		t.Fatalf("Dir = %q, want %q", v.Dir, vaultDir)
	}
	if v.Identity == nil || v.Identity.String() != identity.String() {
		t.Fatal("Open() did not preserve the provided identity")
	}
	if v.Config == nil {
		t.Fatal("Open() returned nil Config")
	}
	if v.Config.VaultDir != vaultDir {
		t.Fatalf("VaultDir = %q, want %q", v.Config.VaultDir, vaultDir)
	}
	if v.Config.DefaultAgent != cfg.DefaultAgent {
		t.Fatalf("DefaultAgent = %q, want %q", v.Config.DefaultAgent, cfg.DefaultAgent)
	}
}

func TestOpenMigratesLegacyRootEntriesToEntriesDir(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir

	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if err := WriteEntry(vaultDir, "work/aws", &Entry{Data: map[string]any{"username": "alice"}}, identity); err != nil {
		t.Fatalf("WriteEntry() error = %v", err)
	}

	newPath := filepath.Join(vaultDir, "entries", "work", "aws.age")
	legacyPath := filepath.Join(vaultDir, "work", "aws.age")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatalf("create legacy dir: %v", err)
	}
	if err := os.Rename(newPath, legacyPath); err != nil {
		t.Fatalf("move entry to legacy path: %v", err)
	}

	if _, err := Open(vaultDir, identity); err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("expected migrated entry at %s: %v", newPath, err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("expected legacy entry removed, got err=%v", err)
	}

	got, err := ReadEntry(vaultDir, "work/aws", identity)
	if err != nil {
		t.Fatalf("ReadEntry() error = %v", err)
	}
	if got.Data["username"] != "alice" {
		t.Fatalf("username = %#v, want alice", got.Data["username"])
	}
}

func TestEntryPathJoinsPaths(t *testing.T) {
	v := &Vault{Dir: "/tmp/vault"}
	want := filepath.Join("/tmp/vault", "entries", "github.com", "user.age")
	if got := EntryPath(v, "github.com/user"); got != want {
		t.Fatalf("EntryPath() = %q, want %q", got, want)
	}
}

func TestEnsureDirCreatesNestedDirectories(t *testing.T) {
	v := &Vault{Dir: t.TempDir()}

	if err := EnsureDir(v, "github.com/user/profile"); err != nil {
		t.Fatalf("EnsureDir() error = %v", err)
	}

	want := filepath.Join(v.Dir, "entries", "github.com", "user")
	if info, err := os.Stat(want); err != nil {
		t.Fatalf("expected %q to exist: %v", want, err)
	} else if !info.IsDir() {
		t.Fatalf("%q is not a directory", want)
	}
}

func TestIsInitialized_True(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir

	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	if !IsInitialized(vaultDir) {
		t.Error("IsInitialized() = false, want true for initialized vault")
	}
}

func TestIsInitialized_False(t *testing.T) {
	vaultDir := t.TempDir()

	if IsInitialized(vaultDir) {
		t.Error("IsInitialized() = true, want false for uninitialized vault")
	}
}

func TestGetRecipient(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir

	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	v, err := Open(vaultDir, identity)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	recipient, err := v.GetRecipient()
	if err != nil {
		t.Fatalf("GetRecipient() error = %v", err)
	}
	if recipient == nil {
		t.Fatal("GetRecipient() returned nil")
	}
	if recipient.String() != identity.Recipient().String() {
		t.Errorf("GetRecipient() = %q, want %q", recipient.String(), identity.Recipient().String())
	}
}

func TestGetRecipient_NilVault(t *testing.T) {
	v := &Vault{Dir: t.TempDir()}
	_, err := v.GetRecipient()
	if err == nil {
		t.Error("expected error for nil vault")
	}
}

func TestValidateIdentity_Success(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir

	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	v, err := Open(vaultDir, identity)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if err := v.ValidateIdentity(identity); err != nil {
		t.Errorf("ValidateIdentity() error = %v, want nil", err)
	}
}

func TestValidateIdentity_Mismatch(t *testing.T) {
	vaultDir := t.TempDir()
	identity1 := testutil.TempIdentity(t)
	identity2 := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir

	if err := Init(vaultDir, identity1, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	v, err := Open(vaultDir, identity1)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if err := v.ValidateIdentity(identity2); err == nil {
		t.Error("ValidateIdentity() expected error for mismatched identity")
	}
}

func TestValidateIdentity_NilIdentity(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir

	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	v, err := Open(vaultDir, identity)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if err := v.ValidateIdentity(nil); err == nil {
		t.Error("ValidateIdentity() expected error for nil identity")
	}
}

func TestHasField(t *testing.T) {
	if hasField([]string{"foo", "bar"}, "bar") != true {
		t.Error("hasField should return true when field exists")
	}
	if hasField([]string{"foo", "bar"}, "baz") != false {
		t.Error("hasField should return false when field does not exist")
	}
	if hasField([]string{}, "foo") != false {
		t.Error("hasField should return false for empty slice")
	}
}

func TestCollectFieldMatches(t *testing.T) {
	matches := make(map[string]struct{})
	CollectFieldMatches(matches, "", map[string]any{
		"username": "alice",
		"password": "secret123",
	}, "alice", nil)
	if _, ok := matches["username"]; !ok {
		t.Error("expected username field to match 'alice'")
	}
	if _, ok := matches["password"]; ok {
		t.Error("expected password field to NOT match 'alice'")
	}

	matches2 := make(map[string]struct{})
	CollectFieldMatches(matches2, "", map[string]any{
		"nested": map[string]any{
			"email": "alice@example.com",
		},
	}, "alice", nil)
	if _, ok := matches2["nested.email"]; !ok {
		t.Error("expected nested.email field to match 'alice'")
	}

	matches3 := make(map[string]struct{})
	CollectFieldMatches(matches3, "", map[string]any{
		"items": []any{"alice", "bob", "alice"},
	}, "alice", nil)
	if _, ok := matches3["items[0]"]; !ok {
		t.Error("expected items[0] to match 'alice'")
	}
	if _, ok := matches3["items[2]"]; !ok {
		t.Error("expected items[2] to match 'alice'")
	}
	if _, ok := matches3["items[1]"]; ok {
		t.Error("expected items[1] to NOT match 'alice'")
	}
}

func TestAutoCommitCreatesGitCommit(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	cfg.Git = &config.GitConfig{
		AutoPush:       false,
		CommitTemplate: "",
	}

	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	v, err := Open(vaultDir, identity)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if err := v.AutoCommit("test commit"); err != nil {
		t.Fatalf("AutoCommit() error = %v", err)
	}
}

func TestAutoCommitNilVault(t *testing.T) {
	var v *Vault

	err := v.AutoCommit("test")
	if err == nil {
		t.Fatal("expected error for nil vault")
	}
}

func TestAutoCommitUsesTemplate(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	cfg.Git = &config.GitConfig{
		AutoPush:       false,
		CommitTemplate: "Custom template message",
	}

	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	v, err := Open(vaultDir, identity)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if err := v.AutoCommit(""); err != nil {
		t.Fatalf("AutoCommit() error = %v", err)
	}
}

func TestAutoCommitWithAutoPush(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	cfg.Git = &config.GitConfig{
		AutoPush:       true,
		CommitTemplate: "",
	}

	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	v, err := Open(vaultDir, identity)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if err := v.AutoCommit("test with push"); err != nil {
		t.Fatalf("AutoCommit() error = %v", err)
	}
}

func TestOpenWithEmptyVaultDir(t *testing.T) {
	_, err := Open("", nil)
	if err == nil {
		t.Fatal("expected error for empty vault dir")
	}
}

func TestOpenWithNilIdentity(t *testing.T) {
	vaultDir := t.TempDir()
	_, err := Open(vaultDir, nil)
	if err == nil {
		t.Fatal("expected error for nil identity")
	}
}

func TestOpenWithPassphraseEmptyVaultDir(t *testing.T) {
	_, err := OpenWithPassphrase("", []byte("passphrase"))
	if err == nil {
		t.Fatal("expected error for empty vault dir")
	}
}

func TestOpenWithPassphraseEmptyPassphrase(t *testing.T) {
	vaultDir := t.TempDir()
	_, err := OpenWithPassphrase(vaultDir, []byte{})
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestInitWithPassphraseEmptyVaultDir(t *testing.T) {
	_, err := InitWithPassphrase("", []byte("passphrase"), config.Default())
	if err == nil {
		t.Fatal("expected error for empty vault dir")
	}
}

func TestInitWithPassphraseEmptyPassphrase(t *testing.T) {
	vaultDir := t.TempDir()
	_, err := InitWithPassphrase(vaultDir, []byte{}, config.Default())
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestInitWithPassphraseNilConfig(t *testing.T) {
	vaultDir := t.TempDir()
	_, err := InitWithPassphrase(vaultDir, []byte("passphrase"), nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestEntryPathWithNilVault(t *testing.T) {
	var v *Vault
	got := EntryPath(v, "github.com/user")
	want := filepath.Join("entries", "github.com", "user.age")
	if got != want {
		t.Errorf("EntryPath(nil, path) = %q, want %q", got, want)
	}
}

func TestEnsureDirWithNilVault(t *testing.T) {
	var v *Vault
	err := EnsureDir(v, "github.com/user")
	if err == nil {
		t.Fatal("expected error for nil vault")
	}
}

func TestGetRecipientNilIdentity(t *testing.T) {
	v := &Vault{Dir: t.TempDir(), Identity: nil}
	_, err := v.GetRecipient()
	if err == nil {
		t.Fatal("expected error for nil identity")
	}
}

func TestValidateIdentityNilVault(t *testing.T) {
	var v *Vault
	err := v.ValidateIdentity(nil)
	if err == nil {
		t.Fatal("expected error for nil vault")
	}
}

func TestNormalizeConfigNil(t *testing.T) {
	normalizeConfig(nil)
}

func TestNormalizeConfigWithNilAgents(t *testing.T) {
	cfg := config.Default()
	cfg.Agents = nil
	normalizeConfig(cfg)
	if cfg.Agents == nil {
		t.Error("Agents should be initialized")
	}
}

func TestInitWithReadOnlyDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod 0 has no effect")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not support Unix-style directory permissions for this test")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer os.Chmod(parent, 0o700)

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	err := Init(parent+"/no-write-vault", identity, cfg)
	if err == nil {
		t.Fatal("Init() on read-only parent = nil, want error")
	}
}

// BenchmarkConfigLoadFromDisk measures the cost of loading vault config from disk.
// This was previously done on every call to isPseudonymizeEnabled and other hot-path functions.
func BenchmarkConfigLoadFromDisk(b *testing.B) {
	vaultDir := b.TempDir()
	identity := testutil.TempIdentity(b)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := Init(vaultDir, identity, cfg); err != nil {
		b.Fatalf("Init() error = %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = config.Load(filepath.Join(vaultDir, "config.yaml"))
	}
}

// BenchmarkConfigLoadWithCache measures the cost of checking pseudonymization
// when config is already loaded (passed as parameter, no disk I/O).
func BenchmarkConfigLoadWithCache(b *testing.B) {
	vaultDir := b.TempDir()
	identity := testutil.TempIdentity(b)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := Init(vaultDir, identity, cfg); err != nil {
		b.Fatalf("Init() error = %v", err)
	}

	// Load config once (simulating what vault.Open does)
	cached, err := config.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		b.Fatalf("Load() error = %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_ = isPseudonymizeEnabled(cached)
	}
}

// BenchmarkEntryStoragePathOldVsNew compares the old (load-from-disk) vs new (cached config) paths.
func BenchmarkEntryStoragePathOldStyle(b *testing.B) {
	vaultDir := b.TempDir()
	identity := testutil.TempIdentity(b)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := Init(vaultDir, identity, cfg); err != nil {
		b.Fatalf("Init() error = %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_ = entryStoragePath(vaultDir, "github.com/user", identity, nil)
	}
}
