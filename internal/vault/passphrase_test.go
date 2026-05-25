package vault

import (
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
)

func TestInitWithPassphraseRoundTrip(t *testing.T) {
	vaultDir := t.TempDir()
	cfg := config.Default()
	cfg.VaultDir = vaultDir

	passphrase := []byte("correct horse battery staple")
	identity, err := InitWithPassphrase(vaultDir, passphrase, cfg)
	if err != nil {
		t.Fatalf("InitWithPassphrase() error = %v", err)
	}

	v, err := OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatalf("OpenWithPassphrase() error = %v", err)
	}

	if v.Identity == nil {
		t.Fatal("OpenWithPassphrase() returned nil identity")
	}
	if got := v.Identity.String(); got != identity.String() {
		t.Fatalf("OpenWithPassphrase() identity = %q, want %q", got, identity.String())
	}
	if v.Config == nil || v.Config.VaultDir != vaultDir {
		t.Fatalf("OpenWithPassphrase() config vault = %v, want %s", v.Config, vaultDir)
	}
}

func TestListSkipsIdentityMetadata(t *testing.T) {
	vaultDir := t.TempDir()
	cfg := config.Default()
	cfg.VaultDir = vaultDir

	identity, err := InitWithPassphrase(vaultDir, []byte("correct horse battery staple"), cfg)
	if err != nil {
		t.Fatalf("InitWithPassphrase() error = %v", err)
	}

	entry := &Entry{Data: map[string]any{"password": "hunter2"}}
	if err = WriteEntry(vaultDir, "demo", entry, identity); err != nil {
		t.Fatalf("WriteEntry() error = %v", err)
	}

	entries, err := List(vaultDir, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 1 || entries[0] != "demo" {
		t.Fatalf("List() = %v, want [demo]", entries)
	}
}
