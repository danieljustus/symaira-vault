package vault

import (
	"testing"

	"github.com/danieljustus/symaira-vault/internal/testutil"
)

func TestVaultList_NilVault(t *testing.T) {
	var v *Vault
	_, err := v.List("prefix")
	if err == nil {
		t.Fatal("expected error when vault is nil")
	}
}

func TestVaultList_ReturnsEntries(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	if _, err := InitWithPassphrase(vaultDir, []byte("test-passphrase"), testConfig(vaultDir)); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := WriteEntry(vaultDir, "alpha", &Entry{Data: map[string]any{"v": "a"}}, id); err != nil {
		t.Fatalf("write alpha: %v", err)
	}
	if err := WriteEntry(vaultDir, "beta", &Entry{Data: map[string]any{"v": "b"}}, id); err != nil {
		t.Fatalf("write beta: %v", err)
	}
	FlushManifestUpdates()

	v, err := Open(vaultDir, id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	entries, err := v.List("")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2: %v", len(entries), entries)
	}
}

func TestVaultList_FilteredByPrefix(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	if _, err := InitWithPassphrase(vaultDir, []byte("test-passphrase"), testConfig(vaultDir)); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := WriteEntry(vaultDir, "work/aws", &Entry{Data: map[string]any{"v": "a"}}, id); err != nil {
		t.Fatalf("write work/aws: %v", err)
	}
	if err := WriteEntry(vaultDir, "personal/github", &Entry{Data: map[string]any{"v": "g"}}, id); err != nil {
		t.Fatalf("write personal/github: %v", err)
	}
	FlushManifestUpdates()

	v, err := Open(vaultDir, id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	entries, err := v.List("work")
	if err != nil {
		t.Fatalf("List(work): %v", err)
	}
	if len(entries) != 1 || entries[0] != "work/aws" {
		t.Fatalf("List(work) = %v, want [work/aws]", entries)
	}
}

func TestVaultFindWithOptions_NilVault(t *testing.T) {
	var v *Vault
	_, err := v.FindWithOptions("query", FindOptions{})
	if err == nil {
		t.Fatal("expected error when vault is nil")
	}
}

func TestVaultFindWithOptions_ReturnsMatches(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	if _, err := InitWithPassphrase(vaultDir, []byte("test-passphrase"), testConfig(vaultDir)); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := WriteEntry(vaultDir, "work/aws", &Entry{Data: map[string]any{"service": "aws", "key": "AKIA123"}}, id); err != nil {
		t.Fatalf("write work/aws: %v", err)
	}
	FlushManifestUpdates()

	v, err := Open(vaultDir, id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	matches, err := v.FindWithOptions("aws", FindOptions{MaxWorkers: 1})
	if err != nil {
		t.Fatalf("FindWithOptions: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least one match for 'aws'")
	}
}

func TestVaultReadEntry_NilVault(t *testing.T) {
	var v *Vault
	_, err := v.ReadEntry("path")
	if err == nil {
		t.Fatal("expected error when vault is nil")
	}
}

func TestVaultReadEntry_ReturnsEntry(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	if _, err := InitWithPassphrase(vaultDir, []byte("test-passphrase"), testConfig(vaultDir)); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := WriteEntry(vaultDir, "test/entry", &Entry{Data: map[string]any{"username": "alice"}}, id); err != nil {
		t.Fatalf("write: %v", err)
	}
	FlushManifestUpdates()

	v, err := Open(vaultDir, id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	entry, err := v.ReadEntry("test/entry")
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if entry == nil {
		t.Fatal("ReadEntry returned nil entry")
	}
	if entry.Data["username"] != "alice" {
		t.Errorf("username = %v, want alice", entry.Data["username"])
	}
}

func TestVaultReadEntry_MissingPath(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	if _, err := InitWithPassphrase(vaultDir, []byte("test-passphrase"), testConfig(vaultDir)); err != nil {
		t.Fatalf("init: %v", err)
	}

	v, err := Open(vaultDir, id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	_, err = v.ReadEntry("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing entry")
	}
}
