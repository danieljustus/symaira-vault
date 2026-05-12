package ui

import (
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/danieljustus/OpenPass/internal/testutil"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

func TestTUIModelLoadsEntries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: LockFileEx access violation in AcquireWriteLock")
	}
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	entries := []struct {
		path string
		data map[string]any
	}{
		{"github.com/user", map[string]any{"username": "alice", "password": "secret1"}},
		{"github.com/work", map[string]any{"username": "bob", "password": "secret2"}},
		{"personal/email", map[string]any{"username": "carol", "password": "secret3"}},
	}

	for _, e := range entries {
		entry := &vaultpkg.Entry{Data: e.data}
		if err := vaultpkg.WriteEntry(vaultDir, e.path, entry, id); err != nil {
			t.Fatalf("WriteEntry(%s) error = %v", e.path, err)
		}
	}

	v := &vaultpkg.Vault{
		Dir:      vaultDir,
		Identity: id,
	}
	svc := vaultsvc.New(slog.Default(), v)

	m := NewTUIModel(svc)

	if !m.loading {
		t.Error("expected model to be in loading state")
	}

	entriesList, err := svc.List("")
	if err != nil {
		t.Fatalf("svc.List() error = %v", err)
	}

	msg := entriesLoadedMsg{entries: entriesList}
	newModel, _ := m.Update(msg)
	newM := newModel.(TUIModel)

	if newM.loading {
		t.Error("expected model to not be in loading state after entries loaded")
	}

	if len(newM.entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(newM.entries))
	}

	if len(newM.filtered) != 3 {
		t.Errorf("expected 3 filtered entries, got %d", len(newM.filtered))
	}
}

func TestTUIModelHandlesListError(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	v := &vaultpkg.Vault{
		Dir:      vaultDir,
		Identity: id,
	}
	svc := vaultsvc.New(slog.Default(), v)

	m := NewTUIModel(svc)

	msg := entriesLoadedMsg{err: filepath.ErrBadPattern}
	newModel, _ := m.Update(msg)
	newM := newModel.(TUIModel)

	if newM.loading {
		t.Error("expected model to not be in loading state after error")
	}

	if newM.err == nil {
		t.Error("expected error to be set")
	}
}

func TestLoadEntriesCmdIntegration(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	if err := vaultpkg.WriteEntry(vaultDir, "test/entry", &vaultpkg.Entry{
		Data: map[string]any{"password": "secret"},
	}, id); err != nil {
		t.Fatalf("WriteEntry error = %v", err)
	}

	v := &vaultpkg.Vault{
		Dir:      vaultDir,
		Identity: id,
	}
	svc := vaultsvc.New(slog.Default(), v)

	entries, err := svc.List("")
	if err != nil {
		t.Fatalf("List error = %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}

	if entries[0] != "test/entry" {
		t.Errorf("expected 'test/entry', got %q", entries[0])
	}
}
