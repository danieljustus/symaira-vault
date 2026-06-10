package ui

import (
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/danieljustus/symaira-vault/internal/testutil"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
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

	vault := &vaultpkg.Vault{
		Dir:      vaultDir,
		Identity: id,
	}

	m := NewTUIModel(vault)

	if !m.loading {
		t.Error("expected model to be in loading state")
	}

	entriesList, err := vaultpkg.List(vault.Dir, "", vault.Identity)
	if err != nil {
		t.Fatalf("vaultpkg.List() error = %v", err)
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
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	vault := &vaultpkg.Vault{
		Dir:      vaultDir,
		Identity: id,
	}

	m := NewTUIModel(vault)

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

func TestTUIModelClearsClipboardBeforeQuitWhenCopyPending(t *testing.T) {
	origWriteClipboard := writeClipboard
	t.Cleanup(func() { writeClipboard = origWriteClipboard })

	tests := []struct {
		name string
		mode mode
		key  tea.KeyMsg
	}{
		{name: "normal q", mode: modeNormal, key: tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}},
		{name: "normal ctrl-c", mode: modeNormal, key: tea.KeyMsg{Type: tea.KeyCtrlC}},
		{name: "filter ctrl-c", mode: modeFilter, key: tea.KeyMsg{Type: tea.KeyCtrlC}},
		{name: "tag filter ctrl-c", mode: modeTagFilter, key: tea.KeyMsg{Type: tea.KeyCtrlC}},
		{name: "confirm delete ctrl-c", mode: modeConfirmDelete, key: tea.KeyMsg{Type: tea.KeyCtrlC}},
		{name: "confirm edit ctrl-c", mode: modeConfirmEdit, key: tea.KeyMsg{Type: tea.KeyCtrlC}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writes := []string{}
			writeClipboard = func(text string) error {
				writes = append(writes, text)
				return nil
			}

			m := NewTUIModel(&vaultpkg.Vault{})
			m.mode = tt.mode
			m.clipboardSeconds = 10

			_, cmd := m.handleKey(tt.key)
			if cmd == nil {
				t.Fatal("expected quit path to clear clipboard before quitting")
			}

			msg := cmd()
			if _, ok := msg.(clipboardQuitClearedMsg); !ok {
				t.Fatalf("message = %T, want clipboardQuitClearedMsg", msg)
			}
			if len(writes) != 1 || writes[0] != "" {
				t.Fatalf("clipboard writes = %#v, want one clear write", writes)
			}

			newModel, quitCmd := m.Update(msg)
			newM := newModel.(TUIModel)
			if newM.clipboardSeconds != 0 {
				t.Fatalf("clipboardSeconds = %d, want 0", newM.clipboardSeconds)
			}
			if quitCmd == nil {
				t.Fatal("expected quit command after clipboard clear")
			}
		})
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

	vault := &vaultpkg.Vault{
		Dir:      vaultDir,
		Identity: id,
	}

	entries, err := vaultpkg.List(vault.Dir, "", vault.Identity)
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
