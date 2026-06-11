package ui

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"

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

func TestTUIModelDebouncesCursorDetailLoads(t *testing.T) {
	origDebounce := detailDebounce
	detailDebounce = time.Hour
	t.Cleanup(func() { detailDebounce = origDebounce })

	m := NewTUIModel(&vaultpkg.Vault{})
	m.loading = false
	m.entries = []string{"a", "b", "c"}
	m.filtered = append([]string(nil), m.entries...)

	next, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	if cmd == nil {
		t.Fatal("expected first cursor move to schedule detail load")
	}
	if next.selected != 1 || next.detailRequest != 1 {
		t.Fatalf("after first move selected=%d request=%d, want selected=1 request=1", next.selected, next.detailRequest)
	}

	next, cmd = next.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	if cmd == nil {
		t.Fatal("expected second cursor move to schedule detail load")
	}
	if next.selected != 2 || next.detailRequest != 2 {
		t.Fatalf("after second move selected=%d request=%d, want selected=2 request=2", next.selected, next.detailRequest)
	}

	model, cmd := next.Update(entryLoadRequestedMsg{requestID: 1, path: "b"})
	if cmd != nil {
		t.Fatal("stale debounced request should not start a decrypt")
	}

	_, cmd = model.(TUIModel).Update(entryLoadRequestedMsg{requestID: 2, path: "c"})
	if cmd == nil {
		t.Fatal("current debounced request should start a decrypt")
	}
}

func TestTUIModelIgnoresStaleEntryLoads(t *testing.T) {
	m := NewTUIModel(&vaultpkg.Vault{})
	m.loading = false
	m.entries = []string{"a", "b"}
	m.filtered = append([]string(nil), m.entries...)
	m.selected = 1
	m.detailRequest = 2

	staleEntry := &vaultpkg.Entry{Data: map[string]any{"password": "stale"}}
	model, cmd := m.Update(entryLoadedMsg{requestID: 1, path: "a", entry: staleEntry})
	if cmd != nil {
		t.Fatal("stale loaded entry should not return a command")
	}
	next := model.(TUIModel)
	if next.entry != nil || next.entryFor != "" {
		t.Fatalf("stale entry updated detail pane: entry=%v entryFor=%q", next.entry, next.entryFor)
	}

	currentEntry := &vaultpkg.Entry{Data: map[string]any{"password": "current"}}
	model, cmd = next.Update(entryLoadedMsg{requestID: 2, path: "b", entry: currentEntry})
	if cmd != nil {
		t.Fatal("current loaded entry should not return a command")
	}
	next = model.(TUIModel)
	if next.entry != currentEntry || next.entryFor != "b" {
		t.Fatalf("current entry not applied: entry=%v entryFor=%q", next.entry, next.entryFor)
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
