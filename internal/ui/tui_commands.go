package ui

import (
	"fmt"
	"os"
	"sort"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	clipboardapp "github.com/danieljustus/symaira-vault/internal/clipboard"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/secureedit"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func loadEntriesCmd(vault *vaultpkg.Vault) tea.Cmd {
	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				msg = entriesLoadedMsg{err: fmt.Errorf("panic loading entries: %v", r)}
			}
		}()
		entries, err := vaultpkg.List(vault.Dir, "", vault.Identity)
		if err != nil {
			return entriesLoadedMsg{err: err}
		}
		sort.Strings(entries)
		return entriesLoadedMsg{entries: entries}
	}
}

func loadEntryCmd(vault *vaultpkg.Vault, path string, requestID uint64) tea.Cmd {
	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				msg = entryLoadedMsg{requestID: requestID, path: path, err: fmt.Errorf("panic loading entry %s: %v", path, r)}
			}
		}()
		entry, err := vaultpkg.ReadEntry(vault.Dir, path, vault.Identity)
		return entryLoadedMsg{requestID: requestID, path: path, entry: entry, err: err}
	}
}

func copyTextCmd(text, message string, cleanup func()) tea.Cmd {
	return func() tea.Msg {
		result := copyTextMsg(text, message)
		if cleanup != nil {
			cleanup()
		}
		return result
	}
}

func copyTextMsg(text, message string) tea.Msg {
	if err := writeClipboard(text); err != nil {
		return copiedMsg{err: fmt.Errorf("copy to clipboard: %w", err)}
	}
	return copiedMsg{message: message}
}

func clearClipboardCmd(seconds int) tea.Cmd {
	return func() tea.Msg {
		done := make(chan struct{})
		var clearErr error
		clipboardapp.StartAutoClear(seconds, func() {
			clearErr = writeClipboard("")
			close(done)
		}, nil)
		<-done
		return clipboardClearedMsg{err: clearErr}
	}
}

func clearClipboardBeforeQuitCmd() tea.Cmd {
	return func() tea.Msg {
		return clipboardQuitClearedMsg{err: writeClipboard("")}
	}
}

func clipboardTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(_ time.Time) tea.Msg {
		return clipboardTickMsg{}
	})
}

func generatePasswordCmd(length int, symbols bool) tea.Cmd {
	return func() tea.Msg {
		password, cleanup, err := vaultcrypto.GeneratePassword(length, symbols)
		return passwordGeneratedMsg{password: password, cleanup: cleanup, err: err}
	}
}

func deleteEntryCmd(vault *vaultpkg.Vault, path string) tea.Cmd {
	return func() tea.Msg {
		err := vaultpkg.DeleteEntry(vault.Dir, path, vault.Identity)
		if err != nil {
			return entryDeletedMsg{path: path, err: err}
		}
		_ = vault.AutoCommitEntry(fmt.Sprintf("Delete %s", path), path)
		vault.Cache.Invalidate()
		return entryDeletedMsg{path: path}
	}
}

func editEntryCmd(vault *vaultpkg.Vault, path string) tea.Cmd {
	return func() tea.Msg {
		entry, err := vaultpkg.ReadEntry(vault.Dir, path, vault.Identity)
		if err != nil {
			return entryEditedMsg{path: path, err: err}
		}
		edited, err := secureedit.EditEntry(entry, os.Getenv("EDITOR"), secureedit.DefaultStreams())
		if err != nil {
			return entryEditedMsg{path: path, err: err}
		}
		if err := vaultpkg.WriteEntryWithRecipients(vault.Dir, path, edited, vault.Identity); err != nil {
			return entryEditedMsg{path: path, err: err}
		}
		_ = vault.AutoCommitEntry(fmt.Sprintf("Edit %s", path), path)
		vault.Cache.Invalidate()
		return entryEditedMsg{path: path}
	}
}

func addEntryCmd(vault *vaultpkg.Vault, path string) tea.Cmd {
	return func() tea.Msg {
		now := time.Now()
		entry := &vaultpkg.Entry{
			Path: path,
			Data: map[string]any{"password": ""},
			Metadata: vaultpkg.EntryMetadata{
				Created: now,
				Updated: now,
				Version: 1,
			},
		}
		edited, err := secureedit.EditEntry(entry, os.Getenv("EDITOR"), secureedit.DefaultStreams())
		if err != nil {
			return entryAddedMsg{path: path, err: err}
		}
		if err := vaultpkg.WriteEntryWithRecipients(vault.Dir, path, edited, vault.Identity); err != nil {
			return entryAddedMsg{path: path, err: err}
		}
		_ = vault.AutoCommitEntry(fmt.Sprintf("Add %s", path), path)
		vault.Cache.Invalidate()
		return entryAddedMsg{path: path}
	}
}
