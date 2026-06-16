// Package ui provides an interactive terminal UI for browsing and editing vault entries.
package ui

import (
	"fmt"
	"os"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	theme "github.com/danieljustus/symaira-vault/internal/ui/theme"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	defaultAutoClearSeconds = 30
	redactedValue           = "\u2022\u2022\u2022\u2022"
	generatedPasswordLength = 20
	keyQuit                 = "ctrl+c"
	keyEnter                = "enter"
	keyEsc                  = "esc"
)

func (m *TUIModel) autoClearSeconds() int {
	if m.vault != nil && m.vault.Config != nil && m.vault.Config.Clipboard != nil {
		if m.vault.Config.Clipboard.AutoClearDuration >= 0 {
			return m.vault.Config.Clipboard.AutoClearDuration
		}
	}
	return defaultAutoClearSeconds
}

type mode int

const (
	modeNormal mode = iota
	modeFilter
	modeConfirmDelete
	modeConfirmEdit
	modeTagFilter
	modeAdd
	modeGenConfig
)

type entryLoadedMsg struct {
	requestID uint64
	path      string
	entry     *vaultpkg.Entry
	err       error
}

type entryLoadRequestedMsg struct {
	requestID uint64
	path      string
}

type entriesLoadedMsg struct {
	entries []string
	err     error
}

type copiedMsg struct {
	message string
	err     error
}

type passwordGeneratedMsg struct {
	password string
	cleanup  func()
	err      error
}

type entryDeletedMsg struct {
	path string
	err  error
}

type entryAddedMsg struct {
	path string
	err  error
}

type entryEditedMsg struct {
	path string
	err  error
}

type clipboardClearedMsg struct {
	err error
}

type clipboardQuitClearedMsg struct {
	err error
}

type clipboardTickMsg struct{}

type logMsg struct {
	message string
	isError bool
}

// TUIModel is the Bubble Tea model for the Symaira Vault two-pane terminal UI.
type TUIModel struct {
	vault *vaultpkg.Vault

	entries  []string
	filtered []string
	selected int
	entry    *vaultpkg.Entry
	entryFor string

	filterInput    textinput.Model
	tagFilterInput textinput.Model
	addPathInput   textinput.Model
	genLengthInput textinput.Model
	genSymbols     bool
	mode           mode
	revealed       bool
	help           bool
	loading        bool
	detailRequest  uint64

	sortMode  int
	filterTag string
	metaCache map[string]vaultpkg.EntryMetadata

	width  int
	height int

	status string
	err    error

	pendingSelectPath string

	clipboardSeconds int
	clipboardMessage string
}

var (
	writeClipboard = clipboard.WriteAll
	detailDebounce = 100 * time.Millisecond

	appStyle = lipgloss.NewStyle().Padding(1, 2)

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(theme.ColorMuted)

	borderFocusStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(theme.ColorFocused)
)

// NewTUIModel creates a Bubble Tea model backed by the provided vault.
func NewTUIModel(vault *vaultpkg.Vault) TUIModel {
	input := textinput.New()
	input.Placeholder = "filter entries"
	input.Prompt = "/ "
	input.CharLimit = 256

	tagInput := textinput.New()
	tagInput.Placeholder = "filter by tag"
	tagInput.Prompt = "t: "
	tagInput.CharLimit = 256

	addInput := textinput.New()
	addInput.Placeholder = "entry path"
	addInput.Prompt = "a: "
	addInput.CharLimit = 256

	genInput := textinput.New()
	genInput.Placeholder = "20"
	genInput.Prompt = "length: "
	genInput.CharLimit = 4

	return TUIModel{
		vault:          vault,
		filterInput:    input,
		tagFilterInput: tagInput,
		addPathInput:   addInput,
		genLengthInput: genInput,
		genSymbols:     true,
		loading:        true,
		status:         "Loading entries...",
	}
}

// Run starts the TUI.
func Run(vault *vaultpkg.Vault) error {
	if vault == nil {
		return fmt.Errorf("nil vault")
	}
	opts := []tea.ProgramOption{tea.WithAltScreen()}
	logPath := os.Getenv("SYMVAULT_TUI_LOG")
	if logPath == "" {
		logPath = os.Getenv("OPENPASS_TUI_LOG")
	}
	if logPath != "" {
		f, err := tea.LogToFile(logPath, "")
		if err != nil {
			return fmt.Errorf("open TUI log: %w", err)
		}
		defer func() { _ = f.Close() }()
	}
	_, err := tea.NewProgram(NewTUIModel(vault), opts...).Run()
	return err
}

func (m TUIModel) Init() tea.Cmd {
	return loadEntriesCmd(m.vault)
}

//nolint:gocyclo
func (m TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	case entriesLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err
			m.status = "Could not load entries"
			return m, nil
		}
		m.entries = msg.entries
		m.applyFilter()
		m.status = fmt.Sprintf("%d entries", len(m.entries))
		if m.pendingSelectPath != "" {
			for i, e := range m.filtered {
				if e == m.pendingSelectPath {
					m.selected = i
					break
				}
			}
			m.pendingSelectPath = ""
		}
		return m, m.loadSelectedEntry()
	case entryLoadRequestedMsg:
		if msg.requestID != m.detailRequest || msg.path != m.selectedPath() {
			return m, nil
		}
		return m, loadEntryCmd(m.vault, msg.path, msg.requestID)
	case entryLoadedMsg:
		if msg.requestID != m.detailRequest || msg.path != m.selectedPath() {
			return m, nil
		}
		if msg.err != nil {
			m.err = msg.err
			m.status = "Could not read entry"
			return m, nil
		}
		m.entry = msg.entry
		m.entryFor = msg.path
		m.err = nil
		return m, nil
	case copiedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.status = "Copy failed"
			return m, nil
		}
		m.err = nil
		m.status = msg.message
		m.clipboardMessage = msg.message
		ttl := m.autoClearSeconds()
		m.clipboardSeconds = ttl
		return m, tea.Batch(clearClipboardCmd(ttl), clipboardTickCmd())
	case passwordGeneratedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.status = "Password generation failed"
			return m, nil
		}
		m.err = nil
		m.status = "Generated password copied to clipboard"
		return m, copyTextCmd(msg.password, "Generated password copied to clipboard", msg.cleanup)
	case entryDeletedMsg:
		m.mode = modeNormal
		if msg.err != nil {
			m.err = msg.err
			m.status = "Delete failed"
			return m, nil
		}
		delete(m.metaCache, msg.path)
		m.err = nil
		m.status = fmt.Sprintf("Deleted %s", msg.path)
		return m, loadEntriesCmd(m.vault)
	case entryAddedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.status = "Add failed"
			return m, nil
		}
		m.err = nil
		m.status = fmt.Sprintf("Added %s", msg.path)
		m.pendingSelectPath = msg.path
		return m, loadEntriesCmd(m.vault)
	case entryEditedMsg:
		m.mode = modeNormal
		if msg.err != nil {
			m.err = msg.err
			m.status = "Edit failed"
			return m, nil
		}
		delete(m.metaCache, msg.path)
		m.err = nil
		m.status = fmt.Sprintf("Updated %s", msg.path)
		return m, m.loadSelectedEntry()
	case clipboardClearedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.status = "Clipboard clear failed"
			return m, nil
		}
		m.clipboardSeconds = 0
		m.status = "Clipboard cleared"
		return m, nil
	case clipboardQuitClearedMsg:
		m.clipboardSeconds = 0
		if msg.err != nil {
			m.err = msg.err
			m.status = "Clipboard clear failed"
		}
		return m, tea.Quit
	case clipboardTickMsg:
		if m.clipboardSeconds > 0 {
			m.clipboardSeconds--
			if m.clipboardSeconds > 0 {
				return m, clipboardTickCmd()
			}
		}
		return m, nil
	case logMsg:
		if msg.isError {
			m.err = fmt.Errorf("%s", msg.message)
			m.status = msg.message
		} else {
			m.status = msg.message
		}
		return m, nil
	}

	return m, nil
}

func (m TUIModel) quitCmd() tea.Cmd {
	if m.clipboardSeconds <= 0 {
		return tea.Quit
	}
	return clearClipboardBeforeQuitCmd()
}

func (m *TUIModel) loadSelectedEntry() tea.Cmd {
	return m.scheduleSelectedEntryLoad(0)
}

func (m *TUIModel) debounceSelectedEntry() tea.Cmd {
	return m.scheduleSelectedEntryLoad(detailDebounce)
}

func (m *TUIModel) scheduleSelectedEntryLoad(delay time.Duration) tea.Cmd {
	path := m.selectedPath()
	if path == "" {
		m.entry = nil
		m.entryFor = ""
		return nil
	}
	if m.entryFor != path {
		m.entry = nil
		m.entryFor = ""
	}
	m.detailRequest++
	requestID := m.detailRequest
	if delay <= 0 {
		return loadEntryCmd(m.vault, path, requestID)
	}
	return tea.Tick(delay, func(time.Time) tea.Msg {
		return entryLoadRequestedMsg{requestID: requestID, path: path}
	})
}

func (m TUIModel) selectedPath() string {
	if m.selected < 0 || m.selected >= len(m.filtered) {
		return ""
	}
	return m.filtered[m.selected]
}

func (m TUIModel) copySelectedPassword() tea.Cmd {
	path := m.selectedPath()
	if path == "" {
		return nil
	}
	return func() tea.Msg {
		entry, err := vaultpkg.ReadEntry(m.vault.Dir, path, m.vault.Identity)
		if err != nil {
			return copiedMsg{err: fmt.Errorf("read password: %w", err)}
		}
		value, ok := entry.Data["password"]
		if !ok {
			return copiedMsg{err: fmt.Errorf("password field not found")}
		}
		return copyTextMsg(fmt.Sprint(value), fmt.Sprintf("Copied password for %s", path))
	}
}
