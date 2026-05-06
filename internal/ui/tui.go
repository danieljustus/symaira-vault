// Package ui provides an interactive terminal UI for browsing and editing vault entries.
package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	clipboardapp "github.com/danieljustus/OpenPass/internal/clipboard"
	vaultcrypto "github.com/danieljustus/OpenPass/internal/crypto"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

const (
	defaultAutoClearSeconds = 30
	redactedValue           = "••••"
	generatedPasswordLength = 20
	keyQuit                 = "ctrl+c"
)

type mode int

const (
	modeNormal mode = iota
	modeFilter
	modeConfirmDelete
	modeConfirmEdit
)

type entryLoadedMsg struct {
	path  string
	entry *vaultpkg.Entry
	err   error
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
	err      error
}

type entryDeletedMsg struct {
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

type logMsg struct {
	message string
	isError bool
}

// TUIModel is the Bubble Tea model for the OpenPass two-pane terminal UI.
type TUIModel struct {
	svc vaultsvc.Service

	entries  []string
	filtered []string
	selected int
	entry    *vaultpkg.Entry
	entryFor string

	filterInput textinput.Model
	mode        mode
	revealed    bool
	help        bool
	loading     bool

	width  int
	height int

	status string
	err    error
}

var (
	appStyle = lipgloss.NewStyle().Padding(1, 2)

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240"))

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("212"))

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("229")).
			Background(lipgloss.Color("62")).
			Bold(true)

	mutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	errorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	keyStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
)

// NewTUIModel creates a Bubble Tea model backed by the provided vault service.
func NewTUIModel(svc vaultsvc.Service) TUIModel {
	input := textinput.New()
	input.Placeholder = "filter entries"
	input.Prompt = "/ "
	input.CharLimit = 256

	return TUIModel{
		svc:         svc,
		filterInput: input,
		loading:     true,
		status:      "Loading entries...",
	}
}

// Run starts the TUI. Command wiring is intentionally left to cmd/ui.go.
func Run(svc vaultsvc.Service) error {
	if svc == nil {
		return fmt.Errorf("nil vault service")
	}
	opts := []tea.ProgramOption{tea.WithAltScreen()}
	if logPath := os.Getenv("OPENPASS_TUI_LOG"); logPath != "" {
		f, err := tea.LogToFile(logPath, "")
		if err != nil {
			return fmt.Errorf("open TUI log: %w", err)
		}
		defer f.Close()
	}
	_, err := tea.NewProgram(NewTUIModel(svc), opts...).Run()
	return err
}

func (m TUIModel) Init() tea.Cmd {
	return loadEntriesCmd(m.svc)
}

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
		return m, m.loadSelectedEntry()
	case entryLoadedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.status = "Could not read entry"
			return m, nil
		}
		if msg.path == m.selectedPath() {
			m.entry = msg.entry
			m.entryFor = msg.path
			m.err = nil
		}
		return m, nil
	case copiedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.status = "Copy failed"
			return m, nil
		}
		m.err = nil
		m.status = msg.message
		return m, clearClipboardCmd(defaultAutoClearSeconds)
	case passwordGeneratedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.status = "Password generation failed"
			return m, nil
		}
		m.err = nil
		m.status = "Generated password copied to clipboard"
		return m, copyTextCmd(msg.password, "Generated password copied to clipboard")
	case entryDeletedMsg:
		m.mode = modeNormal
		if msg.err != nil {
			m.err = msg.err
			m.status = "Delete failed"
			return m, nil
		}
		m.err = nil
		m.status = fmt.Sprintf("Deleted %s", msg.path)
		return m, loadEntriesCmd(m.svc)
	case entryEditedMsg:
		m.mode = modeNormal
		if msg.err != nil {
			m.err = msg.err
			m.status = "Edit failed"
			return m, nil
		}
		m.err = nil
		m.status = fmt.Sprintf("Updated %s", msg.path)
		return m, m.loadSelectedEntry()
	case clipboardClearedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.status = "Clipboard clear failed"
			return m, nil
		}
		m.status = "Clipboard cleared"
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

func (m TUIModel) View() string {
	if m.width == 0 {
		return "Loading OpenPass UI..."
	}

	contentHeight := max(8, m.height-6)
	leftWidth := max(24, m.width/3)
	rightWidth := max(32, m.width-leftWidth-8)

	left := borderStyle.Width(leftWidth).Height(contentHeight).Render(m.leftView(leftWidth, contentHeight))
	right := borderStyle.Width(rightWidth).Height(contentHeight).Render(m.rightView(rightWidth, contentHeight))
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)

	footer := m.statusView()
	if m.help {
		footer = m.helpView()
	}
	if m.mode == modeConfirmDelete || m.mode == modeConfirmEdit {
		footer = m.confirmView()
	}

	return appStyle.Render(lipgloss.JoinVertical(lipgloss.Left, body, footer))
}

//nolint:gocyclo // Key handler dispatches across many keyboard shortcuts by design.
func (m TUIModel) handleKey(msg tea.KeyMsg) (TUIModel, tea.Cmd) {
	if m.mode == modeFilter {
		switch msg.String() {
		case "esc", "enter":
			m.mode = modeNormal
			m.filterInput.Blur()
			return m, m.loadSelectedEntry()
		case keyQuit:
			return m, tea.Quit
		}

		var cmd tea.Cmd
		m.filterInput, cmd = m.filterInput.Update(msg)
		m.applyFilter()
		return m, cmd
	}

	if m.mode == modeConfirmDelete || m.mode == modeConfirmEdit {
		switch msg.String() {
		case "y", "Y":
			path := m.selectedPath()
			if path == "" {
				m.mode = modeNormal
				return m, nil
			}
			if m.mode == modeConfirmDelete {
				return m, deleteEntryCmd(m.svc, path)
			}
			return m, editEntryCmd(m.svc, path)
		case "n", "N", "esc":
			m.mode = modeNormal
			m.status = "Canceled"
			return m, nil
		case keyQuit:
			return m, tea.Quit
		}
		return m, nil
	}

	switch msg.String() {
	case "q", keyQuit:
		return m, tea.Quit
	case "?":
		m.help = !m.help
		return m, nil
	case "/":
		m.mode = modeFilter
		m.filterInput.Focus()
		return m, textinput.Blink
	case "r":
		m.revealed = !m.revealed
		return m, nil
	case "up", "k":
		if m.selected > 0 {
			m.selected--
			return m, m.loadSelectedEntry()
		}
	case "down", "j":
		if m.selected < len(m.filtered)-1 {
			m.selected++
			return m, m.loadSelectedEntry()
		}
	case "home":
		m.selected = 0
		return m, m.loadSelectedEntry()
	case "end":
		if len(m.filtered) > 0 {
			m.selected = len(m.filtered) - 1
			return m, m.loadSelectedEntry()
		}
	case "enter":
		return m, m.copySelectedPassword()
	case "d":
		if m.selectedPath() != "" {
			m.mode = modeConfirmDelete
		}
		return m, nil
	case "e":
		if m.selectedPath() != "" {
			m.mode = modeConfirmEdit
		}
		return m, nil
	case "g":
		return m, generatePasswordCmd()
	}

	return m, nil
}

func (m *TUIModel) applyFilter() {
	query := strings.TrimSpace(m.filterInput.Value())
	m.filtered = m.filtered[:0]
	for _, entry := range m.entries {
		if fuzzyMatch(query, entry) {
			m.filtered = append(m.filtered, entry)
		}
	}
	if m.selected >= len(m.filtered) {
		m.selected = max(0, len(m.filtered)-1)
	}
}

func (m TUIModel) loadSelectedEntry() tea.Cmd {
	path := m.selectedPath()
	if path == "" {
		return nil
	}
	return loadEntryCmd(m.svc, path)
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
		value, err := m.svc.GetField(path, "password")
		if err != nil {
			return copiedMsg{err: fmt.Errorf("read password: %w", err)}
		}
		return copyTextMsg(fmt.Sprint(value), fmt.Sprintf("Copied password for %s", path))
	}
}

func (m TUIModel) leftView(width, height int) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Entries"))
	b.WriteString("\n")
	if m.mode == modeFilter {
		b.WriteString(m.filterInput.View())
	} else if q := strings.TrimSpace(m.filterInput.Value()); q != "" {
		b.WriteString(mutedStyle.Render("Filter: " + q))
	} else {
		b.WriteString(mutedStyle.Render("/ to filter"))
	}
	b.WriteString("\n\n")

	if m.loading {
		b.WriteString("Loading entries...\n")
		return b.String()
	}
	if len(m.filtered) == 0 {
		b.WriteString(mutedStyle.Render("No entries"))
		return b.String()
	}

	listHeight := max(1, height-5)
	start := 0
	if m.selected >= listHeight {
		start = m.selected - listHeight + 1
	}
	end := min(len(m.filtered), start+listHeight)

	for i := start; i < end; i++ {
		line := truncate(m.filtered[i], width-4)
		if i == m.selected {
			line = selectedStyle.Width(width - 4).Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func (m TUIModel) rightView(width, height int) string {
	path := m.selectedPath()
	if path == "" {
		return titleStyle.Render("Details") + "\n\n" + mutedStyle.Render("Select an entry")
	}
	if m.entry == nil || m.entryFor != path {
		return titleStyle.Render(path) + "\n\n" + mutedStyle.Render("Loading details...")
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render(path))
	b.WriteString("\n")
	b.WriteString(mutedStyle.Render("Updated: " + m.entry.Metadata.Updated.Format("2006-01-02 15:04")))
	b.WriteString("\n\n")

	keys := make([]string, 0, len(m.entry.Data))
	for key := range m.entry.Data {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	maxRows := max(1, height-6)
	for i, key := range keys {
		if i >= maxRows {
			b.WriteString(mutedStyle.Render("..."))
			break
		}
		value := fmt.Sprint(m.entry.Data[key])
		if !m.revealed && isSensitiveField(key) {
			value = redactedValue
		}
		line := fmt.Sprintf("%s: %s", keyStyle.Render(key), value)
		b.WriteString(truncate(line, width-4))
		b.WriteString("\n")
	}

	return b.String()
}

func (m TUIModel) statusView() string {
	status := m.status
	if m.err != nil {
		status = errorStyle.Render(m.err.Error())
	}
	keys := "↑/↓ select · Enter copy password · r reveal · e edit · d delete · g generate · ? help · q quit"
	return mutedStyle.Render(keys) + "\n" + status
}

func (m TUIModel) helpView() string {
	return strings.Join([]string{
		titleStyle.Render("Help"),
		"↑/↓ or k/j: move selection",
		"/: fuzzy filter entries",
		"Enter: copy password field to clipboard",
		"r: reveal or redact sensitive fields",
		"e: edit selected entry after confirmation",
		"d: delete selected entry after confirmation",
		"g: generate password and copy it to clipboard",
		"q or Ctrl+C: quit",
	}, "\n")
}

func (m TUIModel) confirmView() string {
	verb := "delete"
	if m.mode == modeConfirmEdit {
		verb = "edit"
	}
	return errorStyle.Render(fmt.Sprintf("Confirm %s %s?", verb, m.selectedPath())) + "  " + mutedStyle.Render("y/N")
}

func loadEntriesCmd(svc vaultsvc.Service) tea.Cmd {
	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				msg = entriesLoadedMsg{err: fmt.Errorf("panic loading entries: %v", r)}
			}
		}()
		entries, err := svc.List("")
		if err != nil {
			return entriesLoadedMsg{err: err}
		}
		sort.Strings(entries)
		return entriesLoadedMsg{entries: entries}
	}
}

func loadEntryCmd(svc vaultsvc.Service, path string) tea.Cmd {
	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				msg = entryLoadedMsg{path: path, err: fmt.Errorf("panic loading entry %s: %v", path, r)}
			}
		}()
		entry, err := svc.GetEntry(path)
		return entryLoadedMsg{path: path, entry: entry, err: err}
	}
}

func copyTextCmd(text, message string) tea.Cmd {
	return func() tea.Msg {
		return copyTextMsg(text, message)
	}
}

func copyTextMsg(text, message string) tea.Msg {
	if err := clipboard.WriteAll(text); err != nil {
		return copiedMsg{err: fmt.Errorf("copy to clipboard: %w", err)}
	}
	return copiedMsg{message: message}
}

func clearClipboardCmd(seconds int) tea.Cmd {
	return func() tea.Msg {
		done := make(chan struct{})
		var clearErr error
		clipboardapp.StartAutoClear(seconds, func() {
			clearErr = clipboard.WriteAll("")
			close(done)
		}, nil)
		<-done
		return clipboardClearedMsg{err: clearErr}
	}
}

func generatePasswordCmd() tea.Cmd {
	return func() tea.Msg {
		password, err := vaultcrypto.GeneratePassword(generatedPasswordLength, true)
		return passwordGeneratedMsg{password: password, err: err}
	}
}

func deleteEntryCmd(svc vaultsvc.Service, path string) tea.Cmd {
	return func() tea.Msg {
		err := svc.Delete(path)
		return entryDeletedMsg{path: path, err: err}
	}
}

func editEntryCmd(svc vaultsvc.Service, path string) tea.Cmd {
	return func() tea.Msg {
		entry, err := svc.GetEntry(path)
		if err != nil {
			return entryEditedMsg{path: path, err: err}
		}

		tmp, err := os.CreateTemp("", "openpass-*.json")
		if err != nil {
			return entryEditedMsg{path: path, err: err}
		}
		tmpPath := tmp.Name()
		defer func() { _ = os.Remove(tmpPath) }()

		encoder := json.NewEncoder(tmp)
		encoder.SetIndent("", "  ")
		if encErr := encoder.Encode(entry); encErr != nil {
			_ = tmp.Close()
			return entryEditedMsg{path: path, err: encErr}
		}
		if closeErr := tmp.Close(); closeErr != nil {
			return entryEditedMsg{path: path, err: closeErr}
		}

		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "vi"
		}
		cmd := exec.Command(editor, tmpPath) //#nosec G204 -- EDITOR is explicitly user-controlled CLI behavior.
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if runErr := cmd.Run(); runErr != nil {
			return entryEditedMsg{path: path, err: fmt.Errorf("run editor: %w", runErr)}
		}

		data, err := os.ReadFile(filepath.Clean(tmpPath)) //#nosec G304 -- tmpPath was created by this process.
		if err != nil {
			return entryEditedMsg{path: path, err: err}
		}
		var edited vaultpkg.Entry
		if err := json.Unmarshal(data, &edited); err != nil {
			return entryEditedMsg{path: path, err: fmt.Errorf("parse edited entry: %w", err)}
		}
		if edited.Data == nil {
			return entryEditedMsg{path: path, err: fmt.Errorf("edited entry must contain data")}
		}
		if err := svc.WriteEntry(path, &edited); err != nil {
			return entryEditedMsg{path: path, err: err}
		}
		return entryEditedMsg{path: path}
	}
}

func fuzzyMatch(query, value string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	value = strings.ToLower(value)
	if strings.Contains(value, query) {
		return true
	}
	queryRunes := []rune(query)
	idx := 0
	for _, r := range value {
		if idx < len(queryRunes) && r == queryRunes[idx] {
			idx++
		}
	}
	return idx == len(queryRunes)
}

func isSensitiveField(field string) bool {
	field = strings.ToLower(field)
	return strings.Contains(field, "pass") ||
		strings.Contains(field, "secret") ||
		strings.Contains(field, "token") ||
		strings.Contains(field, "key") ||
		strings.Contains(field, "otp") ||
		strings.Contains(field, "pin")
}

func truncate(value string, width int) string {
	if width <= 1 || len(value) <= width {
		return value
	}
	return value[:width-1] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
