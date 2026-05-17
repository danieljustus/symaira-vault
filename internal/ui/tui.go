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
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"

	clipboardapp "github.com/danieljustus/OpenPass/internal/clipboard"
	vaultcrypto "github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/envfilter"
	render "github.com/danieljustus/OpenPass/internal/ui/render"
	theme "github.com/danieljustus/OpenPass/internal/ui/theme"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
	taint "github.com/danieljustus/OpenPass/internal/vault/taint"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

const (
	defaultAutoClearSeconds = 30
	redactedValue           = "••••"
	generatedPasswordLength = 20
	keyQuit                 = "ctrl+c"
	keyEnter                = "enter"
	keyEsc                  = "esc"
)

// autoClearSeconds returns the clipboard auto-clear TTL for this TUI session,
// pulled from vault config.Clipboard.AutoClearDuration when available, else
// the compiled-in default. Returning <=0 disables auto-clear, mirroring the
// semantics in internal/clipboard.
func (m *TUIModel) autoClearSeconds() int {
	if m.svc != nil {
		if v := m.svc.Vault(); v != nil && v.Config != nil && v.Config.Clipboard != nil {
			if v.Config.Clipboard.AutoClearDuration >= 0 {
				return v.Config.Clipboard.AutoClearDuration
			}
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

type clipboardTickMsg struct{}

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

	filterInput    textinput.Model
	tagFilterInput textinput.Model
	mode           mode
	revealed       bool
	help           bool
	loading        bool

	sortMode  int // 0=name-asc, 1=name-desc, 2=updated-asc, 3=updated-desc
	filterTag string
	metaCache map[string]vaultpkg.EntryMetadata

	width  int
	height int

	status string
	err    error

	clipboardSeconds int
	clipboardMessage string
}

var (
	appStyle = lipgloss.NewStyle().Padding(1, 2)

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(theme.ColorMuted)

	borderFocusStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(theme.ColorFocused)
)

// NewTUIModel creates a Bubble Tea model backed by the provided vault service.
func NewTUIModel(svc vaultsvc.Service) TUIModel {
	input := textinput.New()
	input.Placeholder = "filter entries"
	input.Prompt = "/ "
	input.CharLimit = 256

	tagInput := textinput.New()
	tagInput.Placeholder = "filter by tag"
	tagInput.Prompt = "t: "
	tagInput.CharLimit = 256

	return TUIModel{
		svc:            svc,
		filterInput:    input,
		tagFilterInput: tagInput,
		loading:        true,
		status:         "Loading entries...",
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
		defer func() { _ = f.Close() }()
	}
	_, err := tea.NewProgram(NewTUIModel(svc), opts...).Run()
	return err
}

func (m TUIModel) Init() tea.Cmd {
	return loadEntriesCmd(m.svc)
}

//nolint:gocyclo // TUI update loop naturally has high cyclomatic complexity
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
		return m, copyTextCmd(msg.password, "Generated password copied to clipboard")
	case entryDeletedMsg:
		m.mode = modeNormal
		if msg.err != nil {
			m.err = msg.err
			m.status = "Delete failed"
			return m, nil
		}
		// Drop the stale cache entry so re-renders see fresh metadata.
		delete(m.metaCache, msg.path)
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
		// Drop the cached metadata for this path so the next sort/filter
		// reflects the edit (tags, updated timestamp).
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

func (m TUIModel) View() string {
	if m.width == 0 {
		return "Loading OpenPass UI..."
	}

	contentHeight := max(8, m.height-6)
	leftWidth := max(24, m.width/3)
	rightWidth := max(32, m.width-leftWidth-8)

	bs := borderStyle
	if m.mode == modeFilter || m.mode == modeTagFilter {
		bs = borderFocusStyle
	}
	left := bs.Width(leftWidth).Height(contentHeight).Render(m.leftView(leftWidth, contentHeight))
	right := bs.Width(rightWidth).Height(contentHeight).Render(m.rightView(rightWidth, contentHeight))
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
		case keyEsc, keyEnter:
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

	if m.mode == modeTagFilter {
		switch msg.String() {
		case keyEnter:
			m.mode = modeNormal
			m.tagFilterInput.Blur()
			m.filterTag = strings.TrimSpace(m.tagFilterInput.Value())
			m.applyFilter()
			return m, m.loadSelectedEntry()
		case keyEsc:
			m.mode = modeNormal
			m.tagFilterInput.Blur()
			m.tagFilterInput.SetValue("")
			m.filterTag = ""
			m.applyFilter()
			return m, m.loadSelectedEntry()
		case keyQuit:
			return m, tea.Quit
		}

		var cmd tea.Cmd
		m.tagFilterInput, cmd = m.tagFilterInput.Update(msg)
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
	case "s":
		m.sortMode = (m.sortMode + 1) % 4
		m.applyFilter()
		return m, nil
	case "t":
		m.ensureMetaCache()
		m.tagFilterInput.SetValue(m.filterTag)
		m.mode = modeTagFilter
		m.tagFilterInput.Focus()
		return m, textinput.Blink
	case "up", "k":
		if m.selected > 0 {
			m.selected--
			m.clipboardSeconds = 0
			return m, m.loadSelectedEntry()
		}
	case "down", "j":
		if m.selected < len(m.filtered)-1 {
			m.selected++
			m.clipboardSeconds = 0
			return m, m.loadSelectedEntry()
		}
	case "home":
		m.selected = 0
		m.clipboardSeconds = 0
		return m, m.loadSelectedEntry()
	case "end":
		if len(m.filtered) > 0 {
			m.selected = len(m.filtered) - 1
			m.clipboardSeconds = 0
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
		if fuzzyMatch(query, entry) && m.tagMatch(entry) {
			m.filtered = append(m.filtered, entry)
		}
	}
	m.sortFiltered()
	if m.selected >= len(m.filtered) {
		m.selected = max(0, len(m.filtered)-1)
	}
}

func (m *TUIModel) ensureMetaCache() {
	if m.metaCache == nil {
		m.metaCache = make(map[string]vaultpkg.EntryMetadata)
	}
	// Fill in any entries that are missing from the cache. After a delete or
	// edit we drop the affected path; this loop re-populates it lazily on the
	// next sort/filter pass.
	for _, path := range m.entries {
		if _, ok := m.metaCache[path]; ok {
			continue
		}
		meta, err := vaultpkg.GetEntryMetadata(m.svc.GetDir(), path, m.svc.GetIdentity())
		if err != nil {
			continue
		}
		m.metaCache[path] = *meta
	}
}

func (m TUIModel) tagMatch(entry string) bool {
	if m.filterTag == "" {
		return true
	}
	meta, ok := m.metaCache[entry]
	if !ok {
		return false
	}
	for _, tag := range meta.Tags {
		if strings.HasPrefix(strings.ToLower(tag), strings.ToLower(m.filterTag)) {
			return true
		}
	}
	return false
}

func (m *TUIModel) sortFiltered() {
	if m.sortMode == 0 || m.sortMode == 1 {
		sort.SliceStable(m.filtered, func(i, j int) bool {
			if m.sortMode == 0 {
				return m.filtered[i] < m.filtered[j]
			}
			return m.filtered[i] > m.filtered[j]
		})
		return
	}
	m.ensureMetaCache()
	sort.SliceStable(m.filtered, func(i, j int) bool {
		mi := m.metaCache[m.filtered[i]]
		mj := m.metaCache[m.filtered[j]]
		if m.sortMode == 2 {
			return mi.Updated.Before(mj.Updated)
		}
		return mi.Updated.After(mj.Updated)
	})
}

func (m TUIModel) availableTags() []string {
	tagSet := make(map[string]struct{})
	for _, meta := range m.metaCache {
		for _, tag := range meta.Tags {
			tagSet[tag] = struct{}{}
		}
	}
	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

func (m TUIModel) sortLabel() string {
	switch m.sortMode {
	case 0:
		return "name↑"
	case 1:
		return "name↓"
	case 2:
		return "updated↑"
	default:
		return "updated↓"
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
	pos := ""
	if len(m.filtered) > 0 {
		pos = fmt.Sprintf(" [%d/%d]", m.selected+1, len(m.filtered))
	}
	b.WriteString(theme.TitleStyle.Render("Entries" + pos))
	b.WriteString(" ")
	b.WriteString(theme.MutedStyle.Render(fmt.Sprintf("[sort: %s]", m.sortLabel())))
	b.WriteString("\n")
	if m.mode == modeFilter {
		b.WriteString(m.filterInput.View())
	} else if m.mode == modeTagFilter {
		b.WriteString(m.tagFilterInput.View())
		tags := m.availableTags()
		if len(tags) > 0 {
			b.WriteString("\n")
			escapedTags := make([]string, len(tags))
			for i, tag := range tags {
				u := taint.Wrap(tag, taint.Provenance{Source: "ui.tag"})
				escapedTags[i] = render.QuoteForTerminal(u)
			}
			b.WriteString(theme.MutedStyle.Render("tags: " + strings.Join(escapedTags, " ")))
		}
	} else if q := strings.TrimSpace(m.filterInput.Value()); q != "" {
		b.WriteString(theme.MutedStyle.Render("Filter: " + q))
		if m.filterTag != "" {
			b.WriteString(" ")
			b.WriteString(theme.MutedStyle.Render(fmt.Sprintf("[tag:%s]", m.filterTag)))
		}
	} else if m.filterTag != "" {
		b.WriteString(theme.MutedStyle.Render(fmt.Sprintf("Tag: %s", m.filterTag)))
	} else {
		b.WriteString(theme.MutedStyle.Render("/ filter · t tag · s sort"))
	}
	b.WriteString("\n\n")

	if m.loading {
		b.WriteString("Loading entries...\n")
		return b.String()
	}
	if len(m.filtered) == 0 {
		b.WriteString(theme.MutedStyle.Render("No entries"))
		return b.String()
	}

	listHeight := max(1, height-5)
	start := 0
	if m.selected >= listHeight {
		start = m.selected - listHeight + 1
	}
	end := min(len(m.filtered), start+listHeight)

	for i := start; i < end; i++ {
		safePath := render.ForTerminal(taint.Wrap(m.filtered[i], taint.Provenance{Source: "ui.path"}))
		line := truncate(safePath, width-4)
		if i == m.selected {
			line = theme.SelectedStyle.Width(width - 4).Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func (m TUIModel) rightView(width, height int) string {
	path := m.selectedPath()
	if path == "" {
		return theme.TitleStyle.Render("Details") + "\n\n" + theme.MutedStyle.Render("Select an entry")
	}
	if m.entry == nil || m.entryFor != path {
		safePath := render.ForTerminal(taint.Wrap(path, taint.Provenance{Source: "ui.path"}))
		return theme.TitleStyle.Render(safePath) + "\n\n" + theme.MutedStyle.Render("Loading details...")
	}

	var b strings.Builder
	safePath := render.ForTerminal(taint.Wrap(path, taint.Provenance{Source: "ui.path"}))
	b.WriteString(theme.TitleStyle.Render(safePath))
	b.WriteString("\n")
	b.WriteString(theme.MutedStyle.Render("Updated: " + m.entry.Metadata.Updated.Format("2006-01-02 15:04")))
	b.WriteString("\n\n")

	keys := make([]string, 0, len(m.entry.Data))
	for key := range m.entry.Data {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	maxRows := max(1, height-6)
	for i, key := range keys {
		if i >= maxRows {
			b.WriteString(theme.MutedStyle.Render("..."))
			break
		}
		rawValue := fmt.Sprint(m.entry.Data[key])
		var value string
		if !m.revealed && isSensitiveField(key) {
			value = redactedValue
		} else {
			u := taint.Wrap(rawValue, taint.Provenance{Source: "ui.entry", EntryPath: m.entry.Path, FieldName: key})
			value = render.ForTerminal(u)
		}
		line := fmt.Sprintf("%s: %s", theme.KeyStyle.Render(key), value)
		b.WriteString(truncate(line, width-4))
		b.WriteString("\n")
	}

	return b.String()
}

func (m TUIModel) statusView() string {
	status := m.status
	if m.err != nil {
		status = theme.ErrorStyle.Render(m.err.Error())
	}
	keys := "↑/↓ select · Enter copy · r reveal · e edit · d delete · g gen · s sort · t tag · / filter · esc clear · ? help · q quit"
	return theme.MutedStyle.Render(keys) + "\n" + status
}

func (m TUIModel) helpView() string {
	return strings.Join([]string{
		theme.TitleStyle.Render("Help"),
		"↑/↓ or k/j: move selection",
		"/: fuzzy filter entries",
		"s: cycle sort (name/updated, asc/desc)",
		"t: filter by tag",
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
	safePath := render.ForTerminal(taint.Wrap(m.selectedPath(), taint.Provenance{Source: "ui.path"}))
	return theme.ErrorStyle.Render(fmt.Sprintf("Confirm %s %s?", verb, safePath)) + "  " + theme.MutedStyle.Render("y/N")
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

func clipboardTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(_ time.Time) tea.Msg {
		return clipboardTickMsg{}
	})
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
		defer func() { _ = secureDeleteFile(tmpPath) }()

		encoder := json.NewEncoder(tmp)
		encoder.SetIndent("", "  ")
		if encErr := encoder.Encode(entry); encErr != nil {
			_ = tmp.Close()
			return entryEditedMsg{path: path, err: encErr}
		}
		if closeErr := tmp.Close(); closeErr != nil {
			return entryEditedMsg{path: path, err: closeErr}
		}

		editor, editorErr := resolveEditor(os.Getenv("EDITOR"))
		if editorErr != nil {
			return entryEditedMsg{path: path, err: editorErr}
		}
		cmd := exec.Command(editor, tmpPath) //#nosec G204 G702 -- editor path resolved via exec.LookPath above.
		envfilter.PrepareCmd(cmd)
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

// resolveEditor returns an absolute path to a usable editor binary. It tries
// the user-provided value (typically $EDITOR) first, then falls back to a
// short list of common editors. Returns an error if none are found on PATH.
func resolveEditor(preferred string) (string, error) {
	candidates := make([]string, 0, 4)
	if preferred != "" {
		candidates = append(candidates, preferred)
	}
	candidates = append(candidates, "vim", "nano", "vi")
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no editor found on PATH (tried %v); set $EDITOR to a valid editor", candidates)
}

// secureDeleteFile overwrites the file at path with zeros, syncs it, and
// then removes it. If overwriting fails, removal is still attempted to
// avoid leaving temporary files behind.
func secureDeleteFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //#nosec G304 -- path comes from tmp.Name() in the same function
	if err != nil {
		// Cannot open, but still try to remove.
		_ = os.Remove(path)
		return err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}

	size := fi.Size()
	zeros := make([]byte, 4096)
	remaining := size
	for remaining > 0 {
		chunk := zeros
		if remaining < int64(len(chunk)) {
			chunk = chunk[:remaining]
		}
		n, werr := f.Write(chunk)
		if werr != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return werr
		}
		remaining -= int64(n)
	}

	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return serr
	}

	// Close before remove on some platforms (Windows).
	_ = f.Close()
	return os.Remove(path)
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
	if width <= 1 {
		return value
	}
	if runewidth.StringWidth(value) <= width {
		return value
	}
	return runewidth.Truncate(value, width, "…")
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
