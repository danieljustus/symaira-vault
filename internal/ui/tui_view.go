package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	render "github.com/danieljustus/symaira-vault/internal/ui/render"
	theme "github.com/danieljustus/symaira-vault/internal/ui/theme"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
	taint "github.com/danieljustus/symaira-vault/internal/vault/taint"
)

const uiPathProvenance = "ui.path"

func (m TUIModel) View() string {
	if m.width == 0 {
		return "Loading Symaira Vault UI..."
	}
	contentHeight := max(8, m.height-6)
	leftWidth := max(24, m.width/3)
	rightWidth := max(32, m.width-leftWidth-8)
	bs := borderStyle
	if m.mode == modeFilter || m.mode == modeTagFilter || m.mode == modeAdd || m.mode == modeGenConfig {
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
	} else if m.mode == modeAdd {
		b.WriteString(m.addPathInput.View())
	} else if m.mode == modeGenConfig {
		b.WriteString(m.genLengthInput.View())
		symbolsLabel := "off"
		if m.genSymbols {
			symbolsLabel = "on"
		}
		b.WriteString(" s: symbols [" + symbolsLabel + "]")
	} else if q := strings.TrimSpace(m.filterInput.Value()); q != "" {
		b.WriteString(theme.MutedStyle.Render("Filter: " + q))
		if m.filterTag != "" {
			b.WriteString(" ")
			b.WriteString(theme.MutedStyle.Render(fmt.Sprintf("[tag:%s]", m.filterTag)))
		}
	} else if m.filterTag != "" {
		b.WriteString(theme.MutedStyle.Render(fmt.Sprintf("Tag: %s", m.filterTag)))
	} else {
		b.WriteString(theme.MutedStyle.Render("/ filter \u00b7 t tag \u00b7 s sort"))
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
	grouped := m.sortMode == 4 || m.sortMode == 5
	var lastType vaultpkg.SecretType
	for i := start; i < end; i++ {
		if grouped {
			currentType := m.secretTypeCache[m.filtered[i]]
			if currentType != lastType {
				header := fmt.Sprintf("  %s %s (%d)", vaultpkg.SecretTypeIcon(currentType), currentType, m.typeCount(currentType))
				b.WriteString(theme.MutedStyle.Render(header))
				b.WriteString("\n")
				lastType = currentType
			}
		}
		safePath := render.ForTerminal(taint.Wrap(m.filtered[i], taint.Provenance{Source: uiPathProvenance}))
		line := truncate(safePath, width-4)
		if i == m.selected {
			line = theme.SelectedStyle.Width(width - 4).Render(line)
		}
		if grouped {
			b.WriteString("  ")
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
		safePath := render.ForTerminal(taint.Wrap(path, taint.Provenance{Source: uiPathProvenance}))
		return theme.TitleStyle.Render(safePath) + "\n\n" + theme.MutedStyle.Render("Loading details...")
	}
	var b strings.Builder
	safePath := render.ForTerminal(taint.Wrap(path, taint.Provenance{Source: uiPathProvenance}))
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
	keys := "\u2191/\u2193 select \u00b7 Enter copy \u00b7 r reveal \u00b7 a add \u00b7 e edit \u00b7 d delete \u00b7 g gen \u00b7 s sort \u00b7 t tag \u00b7 / filter \u00b7 esc clear \u00b7 ? help \u00b7 q quit"
	if m.mode == modeGenConfig {
		keys = "Enter confirm \u00b7 s toggle symbols \u00b7 esc cancel"
	}
	return theme.MutedStyle.Render(keys) + "\n" + status
}

func (m TUIModel) helpView() string {
	return strings.Join([]string{
		theme.TitleStyle.Render("Help"),
		"\u2191/\u2193 or k/j: move selection",
		"/: fuzzy filter entries",
		"s: cycle sort (name/updated/type, asc/desc)",
		"t: filter by tag",
		"a: add a new entry",
		"Enter: copy password field to clipboard",
		"r: reveal or redact sensitive fields",
		"e: edit selected entry after confirmation",
		"d: delete selected entry after confirmation",
		"g: configure and generate password (length, symbols)",
		"q or Ctrl+C: quit",
	}, "\n")
}

func (m TUIModel) confirmView() string {
	verb := "delete"
	if m.mode == modeConfirmEdit {
		verb = "edit"
	}
	safePath := render.ForTerminal(taint.Wrap(m.selectedPath(), taint.Provenance{Source: uiPathProvenance}))
	return theme.ErrorStyle.Render(fmt.Sprintf("Confirm %s %s?", verb, safePath)) + "  " + theme.MutedStyle.Render("y/N")
}
