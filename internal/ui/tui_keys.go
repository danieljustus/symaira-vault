package ui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

//nolint:gocyclo
func (m TUIModel) handleKey(msg tea.KeyMsg) (TUIModel, tea.Cmd) {
	if m.mode == modeFilter {
		switch msg.String() {
		case keyEsc, keyEnter:
			m.mode = modeNormal
			m.filterInput.Blur()
			return m, m.loadSelectedEntry()
		case keyQuit:
			return m, m.quitCmd()
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
			return m, m.quitCmd()
		}
		var cmd tea.Cmd
		m.tagFilterInput, cmd = m.tagFilterInput.Update(msg)
		m.applyFilter()
		return m, cmd
	}
	if m.mode == modeAdd {
		switch msg.String() {
		case keyEsc:
			m.mode = modeNormal
			m.addPathInput.Blur()
			m.status = ""
			return m, nil
		case keyEnter:
			path := strings.TrimSpace(m.addPathInput.Value())
			if path == "" {
				m.status = "Path cannot be empty"
				return m, nil
			}
			m.mode = modeNormal
			m.addPathInput.Blur()
			return m, addEntryCmd(m.vault, path)
		case keyQuit:
			return m, m.quitCmd()
		}
		var cmd tea.Cmd
		m.addPathInput, cmd = m.addPathInput.Update(msg)
		return m, cmd
	}
	if m.mode == modeGenConfig {
		switch msg.String() {
		case keyEsc:
			m.mode = modeNormal
			m.genLengthInput.Blur()
			m.status = ""
			return m, nil
		case keyEnter:
			length := generatedPasswordLength
			val := strings.TrimSpace(m.genLengthInput.Value())
			if val != "" {
				if n, err := strconv.Atoi(val); err == nil && n > 0 && n <= 512 {
					length = n
				} else {
					m.status = "Invalid length (1-512)"
					return m, nil
				}
			}
			m.mode = modeNormal
			m.genLengthInput.Blur()
			return m, generatePasswordCmd(length, m.genSymbols)
		case "s":
			m.genSymbols = !m.genSymbols
			return m, nil
		case keyQuit:
			return m, m.quitCmd()
		}
		var cmd tea.Cmd
		m.genLengthInput, cmd = m.genLengthInput.Update(msg)
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
				return m, deleteEntryCmd(m.vault, path)
			}
			return m, editEntryCmd(m.vault, path)
		case "n", "N", "esc":
			m.mode = modeNormal
			m.status = "Canceled"
			return m, nil
		case keyQuit:
			return m, m.quitCmd()
		}
		return m, nil
	}
	switch msg.String() {
	case "q", keyQuit:
		return m, m.quitCmd()
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
		m.sortMode = (m.sortMode + 1) % 6
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
			return m, m.debounceSelectedEntry()
		}
	case "down", "j":
		if m.selected < len(m.filtered)-1 {
			m.selected++
			m.clipboardSeconds = 0
			return m, m.debounceSelectedEntry()
		}
	case "home":
		m.selected = 0
		m.clipboardSeconds = 0
		return m, m.debounceSelectedEntry()
	case "end":
		if len(m.filtered) > 0 {
			m.selected = len(m.filtered) - 1
			m.clipboardSeconds = 0
			return m, m.debounceSelectedEntry()
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
	case "a":
		m.mode = modeAdd
		m.addPathInput.SetValue("")
		m.addPathInput.Focus()
		return m, textinput.Blink
	case "g":
		m.mode = modeGenConfig
		m.genLengthInput.SetValue("")
		m.genLengthInput.Focus()
		return m, textinput.Blink
	}
	return m, nil
}
