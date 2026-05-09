package wizard

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// MultiDeviceStep is a hint-only step (no side-effects).
type MultiDeviceStep struct {
	selected int // 0=yes, 1=no
	done     bool
}

func NewMultiDeviceStep() *MultiDeviceStep { return &MultiDeviceStep{} }

func (s *MultiDeviceStep) Title() string { return "Multi-Device" }
func (s *MultiDeviceStep) ShouldShow(st WizardState) bool {
	return st.SyncMode == syncGit
}
func (s *MultiDeviceStep) Init() tea.Cmd { return nil }

func (s *MultiDeviceStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "up", "k":
			if s.selected > 0 {
				s.selected--
			}
		case keyDown, "j":
			if s.selected < 1 {
				s.selected++
			}
		case keyEnter, " ":
			s.done = true
			return s, stepDoneCmd()
		}
	}
	return s, nil
}

func (s *MultiDeviceStep) View() string {
	opts := []string{"Yes — I'll add another device later", "No — single device"}
	lines := []string{
		titleStyle.Render("Multi-device setup"),
		"",
		"Do you plan to access this vault from another device?",
		"",
	}
	for i, opt := range opts {
		if i == s.selected {
			lines = append(lines, focusedStyle.Render("▸ "+opt))
		} else {
			lines = append(lines, "  "+opt)
		}
	}
	if s.selected == 0 {
		lines = append(lines, "",
			dimStyle.Render("After setup, run: openpass device pair"),
			dimStyle.Render("On the other device:  openpass device join <url> <token>"),
		)
	}
	lines = append(lines, "", helpStyle.Render("↑/↓ select · Enter to confirm"))
	return strings.Join(lines, "\n")
}

func (s *MultiDeviceStep) WantsMultiDevice() bool { return s.selected == 0 }
