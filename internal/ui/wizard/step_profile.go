package wizard

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// ProfileStep lets the user name this vault profile.
type ProfileStep struct {
	input textinput.Model
	err   string
	done  bool
}

func NewProfileStep() *ProfileStep {
	ti := textinput.New()
	ti.Placeholder = defaultProfile
	ti.SetValue("default")
	ti.CharLimit = 64
	ti.Focus()
	return &ProfileStep{input: ti}
}

func (s *ProfileStep) Title() string                 { return "Profile Name" }
func (s *ProfileStep) ShouldShow(_ WizardState) bool { return true }
func (s *ProfileStep) Init() tea.Cmd                 { return textinput.Blink }

func (s *ProfileStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		if km.String() == keyEnter {
			name := strings.TrimSpace(s.input.Value())
			if name == "" {
				s.err = "profile name must not be empty"
				return s, nil
			}
			if strings.ContainsAny(name, "/ \\") {
				s.err = "profile name must not contain spaces or slashes"
				return s, nil
			}
			s.done = true
			return s, stepDoneCmd()
		}
	}
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	s.err = ""
	return s, cmd
}

func (s *ProfileStep) View() string {
	lines := []string{
		titleStyle.Render("Vault profile name"),
		"",
		"Name this vault profile (used with " + dimStyle.Render("openpass --profile <name>") + ").",
		"",
		s.input.View(),
	}
	if s.err != "" {
		lines = append(lines, "", errorStyle.Render("✗ "+s.err))
	} else {
		lines = append(lines, "", helpStyle.Render("Enter to confirm"))
	}
	return strings.Join(lines, "\n")
}

func (s *ProfileStep) Value() string { return strings.TrimSpace(s.input.Value()) }
