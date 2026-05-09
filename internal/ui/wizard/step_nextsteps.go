package wizard

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// NextStepsStep is the final screen shown after a successful apply.
type NextStepsStep struct {
	state *WizardState
	done  bool
}

func NewNextStepsStep(state *WizardState) *NextStepsStep {
	return &NextStepsStep{state: state}
}

func (s *NextStepsStep) Title() string                 { return "Done" }
func (s *NextStepsStep) ShouldShow(_ WizardState) bool { return true }
func (s *NextStepsStep) Init() tea.Cmd                 { return nil }

func (s *NextStepsStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		if km.String() == keyEnter || km.String() == "q" {
			s.done = true
			return s, tea.Quit
		}
	}
	return s, nil
}

func (s *NextStepsStep) View() string {
	st := s.state
	lines := []string{
		successStyle.Render("✓ OpenPass is ready!"),
		"",
		"Quick-start commands:",
		"",
		"  " + focusedStyle.Render("openpass add <name>") + "         add your first entry",
		"  " + focusedStyle.Render("openpass get <name>") + "         retrieve a password",
		"  " + focusedStyle.Render("openpass doctor") + "             health check",
		"  " + focusedStyle.Render("openpass --help") + "             show all commands",
	}

	if st.SyncMode == syncGit && st.MultiDevice {
		lines = append(lines, "",
			dimStyle.Render("To add another device:"),
			"  "+focusedStyle.Render("openpass device pair")+" on this device",
			"  "+focusedStyle.Render("openpass device join <url> <token>")+" on the other device",
		)
	}

	if len(st.ApplyErrors) > 0 {
		lines = append(lines, "", warnStyle.Render("Some steps had issues — run openpass doctor to diagnose."))
	}

	lines = append(lines, "", helpStyle.Render("Enter or Q to exit"))
	return strings.Join(lines, "\n")
}
