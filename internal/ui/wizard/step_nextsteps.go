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
		successStyle.Render("✓ Symaira Vault is ready!"),
		"",
		"Quick-start commands:",
		"",
		"  " + focusedStyle.Render("symvault add <name>") + "           add your first entry",
		"  " + focusedStyle.Render("symvault get <name>") + "           retrieve a password",
		"  " + focusedStyle.Render("symvault ui") + "                   browse entries in terminal UI",
		"  " + focusedStyle.Render("symvault get --autotype") + "      auto-type passwords into forms",
		"  " + focusedStyle.Render("symvault doctor") + "               health check",
		"  " + focusedStyle.Render("symvault agent install <agent>") + "  configure MCP agent integrations",
		"  " + focusedStyle.Render("symvault auth set <method>") + "    change auth method",
		"  " + focusedStyle.Render("symvault --help") + "               show all commands",
	}

	if st.SyncMode == syncGit && st.MultiDevice {
		lines = append(lines, "",
			dimStyle.Render("Pair another device:"),
			"  "+focusedStyle.Render("symvault device add --pair \"<data>\"")+" on the other device",
			"  "+focusedStyle.Render("symvault device accept <token>")+"   to complete pairing",
		)
	}

	if len(st.ApplyErrors) > 0 {
		lines = append(lines, "", warnStyle.Render("Some steps had issues — run symvault doctor to diagnose."))
	}

	lines = append(lines, "", helpStyle.Render("Enter or Q to exit"))
	return strings.Join(lines, "\n")
}
