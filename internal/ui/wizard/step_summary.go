package wizard

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// SummaryStep shows all choices and asks the user to confirm or go back.
type SummaryStep struct {
	state   *WizardState
	choice  int // 0=apply, 1=back, 2=cancel
	decided bool
}

func NewSummaryStep(state *WizardState) *SummaryStep {
	return &SummaryStep{state: state}
}

func (s *SummaryStep) Title() string                 { return "Summary" }
func (s *SummaryStep) ShouldShow(_ WizardState) bool { return true }
func (s *SummaryStep) Init() tea.Cmd                 { return nil }

func (s *SummaryStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "up", "k":
			if s.choice > 0 {
				s.choice--
			}
		case keyDown, "j":
			if s.choice < 2 {
				s.choice++
			}
		case keyEnter, " ":
			s.decided = true
			return s, stepDoneCmd()
		}
	}
	return s, nil
}

func (s *SummaryStep) View() string {
	st := s.state
	lines := []string{
		titleStyle.Render("Summary — review your choices"),
		"",
	}

	row := func(label, val string) string {
		return fmt.Sprintf("  %-16s %s", label+":", val)
	}

	lines = append(lines, row("Vault", st.VaultDir))
	if !st.ExistingVault {
		pass := strings.Repeat("*", 12)
		meter := MeasureStrength(string(st.Passphrase))
		lines = append(lines, row("Passphrase", fmt.Sprintf("%s (%s)", pass, meter)))
		lines = append(lines, row("Auth", st.AuthMethod))
	}

	syncVal := "local only"
	if st.SyncMode == syncGit {
		pushFlag := ""
		if st.AutoPush {
			pushFlag = ", auto-push"
		}
		syncVal = st.GitRemoteURL + pushFlag
	}
	lines = append(lines, row("Sync", syncVal))

	if len(st.Recipients) > 0 {
		lines = append(lines, row("Recipients", fmt.Sprintf("self + %d additional", len(st.Recipients))))
	} else {
		lines = append(lines, row("Recipients", dimStyle.Render("self only")))
	}

	if len(st.SelectedAgents) > 0 {
		names := make([]string, len(st.SelectedAgents))
		for i, a := range st.SelectedAgents {
			names[i] = a.AgentType
		}
		lines = append(lines, row("AI Agents", strings.Join(names, ", ")))
	} else {
		lines = append(lines, row("AI Agents", dimStyle.Render("none")))
	}

	lines = append(lines, row("Profile", st.ProfileName))
	lines = append(lines, "")

	opts := []string{
		focusedStyle.Render("Apply"),
		"Go back",
		errorStyle.Render("Cancel"),
	}
	for i, opt := range opts {
		cursor := "  "
		if i == s.choice {
			cursor = "▸ "
		}
		lines = append(lines, cursor+opt)
	}
	lines = append(lines, "", helpStyle.Render("↑/↓ select · Enter to confirm"))
	return strings.Join(lines, "\n")
}

// Decision returns 0=apply, 1=back, 2=cancel.
func (s *SummaryStep) Decision() int { return s.choice }
