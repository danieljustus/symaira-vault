package wizard

import (
	"fmt"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/danieljustus/OpenPass/internal/vault"
)

// WelcomeStep greets the user and detects whether a vault already exists.
type WelcomeStep struct {
	vaultDir     string
	existing     bool
	done         bool
	noResume     bool
	resumeFound  bool
	resumeStep   string
	resumeTarget string
	resumeState  *WizardState
}

func NewWelcomeStep(vaultDir string, noResume bool) *WelcomeStep {
	s := &WelcomeStep{
		vaultDir: vaultDir,
		existing: vault.IsInitialized(vaultDir),
		noResume: noResume,
	}
	if !noResume {
		s.checkResume()
	}
	return s
}

func (s *WelcomeStep) checkResume() {
	age, err := ResumeFileAge(s.vaultDir)
	if err != nil || age >= resumeMaxAge {
		return
	}
	state, lastStep, err := LoadResumeState(s.vaultDir)
	if err != nil {
		return
	}
	s.resumeFound = true
	s.resumeStep = lastStep
	s.resumeState = state
	if state.ExistingVault {
		s.resumeTarget = lastStep
	} else {
		s.resumeTarget = "Passphrase"
	}
}

func (s *WelcomeStep) Title() string                 { return "Welcome" }
func (s *WelcomeStep) ShouldShow(_ WizardState) bool { return true }

func (s *WelcomeStep) Init() tea.Cmd { return nil }

func (s *WelcomeStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		if s.resumeFound {
			switch km.String() {
			case "y", "Y":
				s.done = true
				return s, func() tea.Msg {
					return resumeMsg{
						state:     *s.resumeState,
						stepTitle: s.resumeTarget,
					}
				}
			case "n", "N", keyEnter, " ":
				s.resumeFound = false
				s.done = true
				return s, stepDoneCmd()
			}
		}
		if key.Matches(km, key.NewBinding(key.WithKeys(keyEnter, " "))) {
			s.done = true
			return s, stepDoneCmd()
		}
	}
	return s, nil
}

func (s *WelcomeStep) View() string {
	if s.resumeFound {
		body := fmt.Sprintf(
			"%s\n\n%s\n\n%s",
			titleStyle.Render("Resume Previous Setup"),
			fmt.Sprintf("A partially completed setup was found (step: %s).", focusedStyle.Render(s.resumeStep)),
			fmt.Sprintf("Resume from %s?  %s  %s",
				focusedStyle.Render(s.resumeStep),
				focusedStyle.Render("[y]es"),
				helpStyle.Render("[N]o — start fresh"),
			),
		)
		if !s.resumeState.ExistingVault {
			body += "\n\n" + warnStyle.Render("You will need to re-enter your passphrase.")
		}
		return body
	}

	var body string
	if s.existing {
		body = fmt.Sprintf(
			"%s\n\n%s\n\n%s",
			titleStyle.Render("Re-configuring OpenPass"),
			"A vault already exists at "+dimStyle.Render(s.vaultDir)+".",
			"This wizard will let you update your sync, MCP agents, and other settings.\n"+
				warnStyle.Render("Vault passphrase and identity will not be changed."),
		)
	} else {
		body = fmt.Sprintf(
			"%s\n\n%s\n\n%s",
			titleStyle.Render("Welcome to OpenPass"),
			"This wizard will guide you through setting up your password vault.",
			"Press "+focusedStyle.Render("Enter")+" to start  "+helpStyle.Render("Esc to quit"),
		)
	}
	return body
}

// IsDone reports if the user pressed Enter to proceed.
func (s *WelcomeStep) IsDone() bool { return s.done }

// IsExistingVault reports whether a vault was already found.
func (s *WelcomeStep) IsExistingVault() bool { return s.existing }
