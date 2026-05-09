package wizard

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/session"
)

// AuthStep lets the user pick the authentication method.
type AuthStep struct {
	touchIDAvailable bool
	selected         int // 0=touchid, 1=passphrase
	done             bool
}

func NewAuthStep() *AuthStep {
	return &AuthStep{touchIDAvailable: session.BiometricAvailable()}
}

func (s *AuthStep) Title() string { return "Auth Method" }
func (s *AuthStep) ShouldShow(st WizardState) bool {
	// Skip if not Touch ID available or re-configuring (existing vault keeps its identity).
	return s.touchIDAvailable && !st.ExistingVault
}
func (s *AuthStep) Init() tea.Cmd { return nil }

func (s *AuthStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if !s.touchIDAvailable {
		s.done = true
		return s, stepDoneCmd()
	}
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "up", "k", "left":
			if s.selected > 0 {
				s.selected--
			}
		case keyDown, "j", "right":
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

func (s *AuthStep) View() string {
	if !s.touchIDAvailable {
		return strings.Join([]string{
			titleStyle.Render("Authentication"),
			"",
			dimStyle.Render("Touch ID not available on this system."),
			"Vault will use passphrase authentication.",
		}, "\n")
	}

	opts := []string{"Touch ID (recommended)", "Passphrase only"}
	lines := []string{
		titleStyle.Render("Authentication method"),
		"",
		"Touch ID was detected. How should OpenPass unlock the vault?",
		"",
	}
	for i, opt := range opts {
		if i == s.selected {
			lines = append(lines, focusedStyle.Render("▸ "+opt))
		} else {
			lines = append(lines, "  "+opt)
		}
	}
	lines = append(lines, "", helpStyle.Render("↑/↓ select · Enter to confirm"))
	return strings.Join(lines, "\n")
}

// SelectedMethod returns the chosen config auth method string.
func (s *AuthStep) SelectedMethod() string {
	if s.touchIDAvailable && s.selected == 0 {
		return config.AuthMethodTouchID
	}
	return config.AuthMethodPassphrase
}
