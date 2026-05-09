package wizard

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

const minPassphraseLen = 12

// PassphraseStep collects and confirms the vault passphrase.
type PassphraseStep struct {
	pass    textinput.Model
	confirm textinput.Model
	focused int // 0=pass, 1=confirm
	err     string
	done    bool
}

func NewPassphraseStep() *PassphraseStep {
	pass := textinput.New()
	pass.Placeholder = "min 12 characters"
	pass.EchoMode = textinput.EchoPassword
	pass.CharLimit = 1024
	pass.Focus()

	confirm := textinput.New()
	confirm.Placeholder = "repeat passphrase"
	confirm.EchoMode = textinput.EchoPassword
	confirm.CharLimit = 1024

	return &PassphraseStep{pass: pass, confirm: confirm}
}

func (s *PassphraseStep) Title() string                  { return "Passphrase" }
func (s *PassphraseStep) ShouldShow(st WizardState) bool { return !st.ExistingVault }
func (s *PassphraseStep) Init() tea.Cmd                  { return textinput.Blink }

func (s *PassphraseStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "tab", "down":
			s.focused = (s.focused + 1) % 2
			s.focusActive()
			return s, nil
		case "shift+tab", "up":
			s.focused = (s.focused + 1) % 2
			s.focusActive()
			return s, nil
		case keyEnter:
			if s.focused == 0 {
				// Move to confirm field.
				s.focused = 1
				s.focusActive()
				return s, nil
			}
			if err := s.validate(); err != nil {
				s.err = err.Error()
				return s, nil
			}
			s.done = true
			return s, stepDoneCmd()
		}
	}
	var cmd tea.Cmd
	if s.focused == 0 {
		s.pass, cmd = s.pass.Update(msg)
	} else {
		s.confirm, cmd = s.confirm.Update(msg)
	}
	s.err = ""
	return s, cmd
}

func (s *PassphraseStep) View() string {
	strength := MeasureStrength(s.pass.Value())
	strengthLine := dimStyle.Render("Strength: ") + strengthColor(strength).Render(strength.Bar())

	lines := []string{
		titleStyle.Render("Set vault passphrase"),
		"",
		"Passphrase",
		s.pass.View(),
		strengthLine,
		"",
		"Confirm",
		s.confirm.View(),
	}
	if s.err != "" {
		lines = append(lines, "", errorStyle.Render("✗ "+s.err))
	} else {
		lines = append(lines, "", helpStyle.Render("Tab to switch fields · Enter to confirm"))
	}
	return strings.Join(lines, "\n")
}

func (s *PassphraseStep) Passphrase() []byte {
	return []byte(s.pass.Value())
}

func (s *PassphraseStep) focusActive() {
	if s.focused == 0 {
		s.pass.Focus()
		s.confirm.Blur()
	} else {
		s.pass.Blur()
		s.confirm.Focus()
	}
}

func (s *PassphraseStep) validate() error {
	p := s.pass.Value()
	if len(p) < minPassphraseLen {
		return fmt.Errorf("passphrase must be at least %d characters", minPassphraseLen)
	}
	if p != s.confirm.Value() {
		return fmt.Errorf("passphrases do not match")
	}
	return nil
}

func strengthColor(st PassphraseStrength) lipglossStyler {
	switch st {
	case StrengthStrong:
		return successStyle
	case StrengthGood:
		return successStyle
	case StrengthFair:
		return warnStyle
	default:
		return errorStyle
	}
}

type lipglossStyler interface {
	Render(strs ...string) string
}
