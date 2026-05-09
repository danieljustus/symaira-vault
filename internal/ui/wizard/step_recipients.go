package wizard

import (
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/danieljustus/OpenPass/internal/crypto"
)

// RecipientsStep lets the user add additional age public keys.
type RecipientsStep struct {
	input textarea.Model
	err   string
	skip  bool // user chose to skip
	done  bool
}

func NewRecipientsStep() *RecipientsStep {
	ta := textarea.New()
	ta.Placeholder = "age1... (one per line)"
	ta.SetWidth(60)
	ta.SetHeight(5)
	return &RecipientsStep{input: ta}
}

func (s *RecipientsStep) Title() string { return "Recipients" }
func (s *RecipientsStep) ShouldShow(st WizardState) bool {
	return st.SyncMode == syncGit && st.MultiDevice
}
func (s *RecipientsStep) Init() tea.Cmd { return textarea.Blink }

func (s *RecipientsStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "ctrl+s":
			// Submit.
			if err := s.validate(); err != nil {
				s.err = err.Error()
				return s, nil
			}
			s.done = true
			return s, stepDoneCmd()
		case "esc":
			// Skip step.
			s.skip = true
			s.done = true
			return s, stepDoneCmd()
		}
	}
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	s.err = ""
	return s, cmd
}

func (s *RecipientsStep) View() string {
	lines := []string{
		titleStyle.Render("Additional recipients"),
		"",
		"Add age public keys of other devices or colleagues who should",
		"be able to read this vault. " + warnStyle.Render("Recommended: at least one backup key."),
		"",
		s.input.View(),
	}
	if s.err != "" {
		lines = append(lines, "", errorStyle.Render("✗ "+s.err))
	} else {
		lines = append(lines,
			"",
			helpStyle.Render("Ctrl+S to save · Esc to skip"),
		)
	}
	return strings.Join(lines, "\n")
}

func (s *RecipientsStep) validate() error {
	for _, line := range s.lines() {
		if _, err := crypto.ValidateRecipient(line); err != nil {
			return err
		}
	}
	return nil
}

func (s *RecipientsStep) lines() []string {
	var result []string
	for _, line := range strings.Split(s.input.Value(), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

// Recipients returns the validated recipient strings.
func (s *RecipientsStep) Recipients() []string {
	if s.skip {
		return nil
	}
	return s.lines()
}
