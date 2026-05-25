package wizard

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/danieljustus/symaira-vault/internal/crypto"
)

// RecipientsStep lets the user add additional age public keys.
type RecipientsStep struct {
	input      textarea.Model
	err        string
	lineErrors map[int]string
	skip       bool
	done       bool
}

func NewRecipientsStep() *RecipientsStep {
	ta := textarea.New()
	ta.Placeholder = "age1... (one per line)"
	ta.SetWidth(60)
	ta.SetHeight(5)
	return &RecipientsStep{input: ta, lineErrors: make(map[int]string)}
}

func (s *RecipientsStep) Title() string { return "Recipients" }
func (s *RecipientsStep) ShouldShow(st WizardState) bool {
	return st.SyncMode == syncGit && st.MultiDevice
}
func (s *RecipientsStep) Init() tea.Cmd { return textarea.Blink }

func (s *RecipientsStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "ctrl+s", keyEnter:
			if km.String() == keyEnter && !s.inputEmptyOrBlank() {
				break // let textarea handle Enter for newline
			}
			if len(s.lineErrors) > 0 {
				s.err = "fix invalid recipients before saving"
				return s, nil
			}
			if err := s.validate(); err != nil {
				s.err = err.Error()
				return s, nil
			}
			s.done = true
			return s, stepDoneCmd()
		case keyEsc:
			s.skip = true
			s.done = true
			return s, stepDoneCmd()
		}
	}
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	s.err = ""
	s.validateLive()
	return s, cmd
}

func (s *RecipientsStep) inputEmptyOrBlank() bool {
	val := strings.TrimSpace(s.input.Value())
	return val == ""
}

func (s *RecipientsStep) validateLive() {
	s.lineErrors = make(map[int]string)
	for i, line := range s.lines() {
		if _, err := crypto.ValidateRecipient(line); err != nil {
			s.lineErrors[i] = err.Error()
		}
	}
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
	} else if len(s.lineErrors) > 0 {
		lines = append(lines, "")
		for i, line := range strings.Split(s.input.Value(), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if errMsg, invalid := s.lineErrors[i]; invalid {
				lines = append(lines, errorStyle.Render(fmt.Sprintf("  ✗ line %d: %s", i+1, errMsg)))
			}
		}
	}
	if s.err == "" && len(s.lineErrors) == 0 {
		lines = append(lines,
			"",
			helpStyle.Render("Enter (empty line) or Ctrl+S to save · Esc to skip"),
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
