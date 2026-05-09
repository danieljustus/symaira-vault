package wizard

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/danieljustus/OpenPass/internal/pathutil"
)

// VaultPathStep lets the user confirm or change the vault directory.
type VaultPathStep struct {
	input textinput.Model
	err   string
	done  bool
}

func NewVaultPathStep(defaultDir string) *VaultPathStep {
	ti := textinput.New()
	ti.Placeholder = "~/.openpass"
	ti.SetValue(defaultDir)
	ti.Focus()
	ti.CharLimit = 512
	return &VaultPathStep{input: ti}
}

func (s *VaultPathStep) Title() string                  { return "Vault Path" }
func (s *VaultPathStep) ShouldShow(st WizardState) bool { return !st.ExistingVault }
func (s *VaultPathStep) Init() tea.Cmd                  { return textinput.Blink }

func (s *VaultPathStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok && km.String() == keyEnter {
		if err := s.validate(); err != nil {
			s.err = err.Error()
			return s, nil
		}
		s.done = true
		return s, stepDoneCmd()
	}
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	s.err = ""
	return s, cmd
}

func (s *VaultPathStep) View() string {
	lines := []string{
		titleStyle.Render("Vault directory"),
		"",
		"Where should OpenPass store your vault?",
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

func (s *VaultPathStep) Value() string { return strings.TrimSpace(s.input.Value()) }

func (s *VaultPathStep) validate() error {
	v := strings.TrimSpace(s.input.Value())
	if v == "" {
		return fmt.Errorf("vault path must not be empty")
	}
	if pathutil.HasTraversal(v) {
		return fmt.Errorf("invalid path (traversal detected)")
	}
	// Non-empty directory without config.yaml is suspicious but not an error.
	// The vault init will handle it.
	return nil
}
