package wizard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/danieljustus/symaira-vault/internal/pathutil"
)

// VaultPathStep lets the user confirm or change the vault directory.
type VaultPathStep struct {
	input textinput.Model
	err   string
	done  bool
}

func NewVaultPathStep(defaultDir string) *VaultPathStep {
	ti := textinput.New()
	ti.Placeholder = "~/.symaira"
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
		"Where should Symaira Vault store your vault?",
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
	if !filepath.IsAbs(v) {
		abs, err := filepath.Abs(v)
		if err != nil {
			return fmt.Errorf("cannot resolve path: %w", err)
		}
		v = abs
	}
	dir := v
	if fi, err := os.Stat(dir); err == nil && !fi.IsDir() {
		dir = filepath.Dir(dir)
	}
	if err := ensureWritable(dir); err != nil {
		return fmt.Errorf("path not writable: %w", err)
	}
	return nil
}

func ensureWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".symaira-write-test-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}
