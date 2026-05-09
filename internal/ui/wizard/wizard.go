// Package wizard provides the openpass setup interactive wizard.
package wizard

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// stepDone is a message sent when a step has completed its input.
type stepDone struct{}

func stepDoneCmd() tea.Cmd {
	return func() tea.Msg { return stepDone{} }
}

// WizardModel is the top-level Bubbletea model for the setup wizard.
type WizardModel struct {
	steps    []Step
	current  int
	state    WizardState
	width    int
	height   int
	quitting bool
	canceled bool
	applyErr error
}

// NewWizardModel constructs the model with all steps for a given vault dir.
func NewWizardModel(vaultDir string) *WizardModel {
	state := WizardState{
		VaultDir:    vaultDir,
		ProfileName: defaultProfile,
	}

	welcome := NewWelcomeStep(vaultDir)
	state.ExistingVault = welcome.IsExistingVault()

	steps := []Step{
		welcome,
		NewVaultPathStep(vaultDir),
		NewPassphraseStep(),
		NewAuthStep(),
		NewSyncStep(),
		NewMultiDeviceStep(),
		NewRecipientsStep(),
		NewAgentsStep(),
		NewBackupStep(),
		NewProfileStep(),
		NewSummaryStep(&state),
		// NextStepsStep is added dynamically after successful Apply.
	}

	return &WizardModel{
		steps: steps,
		state: state,
	}
}

// Run starts the wizard program and blocks until done.
func Run(vaultDir string) error {
	m := NewWizardModel(vaultDir)
	p := tea.NewProgram(m, tea.WithAltScreen())
	result, err := p.Run()
	if err != nil {
		return fmt.Errorf("wizard: %w", err)
	}
	final, ok := result.(WizardModel)
	if !ok {
		return fmt.Errorf("wizard: unexpected result type")
	}
	if final.canceled {
		return fmt.Errorf("setup canceled")
	}
	return final.applyErr
}

func (m WizardModel) Init() tea.Cmd {
	if len(m.steps) > 0 {
		return m.steps[0].Init()
	}
	return nil
}

func (m WizardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.canceled = true
			m.quitting = true
			return m, tea.Quit
		}

	case stepDone:
		return m.handleStepDone()
	}

	// Delegate to current step.
	if m.current < len(m.steps) {
		updated, cmd := m.steps[m.current].Update(msg)
		m.steps[m.current] = updated
		return m, cmd
	}
	return m, nil
}

func (m WizardModel) handleStepDone() (tea.Model, tea.Cmd) {
	step := m.steps[m.current]

	// Collect state from completed step.
	switch s := step.(type) {
	case *WelcomeStep:
		m.state.ExistingVault = s.IsExistingVault()
	case *VaultPathStep:
		m.state.VaultDir = s.Value()
	case *PassphraseStep:
		m.state.Passphrase = s.Passphrase()
	case *AuthStep:
		m.state.AuthMethod = s.SelectedMethod()
	case *SyncStep:
		m.state.SyncMode = s.Mode()
		m.state.GitRemoteURL = s.RemoteURL()
		m.state.AutoPush = s.AutoPush()
	case *MultiDeviceStep:
		m.state.MultiDevice = s.WantsMultiDevice()
	case *RecipientsStep:
		m.state.Recipients = s.Recipients()
	case *AgentsStep:
		m.state.SelectedAgents = s.Selections()
	case *ProfileStep:
		m.state.ProfileName = s.Value()
	case *SummaryStep:
		switch s.Decision() {
		case 0: // Apply
			// Update the summary step's state pointer (already set, but refresh).
			err := Apply(&m.state)
			m.applyErr = err
			// Append the next-steps screen.
			m.steps = append(m.steps, NewNextStepsStep(&m.state))
		case 1: // Back
			// Go back two steps (skip current summary).
			if m.current > 0 {
				m.current--
				m.advanceToPrevVisible()
			}
			return m, nil
		case 2: // Cancel
			m.canceled = true
			return m, tea.Quit
		}
	case *NextStepsStep:
		return m, tea.Quit
	}

	return m.advanceToNextVisible()
}

// advanceToNextVisible moves to the next step that ShouldShow for the current state.
func (m WizardModel) advanceToNextVisible() (tea.Model, tea.Cmd) {
	for {
		m.current++
		if m.current >= len(m.steps) {
			return m, tea.Quit
		}
		if m.steps[m.current].ShouldShow(m.state) {
			return m, m.steps[m.current].Init()
		}
	}
}

func (m *WizardModel) advanceToPrevVisible() {
	for m.current > 0 {
		m.current--
		if m.steps[m.current].ShouldShow(m.state) {
			return
		}
	}
}

func (m WizardModel) View() string {
	if m.quitting && m.canceled {
		return "Setup canceled.\n"
	}
	if m.current >= len(m.steps) {
		return ""
	}

	step := m.steps[m.current]
	visible := m.visibleSteps()
	pos := m.visiblePos()

	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("240"))

	header := headerStyle.Render(fmt.Sprintf("OpenPass Setup  Step %d/%d — %s", pos+1, len(visible), step.Title()))
	content := step.View()
	footer := helpStyle.Render("Esc to quit")

	// Determine separator.
	sep := strings.Repeat("─", max(m.width, 40))

	return strings.Join([]string{header, sep, "", content, "", sep, footer}, "\n")
}

func (m *WizardModel) visibleSteps() []Step {
	var result []Step
	for _, s := range m.steps {
		if s.ShouldShow(m.state) {
			result = append(result, s)
		}
	}
	return result
}

func (m *WizardModel) visiblePos() int {
	pos := 0
	for i := 0; i < m.current; i++ {
		if m.steps[i].ShouldShow(m.state) {
			pos++
		}
	}
	return pos
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
