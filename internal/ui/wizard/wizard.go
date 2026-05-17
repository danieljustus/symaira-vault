// Package wizard provides the openpass setup interactive wizard.
package wizard

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// stepDone is a message sent when a step has completed its input.
type stepDone struct{}

// resumeMsg is sent when the WelcomeStep decides to resume a previous setup.
type resumeMsg struct {
	state     WizardState
	stepTitle string
}

type applyProgressMsg struct {
	step int
}

type applyDoneMsg struct {
	err error
}

func stepDoneCmd() tea.Cmd {
	return func() tea.Msg { return stepDone{} }
}

// WizardModel is the top-level Bubbletea model for the setup wizard.
type WizardModel struct {
	steps            []Step
	current          int
	state            WizardState
	width            int
	height           int
	quitting         bool
	canceled         bool
	confirmingCancel bool
	applyErr         error
	noResume         bool
	totalSteps       int
	applying         bool
	applyStep        string
	applyErrs        []string
	spinner          spinner.Model
}

// NewWizardModel constructs the model with all steps for a given vault dir.
func NewWizardModel(vaultDir string, keepOnError bool, noResume bool) *WizardModel {
	state := WizardState{
		VaultDir:    vaultDir,
		ProfileName: defaultProfile,
		KeepOnError: keepOnError,
		NoResume:    noResume,
	}

	welcome := NewWelcomeStep(vaultDir, noResume)
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
	}

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("86"))

	total := 0
	for _, s := range steps {
		if s.ShouldShow(state) {
			total++
		}
	}

	return &WizardModel{
		steps:      steps,
		state:      state,
		noResume:   noResume,
		totalSteps: total,
		spinner:    sp,
	}
}

// Run starts the wizard program and blocks until done.
func Run(vaultDir string, keepOnError bool, noResume bool) error {
	m := NewWizardModel(vaultDir, keepOnError, noResume)
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
		// On cancel, the resume state has already been persisted by
		// handleStepDone after each completed step. Tell the user how to
		// pick up where they left off — without this, the user assumes
		// they have to restart from scratch.
		if !final.noResume && final.state.VaultDir != "" {
			if _, _, lerr := LoadResumeState(final.state.VaultDir); lerr == nil {
				fmt.Println()
				fmt.Println("Setup paused. Resume anytime with `openpass setup`.")
				fmt.Println("Start fresh instead: `openpass setup --no-resume`.")
			}
		}
		return fmt.Errorf("setup canceled")
	}
	return final.applyErr
}

func (m WizardModel) Init() tea.Cmd {
	if len(m.steps) > 0 {
		return tea.Batch(m.steps[0].Init(), m.spinner.Tick)
	}
	return m.spinner.Tick
}

func (m WizardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		return m.handleKeyMsg(msg)

	case stepDone:
		if !m.applying {
			return m.handleStepDone()
		}

	case resumeMsg:
		m.state = msg.state
		m.state.Passphrase = nil
		for i, s := range m.steps {
			if s.Title() == msg.stepTitle && s.ShouldShow(m.state) {
				m.current = i
				return m, s.Init()
			}
		}
		return m.handleStepDone()

	case applyProgressMsg:
		return m.handleApplyProgress(msg.step)

	case applyDoneMsg:
		return m.handleApplyDone(msg.err)

	case spinner.TickMsg:
		if m.applying {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	}

	if m.applying {
		return m, nil
	}

	if m.current < len(m.steps) {
		updated, cmd := m.steps[m.current].Update(msg)
		m.steps[m.current] = updated
		return m, cmd
	}
	return m, nil
}

func (m WizardModel) handleKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.confirmingCancel {
		switch msg.String() {
		case "y", "Y":
			m.canceled = true
			m.quitting = true
			return m, tea.Quit
		case "n", "N", keyEsc:
			m.confirmingCancel = false
			return m, nil
		}
		return m, nil
	}

	switch msg.String() {
	case "ctrl+c":
		if m.applying {
			return m, nil
		}
		m.canceled = true
		m.quitting = true
		return m, tea.Quit
	case keyEsc:
		if m.applying {
			return m, nil
		}
		m.confirmingCancel = true
		return m, nil
	}

	if m.applying {
		return m, nil
	}

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
		return m.handleSummaryStep(s)
	case *NextStepsStep:
		return m, tea.Quit
	}

	// Save resume state after each completed step (except SummaryStep).
	if _, isSummary := step.(*SummaryStep); !isSummary {
		if !m.noResume && m.state.VaultDir != "" {
			_ = SaveResumeState(m.state.VaultDir, &m.state, step.Title())
		}
	}

	return m.advanceToNextVisible()
}

func (m WizardModel) handleSummaryStep(s *SummaryStep) (tea.Model, tea.Cmd) {
	switch s.Decision() {
	case 0: // Apply
		m.applying = true
		m.applyStep = "Validating..."
		return m, tea.Batch(m.spinner.Tick, func() tea.Msg { return applyProgressMsg{step: 0} })
	case 1: // Back
		if m.current > 0 {
			m.current--
			m.advanceToPrevVisible()
		}
		return m, nil
	case 2: // Cancel
		m.canceled = true
		return m, tea.Quit
	}
	return m.advanceToNextVisible()
}

var applySteps = []struct {
	label string
	fn    func(*WizardState, *[]string) error
}{
	{"Initializing vault...", func(s *WizardState, e *[]string) error {
		return preFlightCheck(s)
	}},
	{"Initializing vault...", func(s *WizardState, e *[]string) error {
		if s.ExistingVault {
			return nil
		}
		return applyVaultInit(s, e)
	}},
	{"Configuring git...", func(s *WizardState, e *[]string) error {
		applyGit(s, e)
		return nil
	}},
	{"Adding recipients...", func(s *WizardState, e *[]string) error {
		applyRecipients(s, e)
		return nil
	}},
	{"Saving profile...", func(s *WizardState, e *[]string) error {
		applyProfile(s, e)
		return nil
	}},
	{"Installing MCP agents...", func(s *WizardState, e *[]string) error {
		applyAgents(s, e)
		return nil
	}},
}

func (m WizardModel) handleApplyProgress(step int) (tea.Model, tea.Cmd) {
	if step >= len(applySteps) {
		return m.handleApplyFinalize()
	}

	s := applySteps[step]
	m.applyStep = s.label

	err := s.fn(&m.state, &m.applyErrs)

	// Pre-flight failure is fatal.
	if step == 0 && err != nil {
		m.applying = false
		m.applyErr = err
		return m, nil
	}

	// Wipe passphrase after vault init (step 1).
	if step == 1 {
		for i := range m.state.Passphrase {
			m.state.Passphrase[i] = 0
		}
		m.state.Passphrase = nil
	}

	return m, tea.Batch(m.spinner.Tick, func() tea.Msg {
		return applyProgressMsg{step: step + 1}
	})
}

func (m WizardModel) handleApplyFinalize() (tea.Model, tea.Cmd) {
	m.state.ApplyErrors = m.applyErrs

	if len(m.applyErrs) > 0 && !m.state.KeepOnError && !m.state.ExistingVault {
		rollbackInit(&m.state)
	}

	if len(m.applyErrs) > 0 {
		m.applyErr = fmt.Errorf("apply completed with errors — run `openpass doctor` for details")
	}

	_ = DeleteResumeFile(m.state.VaultDir)

	if m.state.MultiDevice && m.state.SyncMode == syncGit {
		m.steps = append(m.steps, NewPairingQRStep(&m.state))
	}
	m.steps = append(m.steps, NewNextStepsStep(&m.state))

	m.applying = false
	return m.advanceToNextVisible()
}

func (m WizardModel) handleApplyDone(err error) (tea.Model, tea.Cmd) {
	m.applying = false
	m.applyErr = err
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

	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("240"))

	sep := strings.Repeat("─", max(m.width, 40))
	footer := helpStyle.Render("Esc to cancel · Ctrl+C to quit")

	if m.applying {
		header := headerStyle.Render(fmt.Sprintf("OpenPass Setup  Step %d/%d — %s", m.totalSteps, m.totalSteps, m.applyStep))
		content := "  " + m.spinner.View() + " " + m.applyStep
		return strings.Join([]string{header, sep, "", content, "", sep, footer}, "\n")
	}

	if m.confirmingCancel {
		content := warnStyle.Render("Cancel setup? All progress will be lost.") + "\n" + helpStyle.Render("y/N")
		return strings.Join([]string{"", content, "", sep, footer}, "\n")
	}

	step := m.steps[m.current]
	pos := m.visiblePos()

	header := headerStyle.Render(fmt.Sprintf("OpenPass Setup  Step %d/%d%s — %s",
		pos+1, m.totalSteps, progressBar(pos, m.totalSteps), step.Title()))
	content := step.View()

	return strings.Join([]string{header, sep, "", content, "", sep, footer}, "\n")
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

func progressBar(pos, total int) string {
	if total <= 1 {
		return ""
	}
	const barWidth = 12
	filled := ((pos + 1) * barWidth) / total
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	return fmt.Sprintf(" %s", bar)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
