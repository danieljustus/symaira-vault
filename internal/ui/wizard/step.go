package wizard

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Step is the interface each wizard screen must implement.
type Step interface {
	// Init returns an initial command, same as tea.Model.Init.
	Init() tea.Cmd
	// Update handles messages and returns the updated model + next command.
	Update(msg tea.Msg) (Step, tea.Cmd)
	// View renders the step content (without the header/footer — the wizard wraps it).
	View() string
	// ShouldShow returns whether this step is applicable given the current state.
	ShouldShow(s WizardState) bool
	// Title returns a short step title shown in the wizard header.
	Title() string
}

// WizardState accumulates all user choices throughout the wizard.
type WizardState struct {
	// Vault
	VaultDir      string
	ExistingVault bool // vault already exists at VaultDir

	// Passphrase (cleared after Apply)
	Passphrase []byte

	// Auth
	AuthMethod string // "passphrase" | "touchid"

	// Sync
	SyncMode     string // "local" | "git"
	GitRemoteURL string
	AutoPush     bool

	// Multi-device (hint only, no side-effect)
	MultiDevice bool

	// Recipients (age1… strings)
	Recipients []string

	// AI agents
	SelectedAgents []AgentSelection

	// Backup hint (no side-effect in wizard)
	BackupDir string

	// Profile
	ProfileName string

	// Apply outcome
	ApplyErrors []string
}

// AgentSelection captures choices for a single MCP agent.
type AgentSelection struct {
	AgentType string // "claude-code" | "openclaw" | "hermes"
	Transport string // "stdio" | "http"
	Scope     string // path scope, default "*"
	ReadOnly  bool
}

// Key constants shared across steps to satisfy goconst linter.
const (
	keyEnter       = "enter"
	keyDown        = "down"
	keyUp          = "up"
	syncGit        = "git"
	defaultProfile = "default"
)

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	focusedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	helpStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	warnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
)
