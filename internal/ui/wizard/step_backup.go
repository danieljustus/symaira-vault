package wizard

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// BackupStep is a hint-only step (no side-effects in the wizard).
type BackupStep struct {
	done bool
}

func NewBackupStep() *BackupStep { return &BackupStep{} }

func (s *BackupStep) Title() string                 { return "Backup Plan" }
func (s *BackupStep) ShouldShow(_ WizardState) bool { return true }
func (s *BackupStep) Init() tea.Cmd                 { return nil }

func (s *BackupStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		if km.String() == keyEnter {
			s.done = true
			return s, stepDoneCmd()
		}
	}
	return s, nil
}

func (s *BackupStep) View() string {
	return strings.Join([]string{
		titleStyle.Render("Backup plan"),
		"",
		warnStyle.Render("Important:") + " back up your identity file outside this device.",
		"",
		"  " + dimStyle.Render("~/<vaultDir>/identity.age"),
		"",
		"Without it, the vault is unrecoverable if Touch ID / Keychain fails.",
		"Suggestions: USB drive, encrypted cloud storage, printed paper backup.",
		"",
		"Auto-backup scheduling via launchd can be configured manually later.",
		"",
		helpStyle.Render("Enter to continue"),
	}, "\n")
}
