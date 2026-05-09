package wizard

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// SyncStep lets the user pick local-only or git-remote sync.
type SyncStep struct {
	mode     int // 0=local, 1=git
	urlInput textinput.Model
	autoPush bool
	phase    int // 0=pick mode, 1=enter URL, 2=autopush
	err      string
	done     bool
}

func NewSyncStep() *SyncStep {
	ti := textinput.New()
	ti.Placeholder = "git@github.com:user/vault.git or https://…"
	ti.CharLimit = 512
	return &SyncStep{autoPush: true, urlInput: ti}
}

func (s *SyncStep) Title() string                 { return "Sync Strategy" }
func (s *SyncStep) ShouldShow(_ WizardState) bool { return true }
func (s *SyncStep) Init() tea.Cmd                 { return nil }

func (s *SyncStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		if s.phase == 1 {
			var cmd tea.Cmd
			s.urlInput, cmd = s.urlInput.Update(msg)
			return s, cmd
		}
		return s, nil
	}
	switch s.phase {
	case 0: // pick local vs git
		switch km.String() {
		case "up", "k":
			if s.mode > 0 {
				s.mode--
			}
		case "down", "j":
			if s.mode < 1 {
				s.mode++
			}
		case keyEnter, " ":
			if s.mode == 0 {
				// Local only — done.
				s.done = true
				return s, stepDoneCmd()
			}
			// Git remote — enter URL.
			s.phase = 1
			s.urlInput.Focus()
			return s, textinput.Blink
		}
	case 1: // enter URL
		if km.String() == keyEnter {
			url := strings.TrimSpace(s.urlInput.Value())
			if url == "" || !looksLikeGitURL(url) {
				s.err = "please enter a valid git URL (https://…, ssh://…, or git@…)"
				return s, nil
			}
			s.err = ""
			s.phase = 2
			return s, nil
		}
		var cmd tea.Cmd
		s.urlInput, cmd = s.urlInput.Update(msg)
		s.err = ""
		return s, cmd
	case 2: // autopush?
		switch km.String() {
		case "y", "Y", keyEnter:
			s.autoPush = true
			s.done = true
			return s, stepDoneCmd()
		case "n", "N":
			s.autoPush = false
			s.done = true
			return s, stepDoneCmd()
		}
	}
	return s, nil
}

func (s *SyncStep) View() string {
	switch s.phase {
	case 0:
		opts := []string{"Local only (no sync)", "Git remote (GitHub, GitLab, self-hosted, …)"}
		lines := []string{
			titleStyle.Render("Sync strategy"),
			"",
			"How should this vault be synchronized?",
			"",
		}
		for i, opt := range opts {
			if i == s.mode {
				lines = append(lines, focusedStyle.Render("▸ "+opt))
			} else {
				lines = append(lines, "  "+opt)
			}
		}
		lines = append(lines, "", helpStyle.Render("↑/↓ select · Enter to confirm"))
		return strings.Join(lines, "\n")

	case 1:
		lines := []string{
			titleStyle.Render("Git remote URL"),
			"",
			s.urlInput.View(),
		}
		if s.err != "" {
			lines = append(lines, "", errorStyle.Render("✗ "+s.err))
		} else {
			lines = append(lines, "", helpStyle.Render("Enter to confirm"))
		}
		return strings.Join(lines, "\n")

	case 2:
		return strings.Join([]string{
			titleStyle.Render("Auto-push on change?"),
			"",
			"Automatically push to " + dimStyle.Render(s.urlInput.Value()) + " after each write?",
			"",
			focusedStyle.Render("Y") + " / " + helpStyle.Render("N") + helpStyle.Render("  (default: Y)"),
		}, "\n")
	}
	return ""
}

// Mode returns "local" or "git".
func (s *SyncStep) Mode() string {
	if s.mode == 0 {
		return "local"
	}
	return syncGit
}

func (s *SyncStep) RemoteURL() string { return strings.TrimSpace(s.urlInput.Value()) }
func (s *SyncStep) AutoPush() bool    { return s.autoPush }

func looksLikeGitURL(u string) bool {
	return strings.HasPrefix(u, "https://") ||
		strings.HasPrefix(u, "http://") ||
		strings.HasPrefix(u, "ssh://") ||
		strings.HasPrefix(u, "git@") ||
		strings.HasPrefix(u, "file://")
}
