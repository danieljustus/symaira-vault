package wizard

import (
	"strings"
	"testing"
)

// snapshotTokens lists strings every render of a step MUST contain. Using a
// list of required tokens (rather than a byte-for-byte golden file) keeps the
// tests resilient to lipgloss style tweaks while still catching regressions
// in what's actually conveyed to the user.
//
// When teatest matures and we adopt full golden snapshots, drop these in
// favor of testdata/*.txt files; until then this is the lightest possible
// safety net for the wizard render path.
func TestWelcomeStep_RenderTokens_NewVault(t *testing.T) {
	t.TempDir() // ensure no vault is detected; vaultDir is empty below
	step := NewWelcomeStep(t.TempDir(), true)
	out := step.View()

	for _, want := range []string{"Welcome to OpenPass", "Enter", "Esc to quit"} {
		if !strings.Contains(out, want) {
			t.Errorf("View() missing %q in render:\n%s", want, out)
		}
	}
}

func TestWelcomeStep_NoCursesArtifacts(t *testing.T) {
	step := NewWelcomeStep(t.TempDir(), true)
	out := step.View()

	// Box-drawing or carriage-return artifacts in a static View() string are
	// a hint that the wizard accidentally embedded TUI control codes.
	for _, forbidden := range []string{"\r", "\x1b[?25"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("View() contains forbidden control sequence %q", forbidden)
		}
	}
}
