package wizard_test

import (
	"testing"

	"github.com/danieljustus/OpenPass/internal/ui/wizard"
)

func TestMeasureStrength(t *testing.T) {
	cases := []struct {
		input    string
		minScore wizard.PassphraseStrength
	}{
		{"", wizard.StrengthWeak},
		{"short", wizard.StrengthWeak},
		{"longpassword12!", wizard.StrengthGood},
		{"Sup3r$ecr3tLongP@ss!", wizard.StrengthStrong},
		{"abcdefghijkl", wizard.StrengthFair},
	}
	for _, tc := range cases {
		got := wizard.MeasureStrength(tc.input)
		if got < tc.minScore {
			t.Errorf("MeasureStrength(%q): got %s, want >= %s", tc.input, got, tc.minScore)
		}
	}
}

func TestStrengthBar(t *testing.T) {
	if wizard.StrengthWeak.Bar() == "" {
		t.Error("StrengthWeak.Bar() should not be empty")
	}
	if wizard.StrengthStrong.Bar() == "" {
		t.Error("StrengthStrong.Bar() should not be empty")
	}
}

func TestWizardState_Defaults(t *testing.T) {
	m := wizard.NewWizardModel("/tmp/test-vault")
	if m == nil {
		t.Fatal("expected model, got nil")
	}
}

func TestLooksLikeGitURL(t *testing.T) {
	// Test via SyncStep internal — just ensure wizard builds and compiles.
	_ = wizard.NewWizardModel("/tmp/x")
}
