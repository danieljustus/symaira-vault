package theme

import (
	"os"
	"testing"
)

func TestParsePreset(t *testing.T) {
	cases := map[string]Preset{
		"":              PresetDefault,
		"default":       PresetDefault,
		"highcontrast":  PresetHighContrast,
		"high-contrast": PresetHighContrast,
		"HC":            PresetHighContrast,
		"colorblind":    PresetColorblind,
		"deuteran":      PresetColorblind,
		"protan":        PresetColorblind,
		"tritan":        PresetColorblind,
		"unknown":       PresetDefault,
	}
	for in, want := range cases {
		if got := ParsePreset(in); got != want {
			t.Errorf("ParsePreset(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestApplyPreset_ChangesColors(t *testing.T) {
	t.Cleanup(func() { ApplyPreset(PresetDefault) })

	ApplyPreset(PresetDefault)
	defaultPrimary := ColorPrimary

	ApplyPreset(PresetHighContrast)
	if ColorPrimary == defaultPrimary {
		t.Errorf("ApplyPreset(HighContrast) did not change ColorPrimary")
	}

	ApplyPreset(PresetDefault)
	if ColorPrimary != defaultPrimary {
		t.Errorf("ApplyPreset(Default) did not restore ColorPrimary")
	}
}

func TestApplyPresetFromEnv(t *testing.T) {
	t.Cleanup(func() { ApplyPreset(PresetDefault) })

	ApplyPreset(PresetDefault)
	defaultError := ColorError

	t.Setenv("OPENPASS_THEME", "colorblind")
	ApplyPresetFromEnv()
	if ColorError == defaultError {
		t.Errorf("OPENPASS_THEME=colorblind did not change ColorError")
	}
}

func TestApplyPresetFromEnv_Symvault(t *testing.T) {
	t.Cleanup(func() { ApplyPreset(PresetDefault) })

	ApplyPreset(PresetDefault)
	defaultError := ColorError

	t.Setenv("SYMVAULT_THEME", "colorblind")
	ApplyPresetFromEnv()
	if ColorError == defaultError {
		t.Errorf("SYMVAULT_THEME=colorblind did not change ColorError")
	}
}

func TestApplyPresetFromEnv_SymvaultPrecedence(t *testing.T) {
	t.Cleanup(func() { ApplyPreset(PresetDefault) })

	ApplyPreset(PresetDefault)
	defaultError := ColorError

	// SYMVAULT_THEME should take precedence over OPENPASS_THEME
	t.Setenv("SYMVAULT_THEME", "highcontrast")
	t.Setenv("OPENPASS_THEME", "colorblind")
	ApplyPresetFromEnv()

	// Verify high contrast was applied (not colorblind)
	if ColorError == defaultError {
		t.Errorf("SYMVAULT_THEME=highcontrast should have applied HighContrast preset")
	}
	// Reset and try with SYMVAULT unset to verify fallback
	_ = os.Unsetenv("SYMVAULT_THEME")
	t.Setenv("OPENPASS_THEME", "colorblind")
	ApplyPreset(PresetDefault)
	ApplyPresetFromEnv()
	if ColorError == defaultError {
		t.Errorf("OPENPASS_THEME=colorblind fallback should have changed ColorError")
	}
}
