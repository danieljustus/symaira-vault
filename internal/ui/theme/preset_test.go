package theme

import "testing"

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
