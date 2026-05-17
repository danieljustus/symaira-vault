package theme

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Preset names a built-in color palette. Selection happens via the
// OPENPASS_THEME env var or the global --theme flag (forwarded by cmd).
type Preset int

const (
	// PresetDefault is the bundled magenta/cyan palette.
	PresetDefault Preset = iota
	// PresetHighContrast maximizes foreground/background contrast for low-light
	// environments and visual-impairment accessibility.
	PresetHighContrast
	// PresetColorblind avoids red/green pairings on the success/error axis,
	// using blue/orange instead — safe for deutan/protan/tritan vision.
	PresetColorblind
)

// ParsePreset normalises a user-supplied preset name. Unknown values fall
// back to PresetDefault so callers don't need to error-handle.
func ParsePreset(s string) Preset {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "highcontrast", "high-contrast", "hc":
		return PresetHighContrast
	case "colorblind", "cb", "deuteran", "protan", "tritan":
		return PresetColorblind
	default:
		return PresetDefault
	}
}

// ApplyPreset re-binds the package-level color tokens to a palette and
// rebuilds the lipgloss styles that depend on them. Call this once at
// process start (after parsing flags).
func ApplyPreset(p Preset) {
	switch p {
	case PresetHighContrast:
		ColorPrimary = lipgloss.AdaptiveColor{Light: "0", Dark: "15"}
		ColorFocused = lipgloss.AdaptiveColor{Light: "21", Dark: "51"}
		ColorError = lipgloss.AdaptiveColor{Light: "9", Dark: "9"}
		ColorMuted = lipgloss.AdaptiveColor{Light: "8", Dark: "7"}
		ColorDim = lipgloss.AdaptiveColor{Light: "8", Dark: "7"}
		ColorWarning = lipgloss.AdaptiveColor{Light: "208", Dark: "208"}
		ColorSuccess = lipgloss.AdaptiveColor{Light: "22", Dark: "10"}
		ColorSelectedBg = lipgloss.AdaptiveColor{Light: "0", Dark: "15"}
		ColorSelectedFg = lipgloss.AdaptiveColor{Light: "15", Dark: "0"}
	case PresetColorblind:
		ColorPrimary = lipgloss.AdaptiveColor{Light: "21", Dark: "33"}
		ColorFocused = lipgloss.AdaptiveColor{Light: "27", Dark: "75"}
		ColorError = lipgloss.AdaptiveColor{Light: "166", Dark: "208"}
		ColorMuted = lipgloss.AdaptiveColor{Light: "243", Dark: "240"}
		ColorDim = lipgloss.AdaptiveColor{Light: "245", Dark: "245"}
		ColorWarning = lipgloss.AdaptiveColor{Light: "172", Dark: "214"}
		ColorSuccess = lipgloss.AdaptiveColor{Light: "27", Dark: "75"}
		ColorSelectedBg = lipgloss.AdaptiveColor{Light: "21", Dark: "33"}
		ColorSelectedFg = lipgloss.AdaptiveColor{Light: "15", Dark: "15"}
	default:
		ColorPrimary = lipgloss.AdaptiveColor{Light: "162", Dark: "212"}
		ColorFocused = lipgloss.AdaptiveColor{Light: "30", Dark: "86"}
		ColorError = lipgloss.AdaptiveColor{Light: "124", Dark: "203"}
		ColorMuted = lipgloss.AdaptiveColor{Light: "243", Dark: "240"}
		ColorDim = lipgloss.AdaptiveColor{Light: "245", Dark: "245"}
		ColorWarning = lipgloss.AdaptiveColor{Light: "130", Dark: "220"}
		ColorSuccess = lipgloss.AdaptiveColor{Light: "28", Dark: "82"}
		ColorSelectedBg = lipgloss.AdaptiveColor{Light: "26", Dark: "62"}
		ColorSelectedFg = lipgloss.AdaptiveColor{Light: "229", Dark: "229"}
	}
	rebuildStyles()
}

func rebuildStyles() {
	TitleStyle = lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary)
	FocusedStyle = lipgloss.NewStyle().Foreground(ColorFocused).Bold(true)
	ErrorStyle = lipgloss.NewStyle().Foreground(ColorError)
	MutedStyle = lipgloss.NewStyle().Foreground(ColorMuted)
	DimStyle = lipgloss.NewStyle().Foreground(ColorDim)
	WarnStyle = lipgloss.NewStyle().Foreground(ColorWarning)
	SuccessStyle = lipgloss.NewStyle().Foreground(ColorSuccess)
	KeyStyle = lipgloss.NewStyle().Foreground(ColorFocused).Bold(true)
	SelectedStyle = lipgloss.NewStyle().
		Foreground(ColorSelectedFg).
		Background(ColorSelectedBg).
		Bold(true)
}

// ApplyPresetFromEnv reads OPENPASS_THEME and applies the matching preset.
func ApplyPresetFromEnv() {
	v := os.Getenv("OPENPASS_THEME")
	if v == "" {
		return
	}
	ApplyPreset(ParsePreset(v))
}
