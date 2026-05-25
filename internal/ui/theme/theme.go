// Package theme provides centralized color tokens and shared lipgloss styles for
// the Symaira Vault UI, TUI, wizard, doctor, and CLI output. All UI components should
// import this package rather than defining their own color constants.
//
// Colors use lipgloss.AdaptiveColor so they render legibly on both dark and light
// terminal backgrounds.
package theme

import "github.com/charmbracelet/lipgloss"

// Adaptive color tokens — each pair specifies a Light (light-background) and Dark
// (dark-background) color value from the 256-color terminal palette.
var (
	// ColorPrimary is the primary accent (pink/magenta). Used for titles, headers.
	ColorPrimary = lipgloss.AdaptiveColor{Light: "162", Dark: "212"}

	// ColorFocused is the focused accent (cyan). Used for focused items, keys.
	ColorFocused = lipgloss.AdaptiveColor{Light: "30", Dark: "86"}

	// ColorError is the error/danger color (red).
	ColorError = lipgloss.AdaptiveColor{Light: "124", Dark: "203"}

	// ColorMuted is muted/secondary text (medium gray).
	ColorMuted = lipgloss.AdaptiveColor{Light: "243", Dark: "240"}

	// ColorDim is dim/subtle text (lighter gray).
	ColorDim = lipgloss.AdaptiveColor{Light: "245", Dark: "245"}

	// ColorWarning is warning/amber.
	ColorWarning = lipgloss.AdaptiveColor{Light: "130", Dark: "220"}

	// ColorSuccess is success/green.
	ColorSuccess = lipgloss.AdaptiveColor{Light: "28", Dark: "82"}

	// ColorSelectedBg is the selection/highlight background (blue).
	ColorSelectedBg = lipgloss.AdaptiveColor{Light: "26", Dark: "62"}

	// ColorSelectedFg is the selection/highlight foreground (cream/yellow).
	ColorSelectedFg = lipgloss.AdaptiveColor{Light: "229", Dark: "229"}
)

// Pre-built lipgloss styles shared across all UI components.
var (
	// TitleStyle is used for headings and section titles.
	TitleStyle = lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary)

	// FocusedStyle is used for the currently focused/active item.
	FocusedStyle = lipgloss.NewStyle().Foreground(ColorFocused).Bold(true)

	// ErrorStyle is used for error messages and danger indicators.
	ErrorStyle = lipgloss.NewStyle().Foreground(ColorError)

	// MutedStyle is used for secondary/less important text.
	MutedStyle = lipgloss.NewStyle().Foreground(ColorMuted)

	// DimStyle is used for the most subtle text (hints, placeholders).
	DimStyle = lipgloss.NewStyle().Foreground(ColorDim)

	// WarnStyle is used for warning messages.
	WarnStyle = lipgloss.NewStyle().Foreground(ColorWarning)

	// SuccessStyle is used for success messages and positive indicators.
	SuccessStyle = lipgloss.NewStyle().Foreground(ColorSuccess)

	// KeyStyle is used for keyboard shortcut labels.
	KeyStyle = lipgloss.NewStyle().Foreground(ColorFocused).Bold(true)

	// SelectedStyle is used for the currently selected list item.
	SelectedStyle = lipgloss.NewStyle().
			Foreground(ColorSelectedFg).
			Background(ColorSelectedBg).
			Bold(true)
)
