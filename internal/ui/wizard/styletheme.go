package wizard

import "github.com/danieljustus/symaira-vault/internal/ui/theme"

// Theme aliases — all wizard step files reference styles by their original names.
// These wrappers delegate to the centralized theme package so that step files
// continue to compile without modification.
var (
	titleStyle   = theme.TitleStyle
	focusedStyle = theme.FocusedStyle
	errorStyle   = theme.ErrorStyle
	helpStyle    = theme.DimStyle
	dimStyle     = theme.DimStyle
	warnStyle    = theme.WarnStyle
	successStyle = theme.SuccessStyle
)
