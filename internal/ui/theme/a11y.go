package theme

import "os"

// ScreenReaderMode reports whether a screen reader is announced via env.
// When true, callers should:
//   - skip box-drawing characters (NVDA/VoiceOver speak them as garbage)
//   - prefer plain "Label: value" lines over visually-aligned tables
//   - emit semantic words ("warning", "error") instead of color cues alone
//
// The env contract is:
//
//	OPENPASS_SCREEN_READER=1   reduce UI to screen-reader-friendly text
//	OPENPASS_SCREEN_READER=0   force normal UI even if other env hints it
//	(unset)                    auto: check NVDA_SCREEN_READER, ORCA_RUNNING
func ScreenReaderMode() bool {
	switch os.Getenv("OPENPASS_SCREEN_READER") {
	case "1", "true", "yes":
		return true
	case "0", "false", "no": //nolint:goconst
		return false
	}
	return os.Getenv("NVDA_SCREEN_READER") != "" || os.Getenv("ORCA_RUNNING") != ""
}
