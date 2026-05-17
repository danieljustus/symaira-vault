package autotype

import (
	"errors"
	"os"
	"time"
)

// ErrFocusChanged is returned when the active window changes between the
// pre-send capture and the actual send, indicating the user lost focus
// (e.g. clicked away or an app stole focus) before the secret was typed.
var ErrFocusChanged = errors.New("autotype: active window changed between capture and send — aborting to prevent typing into the wrong app")

// ErrFocusUnavailable is returned when focus detection is not implemented on
// the current platform; callers may choose to proceed (lenient mode) or fail
// (strict mode).
var ErrFocusUnavailable = errors.New("autotype: cannot detect active window on this platform")

// focusGuardDelay is how long we wait between the two captures. Long enough
// to catch slow focus changes, short enough not to feel laggy.
const focusGuardDelay = 200 * time.Millisecond

// captureActiveWindowFunc is the indirection used by both production and tests.
// Implementations return a stable identifier for the currently focused window
// (e.g. "WM_CLASS:firefox" on X11, "process:Safari" on macOS). Empty string +
// nil error means "focus detection succeeded but no window is focused".
var captureActiveWindowFunc = defaultCaptureActiveWindow

// guardActiveWindow performs a two-shot focus stability check. It returns
// nil if focus is stable, ErrFocusChanged if it differs, or ErrFocusUnavailable
// if the platform has no detection backend (so callers in lenient mode can
// continue and strict-mode callers can refuse).
//
// Strict mode is enabled by OPENPASS_AUTOTYPE_STRICT_FOCUS=1. In lenient mode
// (the default) ErrFocusUnavailable is downgraded to nil so existing users
// see no behavior change.
func guardActiveWindow() error {
	first, err1 := captureActiveWindowFunc()
	if errors.Is(err1, ErrFocusUnavailable) {
		if focusStrictMode() {
			return ErrFocusUnavailable
		}
		return nil
	}
	if err1 != nil {
		return err1
	}

	time.Sleep(focusGuardDelay)

	second, err2 := captureActiveWindowFunc()
	if err2 != nil && !errors.Is(err2, ErrFocusUnavailable) {
		return err2
	}

	if first != "" && second != "" && first != second {
		return ErrFocusChanged
	}
	return nil
}

func focusStrictMode() bool {
	v := os.Getenv("OPENPASS_AUTOTYPE_STRICT_FOCUS")
	return v != "" && v != "0"
}
