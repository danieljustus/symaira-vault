//go:build !linux && !darwin && !windows

package autotype

// defaultCaptureActiveWindow has no implementation on this platform.
// guardActiveWindow downgrades the resulting ErrFocusUnavailable to nil
// in lenient mode, so autotype keeps working as before; strict mode
// (OPENPASS_AUTOTYPE_STRICT_FOCUS=1) refuses to type without a check.
func defaultCaptureActiveWindow() (string, error) {
	return "", ErrFocusUnavailable
}
