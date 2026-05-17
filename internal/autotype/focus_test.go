package autotype

import (
	"errors"
	"testing"
)

func TestGuardActiveWindow_StableFocus(t *testing.T) {
	old := captureActiveWindowFunc
	defer func() { captureActiveWindowFunc = old }()

	captureActiveWindowFunc = func() (string, error) { return "wmclass:firefox", nil }
	if err := guardActiveWindow(); err != nil {
		t.Errorf("guardActiveWindow() err = %v, want nil", err)
	}
}

func TestGuardActiveWindow_FocusChanged(t *testing.T) {
	old := captureActiveWindowFunc
	defer func() { captureActiveWindowFunc = old }()

	calls := 0
	captureActiveWindowFunc = func() (string, error) {
		calls++
		if calls == 1 {
			return "wmclass:firefox", nil
		}
		return "wmclass:slack", nil
	}

	err := guardActiveWindow()
	if !errors.Is(err, ErrFocusChanged) {
		t.Errorf("guardActiveWindow() err = %v, want ErrFocusChanged", err)
	}
}

func TestGuardActiveWindow_UnavailableLenient(t *testing.T) {
	old := captureActiveWindowFunc
	defer func() { captureActiveWindowFunc = old }()

	t.Setenv("OPENPASS_AUTOTYPE_STRICT_FOCUS", "0")
	captureActiveWindowFunc = func() (string, error) { return "", ErrFocusUnavailable }

	if err := guardActiveWindow(); err != nil {
		t.Errorf("guardActiveWindow() err = %v, want nil in lenient mode", err)
	}
}

func TestGuardActiveWindow_UnavailableStrict(t *testing.T) {
	old := captureActiveWindowFunc
	defer func() { captureActiveWindowFunc = old }()

	t.Setenv("OPENPASS_AUTOTYPE_STRICT_FOCUS", "1")
	captureActiveWindowFunc = func() (string, error) { return "", ErrFocusUnavailable }

	err := guardActiveWindow()
	if !errors.Is(err, ErrFocusUnavailable) {
		t.Errorf("guardActiveWindow() err = %v, want ErrFocusUnavailable in strict mode", err)
	}
}

func TestGuardActiveWindow_FirstCaptureFails(t *testing.T) {
	old := captureActiveWindowFunc
	defer func() { captureActiveWindowFunc = old }()

	someErr := errors.New("xdotool crashed")
	captureActiveWindowFunc = func() (string, error) { return "", someErr }

	err := guardActiveWindow()
	if !errors.Is(err, someErr) {
		t.Errorf("guardActiveWindow() err = %v, want %v", err, someErr)
	}
}
