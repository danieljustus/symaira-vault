// Package clipboard provides timer-based clipboard clearing utilities.
package clipboard

import (
	"errors"
	"time"
)

// ErrClipboardNotCleared indicates that a clipboard Read after Clear still
// returned the original secret. This typically happens when a clipboard
// history manager (Klipper, Albert, Maccy, Ditto) restores prior contents.
// Callers should warn the user so they can disable history retention for
// sensitive copies.
var ErrClipboardNotCleared = errors.New("clipboard still contains the copied secret after clear; a clipboard-history manager may have restored it")

// StartAutoClear clears the clipboard after the configured timeout unless canceled.
func StartAutoClear(duration int, clearFn func(), cancelCh <-chan struct{}) {
	if duration <= 0 || clearFn == nil {
		return
	}

	timer := time.NewTimer(time.Duration(duration) * time.Second)
	defer timer.Stop()

	select {
	case <-timer.C:
		clearFn()
	case <-cancelCh:
	}
}

// VerifyCleared reads the clipboard via readFn and returns
// ErrClipboardNotCleared if the contents still match the expected secret.
// Pass the value that was just cleared so the check is exact rather than
// "is the clipboard empty" (some platforms keep an empty-but-formatted
// pasteboard entry after Copy("")).
//
// readFn errors propagate so callers can distinguish "couldn't verify"
// from "verification failed".
func VerifyCleared(expectedAbsent string, readFn func() (string, error)) error {
	if readFn == nil || expectedAbsent == "" {
		return nil
	}
	current, err := readFn()
	if err != nil {
		return err
	}
	if current == expectedAbsent {
		return ErrClipboardNotCleared
	}
	return nil
}

// Countdown reports the remaining seconds until zero unless canceled.
func Countdown(duration int, updateFn func(int), cancelCh <-chan struct{}) {
	if duration <= 0 || updateFn == nil {
		return
	}

	updateFn(duration)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	remaining := duration
	for remaining > 0 {
		select {
		case <-cancelCh:
			return
		case <-ticker.C:
			remaining--
			updateFn(remaining)
		}
	}
}
