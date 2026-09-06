//go:build windows

package diff

import (
	"errors"
	"strings"
	"syscall"
)

func isAlreadyGoneWaitDelayError(waitErr error, deadlineExceeded, treeCancellationIneffective, processExited bool) bool {
	return deadlineExceeded &&
		treeCancellationIneffective &&
		processExited &&
		strings.HasPrefix(waitErr.Error(), "exec: killing Cmd: ") &&
		errors.Is(waitErr, syscall.EINVAL)
}
