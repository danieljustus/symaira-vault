//go:build !windows

package diff

func isAlreadyGoneWaitDelayError(waitErr error, deadlineExceeded, treeCancellationIneffective, processExited bool) bool {
	return false
}
