//go:build windows

package diff

import "os"

func terminationSignal(_ *os.ProcessState) string {
	// Windows process termination is represented by the process exit code.
	return ""
}
