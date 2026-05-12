package vault

import (
	"os"
	"runtime"
	"testing"
)

func TestMain(m *testing.M) {
	if runtime.GOOS == "windows" {
		return // skip vault tests on Windows: LockFileEx access violation in AcquireWriteLock
	}
	os.Exit(m.Run())
}
