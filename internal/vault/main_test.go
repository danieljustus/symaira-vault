package vault

import (
	"os"
	"runtime"
	"testing"
)

func TestMain(m *testing.M) {
	if runtime.GOOS == "windows" && os.Getenv("SYMVAULT_RUN_WINDOWS_CROSSLANG") != "1" {
		return // skip vault tests on Windows: LockFileEx access violation in AcquireWriteLock
	}
	os.Exit(m.Run())
}
