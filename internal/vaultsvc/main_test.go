package vaultsvc

import (
	"os"
	"runtime"
	"testing"
)

func TestMain(m *testing.M) {
	if runtime.GOOS == "windows" {
		return // skip vaultsvc tests on Windows: LockFileEx access violation
	}
	os.Exit(m.Run())
}
