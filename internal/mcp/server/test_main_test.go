package server

import (
	"os"
	"runtime"
	"testing"
)

func TestMain(m *testing.M) {
	if runtime.GOOS == "windows" {
		return // skip mcp tests on Windows: LockFileEx access violation
	}
	_ = os.Unsetenv("OPENPASS_MCP_TOKEN")
	os.Exit(m.Run())
}
