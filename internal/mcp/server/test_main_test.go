package server

import (
	"os"
	"runtime"
	"testing"
)

func TestMain(m *testing.M) {
	// The timeout fixture's filtered child cannot inherit the suite opt-in.
	if runtime.GOOS == "windows" && os.Getenv("SYMVAULT_RUN_WINDOWS_CROSSLANG") != "1" && os.Getenv("SYMAIRA_EXECUTE_SECRET_TIMEOUT_CHILD") != "1" {
		return // Historical Windows suite opt-out; native contract jobs explicitly opt in.
	}
	_ = os.Unsetenv("SYMVAULT_MCP_TOKEN")
	os.Exit(m.Run())
}
