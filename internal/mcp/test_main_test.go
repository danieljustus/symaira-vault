package mcp

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.Unsetenv("OPENPASS_MCP_TOKEN")
	os.Exit(m.Run())
}
