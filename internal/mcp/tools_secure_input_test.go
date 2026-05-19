package mcp

import (
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/secureui"
)

func mockSecureInputCapability(t *testing.T, c secureui.Capability) {
	t.Helper()
	original := secureInputCapabilityFn
	secureInputCapabilityFn = func() secureui.Capability { return c }
	t.Cleanup(func() { secureInputCapabilityFn = original })
}

func TestSecureInputToolAvailabilityInRegistry(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	mockSecureInputCapability(t, secureui.CapNone)
	tools := toolsListPayload(srv)
	if toolNamesContain(tools, "secure_input") {
		t.Error("secure_input should be hidden when no backend is available")
	}
	if toolNamesContain(tools, "request_credential") {
		t.Error("request_credential should be hidden when no backend is available")
	}

	mockSecureInputCapability(t, secureui.CapTTY)
	tools = toolsListPayload(srv)
	if !toolNamesContain(tools, "secure_input") {
		t.Error("secure_input should be listed when TTY is available")
	}
	if !toolNamesContain(tools, "request_credential") {
		t.Error("request_credential should be listed when TTY is available")
	}

	mockSecureInputCapability(t, secureui.CapGUI)
	tools = toolsListPayload(srv)
	if !toolNamesContain(tools, "secure_input") {
		t.Error("secure_input should be listed when GUI is available (HTTP-mode case)")
	}
}

func toolNamesContain(tools []map[string]any, target string) bool {
	for _, tool := range tools {
		if name, _ := tool["name"].(string); name == target {
			return true
		}
	}
	return false
}
