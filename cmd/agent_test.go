package cmd

import (
	"bufio"
	"strings"
	"testing"
)

func TestBuildProfile(t *testing.T) {
	profile := buildProfile("test-agent", "standard", "*", "prompt", true)
	if profile.Name != "test-agent" {
		t.Errorf("Name = %q, want %q", profile.Name, "test-agent")
	}
	if profile.ApprovalMode != "prompt" {
		t.Errorf("ApprovalMode = %q, want %q", profile.ApprovalMode, "prompt")
	}
	if !profile.RequireApproval {
		t.Error("RequireApproval should be true")
	}
}

func TestPromptApprovalMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "default (empty)", input: "\n", expected: "prompt"},
		{name: "choice 1", input: "1\n", expected: "prompt"},
		{name: "choice 2", input: "2\n", expected: "deny"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tc.input))
			result := promptApprovalMode(reader)
			if result != tc.expected {
				t.Errorf("promptApprovalMode() = %q, want %q", result, tc.expected)
			}
		})
	}
}

func TestBuildProfileDefaults(t *testing.T) {
	profile := buildProfile("readonly-agent", "read-only", "bank/*", "deny", false)
	if profile.Name != "readonly-agent" {
		t.Errorf("Name = %q", profile.Name)
	}
	if profile.ApprovalMode != "deny" {
		t.Errorf("ApprovalMode = %q, want %q", profile.ApprovalMode, "deny")
	}
	if profile.RequireApproval {
		t.Error("RequireApproval should be false")
	}
	if len(profile.AllowedPaths) != 1 || profile.AllowedPaths[0] != "bank/*" {
		t.Errorf("AllowedPaths = %v, want [bank/*]", profile.AllowedPaths)
	}
}
