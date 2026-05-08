package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyValidateCmd_Success(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test-policy.yaml")

	content := `
version: "1.0"
description: "Test policy"
rules:
  - name: "allow test"
    priority: 100
    conditions:
      agent_id: "*"
    action: "allow"
`
	if err := os.WriteFile(policyFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	var out strings.Builder
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"policy", "validate", policyFile})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "valid") {
		t.Errorf("output = %q, want to contain 'valid'", output)
	}
}

func TestPolicyValidateCmd_Invalid(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "invalid-policy.yaml")

	content := `
version: "1.0"
rules:
  - name: "invalid"
    action: "not_an_action"
`
	if err := os.WriteFile(policyFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	var out strings.Builder
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"policy", "validate", policyFile})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("Execute() expected error, got nil")
	}
}
