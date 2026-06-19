package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyValidateCmd_Success(t *testing.T) {
	resetVaultState(t)
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
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "valid") {
		t.Errorf("output = %q, want to contain 'valid'", output)
	}
}

func TestPolicyValidateCmd_Invalid(t *testing.T) {
	resetVaultState(t)
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
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("Execute() expected error, got nil")
	}
}

func TestSafePolicyPath(t *testing.T) {
	dir := filepath.Join("vault", "policies")
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid yaml", "dev.yaml", false},
		{"valid yml", "dev.yml", false},
		{"uppercase extension", "DEV.YAML", false},
		{"parent traversal", "../identity.age", true},
		{"nested traversal", "../../etc/passwd", true},
		{"traversal to yaml", "../evil.yaml", true},
		{"path separator", "sub/dev.yaml", true},
		{"absolute path", "/etc/dev.yaml", true},
		{"dot", ".", true},
		{"dotdot", "..", true},
		{"empty", "", true},
		{"no extension", "dev", true},
		{"wrong extension", "identity.age", true},
		{"null byte", "dev\x00.yaml", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := safePolicyPath(dir, tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("safePolicyPath(%q) = %q, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("safePolicyPath(%q) unexpected error: %v", tc.input, err)
			}
			if filepath.Dir(got) != filepath.Clean(dir) {
				t.Errorf("safePolicyPath(%q) = %q, escapes %q", tc.input, got, dir)
			}
		})
	}
}

const testPolicyContent = `version: "1.0"
description: "Test policy"
rules:
  - name: "allow test"
    priority: 100
    conditions:
      agent_id: "*"
    action: "allow"
`

func TestPolicyRemoveCmd_RejectsTraversal(t *testing.T) {
	resetVaultState(t)
	vaultDir := t.TempDir()
	restore := setupVaultFlag(t, vaultDir)
	defer restore()

	// A sensitive sibling file that "../identity.age" would target.
	sentinel := filepath.Join(vaultDir, "identity.age")
	if err := os.WriteFile(sentinel, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	var out strings.Builder
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"policy", "remove", "../identity.age"})
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err == nil {
		t.Fatal("policy remove with traversal name: expected error, got nil")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("sentinel file was removed via traversal: %v", err)
	}
}

func TestPolicyApplyCmd_RejectsSymlinkDest(t *testing.T) {
	resetVaultState(t)
	vaultDir := t.TempDir()
	restore := setupVaultFlag(t, vaultDir)
	defer restore()

	policiesDir := filepath.Join(vaultDir, "policies")
	if err := os.MkdirAll(policiesDir, 0o750); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}

	// Plant a symlink where the applied file would land, pointing at an
	// outside file. SafeWriteFile must refuse to follow it.
	outside := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(outside, []byte("original"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	link := filepath.Join(policiesDir, "evil.yaml")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	src := filepath.Join(t.TempDir(), "evil.yaml")
	if err := os.WriteFile(src, []byte(testPolicyContent), 0o600); err != nil {
		t.Fatalf("write source policy: %v", err)
	}

	var out strings.Builder
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"policy", "apply", src})
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err == nil {
		t.Fatal("policy apply over a symlink: expected error, got nil")
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("read outside target: %v", err)
	}
	if string(data) != "original" {
		t.Fatalf("symlink target was overwritten through the policy directory: %q", data)
	}
}

func TestPolicyApplyRemoveCmd_RoundTrip(t *testing.T) {
	resetVaultState(t)
	vaultDir := t.TempDir()
	restore := setupVaultFlag(t, vaultDir)
	defer restore()

	src := filepath.Join(t.TempDir(), "dev.yaml")
	if err := os.WriteFile(src, []byte(testPolicyContent), 0o600); err != nil {
		t.Fatalf("write source policy: %v", err)
	}

	var out strings.Builder
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"policy", "apply", src})
	defer rootCmd.SetArgs(nil)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("policy apply: %v", err)
	}

	applied := filepath.Join(vaultDir, "policies", "dev.yaml")
	if _, err := os.Stat(applied); err != nil {
		t.Fatalf("applied policy missing: %v", err)
	}

	rootCmd.SetArgs([]string{"policy", "remove", "dev.yaml"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("policy remove: %v", err)
	}
	if _, err := os.Stat(applied); !os.IsNotExist(err) {
		t.Fatalf("policy file still present after remove: %v", err)
	}
}
