package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCmdDoctor_TextOutput(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	t.Cleanup(func() { rootCmd.SetOut(nil) })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "doctor", "--no-network"})
	defer rootCmd.SetArgs(nil)
	_ = rootCmd.Execute()

	out := buf.String()
	if !strings.Contains(out, "OpenPass Doctor") {
		t.Errorf("expected header in output, got: %q", out)
	}
	if !strings.Contains(out, "Score:") {
		t.Errorf("expected Score line in output, got: %q", out)
	}
}

func TestCmdDoctor_JSONOutput(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	t.Cleanup(func() { rootCmd.SetOut(nil) })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "doctor", "--no-network", "--json"})
	defer rootCmd.SetArgs(nil)
	_ = rootCmd.Execute()

	var result struct {
		VaultDir string `json:"vault_dir"`
		Results  []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"results"`
		Score struct {
			Total int `json:"total"`
		} `json:"score"`
	}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v\noutput: %q", err, buf.String())
	}
	if result.VaultDir == "" {
		t.Error("expected non-empty vault_dir in JSON output")
	}
	if len(result.Results) == 0 {
		t.Error("expected at least one result in JSON output")
	}
	if result.Score.Total == 0 {
		t.Error("expected non-zero score total")
	}
}

func TestCmdDoctor_NoNetworkFlag(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	t.Cleanup(func() { rootCmd.SetOut(nil) })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "doctor", "--no-network"})
	defer rootCmd.SetArgs(nil)
	_ = rootCmd.Execute()

	if buf.Len() == 0 {
		t.Error("expected non-empty output with --no-network flag")
	}
}

func TestCmdDoctor_FixFlag_Registered(t *testing.T) {
	flag := doctorCmd.Flags().Lookup("fix")
	if flag == nil {
		t.Fatal("--fix flag not registered on doctorCmd")
	}
	if flag.Value.Type() != "bool" {
		t.Errorf("--fix flag expected type bool, got %s", flag.Value.Type())
	}
}

func TestCmdDoctor_FixFlag_TextOutput(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	t.Cleanup(func() { rootCmd.SetOut(nil) })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "doctor", "--fix", "--no-network"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err != nil {
		t.Errorf("doctor --fix --no-network failed: %v", err)
	}

	out := buf.String()
	if out == "" {
		t.Error("expected non-empty output from doctor --fix --no-network")
	}
}

func TestGetVaultDir_WithVaultFlag(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	dir := getVaultDir()
	if dir == "" {
		t.Error("expected non-empty vault dir")
	}
}
