package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	admin "github.com/danieljustus/OpenPass/cmd/admin"
	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func TestConfigSetCommand_Basic(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vaultDir: /old\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	resetCmdFlags()
	cli.RootCmd.SetArgs([]string{"config", "set", "vaultDir", "/new", "--file", cfgPath})
	defer cli.RootCmd.SetArgs(nil)

	output := captureStdout(func() {
		if err := cli.RootCmd.Execute(); err != nil {
			t.Fatalf("config set failed: %v", err)
		}
	})

	if !strings.Contains(output, "Set vaultDir = /new") {
		t.Errorf("unexpected output: %s", output)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "vaultDir: /new") {
		t.Errorf("config file doesn't contain new value: %s", string(data))
	}
}

func TestConfigSetCommand_BoolValue(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("agents:\n  test:\n    canWrite: false\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	resetCmdFlags()
	cli.RootCmd.SetArgs([]string{"config", "set", "agents.test.canWrite", "true", "--file", cfgPath})
	defer cli.RootCmd.SetArgs(nil)

	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("config set failed: %v", err)
	}

	var node yaml.Node
	data, _ := os.ReadFile(cfgPath)
	if err := yaml.Unmarshal(data, &node); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	doc := node.Content[0]
	for i := 0; i < len(doc.Content)-1; i += 2 {
		if doc.Content[i].Value == "agents" {
			agents := doc.Content[i+1]
			for j := 0; j < len(agents.Content)-1; j += 2 {
				if agents.Content[j].Value == "test" {
					profile := agents.Content[j+1]
					for k := 0; k < len(profile.Content)-1; k += 2 {
						if profile.Content[k].Value == "canWrite" {
							val := profile.Content[k+1]
							if val.Tag != "!!bool" || val.Value != "true" {
								t.Errorf("canWrite = tag=%q value=%q, want !!bool true", val.Tag, val.Value)
							}
							return
						}
					}
				}
			}
		}
	}
	t.Error("could not find agents.test.canWrite in saved config")
}

func TestConfigSetCommand_CreateNestedKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	resetCmdFlags()
	cli.RootCmd.SetArgs([]string{"config", "set", "agents.custom.canWrite", "true", "--file", cfgPath})
	defer cli.RootCmd.SetArgs(nil)

	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("config set failed: %v", err)
	}

	data, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(data), "custom:") || !strings.Contains(string(data), "canWrite:") {
		t.Errorf("config file missing new nested keys: %s", string(data))
	}
}

func TestConfigSetCommand_InvalidatesConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vaultDir: /test\nsessionTimeout: 15m\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	resetCmdFlags()
	cli.RootCmd.SetArgs([]string{"config", "set", "sessionTimeout", "invalid", "--file", cfgPath})
	defer cli.RootCmd.SetArgs(nil)

	err := cli.RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid sessionTimeout value")
	}
	if !strings.Contains(err.Error(), "config is invalid after update") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConfigSetCommand_MissingFile(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "nonexistent.yaml")

	resetCmdFlags()
	cli.RootCmd.SetArgs([]string{"config", "set", "vaultDir", "/new", "--file", cfgPath})
	defer cli.RootCmd.SetArgs(nil)

	err := cli.RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestConfigGetCommand_ExistingKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vaultDir: /my/vault\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	resetCmdFlags()
	cli.RootCmd.SetArgs([]string{"config", "get", "vaultDir", "--file", cfgPath})
	defer cli.RootCmd.SetArgs(nil)

	output := captureStdout(func() {
		if err := cli.RootCmd.Execute(); err != nil {
			t.Fatalf("config get failed: %v", err)
		}
	})

	if !strings.Contains(output, "/my/vault") {
		t.Errorf("expected /my/vault in output, got: %s", output)
	}
}

func TestConfigGetCommand_NestedKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("agents:\n  claude:\n    canWrite: true\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	resetCmdFlags()
	cli.RootCmd.SetArgs([]string{"config", "get", "agents.claude.canWrite", "--file", cfgPath})
	defer cli.RootCmd.SetArgs(nil)

	output := captureStdout(func() {
		if err := cli.RootCmd.Execute(); err != nil {
			t.Fatalf("config get failed: %v", err)
		}
	})

	if !strings.Contains(output, "true") {
		t.Errorf("expected true in output, got: %s", output)
	}
}

func TestConfigGetCommand_MissingKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vaultDir: /test\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	resetCmdFlags()
	cli.RootCmd.SetArgs([]string{"config", "get", "nonexistent.key", "--file", cfgPath})
	defer cli.RootCmd.SetArgs(nil)

	err := cli.RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestConfigGetCommand_MissingFile(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "nonexistent.yaml")

	resetCmdFlags()
	cli.RootCmd.SetArgs([]string{"config", "get", "vaultDir", "--file", cfgPath})
	defer cli.RootCmd.SetArgs(nil)

	err := cli.RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestConfigListCommand(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vaultDir: /test\nagents:\n  a:\n    canWrite: true\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	resetCmdFlags()
	cli.RootCmd.SetArgs([]string{"config", "list", "--file", cfgPath})
	defer cli.RootCmd.SetArgs(nil)

	output := captureStdout(func() {
		if err := cli.RootCmd.Execute(); err != nil {
			t.Fatalf("config list failed: %v", err)
		}
	})

	if !strings.Contains(output, "vaultDir:") || !strings.Contains(output, "/test") {
		t.Errorf("expected config content in output, got: %s", output)
	}
	if !strings.Contains(output, "canWrite:") || !strings.Contains(output, "true") {
		t.Errorf("expected nested config content in output, got: %s", output)
	}
}

func TestConfigListCommand_MissingFile(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "nonexistent.yaml")

	resetCmdFlags()
	cli.RootCmd.SetArgs([]string{"config", "list", "--file", cfgPath})
	defer cli.RootCmd.SetArgs(nil)

	err := cli.RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestConfigListCommand_EmptyConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	resetCmdFlags()
	cli.RootCmd.SetArgs([]string{"config", "list", "--file", cfgPath})
	defer cli.RootCmd.SetArgs(nil)

	output := captureStdout(func() {
		if err := cli.RootCmd.Execute(); err != nil {
			t.Fatalf("config list failed: %v", err)
		}
	})

	if !strings.Contains(output, "{}") {
		t.Errorf("expected empty config output, got: %s", output)
	}
}

func TestConfigKeyCompletionFunc(t *testing.T) {
	matches, directive := admin.ConfigKeyCompletionFunc(nil, nil, "vault")
	found := false
	for _, m := range matches {
		if m == "vaultDir" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected vaultDir in matches with prefix vault, got: %v", matches)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("directive = %d, want %d", directive, cobra.ShellCompDirectiveNoFileComp)
	}
}
