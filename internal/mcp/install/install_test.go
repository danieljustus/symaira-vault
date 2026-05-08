package install

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseAgentType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    AgentType
		wantErr bool
	}{
		{"openclaw", "openclaw", AgentOpenClaw, false},
		{"OpenClaw", "OpenClaw", AgentOpenClaw, false},
		{"claude-code", "claude-code", AgentClaudeCode, false},
		{"claude", "claude", AgentClaudeCode, false},
		{"hermes", "hermes", AgentHermes, false},
		{"unknown", "unknown", "", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAgentType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseAgentType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("ParseAgentType(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestExpandHome(t *testing.T) {
	home, err := osUserHomeDir()
	if err != nil {
		t.Skipf("cannot get home dir: %v", err)
	}

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"tilde only", "~", home},
		{"tilde slash", "~/foo", filepath.Join(home, "foo")},
		{"no tilde", "/abs/path", "/abs/path"},
		{"relative", "foo/bar", "foo/bar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandHome(tt.input)
			if err != nil {
				t.Fatalf("ExpandHome(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("ExpandHome(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestInjectServerConfig(t *testing.T) {
	serverConfig := map[string]any{
		"command": "openpass",
		"args":    []string{"serve", "--stdio"},
		"timeout": 120,
	}

	t.Run("creates new config", func(t *testing.T) {
		config := make(map[string]any)
		updated, changed := InjectServerConfig(config, "mcpServers", "openpass", serverConfig)
		if !changed {
			t.Fatal("expected changed=true for new config")
		}
		servers, ok := updated["mcpServers"].(map[string]any)
		if !ok {
			t.Fatal("expected mcpServers key")
		}
		if _, ok := servers["openpass"]; !ok {
			t.Fatal("expected openpass server entry")
		}
	})

	t.Run("updates existing different config", func(t *testing.T) {
		config := map[string]any{
			"mcpServers": map[string]any{
				"openpass": map[string]any{
					"command": "oldpass",
					"timeout": 60,
				},
			},
		}
		updated, changed := InjectServerConfig(config, "mcpServers", "openpass", serverConfig)
		if !changed {
			t.Fatal("expected changed=true when config differs")
		}
		servers := updated["mcpServers"].(map[string]any)
		got := servers["openpass"].(map[string]any)
		if got["command"] != "openpass" {
			t.Fatalf("expected command updated to openpass, got %v", got["command"])
		}
	})

	t.Run("idempotent same config", func(t *testing.T) {
		config := map[string]any{
			"mcpServers": map[string]any{
				"openpass": map[string]any{
					"command": "openpass",
					"args":    []any{"serve", "--stdio"},
					"timeout": 120,
				},
			},
		}
		_, changed := InjectServerConfig(config, "mcpServers", "openpass", serverConfig)
		if changed {
			t.Fatal("expected changed=false for identical config")
		}
	})

	t.Run("preserves other servers", func(t *testing.T) {
		config := map[string]any{
			"mcpServers": map[string]any{
				"other": map[string]any{
					"command": "other-cmd",
				},
			},
		}
		updated, changed := InjectServerConfig(config, "mcpServers", "openpass", serverConfig)
		if !changed {
			t.Fatal("expected changed=true")
		}
		servers := updated["mcpServers"].(map[string]any)
		if _, ok := servers["other"]; !ok {
			t.Fatal("expected other server to be preserved")
		}
	})
}

func TestJSONConfigRW(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	rw := JSONConfigRW{}

	t.Run("read non-existent returns empty map", func(t *testing.T) {
		data, err := rw.Read(filepath.Join(tmp, "nonexistent.json"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != 0 {
			t.Fatalf("expected empty map, got %v", data)
		}
	})

	t.Run("write and read roundtrip", func(t *testing.T) {
		config := map[string]any{
			"mcpServers": map[string]any{
				"openpass": map[string]any{
					"command": "openpass",
				},
			},
		}
		if err := rw.Write(path, config); err != nil {
			t.Fatalf("write error: %v", err)
		}

		readBack, err := rw.Read(path)
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
		servers, ok := readBack["mcpServers"].(map[string]any)
		if !ok {
			t.Fatal("expected mcpServers")
		}
		if _, ok := servers["openpass"]; !ok {
			t.Fatal("expected openpass server")
		}
	})
}

func TestYAMLConfigRW(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	rw := YAMLConfigRW{}

	t.Run("read non-existent returns empty map", func(t *testing.T) {
		data, err := rw.Read(filepath.Join(tmp, "nonexistent.yaml"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != 0 {
			t.Fatalf("expected empty map, got %v", data)
		}
	})

	t.Run("write and read roundtrip", func(t *testing.T) {
		config := map[string]any{
			"mcp_servers": map[string]any{
				"openpass": map[string]any{
					"command": "openpass",
				},
			},
		}
		if err := rw.Write(path, config); err != nil {
			t.Fatalf("write error: %v", err)
		}

		readBack, err := rw.Read(path)
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
		servers, ok := readBack["mcp_servers"].(map[string]any)
		if !ok {
			t.Fatal("expected mcp_servers")
		}
		if _, ok := servers["openpass"]; !ok {
			t.Fatal("expected openpass server")
		}
	})
}

func TestInstall(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "mcp.json")

	serverConfig := map[string]any{
		"command": "openpass",
		"args":    []string{"serve", "--stdio"},
		"timeout": 120,
	}

	t.Run("creates new config file", func(t *testing.T) {
		result, err := Install(InstallOptions{
			AgentType:    AgentOpenClaw,
			ServerConfig: serverConfig,
			Format:       FormatJSON,
			ConfigPath:   configPath,
			DryRun:       false,
		})
		if err != nil {
			t.Fatalf("install error: %v", err)
		}
		if !result.WasCreated {
			t.Fatal("expected WasCreated=true")
		}
		if _, err := os.Stat(configPath); err != nil {
			t.Fatalf("config file not created: %v", err)
		}
	})

	t.Run("idempotent second run", func(t *testing.T) {
		result, err := Install(InstallOptions{
			AgentType:    AgentOpenClaw,
			ServerConfig: serverConfig,
			Format:       FormatJSON,
			ConfigPath:   configPath,
			DryRun:       false,
		})
		if err != nil {
			t.Fatalf("install error: %v", err)
		}
		if !result.WasUnchanged {
			t.Fatalf("expected WasUnchanged=true, got created=%v updated=%v unchanged=%v",
				result.WasCreated, result.WasUpdated, result.WasUnchanged)
		}
	})

	t.Run("dry run does not create file", func(t *testing.T) {
		dryPath := filepath.Join(tmp, "dry.json")
		_, err := Install(InstallOptions{
			AgentType:    AgentOpenClaw,
			ServerConfig: serverConfig,
			Format:       FormatJSON,
			ConfigPath:   dryPath,
			DryRun:       true,
		})
		if err != nil {
			t.Fatalf("install error: %v", err)
		}
		if _, err := os.Stat(dryPath); !os.IsNotExist(err) {
			t.Fatal("expected dry-run to not create file")
		}
	})
}

func TestDetectAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	t.Run("detects by config file", func(t *testing.T) {
		tmp := t.TempDir()
		configDir := filepath.Join(tmp, ".config", "openclaw")
		if err := os.MkdirAll(configDir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		configPath := filepath.Join(configDir, "mcp.json")
		if err := os.WriteFile(configPath, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		oldHome := osUserHomeDir
		osUserHomeDir = func() (string, error) { return tmp, nil }
		defer func() { osUserHomeDir = oldHome }()

		result, err := DetectAgent(AgentOpenClaw)
		if err != nil {
			t.Fatalf("detect error: %v", err)
		}
		if !result.Detected {
			t.Fatal("expected agent detected by config file")
		}
		if !strings.HasSuffix(result.ConfigPath, ".config/openclaw/mcp.json") {
			t.Fatalf("unexpected config path: %s", result.ConfigPath)
		}
	})

	t.Run("no detection", func(t *testing.T) {
		tmp := t.TempDir()
		oldHome := osUserHomeDir
		osUserHomeDir = func() (string, error) { return tmp, nil }
		defer func() { osUserHomeDir = oldHome }()

		result, err := DetectAgent(AgentOpenClaw)
		if err != nil {
			t.Fatalf("detect error: %v", err)
		}
		if result.Detected {
			t.Fatal("expected agent not detected")
		}
	})
}

func TestBackupConfig(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	content := []byte(`{"mcpServers":{}}`)
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	backupPath, err := BackupConfig(configPath)
	if err != nil {
		t.Fatalf("backup error: %v", err)
	}
	if backupPath == "" {
		t.Fatal("expected backup path")
	}

	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backupData) != string(content) {
		t.Fatal("backup content mismatch")
	}

	// Backup of non-existent file should return empty path.
	noExistPath := filepath.Join(tmp, "nonexistent.json")
	emptyPath, err := BackupConfig(noExistPath)
	if err != nil {
		t.Fatalf("backup non-existent error: %v", err)
	}
	if emptyPath != "" {
		t.Fatalf("expected empty path for non-existent file, got %q", emptyPath)
	}
}

func TestPreviewConfig(t *testing.T) {
	config := map[string]any{
		"mcpServers": map[string]any{
			"openpass": map[string]any{
				"command": "openpass",
			},
		},
	}

	t.Run("json preview", func(t *testing.T) {
		out, err := PreviewConfig(config, FormatJSON)
		if err != nil {
			t.Fatalf("preview error: %v", err)
		}
		if !strings.Contains(out, "mcpServers") {
			t.Fatal("expected mcpServers in preview")
		}
	})

	t.Run("yaml preview", func(t *testing.T) {
		out, err := PreviewConfig(config, FormatYAML)
		if err != nil {
			t.Fatalf("preview error: %v", err)
		}
		if !strings.Contains(out, "mcpServers") {
			t.Fatal("expected mcpServers in preview")
		}
	})
}
