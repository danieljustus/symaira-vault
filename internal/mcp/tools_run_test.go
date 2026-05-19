package mcp

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func mockVaultWithEntry(t *testing.T, path string, data map[string]any) (string, *age.X25519Identity) {
	t.Helper()

	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	entry := &vault.Entry{Data: data}
	if err := vault.WriteEntry(dir, path, entry, identity); err != nil {
		t.Fatalf("write entry %q: %v", path, err)
	}

	return dir, identity
}

func TestHandleRunCommand_BasicRun(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"echo", "hello"},
		},
	}

	result, err := srv.handleRunCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRunCommand() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleRunCommand() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleRunCommand() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if code, _ := output["exit_code"].(float64); code != 0 {
		t.Errorf("exit_code = %v, want 0", code)
	}
	if stdout, _ := output["stdout"].(string); !strings.Contains(stdout, "hello") {
		t.Errorf("stdout = %q, want hello", stdout)
	}
	if d, _ := output["duration_ms"].(float64); d < 0 {
		t.Error("duration_ms should not be negative")
	}
}

func TestHandleRunCommand_SecretEnvInjection(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "github", map[string]any{
		"api_key": "test-token-42",
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "echo $MY_KEY"},
			"env": map[string]any{
				"MY_KEY": "github.api_key",
			},
		},
	}

	result, err := srv.handleRunCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRunCommand() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleRunCommand() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	stdout, _ := output["stdout"].(string)
	if strings.Contains(stdout, "test-token-42") {
		t.Errorf("stdout = %q, should not contain plaintext secret 'test-token-42'", stdout)
	}
	if !strings.Contains(stdout, "***") {
		t.Errorf("stdout = %q, want to contain masked value '***'", stdout)
	}
}

func TestHandleRunCommand_MasksSecretEnvInStdoutAndStderr(t *testing.T) {
	const secret = "synthetic-run-command-success-secret"
	vaultDir, identity := mockVaultWithEntry(t, "github", map[string]any{
		"api_key": secret,
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "printf '%s' \"$MY_KEY\"; printf '%s' \"$MY_KEY\" >&2"},
			"env": map[string]any{
				"MY_KEY": "github.api_key",
			},
		},
	}

	result, err := srv.handleRunCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRunCommand() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleRunCommand() returned error: %s", result.Text)
	}
	if strings.Contains(result.Text, secret) {
		t.Fatalf("result contains raw secret: %q", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	for _, field := range []string{"stdout", "stderr"} {
		text, _ := output[field].(string)
		if !strings.Contains(text, "***") {
			t.Errorf("%s = %q, want masked value '***'", field, text)
		}
	}
}

func TestHandleRunCommand_SecretEnvFullEntry(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "work/aws", map[string]any{
		"username": "alice",
		"password": "secret123",
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "echo $ALL_DATA"},
			"env": map[string]any{
				"ALL_DATA": "work/aws",
			},
		},
	}

	result, err := srv.handleRunCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRunCommand() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleRunCommand() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	stdout, _ := output["stdout"].(string)
	if strings.Contains(stdout, "secret123") {
		t.Errorf("stdout = %q, should not contain plaintext secret 'secret123'", stdout)
	}
	if !strings.Contains(stdout, "***") {
		t.Errorf("stdout = %q, want to contain masked value '***'", stdout)
	}
}

func TestHandleRunCommand_ScopeCheck(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "work/aws", map[string]any{
		"password": "secret123",
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"personal/"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"echo", "test"},
			"env": map[string]any{
				"PASS": "work/aws.password",
			},
		},
	}

	_, err := srv.handleRunCommand(context.Background(), req)
	if err == nil {
		t.Fatal("handleRunCommand() expected error for out-of-scope secret ref, got nil")
	}
	if !strings.Contains(err.Error(), "outside allowed scope") {
		t.Fatalf("error = %v, want 'outside allowed scope'", err)
	}
}

func TestHandleRunCommand_RunDenied(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "readonly",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(false),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"echo", "test"},
		},
	}

	_, err := srv.handleRunCommand(context.Background(), req)
	if err == nil {
		t.Fatal("handleRunCommand() expected error for run-denied agent, got nil")
	}
	if !strings.Contains(err.Error(), "command execution not permitted") {
		t.Fatalf("error = %v, want 'command execution not permitted'", err)
	}
}

func TestHandleRunCommand_Timeout(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sleep", "10"},
			"timeout": float64(1),
		},
	}

	result, err := srv.handleRunCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRunCommand() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleRunCommand() returned nil result")
	}
	if !result.IsError {
		t.Fatal("handleRunCommand() expected error result for timeout")
	}
	if !strings.Contains(result.Text, "timed out") {
		t.Fatalf("result text = %q, want 'timed out'", result.Text)
	}
}

func TestHandleRunCommand_MasksSecretEnvOnTimeoutError(t *testing.T) {
	const secret = "synthetic-run-command-timeout-secret"
	vaultDir, identity := mockVaultWithEntry(t, "github", map[string]any{
		"api_key": secret,
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "printf '%s' \"$MY_KEY\"; printf '%s' \"$MY_KEY\" >&2; exec sleep 10"},
			"env": map[string]any{
				"MY_KEY": "github.api_key",
			},
			"timeout": float64(1),
		},
	}

	result, err := srv.handleRunCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRunCommand() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleRunCommand() returned nil result")
	}
	if !result.IsError {
		t.Fatal("handleRunCommand() expected error result for timeout")
	}
	if strings.Contains(result.Text, secret) {
		t.Fatalf("result contains raw secret: %q", result.Text)
	}
	if !strings.Contains(result.Text, "***") {
		t.Fatalf("result text = %q, want masked stdout", result.Text)
	}
	if !strings.Contains(result.Text, "Exit code: -1") {
		t.Fatalf("result text = %q, want exit code diagnostic", result.Text)
	}
}

func TestHandleRunCommand_InvalidCommand(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio")

	tests := []struct {
		name    string
		args    map[string]any
		wantErr string
	}{
		{
			name:    "missing command",
			args:    map[string]any{},
			wantErr: "missing required argument \"command\"",
		},
		{
			name:    "command not array",
			args:    map[string]any{"command": "not-an-array"},
			wantErr: "must be an array",
		},
		{
			name:    "empty command array",
			args:    map[string]any{"command": []any{}},
			wantErr: "must not be empty",
		},
		{
			name:    "command element not string",
			args:    map[string]any{"command": []any{"echo", 42}},
			wantErr: "must be a string",
		},
		{
			name: "env not object",
			args: map[string]any{
				"command": []any{"echo", "test"},
				"env":     "not-an-object",
			},
			wantErr: "must be an object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := CallToolRequest{Arguments: tt.args}
			result, err := srv.handleRunCommand(context.Background(), req)
			if err != nil {
				t.Fatalf("handleRunCommand() error = %v", err)
			}
			if result == nil {
				t.Fatal("handleRunCommand() returned nil result")
			}
			if !result.IsError {
				t.Error("handleRunCommand() expected error result")
			}
			if !strings.Contains(result.Text, tt.wantErr) {
				t.Errorf("result text = %q, want to contain %q", result.Text, tt.wantErr)
			}
		})
	}
}

func TestHandleRunCommand_MissingSecretRef(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "github", map[string]any{
		"api_key": "test-token",
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"echo", "test"},
			"env": map[string]any{
				"KEY": "github.missing_field",
			},
		},
	}

	result, err := srv.handleRunCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRunCommand() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleRunCommand() returned nil result")
	}
	if !result.IsError {
		t.Fatal("handleRunCommand() expected error result for missing secret ref")
	}
	if !strings.Contains(result.Text, "cannot resolve secret ref") {
		t.Fatalf("result text = %q, want 'cannot resolve secret ref'", result.Text)
	}
}

func TestHandleRunCommand_WorkingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	wd := t.TempDir()
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command":     []any{"pwd"},
			"working_dir": wd,
		},
	}

	result, err := srv.handleRunCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRunCommand() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleRunCommand() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	stdout := strings.TrimSpace(output["stdout"].(string))
	// stdout is wrapped with EmbedAsData; verify the path is contained within.
	if !strings.Contains(stdout, wd) {
		t.Errorf("stdout = %q, want to contain working dir %q", stdout, wd)
	}
}

func TestHandleRunCommand_NonZeroExit(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "exit 42"},
		},
	}

	result, err := srv.handleRunCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRunCommand() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleRunCommand() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleRunCommand() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if code, _ := output["exit_code"].(float64); code != 42 {
		t.Errorf("exit_code = %v, want 42", code)
	}
}

func TestHandleRunCommand_MasksSecretEnvOnNonZeroExit(t *testing.T) {
	const secret = "synthetic-run-command-nonzero-secret"
	vaultDir, identity := mockVaultWithEntry(t, "github", map[string]any{
		"api_key": secret,
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "printf '%s' \"$MY_KEY\"; printf '%s' \"$MY_KEY\" >&2; exit 42"},
			"env": map[string]any{
				"MY_KEY": "github.api_key",
			},
		},
	}

	result, err := srv.handleRunCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRunCommand() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleRunCommand() returned error: %s", result.Text)
	}
	if strings.Contains(result.Text, secret) {
		t.Fatalf("result contains raw secret: %q", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if code, _ := output["exit_code"].(float64); code != 42 {
		t.Errorf("exit_code = %v, want 42", code)
	}
	for _, field := range []string{"stdout", "stderr"} {
		text, _ := output[field].(string)
		if !strings.Contains(text, "***") {
			t.Errorf("%s = %q, want masked value '***'", field, text)
		}
	}
}

func TestHandleRunCommand_ApprovalRequired(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("deny"),
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"echo", "test"},
		},
	}

	_, err := srv.handleRunCommand(context.Background(), req)
	if err == nil {
		t.Fatal("handleRunCommand() expected error for approval-required, got nil")
	}
	if !strings.Contains(err.Error(), "approval required") {
		t.Fatalf("error = %v, want 'approval required'", err)
	}
}

func TestHandleRunCommand_ExecutableAllowlist_Allowed(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:               "test",
		AllowedPaths:       []string{"*"},
		CanRunCommands:     config.BoolPtr(true),
		ApprovalMode:       config.StrPtr("none"),
		AllowedExecutables: []string{"echo", "cat"},
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"echo", "hello"},
		},
	}

	result, err := srv.handleRunCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRunCommand() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleRunCommand() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleRunCommand() returned error: %s", result.Text)
	}
}

func TestHandleRunCommand_ExecutableAllowlist_Denied(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:               "test",
		AllowedPaths:       []string{"*"},
		CanRunCommands:     config.BoolPtr(true),
		ApprovalMode:       config.StrPtr("none"),
		AllowedExecutables: []string{"echo", "cat"},
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "echo hello"},
		},
	}

	_, err := srv.handleRunCommand(context.Background(), req)
	if err == nil {
		t.Fatal("handleRunCommand() expected error for disallowed executable, got nil")
	}
	if !strings.Contains(err.Error(), "not in agent allowlist") {
		t.Fatalf("error = %v, want 'not in agent allowlist'", err)
	}
}

func TestHandleRunCommand_ExecutableAllowlist_EmptyAllowsAll(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:               "test",
		AllowedPaths:       []string{"*"},
		CanRunCommands:     config.BoolPtr(true),
		ApprovalMode:       config.StrPtr("none"),
		AllowedExecutables: []string{},
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"echo", "hello"},
		},
	}

	result, err := srv.handleRunCommand(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRunCommand() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleRunCommand() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleRunCommand() returned error: %s", result.Text)
	}
}
