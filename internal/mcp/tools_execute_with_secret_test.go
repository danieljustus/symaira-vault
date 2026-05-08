package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
)

func TestHandleExecuteWithSecret_BasicRun(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command":     []any{"echo", "hello"},
			"secret_refs": []any{},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleExecuteWithSecret() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleExecuteWithSecret() returned error: %s", result.Text)
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
}

func TestHandleExecuteWithSecret_SecretInjection(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "aws", map[string]any{
		"access_key": "AKIAIOSFODNN7EXAMPLE",
		"secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "echo $AWS_ACCESS_KEY"},
			"secret_refs": []any{
				"op://vault/aws/access_key",
			},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteWithSecret() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if code, _ := output["exit_code"].(float64); code != 0 {
		t.Errorf("exit_code = %v, want 0", code)
	}
	stdout, _ := output["stdout"].(string)
	if strings.Contains(stdout, "AKIAIO...MPLE") {
		t.Errorf("stdout = %q, should not contain plaintext secret", stdout)
	}
	if !strings.Contains(stdout, "***") {
		t.Errorf("stdout = %q, want to contain masked value '***'", stdout)
	}
}

func TestHandleExecuteWithSecret_NeverExposesSecretValue(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "aws", map[string]any{
		"secret_key": "super-secret-value-12345",
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"echo", "success"},
			"secret_refs": []any{
				"op://vault/aws/secret_key",
			},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteWithSecret() returned error: %s", result.Text)
	}

	resultStr := result.Text
	if strings.Contains(resultStr, "super-secret-value-12345") {
		t.Errorf("result contains secret value: %q", resultStr)
	}
}

func TestHandleExecuteWithSecret_MasksSecretInStdoutAndStderr(t *testing.T) {
	const secret = "synthetic-execute-success-secret"
	vaultDir, identity := mockVaultWithEntry(t, "aws", map[string]any{
		"secret_key": secret,
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "printf '%s' \"$AWS_SECRET_KEY\"; printf '%s' \"$AWS_SECRET_KEY\" >&2"},
			"secret_refs": []any{
				"op://vault/aws/secret_key",
			},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteWithSecret() returned error: %s", result.Text)
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
		if text != "***" {
			t.Errorf("%s = %q, want masked value '***'", field, text)
		}
	}
}

//nolint:dupl // similar test structure for different secret ref patterns
func TestHandleExecuteWithSecret_NestedPath(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "work/aws", map[string]any{
		"access_key": "nested-secret-123",
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "echo $WORK_AWS_ACCESS_KEY"},
			"secret_refs": []any{
				"op://vault/work/aws/access_key",
			},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteWithSecret() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if code, _ := output["exit_code"].(float64); code != 0 {
		t.Errorf("exit_code = %v, want 0", code)
	}
}

func TestHandleExecuteWithSecret_ScopeCheck(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "work/aws", map[string]any{
		"password": "secret123",
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"personal/"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"echo", "test"},
			"secret_refs": []any{
				"op://vault/work/aws/password",
			},
		},
	}

	_, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err == nil {
		t.Fatal("handleExecuteWithSecret() expected error for out-of-scope secret ref, got nil")
	}
	if !strings.Contains(err.Error(), "outside allowed scope") {
		t.Fatalf("error = %v, want 'outside allowed scope'", err)
	}
}

func TestHandleExecuteWithSecret_RunDenied(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "readonly",
		AllowedPaths:   []string{"*"},
		CanRunCommands: false,
		ApprovalMode:   "none",
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command":     []any{"echo", "test"},
			"secret_refs": []any{},
		},
	}

	_, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err == nil {
		t.Fatal("handleExecuteWithSecret() expected error for run-denied agent, got nil")
	}
	if !strings.Contains(err.Error(), "command execution not permitted") {
		t.Fatalf("error = %v, want 'command execution not permitted'", err)
	}
}

func TestHandleExecuteWithSecret_ApprovalDeny(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "deny",
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command":     []any{"echo", "test"},
			"secret_refs": []any{},
		},
	}

	_, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err == nil {
		t.Fatal("handleExecuteWithSecret() expected error for approval-deny, got nil")
	}
	if !strings.Contains(err.Error(), "approval mode is 'deny'") {
		t.Fatalf("error = %v, want 'approval mode is 'deny''", err)
	}
}

func TestHandleExecuteWithSecret_ApprovalPromptApproved(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "y", nil },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
		}, nil
	}

	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "prompt",
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command":     []any{"echo", "approved"},
			"secret_refs": []any{},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteWithSecret() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if stdout, _ := output["stdout"].(string); !strings.Contains(stdout, "approved") {
		t.Errorf("stdout = %q, want approved", stdout)
	}
}

func TestHandleExecuteWithSecret_ApprovalPromptDenied(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "n", nil },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
		}, nil
	}

	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "prompt",
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command":     []any{"echo", "test"},
			"secret_refs": []any{},
		},
	}

	_, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err == nil {
		t.Fatal("handleExecuteWithSecret() expected error for approval-denied, got nil")
	}
	if !strings.Contains(err.Error(), "user did not approve") {
		t.Fatalf("error = %v, want 'user did not approve'", err)
	}
}

func TestHandleExecuteWithSecret_ApprovalAuto(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "auto",
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command":     []any{"echo", "auto-ok"},
			"secret_refs": []any{},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteWithSecret() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if stdout, _ := output["stdout"].(string); !strings.Contains(stdout, "auto-ok") {
		t.Errorf("stdout = %q, want auto-ok", stdout)
	}
}

func TestHandleExecuteWithSecret_Timeout(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command":     []any{"sleep", "10"},
			"secret_refs": []any{},
			"timeout":     float64(1),
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleExecuteWithSecret() returned nil result")
	}
	if !result.IsError {
		t.Fatal("handleExecuteWithSecret() expected error result for timeout")
	}
	if !strings.Contains(result.Text, "timed out") {
		t.Fatalf("result text = %q, want 'timed out'", result.Text)
	}
}

func TestHandleExecuteWithSecret_MasksSecretOnTimeoutError(t *testing.T) {
	const secret = "synthetic-execute-timeout-secret"
	vaultDir, identity := mockVaultWithEntry(t, "aws", map[string]any{
		"secret_key": secret,
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "printf '%s' \"$AWS_SECRET_KEY\"; printf '%s' \"$AWS_SECRET_KEY\" >&2; exec sleep 10"},
			"secret_refs": []any{
				"op://vault/aws/secret_key",
			},
			"timeout": float64(1),
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleExecuteWithSecret() returned nil result")
	}
	if !result.IsError {
		t.Fatal("handleExecuteWithSecret() expected error result for timeout")
	}
	if strings.Contains(result.Text, secret) {
		t.Fatalf("result contains raw secret: %q", result.Text)
	}
	if !strings.Contains(result.Text, "Stdout: ***") {
		t.Fatalf("result text = %q, want masked stdout", result.Text)
	}
	if !strings.Contains(result.Text, "Stderr: ***") {
		t.Fatalf("result text = %q, want masked stderr", result.Text)
	}
	if !strings.Contains(result.Text, "Exit code: -1") {
		t.Fatalf("result text = %q, want exit code diagnostic", result.Text)
	}
}

func TestHandleExecuteWithSecret_InvalidParams(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio")

	tests := []struct {
		name    string
		args    map[string]any
		wantErr string
	}{
		{
			name:    "missing command",
			args:    map[string]any{"secret_refs": []any{}},
			wantErr: "missing required argument \"command\"",
		},
		{
			name:    "command not array",
			args:    map[string]any{"command": "not-an-array", "secret_refs": []any{}},
			wantErr: "must be an array",
		},
		{
			name:    "empty command array",
			args:    map[string]any{"command": []any{}, "secret_refs": []any{}},
			wantErr: "must not be empty",
		},
		{
			name:    "command element not string",
			args:    map[string]any{"command": []any{"echo", 42}, "secret_refs": []any{}},
			wantErr: "must be a string",
		},
		{
			name:    "missing secret_refs",
			args:    map[string]any{"command": []any{"echo", "test"}},
			wantErr: "missing required argument \"secret_refs\"",
		},
		{
			name:    "secret_refs not array",
			args:    map[string]any{"command": []any{"echo", "test"}, "secret_refs": "not-an-array"},
			wantErr: "must be an array",
		},
		{
			name:    "secret_ref not string",
			args:    map[string]any{"command": []any{"echo", "test"}, "secret_refs": []any{42}},
			wantErr: "must be a string",
		},
		{
			name:    "invalid op ref format",
			args:    map[string]any{"command": []any{"echo", "test"}, "secret_refs": []any{"invalid-ref"}},
			wantErr: "invalid secret ref",
		},
		{
			name:    "env_vars not object",
			args:    map[string]any{"command": []any{"echo", "test"}, "secret_refs": []any{}, "env_vars": "not-object"},
			wantErr: "must be an object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := CallToolRequest{Arguments: tt.args}
			result, err := srv.handleExecuteWithSecret(context.Background(), req)
			if err != nil {
				t.Fatalf("handleExecuteWithSecret() error = %v", err)
			}
			if result == nil {
				t.Fatal("handleExecuteWithSecret() returned nil result")
			}
			if !result.IsError {
				t.Error("handleExecuteWithSecret() expected error result")
			}
			if !strings.Contains(result.Text, tt.wantErr) {
				t.Errorf("result text = %q, want to contain %q", result.Text, tt.wantErr)
			}
		})
	}
}

func TestHandleExecuteWithSecret_DuplicateEnvVar(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "aws", map[string]any{
		"access_key": "key1",
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"echo", "test"},
			"secret_refs": []any{
				"op://vault/aws/access_key",
				"op://vault/aws/access_key",
			},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleExecuteWithSecret() returned nil result")
	}
	if !result.IsError {
		t.Fatal("handleExecuteWithSecret() expected error result for duplicate env var")
	}
	if !strings.Contains(result.Text, "duplicate environment variable name") {
		t.Fatalf("result text = %q, want 'duplicate environment variable name'", result.Text)
	}
}

func TestHandleExecuteWithSecret_WorkingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	wd := t.TempDir()
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command":     []any{"pwd"},
			"secret_refs": []any{},
			"working_dir": wd,
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteWithSecret() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	stdout := strings.TrimSpace(output["stdout"].(string))
	resolvedOut, err := filepath.EvalSymlinks(stdout)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", stdout, err)
	}
	want, err := filepath.EvalSymlinks(wd)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", wd, err)
	}
	if resolvedOut != want {
		t.Errorf("pwd (resolved) = %q, want %q", resolvedOut, want)
	}
}

func TestHandleExecuteWithSecret_EnvVars(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command":     []any{"sh", "-c", "echo $EXTRA_VAR"},
			"secret_refs": []any{},
			"env_vars": map[string]any{
				"EXTRA_VAR": "extra_value",
			},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteWithSecret() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if stdout, _ := output["stdout"].(string); !strings.Contains(stdout, "extra_value") {
		t.Errorf("stdout = %q, want extra_value", stdout)
	}
}

func TestHandleExecuteWithSecret_NonZeroExit(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command":     []any{"sh", "-c", "exit 42"},
			"secret_refs": []any{},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleExecuteWithSecret() returned nil result")
	}
	if result.IsError {
		t.Fatal("handleExecuteWithSecret() returned error result")
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if code, _ := output["exit_code"].(float64); code != 42 {
		t.Errorf("exit_code = %v, want 42", code)
	}
}

func TestHandleExecuteWithSecret_MasksSecretOnNonZeroExit(t *testing.T) {
	const secret = "synthetic-execute-nonzero-secret"
	vaultDir, identity := mockVaultWithEntry(t, "aws", map[string]any{
		"secret_key": secret,
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "printf '%s' \"$AWS_SECRET_KEY\"; printf '%s' \"$AWS_SECRET_KEY\" >&2; exit 42"},
			"secret_refs": []any{
				"op://vault/aws/secret_key",
			},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteWithSecret() returned error: %s", result.Text)
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
		if text != "***" {
			t.Errorf("%s = %q, want masked value '***'", field, text)
		}
	}
}

func TestHandleExecuteWithSecret_MissingSecretRef(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "github", map[string]any{
		"api_key": "test-token",
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"echo", "test"},
			"secret_refs": []any{
				"op://vault/github/missing_field",
			},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleExecuteWithSecret() returned nil result")
	}
	if !result.IsError {
		t.Fatal("handleExecuteWithSecret() expected error result for missing secret ref")
	}
	if !strings.Contains(result.Text, "cannot resolve secret ref") {
		t.Fatalf("result text = %q, want 'cannot resolve secret ref'", result.Text)
	}
}

//nolint:dupl // similar test structure for different secret ref patterns
func TestHandleExecuteWithSecret_FullEntryRef(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "github", map[string]any{
		"password": "entry-pass-123",
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"sh", "-c", "echo $GITHUB"},
			"secret_refs": []any{
				"op://vault/github",
			},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteWithSecret() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if code, _ := output["exit_code"].(float64); code != 0 {
		t.Errorf("exit_code = %v, want 0", code)
	}
}

func TestParseOpRef(t *testing.T) {
	tests := []struct {
		name       string
		ref        string
		wantEntry  string
		wantField  string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:      "simple entry and field",
			ref:       "op://vault/aws/access_key",
			wantEntry: "aws",
			wantField: "access_key",
		},
		{
			name:      "nested entry path",
			ref:       "op://vault/work/aws/secret_key",
			wantEntry: "work/aws",
			wantField: "secret_key",
		},
		{
			name:      "entry only",
			ref:       "op://vault/github",
			wantEntry: "github",
			wantField: "",
		},
		{
			name:       "missing op:// prefix",
			ref:        "vault/aws/key",
			wantErr:    true,
			wantErrMsg: "expected op:// prefix",
		},
		{
			name:       "only vault",
			ref:        "op://vault",
			wantErr:    true,
			wantErrMsg: "expected at least vault/entry",
		},
		{
			name:      "deeply nested",
			ref:       "op://vault/a/b/c/d/field",
			wantEntry: "a/b/c/d",
			wantField: "field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, field, err := parseOpRef(tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseOpRef() expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("error = %v, want %q", err, tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseOpRef() unexpected error = %v", err)
			}
			if entry != tt.wantEntry {
				t.Errorf("entry = %q, want %q", entry, tt.wantEntry)
			}
			if field != tt.wantField {
				t.Errorf("field = %q, want %q", field, tt.wantField)
			}
		})
	}
}

func TestGenerateEnvVarName(t *testing.T) {
	tests := []struct {
		entryPath string
		field     string
		want      string
	}{
		{"aws", "access_key", "AWS_ACCESS_KEY"},
		{"work/aws", "secret_key", "WORK_AWS_SECRET_KEY"},
		{"github", "", "GITHUB"},
		{"my-app", "api-key", "MY_APP_API_KEY"},
		{"a/b/c", "d", "A_B_C_D"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.entryPath, tt.field), func(t *testing.T) {
			got := generateEnvVarName(tt.entryPath, tt.field)
			if got != tt.want {
				t.Errorf("generateEnvVarName(%q, %q) = %q, want %q", tt.entryPath, tt.field, got, tt.want)
			}
		})
	}
}

func TestSanitizeEnvVarName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ABC_DEF", "ABC_DEF"},
		{"A-B-C", "A_B_C"},
		{"A.B.C", "A_B_C"},
		{"123", "123"},
		{"a@b#c", "a_b_c"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeEnvVarName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeEnvVarName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestHandleExecuteWithSecret_AuditLog(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "aws", map[string]any{
		"access_key": "audit-secret",
	})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test-agent",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"command": []any{"echo", "audit-test"},
			"secret_refs": []any{
				"op://vault/aws/access_key",
			},
		},
	}

	result, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteWithSecret() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteWithSecret() returned error: %s", result.Text)
	}

	if strings.Contains(result.Text, "audit-secret") {
		t.Errorf("result text contains secret value: %q", result.Text)
	}
}

func TestHandleExecuteWithSecret_ApprovalPromptNoTTY(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return nil, errors.New("no tty available")
	}

	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "prompt",
	}, "stdio")

	req := CallToolRequest{
		Arguments: map[string]any{
			"command":     []any{"echo", "test"},
			"secret_refs": []any{},
		},
	}

	_, err := srv.handleExecuteWithSecret(context.Background(), req)
	if err == nil {
		t.Fatal("handleExecuteWithSecret() expected error for no TTY, got nil")
	}
	if !strings.Contains(err.Error(), "approval failed") {
		t.Fatalf("error = %v, want 'approval failed'", err)
	}
}

func TestHandleExecuteWithSecret_ToolRegistered(t *testing.T) {
	_, ok := findToolDefinition("execute_with_secret")
	if !ok {
		t.Fatal("execute_with_secret tool not found in registry")
	}
}

func TestHandleExecuteWithSecret_ToolListed(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio")

	tools := toolsListPayload(srv)
	found := false
	for _, tool := range tools {
		if name, _ := tool["name"].(string); name == "execute_with_secret" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("execute_with_secret not in tools list payload")
	}
}
