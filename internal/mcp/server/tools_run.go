package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	secrets "github.com/danieljustus/symaira-vault/internal/secrets"
)

func (s *Server) handleRunCommand(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if !s.canRunCommands() {
		s.logAudit(ctx, "run_command", "<run-denied>", false)
		metrics.RecordAuthDenial("run_denied", s.agent.Name)
		return nil, runCommandDeniedError(s.agent.Name, "run_command")
	}

	cmdRaw, ok := req.Arguments["command"]
	if !ok {
		s.logAudit(ctx, "run_command", "<invalid>", false)
		return mcp.NewToolResultError("missing required argument \"command\""), nil
	}
	command, err := parseCommandArray(cmdRaw)
	if err != nil {
		s.logAudit(ctx, "run_command", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Enforce per-agent executable allowlist.
	if allowErr := s.checkExecutableAllowlist(command); allowErr != nil {
		s.logAudit(ctx, "run_command", command[0], false)
		metrics.RecordAuthDenial("executable_denied", s.agent.Name)
		return nil, allowErr
	}

	timeoutSeconds, timeoutErr := parseCommandTimeoutSeconds(req.Arguments["timeout"])
	if timeoutErr != nil {
		s.logAudit(ctx, "run_command", "<invalid:timeout>", false)
		return mcp.NewToolResultError(timeoutErr.Error()), nil
	}

	resolvedEnv := make(map[string]string)
	// Audit data: env var names only, never secret values.
	envNames := make([]string, 0)
	if envRaw, ok := req.Arguments["env"]; ok && envRaw != nil {
		envMap, ok := envRaw.(map[string]any)
		if !ok {
			s.logAudit(ctx, "run_command", "<invalid>", false)
			return mcp.NewToolResultError("argument \"env\" must be an object"), nil
		}

		for envName, refRaw := range envMap {
			ref, ok := refRaw.(string)
			if !ok {
				return mcp.NewToolResultError(fmt.Sprintf("env.%s value must be a string secret reference", envName)), nil
			}

			path := extractPathFromRef(ref)
			if !s.checkScope(path) {
				s.logAudit(ctx, "run_command", path, false)
				metrics.RecordAuthDenial("scope_denied", s.agent.Name)
				return nil, fmt.Errorf("access denied: secret ref path %q outside allowed scope", path)
			}

			value, resolveErr := secrets.ResolveSecretRef(s.vault, ref)
			if resolveErr != nil {
				return mcp.NewToolResultError(fmt.Sprintf("cannot resolve secret ref %q: %v", ref, resolveErr)), nil
			}
			resolvedEnv[envName] = value
			envNames = append(envNames, envName)
		}
	}
	sort.Strings(envNames)

	denied := secrets.RejectDenied(resolvedEnv)
	if len(denied) > 0 {
		s.logAudit(ctx, "run_command", "<validation-denied-env>", false)
		return mcp.NewToolResultError(fmt.Sprintf("env contains denied keys: %s", strings.Join(denied, ", "))), nil
	}

	if s.requiresApproval() {
		s.logAudit(ctx, "approval_denied", "run_command", false)
		metrics.RecordApproval(s.agent.Name, "denied")
		return nil, fmt.Errorf("run_command denied: approval required but cannot be granted")
	}

	workingDir := req.GetString("working_dir", "")

	auditPath := strings.Join(command, " ")
	if len(envNames) > 0 {
		auditPath += ", env=[" + strings.Join(envNames, ", ") + "]"
	}

	result, err := secrets.RunCommand(secrets.RunOptions{
		Command:    command,
		Env:        resolvedEnv,
		WorkingDir: workingDir,
		Timeout:    time.Duration(timeoutSeconds) * time.Second,
	})

	if err != nil {
		s.logAudit(ctx, "run_command", auditPath, false)
		if result != nil {
			sanitizedStdout, sanitizedStderr := s.sanitizeRunOutput(result.Stdout, result.Stderr, resolvedEnv)
			sanitizedErr := s.sanitizeKnownSecretValues(err.Error(), resolvedEnv)
			return mcp.NewToolResultError(fmt.Sprintf("%s\nExit code: %d\nStdout: %s\nStderr: %s",
				sanitizedErr, result.ExitCode, EmbedAsData("command_output", sanitizedStdout), EmbedAsData("command_output", sanitizedStderr))), nil
		}
		return mcp.NewToolResultError(s.sanitizeKnownSecretValues(err.Error(), resolvedEnv)), nil
	}

	s.logAudit(ctx, "run_command", auditPath, true)

	sanitizedStdout, sanitizedStderr := s.sanitizeRunOutput(result.Stdout, result.Stderr, resolvedEnv)

	resultJSON, err := json.Marshal(map[string]any{
		"exit_code":   result.ExitCode,
		"stdout":      EmbedAsData("command_output", sanitizedStdout),
		"stderr":      EmbedAsData("command_output", sanitizedStderr),
		"duration_ms": result.Duration.Milliseconds(),
	})
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(resultJSON)), nil
}

// extractPathFromRef returns the entry path portion of a secret reference.
// For "work/aws.password", returns "work/aws".
// For "github", returns "github".
func extractPathFromRef(ref string) string {
	if idx := strings.LastIndex(ref, "."); idx > 0 {
		return ref[:idx]
	}
	return ref
}
