package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/danieljustus/OpenPass/internal/metrics"
	secrets "github.com/danieljustus/OpenPass/internal/secrets"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

func (s *Server) handleRunCommand(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	if !s.canRunCommands() {
		s.logAudit(ctx, "run_command", "<run-denied>", false)
		metrics.RecordAuthDenial("run_denied", s.agent.Name)
		return nil, fmt.Errorf("command execution not permitted for this agent")
	}

	cmdRaw, ok := req.Arguments["command"]
	if !ok {
		s.logAudit(ctx, "run_command", "<invalid>", false)
		return NewToolResultError("missing required argument \"command\""), nil
	}
	cmdSlice, ok := cmdRaw.([]any)
	if !ok {
		s.logAudit(ctx, "run_command", "<invalid>", false)
		return NewToolResultError("argument \"command\" must be an array"), nil
	}
	if len(cmdSlice) == 0 {
		s.logAudit(ctx, "run_command", "<invalid>", false)
		return NewToolResultError("command array must not be empty"), nil
	}
	command := make([]string, len(cmdSlice))
	for i, v := range cmdSlice {
		str, ok := v.(string)
		if !ok {
			s.logAudit(ctx, "run_command", "<invalid>", false)
			return NewToolResultError(fmt.Sprintf("command[%d] must be a string", i)), nil
		}
		command[i] = str
	}

	resolvedEnv := make(map[string]string)
	// Audit data: env var names only, never secret values.
	envNames := make([]string, 0)
	if envRaw, ok := req.Arguments["env"]; ok && envRaw != nil {
		envMap, ok := envRaw.(map[string]any)
		if !ok {
			s.logAudit(ctx, "run_command", "<invalid>", false)
			return NewToolResultError("argument \"env\" must be an object"), nil
		}

		svc := vaultsvc.New(slog.Default(), s.vault)
		for envName, refRaw := range envMap {
			ref, ok := refRaw.(string)
			if !ok {
				return NewToolResultError(fmt.Sprintf("env.%s value must be a string secret reference", envName)), nil
			}

			path := extractPathFromRef(ref)
			if !s.checkScope(path) {
				s.logAudit(ctx, "run_command", path, false)
				metrics.RecordAuthDenial("scope_denied", s.agent.Name)
				return nil, fmt.Errorf("access denied: secret ref path %q outside allowed scope", path)
			}

			value, err := secrets.ResolveSecretRef(svc, ref)
			if err != nil {
				return NewToolResultError(fmt.Sprintf("cannot resolve secret ref %q: %v", ref, err)), nil
			}
			resolvedEnv[envName] = value
			envNames = append(envNames, envName)
		}
	}
	sort.Strings(envNames)

	if s.requiresApproval() {
		s.logAudit(ctx, "approval_denied", "run_command", false)
		metrics.RecordApproval(s.agent.Name, "denied")
		return nil, fmt.Errorf("run_command denied: approval required but cannot be granted")
	}

	workingDir := req.GetString("working_dir", "")
	timeoutSeconds := int(req.GetFloat("timeout", 30))

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
			return NewToolResultError(fmt.Sprintf("%s\nExit code: %d\nStdout: %s\nStderr: %s",
				sanitizedErr, result.ExitCode, sanitizedStdout, sanitizedStderr)), nil
		}
		return NewToolResultError(s.sanitizeKnownSecretValues(err.Error(), resolvedEnv)), nil
	}

	s.logAudit(ctx, "run_command", auditPath, true)

	sanitizedStdout, sanitizedStderr := s.sanitizeRunOutput(result.Stdout, result.Stderr, resolvedEnv)

	resultJSON, err := json.Marshal(map[string]any{
		"exit_code":   result.ExitCode,
		"stdout":      sanitizedStdout,
		"stderr":      sanitizedStderr,
		"duration_ms": result.Duration.Milliseconds(),
	})
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(resultJSON)), nil
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
