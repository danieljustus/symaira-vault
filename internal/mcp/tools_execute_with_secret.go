package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/secrets"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

// handleExecuteWithSecret executes a command with secrets injected as environment
// variables. The agent never sees the secret values — only stdout, stderr, and
// exit code are returned.
//
//nolint:gocyclo // complexity inherent to secret resolution, validation, and command execution
func (s *Server) handleExecuteWithSecret(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	if !s.canRunCommands() {
		s.logAudit(ctx, "execute_with_secret", "<run-denied>", false)
		metrics.RecordAuthDenial("run_denied", s.agent.Name)
		return nil, fmt.Errorf("command execution not permitted for this agent")
	}

	cmdRaw, ok := req.Arguments["command"]
	if !ok {
		s.logAudit(ctx, "execute_with_secret", "<invalid:missing-command>", false)
		return NewToolResultError("missing required argument \"command\""), nil
	}
	cmdSlice, ok := cmdRaw.([]any)
	if !ok {
		s.logAudit(ctx, "execute_with_secret", "<invalid:command-not-array>", false)
		return NewToolResultError("argument \"command\" must be an array"), nil
	}
	if len(cmdSlice) == 0 {
		s.logAudit(ctx, "execute_with_secret", "<invalid:empty-command>", false)
		return NewToolResultError("command array must not be empty"), nil
	}
	command := make([]string, len(cmdSlice))
	for i, v := range cmdSlice {
		str, valid := v.(string)
		if !valid {
			s.logAudit(ctx, "execute_with_secret", "<invalid:command-type>", false)
			return NewToolResultError(fmt.Sprintf("command[%d] must be a string", i)), nil
		}
		command[i] = str
	}

	refsRaw, ok := req.Arguments["secret_refs"]
	if !ok {
		s.logAudit(ctx, "execute_with_secret", "<invalid:missing-secret_refs>", false)
		return NewToolResultError("missing required argument \"secret_refs\""), nil
	}

	secretRefs := make([]string, 0)
	resolvedEnv := make(map[string]string)
	secretEnv := make(map[string]string)
	if refsRaw != nil {
		refsSlice, ok := refsRaw.([]any)
		if !ok {
			s.logAudit(ctx, "execute_with_secret", "<invalid:secret_refs-not-array>", false)
			return NewToolResultError("argument \"secret_refs\" must be an array"), nil
		}

		svc := vaultsvc.New(slog.Default(), s.vault)
		seenEnvVars := make(map[string]bool)

		for i, v := range refsSlice {
			ref, ok := v.(string)
			if !ok {
				s.logAudit(ctx, "execute_with_secret", "<invalid:secret_ref-type>", false)
				return NewToolResultError(fmt.Sprintf("secret_refs[%d] must be a string", i)), nil
			}

			entryPath, field, parseErr := parseOpRef(ref)
			if parseErr != nil {
				s.logAudit(ctx, "execute_with_secret", ref, false)
				return NewToolResultError(fmt.Sprintf("invalid secret ref %q: %v", ref, parseErr)), nil
			}

			if !s.checkScope(entryPath) {
				s.logAudit(ctx, "execute_with_secret", ref, false)
				metrics.RecordAuthDenial("scope_denied", s.agent.Name)
				return nil, fmt.Errorf("access denied: secret ref path %q outside allowed scope", entryPath)
			}

			resolverRef := entryPath
			if field != "" {
				resolverRef = entryPath + "." + field
			}

			value, resolveErr := secrets.ResolveSecretRef(svc, resolverRef)
			if resolveErr != nil {
				s.logAudit(ctx, "execute_with_secret", ref, false)
				return NewToolResultError(fmt.Sprintf("cannot resolve secret ref %q: %v", ref, resolveErr)), nil
			}

			envVarName := generateEnvVarName(entryPath, field)
			if seenEnvVars[envVarName] {
				s.logAudit(ctx, "execute_with_secret", ref, false)
				return NewToolResultError(fmt.Sprintf("duplicate environment variable name %q from secret ref %q", envVarName, ref)), nil
			}
			seenEnvVars[envVarName] = true

			resolvedEnv[envVarName] = value
			secretEnv[envVarName] = value
			secretRefs = append(secretRefs, ref)
		}
	}
	sort.Strings(secretRefs)

	if envRaw, ok := req.Arguments["env_vars"]; ok && envRaw != nil {
		envMap, ok := envRaw.(map[string]any)
		if !ok {
			s.logAudit(ctx, "execute_with_secret", "<invalid:env_vars-not-object>", false)
			return NewToolResultError("argument \"env_vars\" must be an object"), nil
		}
		for k, v := range envMap {
			val, ok := v.(string)
			if !ok {
				s.logAudit(ctx, "execute_with_secret", "<invalid:env_vars-value-type>", false)
				return NewToolResultError(fmt.Sprintf("env_vars.%s value must be a string", k)), nil
			}
			resolvedEnv[k] = val
		}
	}

	approvalErr := s.checkExecuteWithSecretApproval(ctx)
	if approvalErr != nil {
		s.logAudit(ctx, "execute_with_secret", "<approval-denied>", false)
		metrics.RecordApproval(s.agent.Name, "denied")
		return nil, approvalErr
	}

	workingDir := req.GetString("working_dir", "")
	timeoutSeconds := int(req.GetFloat("timeout", 30))

	result, runErr := secrets.RunCommand(secrets.RunOptions{
		Command:    command,
		Env:        resolvedEnv,
		WorkingDir: workingDir,
		Timeout:    time.Duration(timeoutSeconds) * time.Second,
	})

	exitCode := 0
	if result != nil {
		exitCode = result.ExitCode
	}
	if runErr != nil && result == nil {
		exitCode = -1
	}

	auditPath := fmt.Sprintf("command=[%s], refs=%v, exit=%d", strings.Join(command, " "), secretRefs, exitCode)
	s.logAudit(ctx, "execute_with_secret", auditPath, exitCode == 0 && runErr == nil)

	if runErr != nil {
		if result != nil {
			sanitizedStdout, sanitizedStderr := s.sanitizeRunOutput(result.Stdout, result.Stderr, secretEnv)
			sanitizedErr := s.sanitizeKnownSecretValues(runErr.Error(), secretEnv)
			return NewToolResultError(fmt.Sprintf("%s\nExit code: %d\nStdout: %s\nStderr: %s",
				sanitizedErr, result.ExitCode, EmbedAsData("command_output", sanitizedStdout), EmbedAsData("command_output", sanitizedStderr))), nil
		}
		return NewToolResultError(s.sanitizeKnownSecretValues(runErr.Error(), secretEnv)), nil
	}

	sanitizedStdout, sanitizedStderr := s.sanitizeRunOutput(result.Stdout, result.Stderr, secretEnv)
	resultJSON, err := json.Marshal(map[string]any{
		"exit_code":   result.ExitCode,
		"stdout":      EmbedAsData("command_output", sanitizedStdout),
		"stderr":      EmbedAsData("command_output", sanitizedStderr),
		"duration_ms": result.Duration.Milliseconds(),
	})
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(resultJSON)), nil
}

// parseOpRef parses an op:// reference and returns the entry path and field.
// op://vault/entry/field       -> entry="entry", field="field"
// op://vault/nested/entry/field -> entry="nested/entry", field="field"
// op://vault/entry             -> entry="entry", field=""
func parseOpRef(ref string) (string, string, error) {
	const prefix = "op://"
	if !strings.HasPrefix(ref, prefix) {
		return "", "", fmt.Errorf("expected op:// prefix")
	}

	parts := strings.Split(strings.TrimPrefix(ref, prefix), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("expected at least vault/entry")
	}

	// parts[0] is vault name (ignored)
	if len(parts) == 2 {
		return parts[1], "", nil
	}

	entryPath := strings.Join(parts[1:len(parts)-1], "/")
	field := parts[len(parts)-1]
	return entryPath, field, nil
}

// generateEnvVarName creates an environment variable name from the entry path
// and field. The name is uppercased and path separators are replaced with underscores.
//
// Examples:
//   - entry="aws", field="access_key"      -> "AWS_ACCESS_KEY"
//   - entry="work/aws", field="secret_key" -> "WORK_AWS_SECRET_KEY"
//   - entry="github", field=""             -> "GITHUB"
func generateEnvVarName(entryPath, field string) string {
	parts := strings.Split(entryPath, "/")
	nameParts := make([]string, 0, len(parts)+1)
	for _, p := range parts {
		nameParts = append(nameParts, strings.ToUpper(p))
	}
	if field != "" {
		nameParts = append(nameParts, strings.ToUpper(field))
	}
	name := strings.Join(nameParts, "_")
	return sanitizeEnvVarName(name)
}

// sanitizeEnvVarName replaces any character that is not a letter, digit, or
// underscore with an underscore. This ensures the generated name is a valid
// environment variable identifier on all supported platforms.
func sanitizeEnvVarName(name string) string {
	var sb strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('_')
		}
	}
	return sb.String()
}

// checkExecuteWithSecretApproval checks the agent's approval mode for secret-injected execution.
func (s *Server) checkExecuteWithSecretApproval(ctx context.Context) error {
	return s.requireApproval(ctx, Intent{
		Action:  "execute_with_secret",
		Summary: fmt.Sprintf("agent %q requests to execute a command with secret injection", s.agent.Name),
	})
}
