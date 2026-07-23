package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	"github.com/danieljustus/symaira-vault/internal/secrets"
)

// handleExecuteWithSecret executes a command with secrets injected as environment
// variables. The agent never sees the secret values — only stdout, stderr, and
// exit code are returned.
//
//nolint:gocyclo // complexity inherent to secret resolution, validation, and command execution
func (s *Server) handleExecuteWithSecret(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if !s.canRunCommands() {
		s.logAudit(ctx, "execute_with_secret", "<run-denied>", false)
		metrics.RecordAuthDenial("run_denied", s.agent.Name)
		return nil, runCommandDeniedError(s.agent.Name, "execute_with_secret")
	}

	cmdRaw, ok := req.Arguments["command"]
	if !ok {
		s.logAudit(ctx, "execute_with_secret", "<invalid:missing-command>", false)
		return mcp.NewToolResultError("missing required argument \"command\""), nil
	}
	command, err := parseCommandArray(cmdRaw)
	if err != nil {
		var auditTag string
		switch {
		case strings.Contains(err.Error(), "must be an array"):
			auditTag = "<invalid:command-not-array>"
		case strings.Contains(err.Error(), "must not be empty"):
			auditTag = "<invalid:empty-command>"
		default:
			auditTag = "<invalid:command-type>"
		}
		s.logAudit(ctx, "execute_with_secret", auditTag, false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Enforce per-agent executable allowlist.
	if allowErr := s.checkExecutableAllowlist(command); allowErr != nil {
		s.logAudit(ctx, "execute_with_secret", command[0], false)
		metrics.RecordAuthDenial("executable_denied", s.agent.Name)
		return nil, allowErr
	}

	timeoutSeconds, timeoutErr := parseCommandTimeoutSeconds(req.Arguments["timeout"])
	if timeoutErr != nil {
		s.logAudit(ctx, "execute_with_secret", "<invalid:timeout>", false)
		return mcp.NewToolResultError(timeoutErr.Error()), nil
	}

	refsRaw, ok := req.Arguments["secret_refs"]
	if !ok {
		s.logAudit(ctx, "execute_with_secret", "<invalid:missing-secret_refs>", false)
		return mcp.NewToolResultError("missing required argument \"secret_refs\""), nil
	}

	secretRefs := make([]string, 0)
	resolvedEnv := make(map[string]string)
	secretEnv := make(map[string]string)
	if refsRaw != nil {
		refsSlice, ok := refsRaw.([]any)
		if !ok {
			s.logAudit(ctx, "execute_with_secret", "<invalid:secret_refs-not-array>", false)
			return mcp.NewToolResultError("argument \"secret_refs\" must be an array"), nil
		}

		seenEnvVars := make(map[string]bool)

		for i, v := range refsSlice {
			ref, ok := v.(string)
			if !ok {
				s.logAudit(ctx, "execute_with_secret", "<invalid:secret_ref-type>", false)
				return mcp.NewToolResultError(fmt.Sprintf("secret_refs[%d] must be a string", i)), nil
			}

			entryPath, field, parseErr := parseOpRef(ref)
			if parseErr != nil {
				s.logAudit(ctx, "execute_with_secret", ref, false)
				return mcp.NewToolResultError(fmt.Sprintf("invalid secret ref %q: %v", ref, parseErr)), nil
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

			value, resolveErr := secrets.ResolveSecretRef(s.vault, resolverRef)
			if resolveErr != nil {
				s.logAudit(ctx, "execute_with_secret", ref, false)
				return mcp.NewToolResultError(fmt.Sprintf("cannot resolve secret ref %q: %v", ref, resolveErr)), nil
			}

			envVarName := generateEnvVarName(entryPath, field)
			if seenEnvVars[envVarName] {
				s.logAudit(ctx, "execute_with_secret", ref, false)
				return mcp.NewToolResultError(fmt.Sprintf("duplicate environment variable name %q from secret ref %q", envVarName, ref)), nil
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
			return mcp.NewToolResultError("argument \"env_vars\" must be an object"), nil
		}
		for k, v := range envMap {
			val, ok := v.(string)
			if !ok {
				s.logAudit(ctx, "execute_with_secret", "<invalid:env_vars-value-type>", false)
				return mcp.NewToolResultError(fmt.Sprintf("env_vars.%s value must be a string", k)), nil
			}
			resolvedEnv[k] = val
		}
	}

	// Check for denied env vars
	if len(resolvedEnv) > 0 {
		denied := secrets.RejectDenied(resolvedEnv)
		if len(denied) > 0 {
			s.logAudit(ctx, "execute_with_secret", "<validation-denied-env>", false)
			return mcp.NewToolResultError(fmt.Sprintf("env_vars contains denied keys: %s", strings.Join(denied, ", "))), nil
		}
	}

	approvalErr := s.checkExecuteWithSecretApproval(ctx, command, resolvedEnv)
	if approvalErr != nil {
		s.logAudit(ctx, "execute_with_secret", "<approval-denied>", false)
		metrics.RecordApproval(s.agent.Name, "denied")
		return nil, approvalErr
	}

	workingDir := req.GetString("working_dir", "")

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

	redactedCommand := redactSecrets(command, secretEnv)
	auditPath := fmt.Sprintf("command=[%s], refs=%v, exit=%d", strings.Join(redactedCommand, " "), secretRefs, exitCode)
	s.logAudit(ctx, "execute_with_secret", auditPath, exitCode == 0 && runErr == nil)

	if runErr != nil {
		if result != nil {
			sanitizedStdout, sanitizedStderr := s.sanitizeRunOutput(ctx, result.Stdout, result.Stderr, secretEnv)
			sanitizedErr := s.sanitizeKnownSecretValues(runErr.Error(), secretEnv)
			return mcp.NewToolResultError(fmt.Sprintf("%s\nExit code: %d\nStdout: %s\nStderr: %s",
				sanitizedErr, result.ExitCode, EmbedAsData("command_output", sanitizedStdout), EmbedAsData("command_output", sanitizedStderr))), nil
		}
		return mcp.NewToolResultError(s.sanitizeKnownSecretValues(runErr.Error(), secretEnv)), nil
	}

	sanitizedStdout, sanitizedStderr := s.sanitizeRunOutput(ctx, result.Stdout, result.Stderr, secretEnv)
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
func (s *Server) checkExecuteWithSecretApproval(ctx context.Context, command []string, resolvedEnv map[string]string) error {
	return s.requireApproval(ctx, Intent{
		Action: "execute_with_secret",
		Summary: fmt.Sprintf("agent %q requests to execute command [%s] with secret injection (env vars: %v)",
			s.agent.Name, strings.Join(command, " "), mapKeys(resolvedEnv)),
	})
}

// mapKeys returns a sorted slice of keys from the given map.
func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func redactSecrets(command []string, secretEnv map[string]string) []string {
	redacted := make([]string, len(command))
	for i, arg := range command {
		redacted[i] = arg
		for _, secret := range secretEnv {
			if arg == secret {
				redacted[i] = "[REDACTED]"
				break
			}
		}
	}
	return redacted
}
