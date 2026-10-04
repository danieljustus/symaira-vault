package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/mcp/masking"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	secrets "github.com/danieljustus/symaira-vault/internal/secrets"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
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

	reader := vaultpkg.NewReadSession(s.vault.Dir, s.vault.Identity)
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
			resolvedPath, targetErr := s.resolveMCPSecretRefTarget(ref, reader)
			if targetErr != nil {
				return mcp.NewToolResultError(targetErr.Error()), nil
			}
			if !s.checkScope(resolvedPath) {
				s.logAudit(ctx, "run_command", resolvedPath, false)
				metrics.RecordAuthDenial("scope_denied", s.agent.Name)
				return nil, fmt.Errorf("access denied: secret ref path %q outside allowed scope", resolvedPath)
			}

			value, resolveErr := s.resolveMCPSecretRefAtPath(ref, resolvedPath, reader)
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

	resolvedFiles, fileKnownSecrets, fileAudit, filesToolErr, filesErr := s.resolveRunCommandFiles(ctx, req.Arguments["files"], reader)
	if filesErr != nil {
		return nil, filesErr
	}
	if filesToolErr != nil {
		return filesToolErr, nil
	}

	if rawWorkingDir, exists := req.Arguments["working_dir"]; exists && rawWorkingDir != nil {
		if _, ok := rawWorkingDir.(string); !ok {
			s.logAudit(ctx, "run_command", "<invalid:working_dir>", false)
			return mcp.NewToolResultError("argument \"working_dir\" must be a string"), nil
		}
	}

	if s.requiresApproval() {
		s.logAudit(ctx, "approval_denied", "run_command", false)
		metrics.RecordApproval(s.agent.Name, "denied")
		return nil, fmt.Errorf("run_command denied: approval required but cannot be granted")
	}

	workingDir := req.GetString("working_dir", "")

	// knownSecrets is the union of resolved env and file values, used only to
	// redact known secret content out of command output/errors — RunOptions.Env
	// and RunOptions.Files stay separate so files are never set as env vars.
	knownSecrets := make(map[string]string, len(resolvedEnv)+len(fileKnownSecrets))
	for k, v := range resolvedEnv {
		knownSecrets[k] = v
	}
	for k, v := range fileKnownSecrets {
		knownSecrets[k] = v
	}
	auditPath := buildRunCommandAuditPath(command, envNames, fileAudit, knownSecrets)

	result, err := secrets.RunCommand(secrets.RunOptions{
		Command:      command,
		Env:          resolvedEnv,
		Files:        resolvedFiles,
		WorkingDir:   workingDir,
		Timeout:      time.Duration(timeoutSeconds) * time.Second,
		KnownSecrets: knownSecrets,
	})

	if err != nil {
		s.logAudit(ctx, "run_command", auditPath, false)
		if result != nil {
			sanitizedStdout, sanitizedStderr := s.sanitizeRunOutput(ctx, result.Stdout, result.Stderr, knownSecrets)
			sanitizedErr := s.sanitizeKnownSecretValues(err.Error(), knownSecrets)
			return mcp.NewToolResultError(fmt.Sprintf("%s\nExit code: %d\nStdout: %s\nStderr: %s",
				sanitizedErr, result.ExitCode, EmbedAsData("command_output", sanitizedStdout), EmbedAsData("command_output", sanitizedStderr))), nil
		}
		return mcp.NewToolResultError(s.sanitizeKnownSecretValues(err.Error(), knownSecrets)), nil
	}

	s.logAudit(ctx, "run_command", auditPath, true)

	sanitizedStdout, sanitizedStderr := s.sanitizeRunOutput(ctx, result.Stdout, result.Stderr, knownSecrets)

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

func buildRunCommandAuditPath(command, envNames, fileAudit []string, knownSecrets map[string]string) string {
	auditPath := masking.SanitizeWithKnownSecrets(strings.Join(command, " "), knownSecrets, "***")
	if len(envNames) > 0 {
		auditPath += ", env=[" + strings.Join(envNames, ", ") + "]"
	}
	if len(fileAudit) > 0 {
		auditPath += ", files=[" + strings.Join(fileAudit, ", ") + "]"
	}
	return auditPath
}

// resolveRunCommandFiles parses and resolves handleRunCommand's "files"
// argument into plaintext content ready for ephemeral materialization,
// mirroring the "env" map's per-ref scope check and resolution. resolvedFiles
// holds plaintext (post-decode) content keyed by the name the caller chose —
// it is only ever handed to secrets.RunCommand for ephemeral 0600
// materialization and to the output sanitizer, never returned to the agent or
// logged. fileAudit records "name:ref" pairs (never content) for the caller's
// audit log.
//
// The two error-shaped return values mirror handleRunCommand's own
// convention: toolErr is a user-facing tool-result error (bad input,
// unresolvable ref) the caller should return as-is; err is a hard access
// denial the caller should propagate as a JSON-RPC error, matching how the
// rest of handleRunCommand distinguishes the two.
func (s *Server) resolveRunCommandFiles(ctx context.Context, filesRaw any, sessions ...*vaultpkg.ReadSession) (resolvedFiles, knownSecrets map[string]string, fileAudit []string, toolErr *mcp.CallToolResult, err error) {
	reader := vaultpkg.NewReadSession(s.vault.Dir, s.vault.Identity)
	if len(sessions) != 0 && sessions[0] != nil {
		reader = sessions[0]
	}
	resolvedFiles = make(map[string]string)
	knownSecrets = make(map[string]string)
	if filesRaw == nil {
		return resolvedFiles, knownSecrets, nil, nil, nil
	}

	filesMap, ok := filesRaw.(map[string]any)
	if !ok {
		s.logAudit(ctx, "run_command", "<invalid>", false)
		return nil, nil, nil, mcp.NewToolResultError("argument \"files\" must be an object"), nil
	}

	for name, specRaw := range filesMap {
		ref, encoding, specErr := parseFileSpec(specRaw)
		if specErr != nil {
			return nil, nil, nil, mcp.NewToolResultError(fmt.Sprintf("files.%s: %v", name, specErr)), nil
		}

		path := extractPathFromRef(ref)
		if !s.checkScope(path) {
			s.logAudit(ctx, "run_command", path, false)
			metrics.RecordAuthDenial("scope_denied", s.agent.Name)
			return nil, nil, nil, nil, fmt.Errorf("access denied: secret ref path %q outside allowed scope", path)
		}
		resolvedPath, targetErr := s.resolveMCPSecretRefTarget(ref, reader)
		if targetErr != nil {
			return nil, nil, nil, mcp.NewToolResultError(targetErr.Error()), nil
		}
		if !s.checkScope(resolvedPath) {
			s.logAudit(ctx, "run_command", resolvedPath, false)
			metrics.RecordAuthDenial("scope_denied", s.agent.Name)
			return nil, nil, nil, nil, fmt.Errorf("access denied: secret ref path %q outside allowed scope", resolvedPath)
		}

		value, resolveErr := s.resolveMCPSecretRefAtPath(ref, resolvedPath, reader)
		if resolveErr != nil {
			return nil, nil, nil, mcp.NewToolResultError(fmt.Sprintf("cannot resolve secret ref %q: %v", ref, resolveErr)), nil
		}
		knownSecrets[name+":source"] = value

		content := value
		if encoding == "base64" {
			decoded, decErr := base64.StdEncoding.DecodeString(value)
			if decErr != nil {
				return nil, nil, nil, mcp.NewToolResultError(fmt.Sprintf("files.%s: cannot base64-decode resolved value", name)), nil
			}
			content = string(decoded)
		}

		resolvedFiles[name] = content
		knownSecrets[name+":content"] = content
		fileAudit = append(fileAudit, name+":"+ref)
	}
	sort.Strings(fileAudit)

	return resolvedFiles, knownSecrets, fileAudit, nil, nil
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

// resolveMCPSecretRefTarget identifies the entry path selected by the vault's
// path.field-or-dotted-entry convention. Callers must scope-check the candidate
// path before this probes it, then scope-check the returned path before reading
// a fallback bare entry.
func (s *Server) resolveMCPSecretRefTarget(ref string, reader *vaultpkg.ReadSession) (string, error) {
	if idx := strings.LastIndex(ref, "."); idx > 0 {
		candidatePath := ref[:idx]
		candidateField := ref[idx+1:]
		entry, readErr := reader.Get(candidatePath)
		if errors.Is(readErr, vaultpkg.ErrVaultResourceLimit) || errors.Is(readErr, vaultpkg.ErrVaultResourceBusy) {
			return "", readErr
		}
		if readErr == nil {
			if _, ok := entry.Data[candidateField]; ok {
				return candidatePath, nil
			}
		}
	}
	return ref, nil
}

// resolveMCPSecretRefAtPath re-evaluates the reference after its resolved path
// has passed the caller's scope check. A changed interpretation fails closed,
// and the fallback entry is not read until its exact path is verified.
func (s *Server) resolveMCPSecretRefAtPath(ref, expectedPath string, reader *vaultpkg.ReadSession) (string, error) {
	path := ref
	field := ""
	var entry *vaultpkg.Entry
	if idx := strings.LastIndex(ref, "."); idx > 0 {
		candidatePath := ref[:idx]
		candidateField := ref[idx+1:]
		candidate, readErr := reader.Get(candidatePath)
		if errors.Is(readErr, vaultpkg.ErrVaultResourceLimit) || errors.Is(readErr, vaultpkg.ErrVaultResourceBusy) {
			return "", readErr
		}
		if readErr == nil {
			if _, ok := candidate.Data[candidateField]; ok {
				path = candidatePath
				field = candidateField
				entry = candidate
			}
		}
	}
	if path != expectedPath {
		return "", fmt.Errorf("secret ref target changed during resolution")
	}
	if entry == nil {
		var err error
		entry, err = reader.Get(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("secret ref not found: %s", path)
			}
			return "", fmt.Errorf("cannot resolve secret ref %s: %w", ref, err)
		}
	}
	if field != "" {
		value, ok := entry.Data[field]
		if !ok {
			return "", fmt.Errorf("field not found in secret ref %s.%s", path, field)
		}
		return fmt.Sprintf("%v", value), nil
	}
	return fmt.Sprintf("%v", entry.Data), nil
}

// parseFileSpec parses one "files" map entry for run_command. It accepts
// either a bare secret reference string (materialized as raw text, same
// convention as the "env" map) or an object {"ref": "...", "encoding":
// "base64"} for binary content — e.g. a PKCS#12 certificate stored as base64
// — that must be decoded before being written to the ephemeral file.
func parseFileSpec(raw any) (ref, encoding string, err error) {
	switch v := raw.(type) {
	case string:
		return v, "", nil
	case map[string]any:
		refRaw, ok := v["ref"].(string)
		if !ok || refRaw == "" {
			return "", "", fmt.Errorf("missing required \"ref\" string")
		}
		if encRaw, ok := v["encoding"]; ok && encRaw != nil {
			encStr, ok := encRaw.(string)
			if !ok {
				return "", "", fmt.Errorf("\"encoding\" must be a string")
			}
			if encStr != "" && encStr != "base64" {
				return "", "", fmt.Errorf("unsupported encoding %q (supported: base64)", encStr)
			}
			encoding = encStr
		}
		return refRaw, encoding, nil
	default:
		return "", "", fmt.Errorf("must be a string secret reference or {\"ref\":...,\"encoding\":...} object")
	}
}
