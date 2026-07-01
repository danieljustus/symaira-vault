package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// RunResult contains the result of a command execution.
type RunResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
}

// RunOptions configures a command execution.
type RunOptions struct {
	// Command is the executable and its arguments. Must have at least one element.
	Command []string
	// Env contains additional environment variables that overlay os.Environ().
	Env map[string]string
	// Passthrough is a list of parent env var names to add to the whitelist
	// so they pass through to the child process alongside DefaultWhitelist.
	Passthrough []string
	// WorkingDir is the directory the command runs in. Empty means current directory.
	WorkingDir string
	// Timeout is the maximum duration. Zero means no timeout.
	Timeout time.Duration
}

// RunCommand executes a command with the given options and captures the result.
// Environment variables from opts.Env are merged on top of the current process
// environment. Stdout and stderr are each capped at 100KB to prevent memory
// exhaustion from excessive output.
func RunCommand(opts RunOptions) (*RunResult, error) {
	if len(opts.Command) == 0 {
		return nil, fmt.Errorf("command must have at least one element")
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// #nosec G204 — command execution is the intended feature of the run command.
	// Inputs are validated by caller (agent CanRunCommands permission) and the
	// command is executed in a controlled subprocess environment.
	cmd := exec.CommandContext(ctx, opts.Command[0], opts.Command[1:]...)

	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	}

	// Start with a whitelisted env subset as base, then overlay opts.Env.
	// This prevents leaking sensitive process env vars (API keys, OPENPASS_*, AWS_*,
	// etc.) to child processes. Only the DefaultWhitelist vars (plus any passthrough)
	// are passed through. Later entries override earlier ones for the same key.
	whitelist := DefaultWhitelist()
	if len(opts.Passthrough) > 0 {
		whitelist = MergeWhitelist(whitelist, opts.Passthrough)
	}
	cmd.Env = FilterEnv(whitelist)
	for k, v := range opts.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdin = os.Stdin
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	duration := time.Since(start)

	const maxOutput = 100 * 1024

	result := &RunResult{
		Duration: duration,
		Stdout:   string(truncateBytes(stdout.Bytes(), maxOutput)),
		Stderr:   string(truncateBytes(stderr.Bytes(), maxOutput)),
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				result.ExitCode = -1
				return result, fmt.Errorf("command timed out after %s", opts.Timeout)
			}
		} else {
			return nil, fmt.Errorf("failed to run command: %w", runErr)
		}
	}

	return result, nil
}

// truncateBytes returns a copy of data truncated to maxLen bytes.
func truncateBytes(data []byte, maxLen int) []byte {
	if len(data) <= maxLen {
		return data
	}
	truncated := make([]byte, maxLen)
	copy(truncated, data)
	return truncated
}
