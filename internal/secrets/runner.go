package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// RunResult contains the result of a command execution.
type RunResult struct {
	ExitCode        int
	Stdout          string
	Stderr          string
	Duration        time.Duration
	StdoutTruncated bool
	StderrTruncated bool
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

// boundedBuffer captures up to max bytes of written data while still reporting
// every byte as consumed, so a child process pipe is drained (not blocked)
// even once the retained capture is full. This keeps peak memory bounded to
// max regardless of how much output the child actually produces.
type boundedBuffer struct {
	max       int
	data      []byte
	truncated bool
}

func newBoundedBuffer(max int) *boundedBuffer {
	return &boundedBuffer{max: max, data: make([]byte, 0, max)}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if remaining := b.max - len(b.data); remaining > 0 {
		n := len(p)
		if n > remaining {
			n = remaining
		}
		b.data = append(b.data, p[:n]...)
		if n < len(p) {
			b.truncated = true
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

// RunCommand executes a command with the given options and captures the result.
// Environment variables from opts.Env are merged on top of the current process
// environment. Stdout and stderr are each bounded at 100KB during capture to
// prevent memory exhaustion from excessive output; child pipes are drained in
// full so the process is never blocked by the cap.
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

	const maxOutput = 100 * 1024
	stdout := newBoundedBuffer(maxOutput)
	stderr := newBoundedBuffer(maxOutput)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	start := time.Now()
	runErr := cmd.Run()
	duration := time.Since(start)

	result := &RunResult{
		Duration:        duration,
		Stdout:          string(stdout.data),
		Stderr:          string(stderr.data),
		StdoutTruncated: stdout.truncated,
		StderrTruncated: stderr.truncated,
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
