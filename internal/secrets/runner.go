package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
	// RejectedEnvVars lists the names (never values) of ambient parent-process
	// environment variables that were requested via RunOptions.Passthrough but
	// withheld from the child process because their name looks sensitive (see
	// IsSensitiveName). Does not apply to RunOptions.Env, which is caller-
	// supplied and already-resolved (see RunCommand). Sorted, nil when nothing
	// was rejected.
	RejectedEnvVars []string
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
	// Files maps a name to plaintext content that must be materialized into an
	// ephemeral 0600 file for the lifetime of the child process, exposed to it
	// as $SYMVAULT_FILE_<name>. Content is never logged. Every file (and its
	// private directory) is best-effort shredded and removed once the command
	// finishes, regardless of how it finishes — success, non-zero exit, or a
	// timeout kill. Keys must be safe identifiers ([A-Za-z0-9_]+): they become
	// both an env var suffix and a filename.
	Files map[string]string
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

	fileEnv, cleanupFiles, err := materializeFiles(opts.Files)
	if err != nil {
		return nil, err
	}
	defer cleanupFiles()

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
	//
	// Passthrough forwards an *ambient* parent-process variable to the child by
	// name only — the caller never sees or chooses its value, so a
	// sensitive-looking name (VAULT_PASSPHRASE, AWS_SECRET_ACCESS_KEY, ...) is
	// rejected even though the caller asked for it explicitly: fail closed
	// rather than trust that the name was requested with full knowledge of its
	// value. opts.Env is different — it is the caller handing RunCommand an
	// already-resolved value it explicitly chose to inject (e.g. a vault secret
	// the agent asked to inject by name via execute_with_secret); rejecting
	// those by name would break that feature outright, since resolved secret
	// env var names routinely contain KEY/SECRET/TOKEN/PASSWORD. opts.Env still
	// goes through RejectDenied (interpreter/loader injection names) at the
	// call site.
	safePassthrough, rejectedPassthrough := RejectSensitiveNames(opts.Passthrough)
	whitelist := DefaultWhitelist()
	if len(safePassthrough) > 0 {
		whitelist = MergeWhitelist(whitelist, safePassthrough)
	}
	cmd.Env = FilterEnv(whitelist)

	for k, v := range opts.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	for k, v := range fileEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	rejected := append([]string(nil), rejectedPassthrough...)
	sort.Strings(rejected)

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
		RejectedEnvVars: rejected,
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

// isSafeFileName reports whether name is safe to use both as an environment
// variable suffix and as a filename component — no path separators, no "..",
// no empty string.
func isSafeFileName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}

// materializeFiles writes each named secret to a private, 0600 ephemeral file
// and returns the SYMVAULT_FILE_<name> environment assignments plus a cleanup
// function that best-effort shreds and removes every file it created (and the
// private directory holding them). The returned cleanup is always safe to
// call, even after a partial failure — callers should defer it immediately
// after a nil error so cleanup runs no matter how the caller's command
// finishes (success, non-zero exit, or a timeout kill).
func materializeFiles(files map[string]string) (map[string]string, func(), error) {
	noop := func() {}
	if len(files) == 0 {
		return nil, noop, nil
	}

	names := make([]string, 0, len(files))
	for name := range files {
		if !isSafeFileName(name) {
			return nil, noop, fmt.Errorf("invalid file name %q: must match [A-Za-z0-9_]+", name)
		}
		names = append(names, name)
	}
	sort.Strings(names) // deterministic materialization order

	dir, err := os.MkdirTemp("", "symvault-file-*")
	if err != nil {
		return nil, noop, fmt.Errorf("create ephemeral file directory: %w", err)
	}
	// #nosec G302 -- 0700 is correct for a private directory; 0600 would remove the execute bit needed to enter it
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, noop, fmt.Errorf("secure ephemeral file directory: %w", err)
	}

	var written []string
	cleanup := func() {
		for _, p := range written {
			ShredFile(p)
		}
		_ = os.RemoveAll(dir)
	}

	env := make(map[string]string, len(files))
	for _, name := range names {
		path := filepath.Join(dir, name)
		// #nosec G304 -- path is built from filepath.Join(dir, name) where dir is our own MkdirTemp result and name was already validated by isSafeFileName
		if err := os.WriteFile(path, []byte(files[name]), 0o600); err != nil {
			cleanup()
			return nil, noop, fmt.Errorf("materialize file %q: %w", name, err)
		}
		written = append(written, path)
		env["SYMVAULT_FILE_"+name] = path
	}

	return env, cleanup, nil
}

// ShredFile best-effort overwrites a file's content with zeros before
// removing it, so the plaintext does not linger in free disk blocks after
// cleanup. Errors are intentionally swallowed — cleanup must never fail the
// caller, and a failed overwrite still leaves the subsequent remove to try.
func ShredFile(path string) {
	if info, statErr := os.Stat(path); statErr == nil && info.Size() > 0 {
		// #nosec G304 -- path is one of the paths this package just wrote in materializeFiles, reopened only to overwrite it with zeros before removal
		if f, openErr := os.OpenFile(path, os.O_WRONLY, 0o600); openErr == nil {
			_, _ = f.Write(make([]byte, info.Size()))
			_ = f.Sync()
			_ = f.Close()
		}
	}
	_ = os.Remove(path)
}
