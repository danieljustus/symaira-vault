package diff

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Result is the complete observable result of one isolated process run.
type Result struct {
	ExitCode    int
	Signal      string
	TimedOut    bool
	Stdout      []byte
	Stderr      []byte
	Files       []ManifestEntry
	SandboxRoot string
}

const processWaitDelay = 2 * time.Second

// Run executes binary in a fresh HOME/XDG/workspace sandbox.
func Run(binary string, testCase Case) (result Result, err error) {
	absoluteBinary, err := filepath.Abs(binary)
	if err != nil {
		return Result{}, fmt.Errorf("resolve binary: %w", err)
	}
	root, err := os.MkdirTemp("", "symvault-port-")
	if err != nil {
		return Result{}, fmt.Errorf("create sandbox: %w", err)
	}
	defer removeSandbox(root)

	home := filepath.Join(root, "home")
	workspace := filepath.Join(root, "workspace")
	tmp := filepath.Join(root, "tmp")
	runtimeDir := filepath.Join(root, "runtime")
	state := filepath.Join(home, ".local", "state")
	for _, dir := range []string{home, workspace, tmp, runtimeDir, state} {
		if mkdirErr := os.MkdirAll(dir, 0o700); mkdirErr != nil {
			return Result{}, fmt.Errorf("create sandbox directory: %w", mkdirErr)
		}
	}
	for _, setup := range testCase.Setup {
		path, pathErr := safeWorkspacePath(workspace, setup.Path)
		if pathErr != nil {
			return Result{}, pathErr
		}
		if mkdirErr := os.MkdirAll(filepath.Dir(path), 0o700); mkdirErr != nil {
			return Result{}, mkdirErr
		}
		mode := os.FileMode(setup.Mode)
		if mode == 0 {
			mode = 0o600
		}
		if writeErr := os.WriteFile(path, []byte(setup.Content), mode); writeErr != nil {
			return Result{}, writeErr
		}
	}

	replacements := map[string]string{
		"${SANDBOX}":   root,
		"${HOME}":      home,
		"${WORKSPACE}": workspace,
		"${TMPDIR}":    tmp,
	}
	args := replaceAll(testCase.Args, replacements)
	ctx, cancel := context.WithTimeout(context.Background(), testCase.timeout())
	defer cancel()
	command := exec.CommandContext(ctx, absoluteBinary, args...) // #nosec G204 -- explicit harness operand, never derived from fixture output
	command.Dir = workspace
	if testCase.WorkingDir != "" {
		command.Dir, err = safeWorkspacePath(workspace, replace(testCase.WorkingDir, replacements))
		if err != nil {
			return Result{}, err
		}
	}
	command.Env, err = isolatedEnv(home, tmp, runtimeDir, state, testCase.Env, replacements)
	if err != nil {
		return Result{}, err
	}
	command.Stdin = strings.NewReader(replace(testCase.Stdin, replacements))
	stdout := newLimitedBuffer()
	stderr := newLimitedBuffer()
	command.Stdout = stdout
	command.Stderr = stderr
	// WaitDelay bounds os/exec's internal pipe-copy wait when a descendant
	// retains an inherited stdout or stderr handle after this process exits.
	command.WaitDelay = processWaitDelay

	tree, treeErr := processTreeFactory(command)
	if treeErr != nil {
		return Result{}, fmt.Errorf("create process tree: %w", treeErr)
	}

	var cancelMu sync.Mutex
	var cancelOnce sync.Once
	var treeCancelAttempted bool
	var treeCancelEffective bool
	var treeCancelErr error
	command.Cancel = func() error {
		cancelOnce.Do(func() {
			effective, killErr := tree.Kill()
			cancelMu.Lock()
			treeCancelAttempted = true
			treeCancelEffective = effective
			treeCancelErr = killErr
			cancelMu.Unlock()
		})
		cancelMu.Lock()
		defer cancelMu.Unlock()
		if treeCancelErr != nil {
			return treeCancelErr
		}
		if !treeCancelEffective {
			// Tell os/exec that the process tree was already gone. This
			// prevents a late context deadline from becoming a spurious
			// process error while still allowing WaitDelay to surface
			// inherited-pipe cleanup honestly.
			return os.ErrProcessDone
		}
		return nil
	}
	defer func() {
		if closeErr := tree.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close process tree: %w", closeErr))
		}
	}()

	if startErr := command.Start(); startErr != nil {
		return Result{}, fmt.Errorf("start %s: %w", absoluteBinary, startErr)
	}
	// The Windows process tree starts this command suspended. Assign resumes
	// its primary thread only after job membership is established.
	if assignErr := tree.Assign(); assignErr != nil {
		// Assignment can fail while the Windows process is still suspended and
		// outside the job. Do not rely on CommandContext's WaitDelay fallback
		// for this lifecycle failure.
		cleanupErr := cleanupAssignmentFailure(command, cancel, command.Cancel, func() (bool, error) {
			cancelMu.Lock()
			defer cancelMu.Unlock()
			return treeCancelEffective, treeCancelErr
		})
		return Result{}, errors.Join(fmt.Errorf("assign process to tree: %w", assignErr), cleanupErr)
	}

	// CommandContext owns the cancellation watcher. Wait must remain
	// synchronous so os/exec can apply WaitDelay and finish all I/O cleanup
	// before Run returns.
	waitErr := command.Wait()
	cancelMu.Lock()
	treeCancellationAttempted := treeCancelAttempted
	treeCancellationEffective := treeCancelEffective
	treeCancellationErr := treeCancelErr
	cancelMu.Unlock()
	deadlineExceeded := errors.Is(ctx.Err(), context.DeadlineExceeded)
	timedOut := commandTimedOut(ctx, treeCancellationEffective)
	treeCancellationIneffective := treeCancellationAttempted &&
		!treeCancellationEffective &&
		treeCancellationErr == nil
	waitCleanupErr := classifyWaitError(
		waitErr,
		timedOut,
		command.ProcessState != nil && command.ProcessState.Success(),
		deadlineExceeded,
		treeCancellationIneffective,
		command.ProcessState != nil && command.ProcessState.Exited(),
	)
	if waitCleanupErr != nil {
		return Result{}, errors.Join(waitCleanupErr, wrapTreeCancellationError("terminate process tree", treeCancellationErr))
	}
	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}
	if stdout.Truncated() || stderr.Truncated() {
		return Result{}, fmt.Errorf("captured process output exceeded %d bytes per stream", maxCapturedStreamBytes)
	}
	signal := terminationSignal(command.ProcessState)
	files, manifestErr := buildManifest(root)
	if manifestErr != nil {
		return Result{}, fmt.Errorf("manifest sandbox: %w", manifestErr)
	}
	return Result{
		ExitCode:    exitCode,
		Signal:      signal,
		TimedOut:    timedOut,
		Stdout:      append([]byte(nil), stdout.Bytes()...),
		Stderr:      append([]byte(nil), stderr.Bytes()...),
		Files:       files,
		SandboxRoot: root,
	}, wrapTreeCancellationError("terminate process tree", treeCancellationErr)
}

func commandTimedOut(ctx context.Context, effective bool) bool {
	return effective && errors.Is(ctx.Err(), context.DeadlineExceeded)
}

func cleanupAssignmentFailure(command *exec.Cmd, cancel context.CancelFunc, cancelCommand func() error, cancellationState func() (effective bool, treeErr error)) error {
	// Kill the tree first, then explicitly kill the direct process when the
	// tree operation was ineffective. This handles an unassigned suspended
	// Windows child without waiting for os/exec's WaitDelay fallback.
	_ = cancelCommand()
	treeCancellationEffective, treeCancellationErr := cancellationState()

	var directKillErr error
	if !treeCancellationEffective {
		if command.Process == nil {
			directKillErr = errors.New("directly kill process after tree cancellation: process is nil")
		} else if killErr := command.Process.Kill(); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			directKillErr = fmt.Errorf("directly kill process after ineffective tree cancellation: %w", killErr)
		}
	}
	cancel()
	waitErr := command.Wait()
	var waitCleanupErr error
	if waitErr != nil {
		waitCleanupErr = fmt.Errorf("wait for process after assignment failure: %w", waitErr)
	}
	return errors.Join(
		wrapTreeCancellationError("terminate process tree after assignment failure", treeCancellationErr),
		directKillErr,
		waitCleanupErr,
	)
}

func wrapTreeCancellationError(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", prefix, err)
}

func classifyWaitError(waitErr error, timedOut, naturalExit, deadlineExceeded, treeCancellationIneffective, processExited bool) error {
	if waitErr == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return nil
	}
	if isAlreadyGoneWaitDelayError(waitErr, deadlineExceeded, treeCancellationIneffective, processExited) {
		waitErr = exec.ErrWaitDelay
	}
	if timedOut &&
		(errors.Is(waitErr, context.Canceled) ||
			errors.Is(waitErr, context.DeadlineExceeded) ||
			errors.Is(waitErr, exec.ErrWaitDelay)) {
		return nil
	}
	if naturalExit &&
		(errors.Is(waitErr, context.Canceled) ||
			errors.Is(waitErr, context.DeadlineExceeded)) {
		return nil
	}
	return fmt.Errorf("wait for process: %w", waitErr)
}

func isolatedEnv(home, tmp, runtimeDir, state string, extra map[string]string, replacements map[string]string) ([]string, error) {
	env := []string{
		"HOME=" + home,
		"USERPROFILE=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"XDG_DATA_HOME=" + filepath.Join(home, ".local", "share"),
		"XDG_CACHE_HOME=" + filepath.Join(home, ".cache"),
		"XDG_STATE_HOME=" + state,
		"XDG_RUNTIME_DIR=" + runtimeDir,
		"TMPDIR=" + tmp,
		"TMP=" + tmp,
		"TEMP=" + tmp,
		"LANG=C",
		"LC_ALL=C",
		"TZ=UTC",
		"TERM=dumb",
		"NO_COLOR=1",
		"SYMVAULT_TEST_KEYRING=memory",
		"SYMVAULT_SECUREUI=none",
	}
	for _, key := range []string{"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"} {
		if value, ok := lookupEnvFold(key); ok {
			env = append(env, key+"="+value)
		}
	}
	keys := make([]string, 0, len(extra))
	for key := range extra {
		if reservedSandboxEnv(strings.ToUpper(key)) {
			return nil, fmt.Errorf("case environment cannot override sandbox variable %q", key)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+replace(extra[key], replacements))
	}
	return env, nil
}

func reservedSandboxEnv(key string) bool {
	switch key {
	case "HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
		"XDG_STATE_HOME", "XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP",
		"SYMVAULT_TEST_KEYRING", "SYMVAULT_SECUREUI":
		return true
	default:
		return false
	}
}

func lookupEnvFold(key string) (string, bool) {
	if value, ok := os.LookupEnv(key); ok {
		return value, true
	}
	if runtime.GOOS != "windows" {
		return "", false
	}
	for _, pair := range os.Environ() {
		name, value, found := strings.Cut(pair, "=")
		if found && strings.EqualFold(name, key) {
			return value, true
		}
	}
	return "", false
}

func replaceAll(values []string, replacements map[string]string) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = replace(value, replacements)
	}
	return result
}

func replace(value string, replacements map[string]string) string {
	keys := make([]string, 0, len(replacements))
	for key := range replacements {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value = strings.ReplaceAll(value, key, replacements[key])
	}
	return value
}

func safeWorkspacePath(workspace, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", fmt.Errorf("workspace path must be non-empty and relative: %q", rel)
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("workspace path escapes sandbox: %q", rel)
	}
	return filepath.Join(workspace, clean), nil
}

func removeSandbox(path string) {
	for attempt := 0; attempt < 5; attempt++ {
		if err := os.RemoveAll(path); err == nil || os.IsNotExist(err) {
			return
		}
		time.Sleep(time.Duration(1<<attempt) * 10 * time.Millisecond)
	}
}
