package diff

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
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

// Run executes binary in a fresh HOME/XDG/workspace sandbox.
func Run(binary string, testCase Case) (Result, error) {
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
	command := exec.Command(absoluteBinary, args...) // #nosec G204 -- explicit harness operand, never derived from fixture output
	configureProcessTree(command)
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

	if startErr := command.Start(); startErr != nil {
		return Result{}, fmt.Errorf("start %s: %w", absoluteBinary, startErr)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()

	var waitErr error
	timedOut := false
	timer := time.NewTimer(testCase.timeout())
	select {
	case waitErr = <-waitDone:
		timer.Stop()
	case <-timer.C:
		timedOut = true
		killErr := killProcessTree(command)
		select {
		case waitErr = <-waitDone:
		case <-time.After(2 * time.Second):
			_ = command.Process.Kill()
			return Result{}, fmt.Errorf("process did not exit within 2s after timeout")
		}
		if killErr != nil {
			return Result{}, fmt.Errorf("terminate timed-out process tree: %w", killErr)
		}
	}

	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return Result{}, fmt.Errorf("wait for process: %w", waitErr)
		}
	}
	if stdout.Truncated() || stderr.Truncated() {
		return Result{}, fmt.Errorf("captured process output exceeded %d bytes per stream", maxCapturedStreamBytes)
	}
	signal := terminationSignal(command.ProcessState)
	files, err := buildManifest(root)
	if err != nil {
		return Result{}, fmt.Errorf("manifest sandbox: %w", err)
	}
	return Result{
		ExitCode:    exitCode,
		Signal:      signal,
		TimedOut:    timedOut,
		Stdout:      append([]byte(nil), stdout.Bytes()...),
		Stderr:      append([]byte(nil), stderr.Bytes()...),
		Files:       files,
		SandboxRoot: root,
	}, nil
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
