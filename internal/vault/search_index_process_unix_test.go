//go:build !windows

package vault

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func runSearchIndexCommand(dir, target, binary string, args ...string) (string, error) {
	return runSearchIndexCommandWithTimeout(2*time.Minute, dir, target, binary, args...)
}

func runSearchIndexCommandWithTimeout(timeout time.Duration, dir, target, binary string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
	if target != "" {
		cmd.Env = append(os.Environ(), "CARGO_TARGET_DIR="+target)
	}
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(output), ctx.Err()
	}
	return string(output), err
}

func TestSearchIndexCommandTimeoutIsBounded(t *testing.T) {
	started := time.Now()
	_, err := runSearchIndexCommandWithTimeout(50*time.Millisecond, t.TempDir(), "", "sh", "-c", "sleep 10")
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timeout command exceeded deterministic bound: %s", elapsed)
	}
}
