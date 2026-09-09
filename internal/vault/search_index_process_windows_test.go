//go:build windows

package vault

import (
	"context"
	"os"
	"os/exec"
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
