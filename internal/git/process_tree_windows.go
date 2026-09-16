//go:build windows

package git

import "os/exec"

func configureProcessTree(_ *exec.Cmd) {}

func killProcessTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
