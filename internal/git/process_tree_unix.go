//go:build !windows

package git

import (
	"os/exec"
	"syscall"
)

func configureProcessTree(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

func startProcessTree(cmd *exec.Cmd) error {
	return cmd.Start()
}

func killProcessTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func closeProcessTree(*exec.Cmd) error {
	return nil
}
