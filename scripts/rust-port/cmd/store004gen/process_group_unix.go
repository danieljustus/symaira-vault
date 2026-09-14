//go:build !windows

package main

import (
	"errors"
	"os/exec"
	"syscall"
)

func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func startProcessGroup(cmd *exec.Cmd) error {
	return cmd.Start()
}

func killProcessGroup(cmd *exec.Cmd) (bool, error) {
	if cmd.Process == nil {
		return false, nil
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func closeProcessGroup(*exec.Cmd) error { return nil }
