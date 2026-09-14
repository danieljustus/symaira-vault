//go:build windows

package main

import (
	"os/exec"
)

func configureProcessGroup(cmd *exec.Cmd) {}

func killProcessGroup(cmd *exec.Cmd) (bool, error) {
	if cmd.Process == nil {
		return false, nil
	}
	if err := cmd.Process.Kill(); err != nil {
		return false, err
	}
	return true, nil
}
