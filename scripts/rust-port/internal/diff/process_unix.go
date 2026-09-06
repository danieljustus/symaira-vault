//go:build !windows

package diff

import (
	"errors"
	"os/exec"
	"syscall"
)

type unixProcessTree struct {
	cmd *exec.Cmd
}

func newProcessTree(cmd *exec.Cmd) (processTree, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return &unixProcessTree{cmd: cmd}, nil
}

func (t *unixProcessTree) Assign() error {
	return nil
}

func (t *unixProcessTree) Kill() (bool, error) {
	if t.cmd.Process == nil {
		return false, nil
	}
	err := syscall.Kill(-t.cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (t *unixProcessTree) Close() error {
	return nil
}
