//go:build windows

package diff

import (
	"fmt"
	"os/exec"
)

func configureProcessTree(_ *exec.Cmd) {}

func killProcessTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	// taskkill /T terminates descendants as well as the direct process. Keep a
	// direct Kill fallback for minimal Windows environments without taskkill.
	if err := exec.Command("taskkill", "/T", "/F", "/PID", fmt.Sprint(cmd.Process.Pid)).Run(); err == nil {
		return nil
	}
	return cmd.Process.Kill()
}
