//go:build darwin

package autotype

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/danieljustus/OpenPass/internal/envfilter"
)

func defaultCaptureActiveWindow() (string, error) {
	cmd := exec.Command("osascript", "-e",
		`tell application "System Events" to get name of first application process whose frontmost is true`)
	envfilter.PrepareCmd(cmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", ErrFocusUnavailable
	}
	return "process:" + strings.TrimSpace(out.String()), nil
}
