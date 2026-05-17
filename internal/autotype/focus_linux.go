//go:build linux

package autotype

import (
	"bytes"
	"os"
	"os/exec"
	"strings"

	"github.com/danieljustus/OpenPass/internal/envfilter"
)

func defaultCaptureActiveWindow() (string, error) {
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		return "", ErrFocusUnavailable
	}
	path, err := lookPath("xdotool")
	if err != nil {
		return "", ErrFocusUnavailable
	}
	// "getactivewindow getwindowclassname" returns the WM_CLASS, which is the
	// most stable identifier for "the same application" across re-focus events.
	cmd := exec.Command(path, "getactivewindow", "getwindowclassname")
	envfilter.PrepareCmd(cmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", ErrFocusUnavailable
	}
	return "wmclass:" + strings.TrimSpace(out.String()), nil
}
