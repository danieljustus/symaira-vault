//go:build linux

package secureui

import (
	"bytes"
	"os"
	"os/exec"
	"strings"

	"github.com/danieljustus/OpenPass/internal/envfilter"
)

// defaultCapsLockDetector probes xset for the X11 LED state. On Wayland (no
// $DISPLAY) we skip — there is no portable user-space API and `setxkbmap`
// queries require the server protocol. Returns false on any failure so the
// caller silently proceeds.
func defaultCapsLockDetector() bool {
	if os.Getenv("DISPLAY") == "" {
		return false
	}
	cmd := exec.Command("xset", "q")
	envfilter.PrepareCmd(cmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return false
	}
	for _, line := range strings.Split(out.String(), "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "caps lock:") {
			idx := strings.Index(l, "caps lock:")
			rest := strings.TrimSpace(l[idx+len("caps lock:"):])
			return strings.HasPrefix(rest, "on")
		}
	}
	return false
}
