//go:build darwin

package session

import (
	"os/exec"
	"strings"
)

// HasGUISession reports whether the process runs inside a macOS Aqua
// (GUI) session. Biometric prompts (Touch ID) are LocalAuthentication
// GUI prompts: they can be shown without a controlling TTY, but only
// when an Aqua session is present. launchctl managername returns "Aqua"
// for GUI login sessions and "Background"/"System" for SSH, daemon and
// CI contexts.
func HasGUISession() bool {
	out, err := exec.Command("launchctl", "managername").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "Aqua"
}
