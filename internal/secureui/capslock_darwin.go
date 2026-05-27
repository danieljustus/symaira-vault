//go:build darwin

package secureui

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/secrets"
)

// defaultCapsLockDetector inspects `ioreg` for the AlphaLock modifier.
// ioreg is preinstalled on every macOS install; the call is fast (<10ms)
// and never blocks waiting for an interactive prompt. On parse failure we
// return false (best-effort).
func defaultCapsLockDetector() bool {
	cmd := exec.Command("ioreg", "-l", "-w0", "-n", "IOHIDSystem")
	secrets.PrepareCmd(cmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return false
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, `"AlphaLock"`) {
			return strings.Contains(line, "=1") || strings.Contains(line, "= 1")
		}
	}
	return false
}
