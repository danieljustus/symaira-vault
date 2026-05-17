//go:build darwin

// Package autotype provides cross-platform automated typing functionality
// for filling credentials into other applications.
package autotype

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/danieljustus/OpenPass/internal/envfilter"
)

func init() {
	defaultAutotypeFactory = NewDarwinAutotype
}

type darwinAutotype struct{}

func (a *darwinAutotype) Type(text string) error {
	if err := guardActiveWindow(); err != nil {
		return err
	}
	escaped := escapeAppleScriptString(text)
	script := fmt.Sprintf(`tell application "System Events" to keystroke "%s"`, escaped)

	// osascript reads from stdin when invoked without -e/-s and with no script
	// path argument. Routing the AppleScript (which contains the password
	// inline) through stdin keeps it out of argv where any local user could
	// read it via `ps -ef`.
	cmd := exec.Command("osascript")
	envfilter.PrepareCmd(cmd)
	cmd.Stdin = strings.NewReader(script)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("autotype failed: %w", err)
	}
	return nil
}

func NewDarwinAutotype() Autotype {
	return &darwinAutotype{}
}
