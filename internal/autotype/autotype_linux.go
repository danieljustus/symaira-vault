//go:build linux

// Package autotype provides cross-platform automated typing functionality
// for filling credentials into other applications.
package autotype

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/danieljustus/OpenPass/internal/envfilter"
)

func init() {
	defaultAutotypeFactory = NewLinuxAutotype
}

var (
	lookPath    = exec.LookPath
	execCommand = exec.Command
)

type linuxAutotype struct{}

func (a *linuxAutotype) Type(text string) error {
	if err := guardActiveWindow(); err != nil {
		return err
	}
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		return a.typeWayland(text)
	}
	return a.typeX11(text)
}

// runWithStdin spawns cmd with text written to its stdin and waits for it to
// finish. Passing the password via stdin (instead of argv) hides it from
// process listings like `ps -ef` and /proc/<pid>/cmdline.
func runWithStdin(cmd *exec.Cmd, text string) error {
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

func (a *linuxAutotype) typeX11(text string) error {
	if _, err := lookPath("xdotool"); err != nil {
		return fmt.Errorf("autotype failed: xdotool not installed")
	}
	// xdotool reads text from stdin when --file - is used. This keeps the
	// password out of argv, where any local user could read it via ps.
	cmd := execCommand("xdotool", "type", "--clearmodifiers", "--delay", "0", "--file", "-")
	envfilter.PrepareCmd(cmd)
	if err := runWithStdin(cmd, text); err != nil {
		return fmt.Errorf("autotype failed (xdotool may not be installed or display not available): %w", err)
	}
	return nil
}

func (a *linuxAutotype) typeWayland(text string) error {
	if _, err := lookPath("wtype"); err == nil {
		// wtype reads from stdin when "-" is given as the argument.
		cmd := execCommand("wtype", "-")
		envfilter.PrepareCmd(cmd)
		if err := runWithStdin(cmd, text); err != nil {
			return fmt.Errorf("autotype failed (wtype): %w", err)
		}
		return nil
	}

	if _, err := lookPath("ydotool"); err == nil {
		// ydotool reads from a file specified with --file; /dev/stdin
		// routes the text through stdin so it doesn't appear in argv.
		cmd := execCommand("ydotool", "type", "--file", "/dev/stdin")
		envfilter.PrepareCmd(cmd)
		if err := runWithStdin(cmd, text); err != nil {
			return fmt.Errorf("autotype failed (ydotool): %w", err)
		}
		return nil
	}

	return fmt.Errorf("autotype: Wayland session detected but neither `wtype` nor `ydotool` is installed.\n" +
		"Install one of them:\n" +
		"  Debian/Ubuntu: sudo apt install wtype  (or sudo apt install ydotool)\n" +
		"  Arch:          sudo pacman -S wtype     (or ydotool)\n" +
		"  Fedora:        sudo dnf install wtype   (or ydotool)\n" +
		"`openpass doctor` will warn about this on every run until one is available")
}

func NewLinuxAutotype() Autotype {
	return &linuxAutotype{}
}
