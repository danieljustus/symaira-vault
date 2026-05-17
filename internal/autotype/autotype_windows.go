//go:build windows

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
	defaultAutotypeFactory = NewWindowsAutotype
}

type windowsAutotype struct{}

// readSendKeysWrapper is a small PowerShell snippet that reads the password
// to be typed from stdin and forwards it to WScript.Shell.SendKeys. The text
// itself never appears in process argv, so a local user cannot recover it
// from Get-Process / wmic / Task Manager command-line listings.
const readSendKeysWrapper = `$ErrorActionPreference = 'Stop';
$text = [System.Console]::In.ReadToEnd();
$wshell = New-Object -ComObject WScript.Shell;
$wshell.SendKeys($text);`

func (a *windowsAutotype) Type(text string) error {
	if err := guardActiveWindow(); err != nil {
		return err
	}
	escaped := escapeSendKeysString(text)

	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", readSendKeysWrapper)
	envfilter.PrepareCmd(cmd)
	cmd.Stdin = strings.NewReader(escaped)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("autotype failed: %w", err)
	}
	return nil
}

func NewWindowsAutotype() Autotype {
	return &windowsAutotype{}
}
