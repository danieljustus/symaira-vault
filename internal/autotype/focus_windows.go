//go:build windows

package autotype

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/danieljustus/OpenPass/internal/envfilter"
)

// defaultCaptureActiveWindow shells out to PowerShell to read the foreground
// process name. We deliberately avoid loading user32.dll via syscall to keep
// the binary CGO-free; the small overhead is acceptable for a focus check.
const foregroundProbe = `Add-Type @"
using System;
using System.Runtime.InteropServices;
public class W { [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
                 [DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(IntPtr h, out int pid); }
"@;
$h = [W]::GetForegroundWindow();
[int]$pid = 0;
[void][W]::GetWindowThreadProcessId($h, [ref]$pid);
$p = Get-Process -Id $pid -ErrorAction SilentlyContinue;
if ($p) { $p.ProcessName }`

func defaultCaptureActiveWindow() (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", foregroundProbe)
	envfilter.PrepareCmd(cmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", ErrFocusUnavailable
	}
	name := strings.TrimSpace(out.String())
	if name == "" {
		return "", ErrFocusUnavailable
	}
	return "process:" + name, nil
}
