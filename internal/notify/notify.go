// Package notify provides cross-platform desktop notifications for security events.
//
// Supported platforms:
//   - macOS: osascript (display notification)
//   - Linux: notify-send (libnotify)
//   - Windows: PowerShell BurntToast / MessageBox fallback
//   - Other: no-op (log-only)
//
// Notifications are best-effort and never block the caller. Opt-out via
// OPENPASS_NO_NOTIFY=1 or filter by level via OPENPASS_NOTIFY_LEVEL.
package notify

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Level represents notification severity.
type Level int

const (
	// LevelInfo is for routine informational notifications.
	LevelInfo Level = iota
	// LevelWarn is for warnings the user should notice soon.
	LevelWarn
	// LevelCritical is for security events demanding immediate attention.
	LevelCritical
)

func parseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return LevelCritical
	case "warn", "warning":
		return LevelWarn
	default:
		return LevelInfo
	}
}

// suppressed returns true when notifications should be skipped entirely.
// OPENPASS_NO_NOTIFY=1 suppresses everything; OPENPASS_NOTIFY_LEVEL filters
// out events below the configured threshold (e.g. LEVEL=critical only
// shows critical events).
func suppressed(want Level) bool {
	if v := os.Getenv("OPENPASS_NO_NOTIFY"); v != "" && v != "0" && v != "false" {
		return true
	}
	if min := os.Getenv("OPENPASS_NOTIFY_LEVEL"); min != "" {
		return want < parseLevel(min)
	}
	return false
}

// Notify displays a desktop notification with the given title and message.
// Returns nil on success (or when the platform doesn't support notifications).
// Errors are logged but never returned to avoid blocking the caller.
func Notify(title, message string) {
	notifyLevel(LevelInfo, title, message)
}

// AlertNotify sends a high-urgency notification for security events.
// On supported platforms, this uses the "alert" or "critical" urgency level.
func AlertNotify(title, message string) {
	NotifyCritical(title, message)
}

// NotifyCritical sends a critical-urgency notification (persistent on macOS,
// critical on Linux). This should only be used for security events that
// require immediate user attention.
func NotifyCritical(title, message string) {
	notifyLevel(LevelCritical, title, message)
}

// NotifyWarn sends a warning-level notification (the middle severity).
func NotifyWarn(title, message string) {
	notifyLevel(LevelWarn, title, message)
}

func notifyLevel(level Level, title, message string) {
	if suppressed(level) {
		slog.Debug("notification suppressed", "level", level, "title", title)
		return
	}
	cmd := buildCommand(level, title, message)
	if cmd == nil {
		slog.Debug("desktop notification not supported on " + runtime.GOOS)
		return
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		slog.Warn("desktop notification failed", "error", err, "output", string(out))
	}
}

func buildCommand(level Level, title, message string) *exec.Cmd {
	switch runtime.GOOS {
	case "darwin":
		if level == LevelCritical {
			return exec.Command("osascript", "-e",
				fmt.Sprintf(`display notification %q with title %q subtitle %q sound name "default"`,
					message, "SECURITY ALERT", title))
		}
		return exec.Command("osascript", "-e",
			fmt.Sprintf(`display notification %q with title %q`, message, title))
	case "linux":
		urgency := "normal"
		switch level {
		case LevelCritical:
			urgency = "critical"
		case LevelWarn:
			urgency = "normal"
		case LevelInfo:
			urgency = "low"
		}
		return exec.Command("notify-send", "--urgency="+urgency, title, message)
	case "windows":
		return buildWindowsCommand(level, title, message)
	default:
		return nil
	}
}

// buildWindowsCommand emits a PowerShell snippet that uses BurntToast when
// available and falls back to a MessageBox so users see *something*. Both
// run via stdin so the message stays out of process argv.
func buildWindowsCommand(level Level, title, message string) *exec.Cmd {
	severity := "Information"
	switch level {
	case LevelInfo:
		severity = "Information"
	case LevelWarn:
		severity = "Warning"
	case LevelCritical:
		severity = "Error"
	}
	script := fmt.Sprintf(`
$title = %q
$msg   = %q
if (Get-Module -ListAvailable -Name BurntToast) {
    Import-Module BurntToast
    New-BurntToastNotification -Text $title, $msg | Out-Null
} else {
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    [System.Windows.Forms.MessageBox]::Show($msg, $title, 'OK', '%s') | Out-Null
}`, title, message, severity)
	return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
}
