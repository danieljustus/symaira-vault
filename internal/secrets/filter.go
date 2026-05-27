package secrets

import (
	"os"
	"os/exec"
	"sort"
	"strings"
)

// DefaultWhitelist returns the default set of safe environment variables
// that are allowed to pass through to subprocesses.
//
// These include:
//   - Basic POSIX: PATH, HOME, TMPDIR, TEMP, TMP, USER, LOGNAME, SHELL
//   - Locale: LANG, LC_ALL
//   - Terminal: TERM, COLORTERM
//   - Display (X11): DISPLAY, XAUTHORITY
//   - Git: GIT_ASKPASS, GIT_SSH, GIT_SSH_COMMAND, SSH_AUTH_SOCK, SSH_AGENT_LAUNCHER
//   - GPG: GNUPGHOME
func DefaultWhitelist() []string {
	return []string{
		"PATH",
		"HOME",
		"TMPDIR",
		"TEMP",
		"TMP",
		"USER",
		"LOGNAME",
		"LANG",
		"LC_ALL",
		"SHELL",
		"TERM",
		"COLORTERM",
		"DISPLAY",
		"XAUTHORITY",
		"GIT_ASKPASS",
		"GIT_SSH",
		"GIT_SSH_COMMAND",
		"SSH_AUTH_SOCK",
		"SSH_AGENT_LAUNCHER",
		"GNUPGHOME",
	}
}

// FilterEnv returns only the environment variables from os.Environ()
// whose names appear in the whitelist. Returns an empty (nil) slice
// when whitelist is empty.
func FilterEnv(whitelist []string) []string {
	if len(whitelist) == 0 {
		return nil
	}
	wl := make(map[string]bool, len(whitelist))
	for _, v := range whitelist {
		wl[v] = true
	}
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) > 0 && wl[parts[0]] {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// MergeWhitelist merges multiple whitelists into one without duplicates.
// The order of first occurrence is preserved. Returns an empty slice
// when called with no arguments.
func MergeWhitelist(lists ...[]string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, list := range lists {
		for _, v := range list {
			if !seen[v] {
				seen[v] = true
				result = append(result, v)
			}
		}
	}
	return result
}

// PrepareCmd sets the Env field on cmd using the default whitelist.
// Additional env var names can be passed to extend the whitelist
// (e.g., for tool-specific vars like GIT_SSH_COMMAND).
//
// Usage:
//
//	cmd := exec.Command("git", "status")
//	envfilter.PrepareCmd(cmd)
//	if err := cmd.Run(); err != nil { ... }
//
//	// With additional vars:
//	envfilter.PrepareCmd(cmd, "GIT_SSH_COMMAND", "SSH_AUTH_SOCK")
func PrepareCmd(cmd *exec.Cmd, additional ...string) {
	whitelist := DefaultWhitelist()
	if len(additional) > 0 {
		whitelist = MergeWhitelist(DefaultWhitelist(), additional)
	}
	cmd.Env = FilterEnv(whitelist)
}

// DeniedEnvVars returns the list of environment variable names that are
// denied from agent-supplied env_vars to prevent interpreter/loader injection.
func DeniedEnvVars() []string {
	return []string{
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH",
		"NODE_OPTIONS", "PYTHONSTARTUP", "PYTHONPATH",
		"BASH_ENV", "ENV", "RUBYOPT", "PERL5OPT", "PERL5LIB",
	}
}

// RejectDenied returns a sorted slice of denied env var keys found in the input map.
func RejectDenied(env map[string]string) []string {
	denied := DeniedEnvVars()
	deniedSet := make(map[string]bool, len(denied))
	for _, v := range denied {
		deniedSet[v] = true
	}
	var rejected []string
	for k := range env {
		if deniedSet[k] {
			rejected = append(rejected, k)
		}
	}
	sort.Strings(rejected)
	return rejected
}
