package health

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/session"
)

func checkAuthMethod(vaultDir string, _ Options) Result {
	r := Result{ID: "auth.method", Name: "Auth method"}
	cfgPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(cfgPath)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot load config to determine auth method"
		return r
	}
	method := cfg.EffectiveAuthMethod()
	if method == configpkg.AuthMethodTouchID {
		if session.BiometricAvailable() {
			r.Status = StatusOK
			r.Message = "passphrase + Touch ID active"
		} else {
			r.Status = StatusWarn
			r.Message = "configured as Touch ID but biometric not available on this system"
			r.Hint = "run `symvault auth set passphrase` to switch to passphrase-only"
		}
	} else {
		r.Status = StatusOK
		r.Message = "auth method: " + method
	}
	return r
}

func checkSessionCache(vaultDir string, _ Options) Result {
	r := Result{ID: "session.cache", Name: "Session cache"}
	status := session.GetCacheStatus()
	r.Status = StatusOK
	if status.Backend == "memory" || status.Backend == "" {
		r.Status = StatusWarn
		r.Message = "session cache uses in-memory backend (not persistent)"
		r.Hint = "install a system keyring (macOS Keychain, GNOME Keyring, KWallet) for persistent sessions"
	} else {
		r.Message = fmt.Sprintf("backend: %s, persistent: %v", status.Backend, status.Persistent)
	}
	return r
}

func checkAutoTypeBackend(_ string, _ Options) Result {
	r := Result{ID: "tooling.autotype.backend", Name: "Auto-type backend"}
	switch runtime.GOOS {
	case osDarwin:
		if _, err := exec.LookPath("osascript"); err != nil {
			r.Status = StatusWarn
			r.Message = "osascript not found — autotype unavailable on macOS"
			r.Hint = "install Xcode command line tools: xcode-select --install"
		} else {
			r.Status = StatusOK
			r.Message = "osascript available"
		}
	case osLinux:
		if _, err := exec.LookPath("xdotool"); err != nil {
			r.Status = StatusWarn
			r.Message = "xdotool not found — autotype unavailable on X11"
			r.Hint = "install xdotool (apt install xdotool, dnf install xdotool)"
		} else {
			r.Status = StatusOK
			r.Message = "xdotool available"
		}
	default:
		r.Status = StatusOK
		r.Message = "not applicable on " + runtime.GOOS
	}
	return r
}

func checkClipboardBackend(_ string, _ Options) Result {
	r := Result{ID: "tooling.clipboard.backend", Name: "Clipboard backend"}
	switch runtime.GOOS {
	case osDarwin:
		if _, err := exec.LookPath("pbcopy"); err != nil {
			r.Status = StatusWarn
			r.Message = "pbcopy not found — clipboard unavailable"
		} else {
			r.Status = StatusOK
			r.Message = "pbcopy available"
		}
	case osLinux:
		for _, name := range []string{"xclip", "wl-copy"} {
			if _, err := exec.LookPath(name); err == nil {
				r.Status = StatusOK
				r.Message = name + " available"
				return r
			}
		}
		r.Status = StatusWarn
		r.Message = "no clipboard tool found (xclip or wl-clipboard)"
		r.Hint = "install xclip (apt install xclip) or wl-clipboard (apt install wl-clipboard)"
	default:
		r.Status = StatusOK
		r.Message = "not applicable on " + runtime.GOOS
	}
	return r
}

func checkDaemonStatus(_ string, _ Options) Result {
	r := Result{ID: "daemon.status", Name: "Daemon status"}
	home, err := os.UserHomeDir()
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot determine home directory"
		return r
	}
	var svcPath string
	switch runtime.GOOS {
	case osDarwin:
		svcPath = filepath.Join(home, "Library", "LaunchAgents", "com.symvault.mcp.plist")
	case osLinux:
		svcPath = filepath.Join(home, ".config", "systemd", "user", "symvault-mcp.service")
	default:
		r.Status = StatusOK
		r.Message = "daemon not supported on " + runtime.GOOS
		return r
	}
	info, err := os.Stat(svcPath)
	if err != nil {
		if os.IsNotExist(err) {
			r.Status = StatusOK
			r.Message = "daemon not installed"
			return r
		}
		r.Status = StatusWarn
		r.Message = "cannot stat daemon file: " + err.Error()
		return r
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("daemon file has mode %o (expected 0600)", perm)
		r.Hint = "run chmod 0600 " + svcPath
	} else {
		r.Status = StatusOK
		r.Message = "daemon installed with correct permissions"
	}
	return r
}

func checkSecureUI(_ string, _ Options) Result {
	r := Result{ID: "tooling.secureui", Name: "Secure input UI"}
	switch runtime.GOOS {
	case osDarwin:
		if _, err := exec.LookPath("osascript"); err != nil {
			r.Status = StatusWarn
			r.Message = "osascript not found — secure input dialogs unavailable"
		} else {
			r.Status = StatusOK
			r.Message = "osascript available (GUI dialogs)"
		}
	case osLinux:
		var found string
		for _, name := range []string{"zenity", "kdialog"} {
			if _, err := exec.LookPath(name); err == nil {
				found = name
				break
			}
		}
		if found != "" {
			r.Status = StatusOK
			r.Message = found + " available (GUI dialogs)"
		} else {
			r.Status = StatusWarn
			r.Message = "no GUI dialog tool found (zenity or kdialog)"
			r.Hint = "install zenity (apt install zenity) or kdialog"
		}
	default:
		r.Status = StatusOK
		r.Message = "no GUI secure input available on " + runtime.GOOS
	}
	return r
}

func checkPreCommitHooks(_ string, _ Options) Result {
	r := Result{ID: "tooling.precommit", Name: "Pre-commit hooks"}
	cwd, err := os.Getwd()
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot determine working directory"
		return r
	}
	preCommitPath := filepath.Join(cwd, ".pre-commit-config.yaml")
	if _, statErr := os.Stat(preCommitPath); os.IsNotExist(statErr) {
		r.Status = StatusOK
		r.Message = "no .pre-commit-config.yaml (not a dev environment)"
		return r
	}
	gitDir := filepath.Join(cwd, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	if _, statErr := os.Stat(hooksDir); os.IsNotExist(statErr) {
		r.Status = StatusWarn
		r.Message = ".pre-commit-config.yaml exists but not a git repository"
		return r
	}
	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot read hooks directory: " + err.Error()
		return r
	}
	var hookCount int
	for _, e := range entries {
		if !e.IsDir() && e.Name() != ".gitignore" {
			hookCount++
		}
	}
	if hookCount == 0 {
		r.Status = StatusWarn
		r.Message = "pre-commit hooks not installed"
		r.Hint = "run `pre-commit install` to activate hooks"
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("%d hook(s) installed", hookCount)
	}
	return r
}

// InspectPassphraseSourceFilesForTest is an exported helper for package health unit tests.
func InspectPassphraseSourceFilesForTest(candidates []string) (string, os.FileMode, bool) {
	return inspectPassphraseSourceFiles(candidates)
}

func inspectPassphraseSourceFiles(candidates []string) (foundPath string, perm os.FileMode, hasUnsafePerm bool) {
	if len(candidates) == 0 {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			candidates = append(candidates,
				filepath.Join(home, ".env"),
				filepath.Join(home, ".bashrc"),
				filepath.Join(home, ".zshrc"),
				filepath.Join(home, ".bash_profile"),
				filepath.Join(home, ".profile"),
				filepath.Join(home, ".config", "fish", "config.fish"),
			)
		}
		cwd, err := os.Getwd()
		if err == nil && cwd != "" {
			candidates = append(candidates,
				filepath.Join(cwd, ".env"),
				filepath.Join(cwd, ".env.local"),
			)
		}
	}

	for _, p := range candidates {
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			continue
		}
		// #nosec G304 -- production candidates are fixed local shell/config paths; caller-supplied candidates exist only for unit tests.
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		buf := make([]byte, 1024*1024)
		n, _ := f.Read(buf)
		_ = f.Close()
		content := string(buf[:n])

		if strings.Contains(content, "SYMVAULT_PASSPHRASE") || strings.Contains(content, "OPENPASS_PASSPHRASE") {
			mode := info.Mode().Perm()
			isUnsafe := (mode & 0077) != 0
			return p, mode, isUnsafe
		}
	}
	return "", 0, false
}

func checkEnvPassphrase(vaultDir string, _ Options) Result {
	r := Result{ID: "security.env_passphrase", Name: "Environment passphrase"}
	cfgPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(cfgPath)
	if err != nil && !os.IsNotExist(err) {
		r.Status = StatusWarn
		r.Message = "cannot load config to determine env-passphrase guard status"
		return r
	}
	if cfg == nil {
		cfg = &configpkg.Config{}
	}
	var envVarName string
	envPass := os.Getenv("SYMVAULT_PASSPHRASE")
	if envPass != "" {
		envVarName = "SYMVAULT_PASSPHRASE"
	} else {
		envPass = os.Getenv("OPENPASS_PASSPHRASE")
		if envPass != "" {
			envVarName = "OPENPASS_PASSPHRASE"
		}
	}

	sourceFile, sourcePerm, hasUnsafePerm := inspectPassphraseSourceFiles(nil)

	if envPass == "" && !hasUnsafePerm {
		r.Status = StatusOK
		if cfg.Security != nil && cfg.Security.DisableEnvPassphrase {
			r.Message = "not set (environment passphrase disabled in config)"
		} else {
			r.Message = "not set"
		}
		return r
	}

	r.Status = StatusWarn

	var msg string
	if envVarName == "" {
		envVarName = "passphrase environment variable"
	}

	if hasUnsafePerm {
		msg = fmt.Sprintf("%s is referenced in source file %s with overly permissive permissions %04o (expected 0600)", envVarName, sourceFile, sourcePerm)
	} else if envPass != "" {
		switch {
		case cfg.Security != nil && cfg.Security.DisableEnvPassphrase:
			msg = fmt.Sprintf("%s is set despite security.disable_env_passphrase: true", envVarName)
		case cfg.Security == nil || !cfg.Security.AllowEnvPassphrase:
			msg = fmt.Sprintf("%s is set in environment but allow_env_passphrase is false (default-deny) — variable is ignored", envVarName)
		default:
			msg = fmt.Sprintf("%s is set and allowed — passphrase is present in process environment and readable by child processes/dumps", envVarName)
		}
	}
	r.Message = msg

	var hints []string
	if hasUnsafePerm {
		hints = append(hints, fmt.Sprintf("run `chmod 0600 %s` to restrict file permissions", sourceFile))
	}

	switch {
	case runtime.GOOS == osDarwin:
		if session.BiometricAvailable() {
			hints = append(hints, "on macOS, Touch ID / Keychain is recommended over environment passphrase variables")
		} else {
			hints = append(hints, "on macOS, Keychain session storage is recommended over environment passphrase variables")
		}
	case os.Getenv("CI") != "" || os.Getenv("CONTINUOUS_INTEGRATION") != "":
		hints = append(hints, "in CI/headless environments, use restricted permissions (0600) or short-lived token injection")
	default:
		hints = append(hints, fmt.Sprintf("unset %s and use `symvault unlock` with interactive prompt or OS keychain", envVarName))
	}

	r.Hint = strings.Join(hints, "; ")
	return r
}

func checkSessionKeyring(vaultDir string, _ Options) Result {
	r := Result{ID: "session.keyring", Name: "Session keyring roundtrip"}
	testData := "symvault-doctor-test"

	saveDone := make(chan error, 1)
	go func() {
		saveDone <- session.SavePassphrase(vaultDir, []byte(testData), 10*time.Second)
	}()
	select {
	case err := <-saveDone:
		if err != nil {
			r.Status = StatusWarn
			r.Message = "cannot write to keyring: " + err.Error()
			r.Hint = "check OS keyring availability (macOS Keychain, GNOME Keyring, etc.)"
			return r
		}
	case <-time.After(5 * time.Second):
		r.Status = StatusWarn
		r.Message = "save to keyring timed out — keyring unavailable in this environment"
		return r
	}

	loadDone := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data, err := session.LoadPassphrase(vaultDir)
		loadDone <- struct {
			data []byte
			err  error
		}{data, err}
	}()
	var loaded []byte
	select {
	case res := <-loadDone:
		if res.err != nil {
			r.Status = StatusFail
			r.Message = "keyring roundtrip failed: " + res.err.Error()
			_ = session.ClearSession(vaultDir)
			return r
		}
		loaded = res.data
	case <-time.After(5 * time.Second):
		r.Status = StatusWarn
		r.Message = "load from keyring timed out — keyring unavailable in this environment"
		_ = session.ClearSession(vaultDir)
		return r
	}

	if string(loaded) != testData {
		r.Status = StatusFail
		r.Message = "keyring returned corrupted data"
		_ = session.ClearSession(vaultDir)
		return r
	}
	_ = session.ClearSession(vaultDir)
	r.Status = StatusOK
	r.Message = "keyring encrypt/decrypt roundtrip OK"
	return r
}
