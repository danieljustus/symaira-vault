// Package installmethod detects how Symaira Vault was installed to determine
// whether self-update is safe or if the user should update via their
// package manager, Go toolchain, or by rebuilding from source.
package installmethod

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// InstallMethod describes how a binary was installed.
type InstallMethod string

const (
	// DirectDownload indicates the binary was downloaded directly from a
	// GitHub release or similar source and placed into a user-writable
	// directory. Self-update is safe for this method.
	DirectDownload InstallMethod = "direct-download"

	// Homebrew indicates the binary was installed via Homebrew (macOS or
	// Linux). Users should update with "brew upgrade".
	Homebrew InstallMethod = "homebrew"

	// GoInstall indicates the binary was installed via "go install". Users
	// should update with "go install ...@latest".
	GoInstall InstallMethod = "go-install"

	// PackageManager indicates the binary was installed via a system package
	// manager such as APT, YUM, or Pacman.
	PackageManager InstallMethod = "package-manager"

	// BuildFromSource indicates the binary was compiled locally (go build,
	// make, etc.) and may be in a build directory or non-standard path.
	BuildFromSource InstallMethod = "build-from-source"

	// Unknown indicates the installation method could not be determined.
	Unknown InstallMethod = "unknown"
)

var (
	// ErrEmptyBinaryPath is returned by Detect when given an empty path.
	ErrEmptyBinaryPath = errors.New("binary path must not be empty")
)

// Detect examines the binary at binaryPath and returns the most likely
// installation method. It uses a layered heuristic:
//
//  1. Environment variables (HOMEBREW_PREFIX, GOPATH, GOMODCACHE)
//  2. Binary path patterns (/opt/homebrew/bin, /usr/local/bin, etc.)
//  3. Package manager receipt files (dpkg info, Homebrew Cellar)
//  4. Go module cache markers (@version in path, /pkg/mod/)
//  5. Fallback: directory writability check
//
// binaryPath may be absolute or relative; symlinks are resolved before
// inspection.
func Detect(binaryPath string) (InstallMethod, error) {
	if binaryPath == "" {
		return Unknown, ErrEmptyBinaryPath
	}

	realPath, err := filepath.EvalSymlinks(binaryPath)
	if err != nil {
		realPath = binaryPath
	}

	absPath, err := filepath.Abs(realPath)
	if err != nil {
		absPath = realPath
	}

	if method := detectFromEnv(absPath); method != Unknown {
		return method, nil
	}

	if method := detectFromPath(absPath); method != Unknown {
		return method, nil
	}

	if method := detectFromReceipts(absPath); method != Unknown {
		return method, nil
	}

	if method := detectFromGoCache(absPath); method != Unknown {
		return method, nil
	}

	return detectFromWritability(absPath), nil
}

// IsSelfUpdateSupported returns true only for DirectDownload.
func IsSelfUpdateSupported(method InstallMethod) bool {
	return method == DirectDownload
}

// Guidance returns actionable upgrade instructions for the given method.
func Guidance(method InstallMethod) string {
	switch method {
	case DirectDownload:
		return "Re-run the quick install script: curl -sSfL https://raw.githubusercontent.com/danieljustus/Symaira Vault/main/scripts/install.sh | sh"
	case Homebrew:
		return "Update via Homebrew: brew upgrade symvault"
	case GoInstall:
		return "Update via Go: go install github.com/danieljustus/symaira-vault@latest"
	case PackageManager:
		return "Update via your system package manager (e.g., apt upgrade, yum update, pacman -Syu)"
	case BuildFromSource:
		return "Rebuild from source: git pull && go build ./cmd/symvault"
	case Unknown:
		return "Unable to determine installation method. Reinstall from https://github.com/danieljustus/symaira-vault/releases"
	default:
		return ""
	}
}

func detectFromEnv(absPath string) InstallMethod {
	if prefix := os.Getenv("HOMEBREW_PREFIX"); prefix != "" {
		if resolved, err := filepath.EvalSymlinks(prefix); err == nil {
			prefix = resolved
		}
		if strings.HasPrefix(absPath, prefix) {
			return Homebrew
		}
	}

	if gopath := os.Getenv("GOPATH"); gopath != "" {
		if resolved, err := filepath.EvalSymlinks(gopath); err == nil {
			gopath = resolved
		}
		binDir := filepath.Join(gopath, "bin")
		if strings.HasPrefix(absPath, binDir) {
			return GoInstall
		}
	}

	if gomodcache := os.Getenv("GOMODCACHE"); gomodcache != "" {
		if resolved, err := filepath.EvalSymlinks(gomodcache); err == nil {
			gomodcache = resolved
		}
		if strings.HasPrefix(absPath, gomodcache) {
			return GoInstall
		}
	}

	return Unknown
}

func detectFromPath(absPath string) InstallMethod {
	home, _ := os.UserHomeDir()

	if strings.Contains(absPath, "/opt/homebrew/") {
		return Homebrew
	}

	if strings.Contains(absPath, "/usr/local/Cellar/") {
		return Homebrew
	}

	if strings.Contains(absPath, "/.linuxbrew/") {
		return Homebrew
	}

	if strings.HasPrefix(absPath, "/usr/bin/") {
		return PackageManager
	}

	if strings.HasPrefix(absPath, "/usr/local/bin/") {
		return DirectDownload
	}

	if gopath := os.Getenv("GOPATH"); gopath != "" {
		if resolved, err := filepath.EvalSymlinks(gopath); err == nil {
			gopath = resolved
		}
		binDir := filepath.Join(gopath, "bin") + string(filepath.Separator)
		if strings.HasPrefix(absPath, binDir) {
			return GoInstall
		}
	}

	if home != "" {
		goBin := filepath.Join(home, "go", "bin") + string(filepath.Separator)
		if strings.HasPrefix(absPath, goBin) {
			return GoInstall
		}
	}

	if home != "" {
		userBins := []string{
			filepath.Join(home, "bin"),
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, ".cargo", "bin"),
		}
		for _, dir := range userBins {
			prefix := dir + string(filepath.Separator)
			if strings.HasPrefix(absPath, prefix) {
				return DirectDownload
			}
		}
	}

	return Unknown
}

func detectFromReceipts(absPath string) InstallMethod {
	if strings.Contains(absPath, "/Cellar/") {
		return Homebrew
	}

	if _, err := os.Stat("/var/lib/dpkg/info/symvault.list"); err == nil {
		return PackageManager
	}

	return Unknown
}

func detectFromGoCache(absPath string) InstallMethod {
	if strings.Contains(absPath, "@") {
		return GoInstall
	}

	if strings.Contains(absPath, "/pkg/mod/") {
		return GoInstall
	}

	return Unknown
}

func detectFromWritability(absPath string) InstallMethod {
	if runtime.GOOS == "windows" {
		return BuildFromSource
	}

	dir := filepath.Dir(absPath)
	info, err := os.Stat(dir)
	if err != nil {
		return Unknown
	}

	if info.Mode().Perm()&0200 != 0 {
		return DirectDownload
	}

	if info.Mode().Perm()&0022 != 0 {
		return DirectDownload
	}

	return BuildFromSource
}
