// Package installmethod detects how Symaira Vault was installed to determine
// whether self-update is safe or if the user should update via their
// package manager, Go toolchain, or by rebuilding from source.
//
// Detection itself is delegated to corekit's generalized installmethod
// package; this package keeps only the vault-specific guidance text (exact
// CLI wording, install script URL, legacy openpass→symvault migration
// instructions).
package installmethod

import (
	corekitinstallmethod "github.com/danieljustus/symaira-corekit/updatecheck/installmethod"
)

// InstallMethod describes how a binary was installed.
type InstallMethod = corekitinstallmethod.InstallMethod

const (
	// DirectDownload indicates the binary was downloaded directly from a
	// GitHub release or similar source and placed into a user-writable
	// directory. Self-update is safe for this method.
	DirectDownload = corekitinstallmethod.DirectDownload

	// Homebrew indicates the binary was installed via Homebrew (macOS or
	// Linux). Users should update with "brew upgrade".
	Homebrew = corekitinstallmethod.Homebrew

	// GoInstall indicates the binary was installed via "go install". Users
	// should update with "go install ...@latest".
	GoInstall = corekitinstallmethod.GoInstall

	// PackageManager indicates the binary was installed via a system package
	// manager such as APT, YUM, or Pacman.
	PackageManager = corekitinstallmethod.PackageManager

	// BuildFromSource indicates the binary was compiled locally (go build,
	// make, etc.) and may be in a build directory or non-standard path.
	BuildFromSource = corekitinstallmethod.BuildFromSource

	// Unknown indicates the installation method could not be determined.
	Unknown = corekitinstallmethod.Unknown
)

// ErrEmptyBinaryPath is returned by Detect when given an empty path.
var ErrEmptyBinaryPath = corekitinstallmethod.ErrEmptyBinaryPath

// Detect examines the binary at binaryPath and returns the most likely
// installation method. See corekit's updatecheck/installmethod package for
// the detection heuristic.
func Detect(binaryPath string) (InstallMethod, error) {
	return corekitinstallmethod.Detect(binaryPath)
}

// IsSelfUpdateSupported returns true only for DirectDownload.
func IsSelfUpdateSupported(method InstallMethod) bool {
	return corekitinstallmethod.IsSelfUpdateSupported(method)
}

// Guidance returns actionable upgrade instructions for the given method.
func Guidance(method InstallMethod) string {
	switch method {
	case DirectDownload:
		return "Re-run the quick install script: curl -sSfL https://raw.githubusercontent.com/danieljustus/symaira-vault/main/scripts/install.sh | sh"
	case Homebrew:
		return "Update via Homebrew: brew update && brew upgrade symvault"
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

// LegacyGuidance returns migration instructions for users moving from the
// legacy "openpass" binary name to "symvault".
func LegacyGuidance(method InstallMethod) string {
	switch method {
	case Homebrew:
		return "Migrate via Homebrew:\n  brew update\n  brew upgrade"
	case DirectDownload:
		return "Migrate via quick install script:\n  curl -sSfL https://raw.githubusercontent.com/danieljustus/symaira-vault/main/scripts/install.sh | sh"
	case GoInstall:
		return "Migrate via Go:\n  go install github.com/danieljustus/symaira-vault@latest"
	case PackageManager:
		return "Migrate via your system package manager:\n  # Uninstall the old openpass package\n  # Then install the new symvault package"
	default:
		return Guidance(method)
	}
}
