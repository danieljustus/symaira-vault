// Package update provides functionality for checking and applying Symaira Vault updates.
package update

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	corekitupdateapply "github.com/danieljustus/symaira-corekit/updatecheck/updateapply"

	"github.com/danieljustus/symaira-vault/internal/update/installmethod"
)

const binaryName = "symvault"

// ApplyResult contains details about a completed self-update.
type ApplyResult struct {
	Method     installmethod.InstallMethod `json:"method"`
	OldVersion string                      `json:"old_version"`
	NewVersion string                      `json:"new_version"`
	// BackupPath is retained for output compatibility. Corekit removes its
	// temporary backup after a successful atomic swap, so completed updates do
	// not expose a persistent backup path.
	BackupPath string `json:"backup_path,omitempty"`
	BinaryPath string `json:"binary_path"`
	DryRun     bool   `json:"dry_run"`
}

// ErrUnsupportedMethod indicates self-update is not available for the
// detected installation method.
type ErrUnsupportedMethod struct {
	Method   installmethod.InstallMethod
	Guidance string
}

func (e *ErrUnsupportedMethod) Error() string {
	return fmt.Sprintf("self-update is not supported for %s installation", e.Method)
}

// InfoResult contains details about the installation method.
type InfoResult struct {
	Method              installmethod.InstallMethod `json:"method"`
	BinaryPath          string                      `json:"binary_path"`
	SelfUpdateSupported bool                        `json:"self_update_supported"`
	Guidance            string                      `json:"guidance"`
}

func getBinaryPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve binary path: %w", err)
	}
	return p, nil
}

func binaryFileName() string {
	if runtime.GOOS == "windows" {
		return binaryName + ".exe"
	}
	return binaryName
}

func newCorekitApplier() *corekitupdateapply.Applier {
	cfg := cosignConfig()
	applier := corekitupdateapply.NewApplier()
	applier.CheckInstallMethod = true
	applier.BinaryName = binaryName
	applier.CosignConfig = &cfg
	applier.ExtractBinary = binaryFileName()
	return applier
}

// Apply performs a self-update through corekit's download, checksum, Cosign,
// archive extraction and atomic swap pipeline. Vault retains the release-line
// filtering, metrics and installation guidance around that shared pipeline.
// If dryRun is true, the complete apply pipeline runs against a temporary copy
// of the current binary and the installed binary is left untouched.
func Apply(ctx context.Context, currentVersion string, force, dryRun bool) (*ApplyResult, error) {
	binaryPath, err := getBinaryPath()
	if err != nil {
		return nil, err
	}

	method, err := installmethod.Detect(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("detect install method: %w", err)
	}

	if !installmethod.IsSelfUpdateSupported(method) {
		return nil, &ErrUnsupportedMethod{
			Method:   method,
			Guidance: installmethod.Guidance(method),
		}
	}

	checker := NewChecker(nil)
	result, err := checker.CheckWithForce(ctx, currentVersion, force)
	if err != nil {
		return nil, fmt.Errorf("check for updates: %w", err)
	}

	if !result.UpdateAvailable || result.release == nil {
		return &ApplyResult{
			Method:     method,
			OldVersion: currentVersion,
			NewVersion: currentVersion,
			BinaryPath: binaryPath,
			DryRun:     dryRun,
		}, nil
	}

	targetPath := binaryPath
	var dryRunDir string
	if dryRun {
		dryRunDir, err = os.MkdirTemp("", "symvault-update-dry-run-*")
		if err != nil {
			return nil, fmt.Errorf("create dry-run directory: %w", err)
		}
		defer func() { _ = os.RemoveAll(dryRunDir) }()

		targetPath = filepath.Join(dryRunDir, binaryFileName())
		currentBinary, readErr := os.ReadFile(binaryPath) //nolint:gosec // path comes from os.Executable
		if readErr != nil {
			return nil, fmt.Errorf("read current binary for dry-run: %w", readErr)
		}
		mode := os.FileMode(0o755)
		if info, statErr := os.Stat(binaryPath); statErr == nil {
			mode = info.Mode().Perm()
		}
		if writeErr := os.WriteFile(targetPath, currentBinary, mode); writeErr != nil {
			return nil, fmt.Errorf("seed dry-run binary: %w", writeErr)
		}
	}

	applier := newCorekitApplier()
	if dryRun {
		// The temporary copy is intentionally outside the installed location;
		// Vault already performed the user-facing install-method check above.
		applier.CheckInstallMethod = false
	}
	if err := applier.Apply(ctx, result.release, targetPath); err != nil {
		return nil, fmt.Errorf("apply update: %w", err)
	}

	return &ApplyResult{
		Method:     method,
		OldVersion: currentVersion,
		NewVersion: result.LatestVersion,
		BinaryPath: binaryPath,
		DryRun:     dryRun,
	}, nil
}

// Info detects the installation method and returns details about it.
func Info() (*InfoResult, error) {
	binaryPath, err := getBinaryPath()
	if err != nil {
		return nil, err
	}

	method, err := installmethod.Detect(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("detect install method: %w", err)
	}

	return &InfoResult{
		Method:              method,
		BinaryPath:          binaryPath,
		SelfUpdateSupported: installmethod.IsSelfUpdateSupported(method),
		Guidance:            installmethod.Guidance(method),
	}, nil
}
