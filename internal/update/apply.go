package update

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/update/installmethod"
)

const (
	binaryName       = "symvault"
	legacyBinaryName = "openpass"
)

// ApplyResult contains details about a completed self-update.
type ApplyResult struct {
	Method           installmethod.InstallMethod `json:"method"`
	OldVersion       string                      `json:"old_version"`
	NewVersion       string                      `json:"new_version"`
	BackupPath       string                      `json:"backup_path,omitempty"`
	BinaryPath       string                      `json:"binary_path"`
	DryRun           bool                        `json:"dry_run"`
	LegacySymlinkPath string                     `json:"legacy_symlink_path,omitempty"`
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
	IsLegacyBinary      bool                        `json:"is_legacy_binary"`
}

func getBinaryPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve binary path: %w", err)
	}
	return p, nil
}

// isLegacyBinary reports whether the binary at binaryPath has the legacy
// "openpass" name instead of the current "symvault" name.
func isLegacyBinary(binaryPath string) bool {
	normalized := strings.ReplaceAll(binaryPath, "\\", "/")
	base := filepath.Base(normalized)
	base = strings.TrimSuffix(base, ".exe")
	return base == legacyBinaryName
}

// createLegacySymlink creates a symbolic link from the legacy binary name
// (openpass) to the new binary name (symvault) in the same directory.
// On Windows it returns an empty path and no error because Windows symlink
// handling for executables is unreliable.
func createLegacySymlink(symvaultPath string) (string, error) {
	if runtime.GOOS == windowsOS {
		// Windows symlinks for executables require special privileges and
		// behave inconsistently; skip the symlink and let the user update
		// their PATH or scripts manually.
		return "", nil
	}

	dir := filepath.Dir(symvaultPath)
	legacyPath := filepath.Join(dir, legacyBinaryName)

	_ = os.Remove(legacyPath)

	relTarget := filepath.Base(symvaultPath)
	if err := os.Symlink(relTarget, legacyPath); err != nil {
		return "", fmt.Errorf("create legacy symlink %q -> %q: %w", legacyPath, relTarget, err)
	}

	return legacyPath, nil
}

// Apply performs a self-update: downloads, verifies, and replaces the
// current binary. If force is true, the update check cache is bypassed.
// If dryRun is true, all steps except the final binary replacement are
// performed — useful for previewing what would happen.
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

	if !result.UpdateAvailable {
		return &ApplyResult{
			Method:     method,
			OldVersion: currentVersion,
			NewVersion: currentVersion,
			BinaryPath: binaryPath,
			DryRun:     dryRun,
		}, nil
	}

	archiveData, err := DownloadArchive(ctx, result.LatestVersion, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, fmt.Errorf("download update: %w", err)
	}

	checksums, err := FetchChecksums(ctx, result.LatestVersion)
	if err != nil {
		return nil, fmt.Errorf("fetch checksums: %w", err)
	}

	// Verify the cosign signature on the checksums file before trusting its
	// SHA256 hashes. This ensures the checksums were published by the
	// Symaira Vault release workflow and haven't been tampered with.
	sig, err := FetchCosignSignature(ctx, result.LatestVersion)
	if err != nil {
		return nil, fmt.Errorf("fetch cosign signature: %w", err)
	}

	cert, err := FetchCosignCertificate(ctx, result.LatestVersion)
	if err != nil {
		return nil, fmt.Errorf("fetch cosign certificate: %w", err)
	}

	if cosignErr := VerifyCosignSignature([]byte(checksums), sig, cert); cosignErr != nil {
		return nil, fmt.Errorf("cosign verification failed: %w", cosignErr)
	}

	an := archiveName(result.LatestVersion, runtime.GOOS, runtime.GOARCH)
	if verifyErr := VerifyChecksum(archiveData, checksums, an); verifyErr != nil {
		return nil, fmt.Errorf("verify checksum: %w", verifyErr)
	}

	newBinaryData, err := extractBinaryFromArchive(archiveData)
	if err != nil {
		return nil, fmt.Errorf("extract binary from archive: %w", err)
	}

	if dryRun {
		return &ApplyResult{
			Method:     method,
			OldVersion: currentVersion,
			NewVersion: result.LatestVersion,
			BinaryPath: binaryPath,
			DryRun:     true,
		}, nil
	}

	if err := Replace(binaryPath, newBinaryData); err != nil {
		return nil, fmt.Errorf("replace binary: %w", err)
	}

	bp := binaryPath + backupSuffix
	if runtime.GOOS == windowsOS {
		bp = binaryPath + windowsBackupSuffix
	}

	applyResult := &ApplyResult{
		Method:     method,
		OldVersion: currentVersion,
		NewVersion: result.LatestVersion,
		BackupPath: bp,
		BinaryPath: binaryPath,
	}

	if isLegacyBinary(binaryPath) {
		symlinkPath, err := createLegacySymlink(binaryPath)
		if err == nil && symlinkPath != "" {
			applyResult.LegacySymlinkPath = symlinkPath
		}
	}

	return applyResult, nil
}

func extractBinaryFromArchive(archiveData []byte) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "symvault-update-*")
	if err != nil {
		return nil, fmt.Errorf("create temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	binName := binaryName
	if runtime.GOOS == windowsOS {
		binName += ".exe"
	}

	var extractedPath string
	if runtime.GOOS == windowsOS {
		extractedPath, err = ExtractZip(archiveData, tmpDir, binName)
	} else {
		extractedPath, err = ExtractTarGz(archiveData, tmpDir, binName)
	}
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Clean(extractedPath))
	if err != nil {
		return nil, fmt.Errorf("read extracted binary: %w", err)
	}
	return data, nil
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
		IsLegacyBinary:      isLegacyBinary(binaryPath),
	}, nil
}
