package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/update/installmethod"
)

func TestApplyResult_Fields(t *testing.T) {
	r := &ApplyResult{
		Method:            installmethod.DirectDownload,
		OldVersion:        "1.0.0",
		NewVersion:        "2.0.0",
		BackupPath:        "/usr/local/bin/symvault.backup",
		BinaryPath:        "/usr/local/bin/symvault",
		DryRun:            false,
		LegacySymlinkPath: "/usr/local/bin/openpass",
	}

	if r.Method != installmethod.DirectDownload {
		t.Errorf("Method = %q, want %q", r.Method, installmethod.DirectDownload)
	}
	if r.OldVersion != "1.0.0" {
		t.Errorf("OldVersion = %q, want %q", r.OldVersion, "1.0.0")
	}
	if r.NewVersion != "2.0.0" {
		t.Errorf("NewVersion = %q, want %q", r.NewVersion, "2.0.0")
	}
	if r.BackupPath != "/usr/local/bin/symvault.backup" {
		t.Errorf("BackupPath = %q, want %q", r.BackupPath, "/usr/local/bin/symvault.backup")
	}
	if r.BinaryPath != "/usr/local/bin/symvault" {
		t.Errorf("BinaryPath = %q, want %q", r.BinaryPath, "/usr/local/bin/symvault")
	}
	if r.DryRun {
		t.Error("DryRun = true, want false")
	}
	if r.LegacySymlinkPath != "/usr/local/bin/openpass" {
		t.Errorf("LegacySymlinkPath = %q, want %q", r.LegacySymlinkPath, "/usr/local/bin/openpass")
	}
}

func TestApplyResult_DryRun(t *testing.T) {
	r := &ApplyResult{
		Method:     installmethod.GoInstall,
		OldVersion: "1.0.0",
		NewVersion: "1.5.0",
		BinaryPath: "/home/user/go/bin/symvault",
		DryRun:     true,
	}
	if !r.DryRun {
		t.Error("DryRun = false, want true")
	}
}

func TestApplyResult_BackupPath(t *testing.T) {
	r := &ApplyResult{
		BackupPath: "/custom/path/symvault.backup",
	}
	if r.BackupPath != "/custom/path/symvault.backup" {
		t.Errorf("BackupPath = %q", r.BackupPath)
	}
}

func TestErrUnsupportedMethod_Error(t *testing.T) {
	e := &ErrUnsupportedMethod{
		Method:   installmethod.Homebrew,
		Guidance: "brew upgrade symvault",
	}
	msg := e.Error()
	if !strings.Contains(msg, "homebrew") {
		t.Errorf("Error() = %q, want it to contain 'homebrew'", msg)
	}
	if !strings.Contains(msg, "not supported") {
		t.Errorf("Error() = %q, want it to contain 'not supported'", msg)
	}
}

func TestErrUnsupportedMethod_AllMethods(t *testing.T) {
	methods := []installmethod.InstallMethod{
		installmethod.Homebrew,
		installmethod.GoInstall,
		installmethod.PackageManager,
		installmethod.BuildFromSource,
		installmethod.Unknown,
	}
	for _, m := range methods {
		t.Run(string(m), func(t *testing.T) {
			e := &ErrUnsupportedMethod{
				Method:   m,
				Guidance: installmethod.Guidance(m),
			}
			msg := e.Error()
			if !strings.Contains(msg, string(m)) {
				t.Errorf("Error() = %q, want it to contain %q", msg, string(m))
			}
		})
	}
}

func TestInfoResult_Fields(t *testing.T) {
	r := &InfoResult{
		Method:              installmethod.DirectDownload,
		BinaryPath:          "/usr/local/bin/symvault",
		SelfUpdateSupported: true,
		Guidance:            "curl ...",
	}
	if r.Method != installmethod.DirectDownload {
		t.Errorf("Method = %q, want %q", r.Method, installmethod.DirectDownload)
	}
	if r.BinaryPath != "/usr/local/bin/symvault" {
		t.Errorf("BinaryPath = %q, want %q", r.BinaryPath, "/usr/local/bin/symvault")
	}
	if !r.SelfUpdateSupported {
		t.Error("SelfUpdateSupported = false, want true")
	}
	if r.Guidance == "" {
		t.Error("Guidance should not be empty")
	}
}

func TestInfoResult_NotSupported(t *testing.T) {
	r := &InfoResult{
		Method:              installmethod.Homebrew,
		SelfUpdateSupported: false,
		Guidance:            installmethod.Guidance(installmethod.Homebrew),
	}
	if r.SelfUpdateSupported {
		t.Error("SelfUpdateSupported = true, want false for homebrew")
	}
	if r.Guidance == "" {
		t.Error("Guidance should not be empty for homebrew")
	}
}

func TestInfo_ReturnsResult(t *testing.T) {
	info, err := Info()
	if err != nil {
		t.Fatalf("Info() error = %v", err)
	}
	if info.BinaryPath == "" {
		t.Error("Info().BinaryPath should not be empty")
	}
	if info.Method == "" {
		t.Error("Info().Method should not be empty")
	}
}

func TestApply_NonSemverVersion(t *testing.T) {
	// A non-semver version string (e.g. "dev") causes the Checker to
	// return an uncheckable Result immediately, avoiding network calls.
	result, err := Apply(context.Background(), "dev", false, false)
	if err != nil {
		var unsupported *ErrUnsupportedMethod
		if errors.As(err, &unsupported) {
			t.Skipf("self-update not supported for test binary (method=%s)", unsupported.Method)
		}
		t.Fatalf("Apply() error = %v", err)
	}
	if result.OldVersion != "dev" {
		t.Errorf("OldVersion = %q, want %q", result.OldVersion, "dev")
	}
	if result.NewVersion != "dev" {
		t.Errorf("NewVersion = %q, want %q", result.NewVersion, "dev")
	}
	if result.DryRun {
		t.Error("DryRun = true, want false")
	}
}

func TestApply_NonSemverVersion_DryRun(t *testing.T) {
	result, err := Apply(context.Background(), "test", false, true)
	if err != nil {
		var unsupported *ErrUnsupportedMethod
		if errors.As(err, &unsupported) {
			t.Skipf("self-update not supported for test binary (method=%s)", unsupported.Method)
		}
		t.Fatalf("Apply() error = %v", err)
	}
	if !result.DryRun {
		t.Error("DryRun = false, want true")
	}
}

func TestApply_EmptyVersion(t *testing.T) {
	result, err := Apply(context.Background(), "", false, false)
	if err != nil {
		var unsupported *ErrUnsupportedMethod
		if errors.As(err, &unsupported) {
			t.Skipf("self-update not supported for test binary (method=%s)", unsupported.Method)
		}
		t.Fatalf("Apply() error = %v", err)
	}
	if result.OldVersion != "" {
		t.Errorf("OldVersion = %q, want empty", result.OldVersion)
	}
	if result.DryRun {
		t.Error("DryRun = true, want false")
	}
}

func TestExtractBinaryFromArchive_TarGz(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tar.gz is not used on windows")
	}

	archive := buildTestTarGz(map[string]string{
		"symvault": "binary-content-here",
	}, false)

	data, err := extractBinaryFromArchive(archive)
	if err != nil {
		t.Fatalf("extractBinaryFromArchive() error = %v", err)
	}
	if string(data) != "binary-content-here" {
		t.Errorf("got content %q, want %q", string(data), "binary-content-here")
	}
}

func TestExtractBinaryFromArchive_TarGz_Nested(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tar.gz is not used on windows")
	}

	// Archive with the binary nested in a subdirectory, mimicking the
	// GoReleaser layout: symvault_<version>_<os>_<arch>/symvault
	archive := buildTestTarGz(map[string]string{
		"symvault_1.0.0_darwin_arm64/symvault": "nested-binary",
		"symvault_1.0.0_darwin_arm64/LICENSE":  "MIT",
	}, true)

	data, err := extractBinaryFromArchive(archive)
	if err != nil {
		t.Fatalf("extractBinaryFromArchive() error = %v", err)
	}
	if string(data) != "nested-binary" {
		t.Errorf("got content %q, want %q", string(data), "nested-binary")
	}
}

func TestExtractBinaryFromArchive_InvalidData(t *testing.T) {
	_, err := extractBinaryFromArchive([]byte("not-an-archive"))
	if err == nil {
		t.Fatal("expected error with invalid archive data")
	}
}

func TestExtractBinaryFromArchive_EmptyData(t *testing.T) {
	_, err := extractBinaryFromArchive([]byte{})
	if err == nil {
		t.Fatal("expected error with empty archive data")
	}
}

func TestExtractBinaryFromArchive_NoBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tar.gz is not used on windows")
	}

	archive := buildTestTarGz(map[string]string{
		"README.md": "# Symaira Vault",
		"LICENSE":   "MIT",
	}, false)

	_, err := extractBinaryFromArchive(archive)
	if err == nil {
		t.Fatal("expected ErrBinaryNotFound")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain 'not found'", err.Error())
	}
}

func TestIsLegacyBinary(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"symvault unix", "/usr/local/bin/symvault", false},
		{"openpass unix", "/usr/local/bin/openpass", true},
		{"symvault windows", `C:\\bin\\symvault.exe`, false},
		{"openpass windows", `C:\\bin\\openpass.exe`, true},
		{"other binary", "/usr/local/bin/other", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLegacyBinary(tt.path)
			if got != tt.expected {
				t.Errorf("isLegacyBinary(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestCreateLegacySymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks on windows are unreliable for executables")
	}

	tmpDir := t.TempDir()
	symvaultPath := filepath.Join(tmpDir, "symvault")

	if err := os.WriteFile(symvaultPath, []byte("dummy binary"), 0o755); err != nil {
		t.Fatalf("failed to create dummy binary: %v", err)
	}

	symlinkPath, err := createLegacySymlink(symvaultPath)
	if err != nil {
		t.Fatalf("createLegacySymlink() error = %v", err)
	}

	expectedPath := filepath.Join(tmpDir, "openpass")
	if symlinkPath != expectedPath {
		t.Errorf("createLegacySymlink() path = %q, want %q", symlinkPath, expectedPath)
	}

	target, err := os.Readlink(symlinkPath)
	if err != nil {
		t.Fatalf("os.Readlink(%q) error = %v", symlinkPath, err)
	}
	if target != "symvault" {
		t.Errorf("symlink target = %q, want %q", target, "symvault")
	}
}

func TestCreateLegacySymlink_OverwritesExisting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks on windows are unreliable for executables")
	}

	tmpDir := t.TempDir()
	symvaultPath := filepath.Join(tmpDir, "symvault")
	legacyPath := filepath.Join(tmpDir, "openpass")

	if err := os.WriteFile(symvaultPath, []byte("dummy binary"), 0o755); err != nil {
		t.Fatalf("failed to create dummy binary: %v", err)
	}

	if err := os.WriteFile(legacyPath, []byte("old binary"), 0o755); err != nil {
		t.Fatalf("failed to create old binary: %v", err)
	}

	symlinkPath, err := createLegacySymlink(symvaultPath)
	if err != nil {
		t.Fatalf("createLegacySymlink() error = %v", err)
	}

	info, err := os.Lstat(symlinkPath)
	if err != nil {
		t.Fatalf("os.Lstat(%q) error = %v", symlinkPath, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("expected %q to be a symlink, got mode %v", symlinkPath, info.Mode())
	}
}

func TestInfoResult_LegacyBinary(t *testing.T) {
	r := &InfoResult{
		Method:              installmethod.DirectDownload,
		BinaryPath:          "/usr/local/bin/openpass",
		SelfUpdateSupported: true,
		Guidance:            "curl ...",
		IsLegacyBinary:      true,
	}
	if !r.IsLegacyBinary {
		t.Error("IsLegacyBinary = false, want true")
	}
}

func TestInfoResult_NotLegacyBinary(t *testing.T) {
	r := &InfoResult{
		Method:              installmethod.DirectDownload,
		BinaryPath:          "/usr/local/bin/symvault",
		SelfUpdateSupported: true,
		Guidance:            "curl ...",
		IsLegacyBinary:      false,
	}
	if r.IsLegacyBinary {
		t.Error("IsLegacyBinary = true, want false")
	}
}
