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
		Method:     installmethod.DirectDownload,
		OldVersion: "1.0.0",
		NewVersion: "2.0.0",
		BackupPath: "/usr/local/bin/symvault.backup",
		BinaryPath: "/usr/local/bin/symvault",
		DryRun:     false,
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

func TestVerifyBinary(t *testing.T) {
	if runtime.GOOS == windowsOS {
		t.Skip("skipping: shell script binaries are not supported on windows")
	}

	path := filepath.Join(t.TempDir(), "symvault")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' symvault-test\n"), 0o755); err != nil { //nolint:gosec
		t.Fatalf("write test binary: %v", err)
	}

	if err := verifyBinary(path); err != nil {
		t.Fatalf("verifyBinary() error = %v", err)
	}
}

func TestVerifyBinary_Failure(t *testing.T) {
	if runtime.GOOS == windowsOS {
		t.Skip("skipping: shell script binaries are not supported on windows")
	}

	path := filepath.Join(t.TempDir(), "symvault")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil { //nolint:gosec
		t.Fatalf("write test binary: %v", err)
	}

	if err := verifyBinary(path); err == nil {
		t.Fatal("verifyBinary() error = nil, want command failure")
	}
}

func TestNewCorekitApplierConfig(t *testing.T) {
	applier := newCorekitApplier()
	if applier == nil {
		t.Fatal("newCorekitApplier() returned nil")
	}
	if !applier.CheckInstallMethod {
		t.Fatal("CheckInstallMethod = false, want true")
	}
	if applier.BinaryName != binaryName {
		t.Fatalf("BinaryName = %q, want %q", applier.BinaryName, binaryName)
	}
	if applier.CosignConfig == nil {
		t.Fatal("CosignConfig = nil, want release artifact configuration")
	}
	if applier.CosignConfig.BinaryName != releaseArtifactName {
		t.Fatalf("CosignConfig.BinaryName = %q, want %q", applier.CosignConfig.BinaryName, releaseArtifactName)
	}
	if applier.ExtractBinary != binaryFileName() {
		t.Fatalf("ExtractBinary = %q, want %q", applier.ExtractBinary, binaryFileName())
	}
	if applier.ValidateBinary == nil {
		t.Fatal("ValidateBinary = nil, want post-swap executable validation")
	}
	if applier.CosignConfig == nil {
		t.Fatal("CosignConfig = nil, want repository-specific verification config")
	}
	if applier.CosignConfig.Repo != "danieljustus/symaira-vault" {
		t.Fatalf("CosignConfig.Repo = %q, want repository slug", applier.CosignConfig.Repo)
	}
	if applier.CosignConfig.IdentityRegexp != CosignIdentityRegexp {
		t.Fatal("CosignConfig.IdentityRegexp does not use the Vault release identity")
	}
}
