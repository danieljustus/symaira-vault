package update

import (
	"context"
	"errors"
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
		BackupPath: "/usr/local/bin/symaira.backup",
		BinaryPath: "/usr/local/bin/symaira",
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
	if r.BackupPath != "/usr/local/bin/symaira.backup" {
		t.Errorf("BackupPath = %q, want %q", r.BackupPath, "/usr/local/bin/symaira.backup")
	}
	if r.BinaryPath != "/usr/local/bin/symaira" {
		t.Errorf("BinaryPath = %q, want %q", r.BinaryPath, "/usr/local/bin/symaira")
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
		BinaryPath: "/home/user/go/bin/symaira",
		DryRun:     true,
	}
	if !r.DryRun {
		t.Error("DryRun = false, want true")
	}
}

func TestApplyResult_BackupPath(t *testing.T) {
	r := &ApplyResult{
		BackupPath: "/custom/path/symaira.backup",
	}
	if r.BackupPath != "/custom/path/symaira.backup" {
		t.Errorf("BackupPath = %q", r.BackupPath)
	}
}

func TestErrUnsupportedMethod_Error(t *testing.T) {
	e := &ErrUnsupportedMethod{
		Method:   installmethod.Homebrew,
		Guidance: "brew upgrade symaira",
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
		BinaryPath:          "/usr/local/bin/symaira",
		SelfUpdateSupported: true,
		Guidance:            "curl ...",
	}
	if r.Method != installmethod.DirectDownload {
		t.Errorf("Method = %q, want %q", r.Method, installmethod.DirectDownload)
	}
	if r.BinaryPath != "/usr/local/bin/symaira" {
		t.Errorf("BinaryPath = %q, want %q", r.BinaryPath, "/usr/local/bin/symaira")
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
		"symaira": "binary-content-here",
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
	// GoReleaser layout: symaira_<version>_<os>_<arch>/symaira
	archive := buildTestTarGz(map[string]string{
		"symaira_1.0.0_darwin_arm64/symaira": "nested-binary",
		"symaira_1.0.0_darwin_arm64/LICENSE":  "MIT",
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
