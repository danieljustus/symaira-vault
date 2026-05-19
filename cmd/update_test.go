package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	admin "github.com/danieljustus/OpenPass/cmd/admin"
	cli "github.com/danieljustus/OpenPass/internal/cli"

	"gopkg.in/yaml.v3"

	updatepkg "github.com/danieljustus/OpenPass/internal/update"
)

type stubUpdateChecker struct {
	currentVersion string
	err            error
	forceUsed      bool
	result         *updatepkg.Result
}

func (s *stubUpdateChecker) Check(_ context.Context, currentVersion string) (*updatepkg.Result, error) {
	s.currentVersion = currentVersion
	return s.result, s.err
}

func (s *stubUpdateChecker) CheckWithForce(_ context.Context, currentVersion string, force bool) (*updatepkg.Result, error) {
	s.currentVersion = currentVersion
	s.forceUsed = force
	return s.result, s.err
}

func prepareRootCommandOutput(t *testing.T) *bytes.Buffer {
	t.Helper()

	resetCommandTestState()
	t.Cleanup(resetCommandTestState)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	return buf
}

func setUpdateCheckerForTest(t *testing.T, checker admin.UpdateChecker) {
	t.Helper()

	original := admin.UpdateCheckerFactory
	admin.UpdateCheckerFactory = func() admin.UpdateChecker { return checker }
	t.Cleanup(func() { admin.UpdateCheckerFactory = original })
}

func setVersionInfoForTest(t *testing.T, version string) {
	t.Helper()

	originalVersion := cli.AppVersion
	originalCommit := cli.AppCommit
	originalDate := cli.AppDate
	SetVersionInfo(version, "test-commit", "test-date")
	t.Cleanup(func() {
		SetVersionInfo(originalVersion, originalCommit, originalDate)
	})
}

func TestUpdateCheckCommandReportsAvailableUpdate(t *testing.T) {
	buf := prepareRootCommandOutput(t)
	setVersionInfoForTest(t, "1.0.0")

	checker := &stubUpdateChecker{
		result: &updatepkg.Result{
			CurrentVersion:  "1.0.0",
			LatestVersion:   "1.1.0",
			ReleaseURL:      "https://github.com/danieljustus/OpenPass/releases/tag/v1.1.0",
			Checkable:       true,
			UpdateAvailable: true,
		},
	}
	setUpdateCheckerForTest(t, checker)

	rootCmd.SetArgs([]string{"update", "check"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected Execute() to return an error for update available")
	}

	got := buf.String()
	for _, want := range []string{
		"Update available: 1.0.0 -> 1.1.0",
		"https://github.com/danieljustus/OpenPass/releases/tag/v1.1.0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q: %q", want, got)
		}
	}
	if checker.currentVersion != "1.0.0" {
		t.Fatalf("checker received version %q, want %q", checker.currentVersion, "1.0.0")
	}
}

func TestUpdateCheckCommandReportsUpToDate(t *testing.T) {
	buf := prepareRootCommandOutput(t)
	setVersionInfoForTest(t, "1.0.0")

	setUpdateCheckerForTest(t, &stubUpdateChecker{
		result: &updatepkg.Result{
			CurrentVersion: "1.0.0",
			LatestVersion:  "1.0.0",
			Checkable:      true,
		},
	})

	rootCmd.SetArgs([]string{"update", "check"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "OpenPass is up to date (1.0.0).") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestUpdateCheckCommandHandlesNonReleaseBuild(t *testing.T) {
	buf := prepareRootCommandOutput(t)
	setVersionInfoForTest(t, "dev")

	checker := &stubUpdateChecker{
		result: &updatepkg.Result{
			CurrentVersion: "dev",
			Checkable:      false,
		},
	}
	setUpdateCheckerForTest(t, checker)

	rootCmd.SetArgs([]string{"update", "check"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "Update checks are only available for stable release builds. Current version: dev") {
		t.Fatalf("unexpected output: %q", got)
	}
	if checker.currentVersion != "dev" {
		t.Fatalf("checker received version %q, want %q", checker.currentVersion, "dev")
	}
}

func TestUpdateCheckCommandReturnsCheckerError(t *testing.T) {
	prepareRootCommandOutput(t)
	setVersionInfoForTest(t, "1.0.0")
	setUpdateCheckerForTest(t, &stubUpdateChecker{err: errors.New("boom")})

	rootCmd.SetArgs([]string{"update", "check"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected Execute() to return an error")
	}
	if !strings.Contains(err.Error(), "check for updates: boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateCheckCommandDoesNotRequireVault(t *testing.T) {
	buf := prepareRootCommandOutput(t)
	setVersionInfoForTest(t, "dev")
	setUpdateCheckerForTest(t, &stubUpdateChecker{
		result: &updatepkg.Result{
			CurrentVersion: "dev",
			Checkable:      false,
		},
	})

	originalHome := os.Getenv("HOME")
	originalVaultEnv := os.Getenv("OPENPASS_VAULT")
	originalVault := vault
	originalChanged := vaultFlag.Changed
	_ = os.Unsetenv("HOME")
	_ = os.Unsetenv("OPENPASS_VAULT")
	vault = "~/.openpass"
	if vaultFlag != nil {
		_ = vaultFlag.Value.Set(vault)
		vaultFlag.Changed = false
	}
	t.Cleanup(func() {
		_ = os.Setenv("HOME", originalHome)
		_ = os.Setenv("OPENPASS_VAULT", originalVaultEnv)
		vault = originalVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(originalVault)
			vaultFlag.Changed = originalChanged
		}
	})

	rootCmd.SetArgs([]string{"update", "check"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !strings.Contains(buf.String(), "stable release builds") {
		t.Fatalf("unexpected output: %q", buf.String())
	}
}

func TestUpdateCheckCommandJSONOutput(t *testing.T) {
	buf := prepareRootCommandOutput(t)
	setVersionInfoForTest(t, "1.0.0")

	checker := &stubUpdateChecker{
		result: &updatepkg.Result{
			CurrentVersion:  "1.0.0",
			LatestVersion:   "1.1.0",
			ReleaseURL:      "https://github.com/danieljustus/OpenPass/releases/tag/v1.1.0",
			Checkable:       true,
			UpdateAvailable: true,
		},
	}
	setUpdateCheckerForTest(t, checker)

	rootCmd.SetArgs([]string{"update", "check", "--json"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected Execute() to return an error for update available with --json")
	}

	got := buf.String()
	for _, want := range []string{
		`"current_version": "1.0.0"`,
		`"latest_version": "1.1.0"`,
		`"release_url": "https://github.com/danieljustus/OpenPass/releases/tag/v1.1.0"`,
		`"checkable": true`,
		`"update_available": true`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("JSON output missing %q: %q", want, got)
		}
	}
}

func TestUpdateCheckCommandJSONOutputNoUpdate(t *testing.T) {
	buf := prepareRootCommandOutput(t)
	setVersionInfoForTest(t, "1.0.0")

	checker := &stubUpdateChecker{
		result: &updatepkg.Result{
			CurrentVersion: "1.0.0",
			LatestVersion:  "1.0.0",
			Checkable:      true,
		},
	}
	setUpdateCheckerForTest(t, checker)

	rootCmd.SetArgs([]string{"update", "check", "--json"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	got := buf.String()
	for _, want := range []string{
		`"current_version": "1.0.0"`,
		`"latest_version": "1.0.0"`,
		`"checkable": true`,
		`"update_available": false`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("JSON output missing %q: %q", want, got)
		}
	}
}

func TestUpdateCheckCommandQuietModeUpdateAvailable(t *testing.T) {
	buf := prepareRootCommandOutput(t)
	setVersionInfoForTest(t, "1.0.0")

	checker := &stubUpdateChecker{
		result: &updatepkg.Result{
			CurrentVersion:  "1.0.0",
			LatestVersion:   "1.1.0",
			ReleaseURL:      "https://github.com/danieljustus/OpenPass/releases/tag/v1.1.0",
			Checkable:       true,
			UpdateAvailable: true,
		},
	}
	setUpdateCheckerForTest(t, checker)

	admin.UpdateCheckCmd.SilenceUsage = true
	admin.UpdateCheckCmd.SilenceErrors = true

	rootCmd.SetArgs([]string{"update", "check", "--quiet"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected Execute() to return an error for update available with --quiet")
	}

	got := buf.String()
	if got != "" {
		t.Fatalf("expected no output with --quiet, got: %q", got)
	}
}

func TestUpdateCheckCommandQuietModeNoUpdate(t *testing.T) {
	buf := prepareRootCommandOutput(t)
	setVersionInfoForTest(t, "1.0.0")

	checker := &stubUpdateChecker{
		result: &updatepkg.Result{
			CurrentVersion: "1.0.0",
			LatestVersion:  "1.0.0",
			Checkable:      true,
		},
	}
	setUpdateCheckerForTest(t, checker)

	rootCmd.SetArgs([]string{"update", "check", "--quiet"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	got := buf.String()
	if got != "" {
		t.Fatalf("expected no output with --quiet, got: %q", got)
	}
}

func TestUpdateCheckCommandForceFlag(t *testing.T) {
	prepareRootCommandOutput(t)
	setVersionInfoForTest(t, "1.0.0")

	checker := &stubUpdateChecker{
		result: &updatepkg.Result{
			CurrentVersion: "1.0.0",
			LatestVersion:  "1.0.0",
			Checkable:      true,
		},
	}
	setUpdateCheckerForTest(t, checker)

	rootCmd.SetArgs([]string{"update", "check", "--force"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !checker.forceUsed {
		t.Fatal("expected --force flag to be passed to checker")
	}
}

func TestUpdateCacheTTL_UserHomeDirError(t *testing.T) {
	origHome := os.Getenv("HOME")
	origUserProfile := os.Getenv("USERPROFILE")
	_ = os.Unsetenv("HOME")
	_ = os.Unsetenv("USERPROFILE")
	defer func() {
		_ = os.Setenv("HOME", origHome)
		_ = os.Setenv("USERPROFILE", origUserProfile)
	}()

	ttl := admin.UpdateCacheTTL()
	if ttl != updatepkg.DefaultCacheTTL {
		t.Fatalf("admin.UpdateCacheTTL() = %v, want %v", ttl, updatepkg.DefaultCacheTTL)
	}
}

func TestUpdateCacheTTL_ConfigLoadError(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.Setenv("HOME", tmpDir)
	defer func() {
		home, _ := os.UserHomeDir()
		_ = os.Setenv("HOME", home)
	}()

	// Ensure .openpass directory doesn't exist so config load fails
	_ = os.RemoveAll(filepath.Join(tmpDir, ".openpass"))

	ttl := admin.UpdateCacheTTL()
	if ttl != updatepkg.DefaultCacheTTL {
		t.Fatalf("admin.UpdateCacheTTL() = %v, want %v", ttl, updatepkg.DefaultCacheTTL)
	}
}

func TestUpdateCacheTTL_CustomCacheTTL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	tmpDir := t.TempDir()
	_ = os.Setenv("HOME", tmpDir)
	defer func() {
		home, _ := os.UserHomeDir()
		_ = os.Setenv("HOME", home)
	}()

	openpassDir := filepath.Join(tmpDir, ".openpass")
	if err := os.MkdirAll(openpassDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	customTTL := 2 * time.Hour
	cfg := map[string]any{
		"update": map[string]any{
			"cache_ttl": customTTL.String(),
		},
	}
	data, _ := yaml.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(openpassDir, "config.yaml"), data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ttl := admin.UpdateCacheTTL()
	if ttl != customTTL {
		t.Fatalf("admin.UpdateCacheTTL() = %v, want %v", ttl, customTTL)
	}
}

func TestUpdateCacheTTL_DefaultWhenNoUpdateConfig(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.Setenv("HOME", tmpDir)
	defer func() {
		home, _ := os.UserHomeDir()
		_ = os.Setenv("HOME", home)
	}()

	openpassDir := filepath.Join(tmpDir, ".openpass")
	if err := os.MkdirAll(openpassDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := map[string]any{
		"vault_dir": "/tmp/vault",
	}
	data, _ := yaml.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(openpassDir, "config.yaml"), data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ttl := admin.UpdateCacheTTL()
	if ttl != updatepkg.DefaultCacheTTL {
		t.Fatalf("admin.UpdateCacheTTL() = %v, want %v", ttl, updatepkg.DefaultCacheTTL)
	}
}
