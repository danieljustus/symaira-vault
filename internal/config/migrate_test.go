package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMigrateLegacyToXDG_NoLegacy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("SYMVAULT_NO_PATH_MIGRATION", "")

	migrated, err := MigrateLegacyToXDG()
	if err != nil {
		t.Fatalf("MigrateLegacyToXDG() error = %v", err)
	}
	if migrated {
		t.Error("MigrateLegacyToXDG() returned true, want false when no legacy dir")
	}

	// XDG dirs should not have been created.
	xdgDataDir := filepath.Join(home, ".local", "share", "symaira-vault")
	if _, err := os.Stat(xdgDataDir); err == nil {
		t.Error("XDG data dir was created without a legacy dir")
	}
}

func TestMigrateLegacyToXDG_WithLegacy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("SYMVAULT_NO_PATH_MIGRATION", "")

	legacyDir := filepath.Join(home, LegacyVaultSubdir)
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(legacy) error = %v", err)
	}

	// Create legacy files.
	writeTestFile(t, filepath.Join(legacyDir, "config.yaml"), "vault: {}")
	writeTestFile(t, filepath.Join(legacyDir, "devices.json"), "[]")
	writeTestFile(t, filepath.Join(legacyDir, "update-cache.json"), "{}")

	vaultDir := filepath.Join(legacyDir, "vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(vault) error = %v", err)
	}
	writeTestFile(t, filepath.Join(vaultDir, "identity.age"), "age-key")

	auditDir := filepath.Join(legacyDir, "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(audit) error = %v", err)
	}
	writeTestFile(t, filepath.Join(auditDir, "log.jsonl"), "audit-entry")

	pairingDir := filepath.Join(legacyDir, "pairing")
	if err := os.MkdirAll(pairingDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(pairing) error = %v", err)
	}
	writeTestFile(t, filepath.Join(pairingDir, "request.json"), "pair-req")

	migrated, err := MigrateLegacyToXDG()
	if err != nil {
		t.Fatalf("MigrateLegacyToXDG() error = %v", err)
	}
	if !migrated {
		t.Error("MigrateLegacyToXDG() returned false, want true")
	}

	// Verify config was migrated to XDG config dir.
	xdgConfigDir := filepath.Join(home, ".config", "symaira-vault")
	assertFileContent(t, filepath.Join(xdgConfigDir, "config.yaml"), "vault: {}")

	// Verify vault data migrated to XDG data dir.
	xdgDataDir := filepath.Join(home, ".local", "share", "symaira-vault")
	assertFileContent(t, filepath.Join(xdgDataDir, "devices.json"), "[]")
	assertFileContent(t, filepath.Join(xdgDataDir, "vault", "identity.age"), "age-key")
	assertFileContent(t, filepath.Join(xdgDataDir, "audit", "log.jsonl"), "audit-entry")
	assertFileContent(t, filepath.Join(xdgDataDir, "pairing", "request.json"), "pair-req")

	// Verify update cache migrated to XDG cache dir.
	xdgCacheDir := filepath.Join(home, ".cache", "symaira-vault")
	assertFileContent(t, filepath.Join(xdgCacheDir, "update-cache.json"), "{}")

	// Verify marker was left in legacy dir.
	assertFileExists(t, filepath.Join(legacyDir, migrationMarker))

	// Verify legacy dir was NOT deleted.
	assertDirExists(t, legacyDir)
}

func TestMigrateLegacyToXDG_AlreadyMigrated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("SYMVAULT_NO_PATH_MIGRATION", "")

	// Create legacy dir with marker already present.
	legacyDir := filepath.Join(home, LegacyVaultSubdir)
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(legacy) error = %v", err)
	}
	writeTestFile(t, filepath.Join(legacyDir, migrationMarker), "already done")

	migrated, err := MigrateLegacyToXDG()
	if err != nil {
		t.Fatalf("MigrateLegacyToXDG() error = %v", err)
	}
	if migrated {
		t.Error("MigrateLegacyToXDG() returned true, want false when marker exists")
	}

	// XDG dirs should not have been created.
	xdgDataDir := filepath.Join(home, ".local", "share", "symaira-vault")
	if _, err := os.Stat(xdgDataDir); err == nil {
		t.Error("XDG data dir was created when marker already existed")
	}
}

func TestMigrateLegacyToXDG_MarkerPreventsRerun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("SYMVAULT_NO_PATH_MIGRATION", "")

	legacyDir := filepath.Join(home, LegacyVaultSubdir)
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(legacy) error = %v", err)
	}
	writeTestFile(t, filepath.Join(legacyDir, "config.yaml"), "vault: {}")

	// First run — should migrate.
	migrated1, err := MigrateLegacyToXDG()
	if err != nil {
		t.Fatalf("first MigrateLegacyToXDG() error = %v", err)
	}
	if !migrated1 {
		t.Fatal("first run should migrate")
	}

	// Verify config was migrated.
	xdgConfigDir := filepath.Join(home, ".config", "symaira-vault")
	assertFileContent(t, filepath.Join(xdgConfigDir, "config.yaml"), "vault: {}")

	// Verify marker exists.
	assertFileExists(t, filepath.Join(legacyDir, migrationMarker))

	// Second run — should be a no-op.
	migrated2, err := MigrateLegacyToXDG()
	if err != nil {
		t.Fatalf("second MigrateLegacyToXDG() error = %v", err)
	}
	if migrated2 {
		t.Error("second run should not migrate again")
	}
}

func TestMigrateLegacyToXDG_EnvSkip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("SYMVAULT_NO_PATH_MIGRATION", "1")

	// Create legacy dir with data.
	legacyDir := filepath.Join(home, LegacyVaultSubdir)
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(legacy) error = %v", err)
	}
	writeTestFile(t, filepath.Join(legacyDir, "config.yaml"), "vault: {}")

	migrated, err := MigrateLegacyToXDG()
	if err != nil {
		t.Fatalf("MigrateLegacyToXDG() error = %v", err)
	}
	if migrated {
		t.Error("MigrateLegacyToXDG() returned true when SYMVAULT_NO_PATH_MIGRATION=1")
	}

	// XDG dirs should not have been created.
	xdgDataDir := filepath.Join(home, ".local", "share", "symaira-vault")
	if _, err := os.Stat(xdgDataDir); err == nil {
		t.Error("XDG data dir was created when migration was skipped via env var")
	}
}

// --- helpers ---

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	if got := string(data); got != want {
		t.Errorf("file %s content = %q, want %q", path, got, want)
	}
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v (file should exist)", path, err)
	}
	if info.IsDir() {
		t.Errorf("%s is a directory, want a file", path)
	}
}

func assertDirExists(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v (dir should exist)", path, err)
	}
	if !info.IsDir() {
		t.Errorf("%s is a file, want a directory", path)
	}
}
