package config

import (
	"errors"
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

func TestPreviewLegacyToXDG_IsNonMutatingAndComplete(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	legacy := filepath.Join(home, LegacyVaultSubdir)
	writeTestFile(t, filepath.Join(legacy, "config.yaml"), "secret: value")
	writeTestFile(t, filepath.Join(legacy, "vault", "identity.age"), "identity")
	before, _ := os.ReadDir(home)
	plan, err := PreviewLegacyToXDG()
	if err != nil {
		t.Fatal(err)
	}
	if !plan.NeedsMigration || len(plan.Items) != 3 {
		t.Fatalf("plan = %+v, want migration with 3 items", plan)
	}
	if _, err := os.Stat(filepath.Join(home, ".migration-state.json")); !os.IsNotExist(err) {
		t.Fatal("preview created state")
	}
	after, _ := os.ReadDir(home)
	if len(before) != len(after) {
		t.Fatal("preview mutated HOME")
	}
}

func TestMigrateLegacyToXDG_InterruptionRecovery(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	legacy := filepath.Join(home, LegacyVaultSubdir)
	writeTestFile(t, filepath.Join(legacy, "config.yaml"), "stable")
	calls := 0
	MigrationPhaseHook = func(phase string) error {
		if phase == "published" {
			calls++
			if calls == 1 {
				return errors.New("injected interruption")
			}
		}
		return nil
	}
	t.Cleanup(func() { MigrationPhaseHook = nil })
	if _, err := MigrateLegacyToXDG(); err == nil {
		t.Fatal("interrupted migration succeeded")
	}
	if _, err := os.Stat(filepath.Join(legacy, migrationStateFile)); err != nil {
		t.Fatalf("state marker missing: %v", err)
	}
	MigrationPhaseHook = nil
	migrated, err := MigrateLegacyToXDG()
	if err != nil || !migrated {
		t.Fatalf("recovery rerun = %v, %v", migrated, err)
	}
	assertFileContent(t, filepath.Join(home, "cfg", "symaira-vault", "config.yaml"), "stable")
	assertFileExists(t, filepath.Join(legacy, migrationMarker))
}

func TestMigrateLegacyToXDG_RejectsSymlinkSource(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	legacy := filepath.Join(home, LegacyVaultSubdir)
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "outside"), filepath.Join(legacy, "vault")); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacyToXDG(); err == nil {
		t.Fatal("symlink source was accepted")
	}
	if _, err := os.Stat(filepath.Join(home, "data")); !os.IsNotExist(err) {
		t.Fatal("symlink rejection created destination")
	}
}

func TestMigrateLegacyToXDG_RecoveryRejectsTamperedDestination(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	legacy := filepath.Join(home, LegacyVaultSubdir)
	writeTestFile(t, filepath.Join(legacy, "config.yaml"), "stable")
	backup := filepath.Join(legacy, migrationBackupDir)
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	state := migrationState{Version: 1, BackupDir: backup, Published: []string{filepath.Join(home, "unrelated")}}
	if err := writeJSONAtomic(filepath.Join(legacy, migrationStateFile), state); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(home, "unrelated")
	writeTestFile(t, filepath.Join(unrelated, "keep"), "user data")
	if err := RecoverLegacyToXDGMigration(); err == nil {
		t.Fatal("tampered recovery state was accepted")
	}
	assertFileContent(t, filepath.Join(unrelated, "keep"), "user data")
}

func TestMigrateLegacyToXDG_RecoveryRejectsSymlinkRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg-link"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	legacy := filepath.Join(home, LegacyVaultSubdir)
	writeTestFile(t, filepath.Join(legacy, "config.yaml"), "stable")
	outside := filepath.Join(home, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "cfg-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacyToXDG(); err == nil {
		t.Fatal("symlink XDG root was accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "symaira-vault")); !os.IsNotExist(err) {
		t.Fatal("symlink target was modified")
	}
}

func TestMigrateLegacyToXDG_RecoveryRemovesPartialCopy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	legacy := filepath.Join(home, LegacyVaultSubdir)
	writeTestFile(t, filepath.Join(legacy, "vault", "identity.age"), "identity")
	interrupted := false
	MigrationPhaseHook = func(phase string) error {
		if phase == "published" && !interrupted {
			interrupted = true
			dst := filepath.Join(home, "data", DataSubdir, "vault")
			writeTestFile(t, filepath.Join(dst, "partial"), "partial")
			return errors.New("injected copy crash")
		}
		return nil
	}
	t.Cleanup(func() { MigrationPhaseHook = nil })
	if _, err := MigrateLegacyToXDG(); err == nil {
		t.Fatal("interrupted migration succeeded")
	}
	MigrationPhaseHook = nil
	migrated, err := MigrateLegacyToXDG()
	if err != nil || !migrated {
		t.Fatalf("recovery rerun = %v, %v", migrated, err)
	}
	assertFileContent(t, filepath.Join(home, "data", DataSubdir, "vault", "identity.age"), "identity")
	if _, err := os.Stat(filepath.Join(home, "data", DataSubdir, "vault", "partial")); !os.IsNotExist(err) {
		t.Fatal("partial copy survived recovery")
	}
}
