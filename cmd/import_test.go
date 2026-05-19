package cmd

import (
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

var expectedCSVImportPaths = []string{
	"Bank-Checking",
	"GitHub,-Personal",
	"Work-AWS",
}

func TestImportCommandDryRunDoesNotWriteEntries(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	output := runImportCommand(t, string(passphrase), "--vault", vaultDir, "import", "csv", csvImportFixture(t), "--dry-run")

	svc := importTestVaultService(t, vaultDir, string(passphrase))
	entries, err := svc.List("")
	if err != nil {
		t.Fatalf("list entries: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("dry-run wrote entries: %#v", entries)
	}
	for _, path := range expectedCSVImportPaths {
		if !strings.Contains(output, "Would import: "+path) {
			t.Errorf("dry-run output missing %q: %s", path, output)
		}
	}
	if !strings.Contains(output, "Import summary: 3 imported, 0 skipped") {
		t.Errorf("dry-run output missing summary: %s", output)
	}
}

func TestImportCommandCSVWritesEntries(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	output := runImportCommand(t, string(passphrase), "--vault", vaultDir, "import", "csv", csvImportFixture(t))

	if !strings.Contains(output, "Import summary: 3 imported, 0 skipped") {
		t.Errorf("import output missing summary: %s", output)
	}
	svc := importTestVaultService(t, vaultDir, string(passphrase))
	assertCSVImportedEntries(t, svc, "")
}

func TestImportCommandSkipExistingDoesNotChangeEntries(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	defer setupVaultFlag(t, vaultDir)()
	source := csvImportFixture(t)

	runImportCommand(t, string(passphrase), "--vault", vaultDir, "import", "csv", source)
	svc := importTestVaultService(t, vaultDir, string(passphrase))
	before := snapshotImportEntries(t, svc, expectedCSVImportPaths)

	output := runImportCommand(t, string(passphrase), "--vault", vaultDir, "import", "csv", source, "--skip-existing")
	after := snapshotImportEntries(t, svc, expectedCSVImportPaths)

	if !reflect.DeepEqual(after, before) {
		t.Fatalf("entries changed with --skip-existing\nbefore: %#v\nafter:  %#v", before, after)
	}
	if !strings.Contains(output, "Import summary: 0 imported, 3 skipped") {
		t.Errorf("skip-existing output missing summary: %s", output)
	}
}

func TestImportCommandOverwriteUpdatesExistingEntries(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	source := csvImportFixture(t)

	runImportCommand(t, string(passphrase), "--vault", vaultDir, "import", "csv", source)
	svc := importTestVaultService(t, vaultDir, string(passphrase))
	if err := svc.SetFields("GitHub,-Personal", map[string]any{
		"username": "changed@example.com",
		"extra":    "remove-me",
	}); err != nil {
		t.Fatalf("modify imported entry: %v", err)
	}

	output := runImportCommand(t, string(passphrase), "--vault", vaultDir, "import", "csv", source, "--overwrite")
	entry, err := svc.GetEntry("GitHub,-Personal")
	if err != nil {
		t.Fatalf("get overwritten entry: %v", err)
	}

	if entry.Data["username"] != "user@example.com" {
		t.Errorf("username was not overwritten, got %#v", entry.Data["username"])
	}
	if _, ok := entry.Data["extra"]; ok {
		t.Errorf("overwrite kept stale field: %#v", entry.Data)
	}
	if !strings.Contains(output, "Import summary: 3 imported, 0 skipped") {
		t.Errorf("overwrite output missing summary: %s", output)
	}
}

func TestImportCommandPrefixWritesEntriesUnderPrefix(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	output := runImportCommand(t, string(passphrase), "--vault", vaultDir, "import", "csv", csvImportFixture(t), "--prefix", "imports/")

	if !strings.Contains(output, "Imported: imports/GitHub,-Personal") {
		t.Errorf("prefix output missing imported path: %s", output)
	}
	svc := importTestVaultService(t, vaultDir, string(passphrase))
	assertCSVImportedEntries(t, svc, "imports/")
}

func runImportCommand(t *testing.T, passphrase string, args ...string) string {
	t.Helper()
	if err := os.Setenv("OPENPASS_PASSPHRASE", passphrase); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}
	cli.RootCmd.SetArgs(args)
	defer cli.RootCmd.SetArgs(nil)

	var execErr error
	output := captureStdout(func() {
		execErr = cli.RootCmd.Execute()
	})
	if execErr != nil {
		t.Fatalf("import command failed: %v", execErr)
	}
	return output
}

func csvImportFixture(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate import test file")
	}
	return filepath.Join(filepath.Dir(file), "..", "testdata", "importer", "csv", "sample.csv")
}

func importTestVaultService(t *testing.T, vaultDir, passphrase string) vaultsvc.Service {
	t.Helper()
	v, err := vaultpkg.OpenWithPassphrase(vaultDir, []byte(passphrase))
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	return vaultsvc.New(slog.Default(), v)
}

func assertCSVImportedEntries(t *testing.T, svc vaultsvc.Service, prefix string) {
	t.Helper()
	entryAssertions := map[string]map[string]any{
		"GitHub,-Personal": {
			"username": "user@example.com",
			"password": "mysecretpassword",
			"url":      "https://github.com/login",
			"notes":    "Primary account, includes comma in title",
		},
		"Bank-Checking": {
			"username": "bank.user@example.com",
			"password": "p@ss,with,commas",
			"url":      "https://bank.example.com/login",
			"notes":    "Security questions: mother's maiden name? Use generated answers.",
		},
		"Work-AWS": {
			"username": "admin@company.com",
			"password": "work-aws-secret",
			"url":      "https://aws.amazon.com",
			"notes":    "TOTP enabled; owner: Cloud Team",
		},
	}

	for path, want := range entryAssertions {
		entry, err := svc.GetEntry(prefix + path)
		if err != nil {
			t.Fatalf("get imported entry %q: %v", prefix+path, err)
		}
		for field, wantValue := range want {
			if entry.Data[field] != wantValue {
				t.Errorf("%s.%s = %#v, want %#v", prefix+path, field, entry.Data[field], wantValue)
			}
		}
	}
}

func TestImportQuarantineMutualExclusion(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	if err := os.Setenv("OPENPASS_PASSPHRASE", string(passphrase)); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}
	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "import", "csv", csvImportFixture(t), "--quarantine", "--prefix", "myprefix/"})
	defer cli.RootCmd.SetArgs(nil)

	var execErr error
	captureStdout(func() {
		execErr = cli.RootCmd.Execute()
	})
	if execErr == nil {
		t.Fatal("expected error combining --quarantine and --prefix, got nil")
	}
	if !strings.Contains(execErr.Error(), "--quarantine and --prefix cannot be used together") {
		t.Errorf("unexpected error message: %v", execErr)
	}
}

func TestImportQuarantinePath(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	if err := os.Setenv("OPENPASS_PASSPHRASE", string(passphrase)); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}
	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "import", "csv", csvImportFixture(t), "--quarantine"})
	defer cli.RootCmd.SetArgs(nil)

	var execErr error
	output := captureStdout(func() {
		execErr = cli.RootCmd.Execute()
	})
	if execErr != nil {
		t.Fatalf("import --quarantine failed: %v", execErr)
	}

	// Output should contain the quarantine import ID line
	if !strings.Contains(output, "Quarantine import ID: import-") {
		t.Errorf("output missing quarantine import ID: %s", output)
	}

	// Verify entries are stored under quarantine/<import-id>/
	svc := importTestVaultService(t, vaultDir, string(passphrase))
	quarantined, err := svc.List("quarantine/")
	if err != nil {
		t.Fatalf("list quarantine entries: %v", err)
	}
	if len(quarantined) == 0 {
		t.Fatal("no entries imported under quarantine/ prefix")
	}
	// All quarantined entries must be under quarantine/import-YYYYMMDD-<hex>/
	for _, e := range quarantined {
		if !strings.HasPrefix(e, "quarantine/import-") {
			t.Errorf("entry %q not under quarantine/import-* prefix", e)
		}
	}
	// Verify that exactly the 3 CSV entries are present
	if len(quarantined) != 3 {
		t.Errorf("expected 3 quarantined entries, got %d: %v", len(quarantined), quarantined)
	}
}

func TestImportReviewListEmpty(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	if err := os.Setenv("OPENPASS_PASSPHRASE", string(passphrase)); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}
	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "import", "review", "list"})
	defer cli.RootCmd.SetArgs(nil)

	var execErr error
	output := captureStdout(func() {
		execErr = cli.RootCmd.Execute()
	})
	if execErr != nil {
		t.Fatalf("import review list failed: %v", execErr)
	}
	if !strings.Contains(output, "No quarantined imports found.") {
		t.Errorf("expected empty message, got: %s", output)
	}
}

func TestImportReviewList(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	// First do a quarantine import to create an import batch
	if err := os.Setenv("OPENPASS_PASSPHRASE", string(passphrase)); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}
	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "import", "csv", csvImportFixture(t), "--quarantine"})
	var importOutput string
	var importErr error
	importOutput = captureStdout(func() {
		importErr = cli.RootCmd.Execute()
	})
	cli.RootCmd.SetArgs(nil)
	if importErr != nil {
		t.Fatalf("quarantine import failed: %v", importErr)
	}

	// Extract the import-id from the output
	var importID string
	for _, line := range strings.Split(importOutput, "\n") {
		if strings.HasPrefix(line, "Quarantine import ID: ") {
			importID = strings.TrimSpace(strings.TrimPrefix(line, "Quarantine import ID: "))
		}
	}
	if importID == "" {
		t.Fatalf("could not extract import-id from output: %s", importOutput)
	}

	// Re-set passphrase (cli.UnlockVault unsets it after each use)
	if err := os.Setenv("OPENPASS_PASSPHRASE", string(passphrase)); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}

	// Now run review list
	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "import", "review", "list"})
	var listErr error
	listOutput := captureStdout(func() {
		listErr = cli.RootCmd.Execute()
	})
	cli.RootCmd.SetArgs(nil)
	if listErr != nil {
		t.Fatalf("import review list failed: %v", listErr)
	}
	if !strings.Contains(listOutput, importID) {
		t.Errorf("review list missing import-id %q: %s", importID, listOutput)
	}
	if !strings.Contains(listOutput, "(3 entries)") {
		t.Errorf("review list missing entry count: %s", listOutput)
	}
}

func TestImportReviewPromote(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	// Quarantine import
	if err := os.Setenv("OPENPASS_PASSPHRASE", string(passphrase)); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}
	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "import", "csv", csvImportFixture(t), "--quarantine"})
	var importOutput string
	var importErr error
	importOutput = captureStdout(func() {
		importErr = cli.RootCmd.Execute()
	})
	cli.RootCmd.SetArgs(nil)
	if importErr != nil {
		t.Fatalf("quarantine import failed: %v", importErr)
	}

	// Extract the import-id
	var importID string
	for _, line := range strings.Split(importOutput, "\n") {
		if strings.HasPrefix(line, "Quarantine import ID: ") {
			importID = strings.TrimSpace(strings.TrimPrefix(line, "Quarantine import ID: "))
		}
	}
	if importID == "" {
		t.Fatalf("could not extract import-id from output: %s", importOutput)
	}

	// Re-set passphrase (cli.UnlockVault unsets it after each use)
	if err := os.Setenv("OPENPASS_PASSPHRASE", string(passphrase)); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}

	// Promote
	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "import", "review", "promote", importID})
	var promoteErr error
	promoteOutput := captureStdout(func() {
		promoteErr = cli.RootCmd.Execute()
	})
	cli.RootCmd.SetArgs(nil)
	if promoteErr != nil {
		t.Fatalf("import review promote failed: %v", promoteErr)
	}

	// All 3 CSV entries should be promoted
	for _, p := range expectedCSVImportPaths {
		if !strings.Contains(promoteOutput, "Promoted: "+p) {
			t.Errorf("promote output missing %q: %s", p, promoteOutput)
		}
	}

	// Verify entries now exist at final paths
	svc := importTestVaultService(t, vaultDir, string(passphrase))
	assertCSVImportedEntries(t, svc, "")

	// Quarantine prefix should be empty
	quarantined, err := svc.List("quarantine/")
	if err != nil {
		t.Fatalf("list quarantine: %v", err)
	}
	if len(quarantined) != 0 {
		t.Errorf("quarantine not cleaned up: %v", quarantined)
	}
}

func TestImportReviewPromoteSkipsExisting(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	// Quarantine import
	if err := os.Setenv("OPENPASS_PASSPHRASE", string(passphrase)); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}
	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "import", "csv", csvImportFixture(t), "--quarantine"})
	var importOutput string
	var importErr error
	importOutput = captureStdout(func() {
		importErr = cli.RootCmd.Execute()
	})
	cli.RootCmd.SetArgs(nil)
	if importErr != nil {
		t.Fatalf("quarantine import failed: %v", importErr)
	}

	// Extract the import-id
	var importID string
	for _, line := range strings.Split(importOutput, "\n") {
		if strings.HasPrefix(line, "Quarantine import ID: ") {
			importID = strings.TrimSpace(strings.TrimPrefix(line, "Quarantine import ID: "))
		}
	}
	if importID == "" {
		t.Fatalf("could not extract import-id from output: %s", importOutput)
	}

	// Create a conflicting destination entry
	svc := importTestVaultService(t, vaultDir, string(passphrase))
	if err := svc.SetFields("GitHub,-Personal", map[string]any{
		"username": "existing@example.com",
	}); err != nil {
		t.Fatalf("create conflicting destination entry: %v", err)
	}

	// Re-set passphrase
	if err := os.Setenv("OPENPASS_PASSPHRASE", string(passphrase)); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}

	// Promote WITHOUT --overwrite — should fail
	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "import", "review", "promote", importID})
	var promoteErr error
	promoteOutput := captureStdout(func() {
		promoteErr = cli.RootCmd.Execute()
	})
	cli.RootCmd.SetArgs(nil)
	if promoteErr == nil {
		t.Fatal("expected error when destination already exists without --overwrite, got nil")
	}

	// Warning output should mention "already exists"
	if !strings.Contains(promoteOutput, "already exists") {
		t.Errorf("promote output missing 'already exists' warning: %s", promoteOutput)
	}

	// Quarantine entry should still exist (not deleted)
	quarantined, err := svc.List("quarantine/")
	if err != nil {
		t.Fatalf("list quarantine: %v", err)
	}
	if len(quarantined) == 0 {
		t.Error("quarantine was cleaned up despite promote failure")
	}
}

func TestImportReviewPromoteOverwrite(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	// Quarantine import
	if err := os.Setenv("OPENPASS_PASSPHRASE", string(passphrase)); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}
	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "import", "csv", csvImportFixture(t), "--quarantine"})
	var importOutput string
	var importErr error
	importOutput = captureStdout(func() {
		importErr = cli.RootCmd.Execute()
	})
	cli.RootCmd.SetArgs(nil)
	if importErr != nil {
		t.Fatalf("quarantine import failed: %v", importErr)
	}

	// Extract the import-id
	var importID string
	for _, line := range strings.Split(importOutput, "\n") {
		if strings.HasPrefix(line, "Quarantine import ID: ") {
			importID = strings.TrimSpace(strings.TrimPrefix(line, "Quarantine import ID: "))
		}
	}
	if importID == "" {
		t.Fatalf("could not extract import-id from output: %s", importOutput)
	}

	// Create a conflicting destination entry with stale data
	svc := importTestVaultService(t, vaultDir, string(passphrase))
	if err := svc.SetFields("GitHub,-Personal", map[string]any{
		"username": "stale@example.com",
		"extra":    "stale-field",
	}); err != nil {
		t.Fatalf("create conflicting destination entry: %v", err)
	}

	// Re-set passphrase
	if err := os.Setenv("OPENPASS_PASSPHRASE", string(passphrase)); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}

	// Promote WITH --overwrite — should succeed
	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "import", "review", "promote", importID, "--overwrite"})
	var promoteErr error
	captureStdout(func() {
		promoteErr = cli.RootCmd.Execute()
	})
	cli.RootCmd.SetArgs(nil)
	if promoteErr != nil {
		t.Fatalf("import review promote --overwrite failed: %v", promoteErr)
	}

	// Destination entry should have been updated with imported data
	entry, err := svc.GetEntry("GitHub,-Personal")
	if err != nil {
		t.Fatalf("get overwritten entry: %v", err)
	}
	if entry.Data["username"] != "user@example.com" {
		t.Errorf("username was not overwritten, got %#v", entry.Data["username"])
	}

	// Quarantine should be empty
	quarantined, err := svc.List("quarantine/")
	if err != nil {
		t.Fatalf("list quarantine: %v", err)
	}
	if len(quarantined) != 0 {
		t.Errorf("quarantine not cleaned up after --overwrite promote: %v", quarantined)
	}
}

func TestImportReviewPromoteNotFound(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	if err := os.Setenv("OPENPASS_PASSPHRASE", string(passphrase)); err != nil {
		t.Fatalf("set passphrase env: %v", err)
	}

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "import", "review", "promote", "import-00000000-deadbeef"})
	defer cli.RootCmd.SetArgs(nil)

	var execErr error
	captureStdout(func() {
		execErr = cli.RootCmd.Execute()
	})
	if execErr == nil {
		t.Fatal("expected error for unknown import-id, got nil")
	}
	if !strings.Contains(execErr.Error(), "no quarantined entries found") {
		t.Errorf("unexpected error message: %v", execErr)
	}
}

func snapshotImportEntries(t *testing.T, svc vaultsvc.Service, paths []string) map[string]*vaultpkg.Entry {
	t.Helper()
	snapshot := make(map[string]*vaultpkg.Entry, len(paths))
	for _, path := range paths {
		entry, err := svc.GetEntry(path)
		if err != nil {
			t.Fatalf("get entry %q: %v", path, err)
		}
		snapshot[path] = entry
	}
	return snapshot
}
