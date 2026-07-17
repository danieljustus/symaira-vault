package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/exporter"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStderr := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = origStderr })
	fn()
	w.Close()
	os.Stderr = origStderr
	var buf strings.Builder
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Fatalf("copy stderr: %v", copyErr)
	}
	return buf.String()
}

func TestExport_ConfirmDecline_NoOutput(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "should-not-exist.csv")

	origConfirm := confirmExport
	confirmExport = func(_ string, _ bool) (bool, error) { return false, nil }
	t.Cleanup(func() { confirmExport = origConfirm })

	stderr := captureStderr(t, func() {
		cmd := cli.RootCmd
		cmd.SetArgs([]string{"export", "--format", "csv", "--output", outputPath})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("export: %v", err)
		}
	})

	if _, err := os.Stat(outputPath); err == nil {
		t.Error("output file should not exist after decline")
	}
	if !strings.Contains(stderr, "Export canceled.") {
		t.Errorf("stderr missing cancel message, got: %q", stderr)
	}
}

func TestExport_ConfirmAccept_WithEntries(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := "test-passphrase"
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, []byte(passphrase), config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	origVault := cli.Vault
	cli.Vault = vaultDir
	t.Cleanup(func() { cli.Vault = origVault })
	t.Setenv("SYMVAULT_PASSPHRASE", passphrase)

	v, err := cli.UnlockVault(vaultDir, true)
	if err != nil {
		t.Fatalf("unlock vault: %v", err)
	}
	vs := cli.NewVaultService(v, nil)
	if setErr := vs.SetFields("test/entry", map[string]any{"password": "secret123"}); setErr != nil {
		t.Fatalf("set entry: %v", setErr)
	}

	origConfirm := confirmExport
	confirmExport = func(_ string, _ bool) (bool, error) { return true, nil }
	t.Cleanup(func() { confirmExport = origConfirm })

	outputPath := filepath.Join(t.TempDir(), "export.csv")

	cmd := cli.RootCmd
	cmd.SetArgs([]string{"export", "--format", "csv", "--output", outputPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(data) == 0 {
		t.Error("export produced empty output")
	}
}

func TestExport_YesFlag_SkipsPrompt(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := "test-passphrase"
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, []byte(passphrase), config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	origVault := cli.Vault
	cli.Vault = vaultDir
	t.Cleanup(func() { cli.Vault = origVault })
	t.Setenv("SYMVAULT_PASSPHRASE", passphrase)

	v, err := cli.UnlockVault(vaultDir, true)
	if err != nil {
		t.Fatalf("unlock vault: %v", err)
	}
	vs := cli.NewVaultService(v, nil)
	if setErr := vs.SetFields("test/entry", map[string]any{"password": "secret123"}); setErr != nil {
		t.Fatalf("set entry: %v", setErr)
	}

	var capturedForce bool
	origConfirm := confirmExport
	confirmExport = func(_ string, force bool) (bool, error) {
		capturedForce = force
		return true, nil
	}
	t.Cleanup(func() { confirmExport = origConfirm })

	outputPath := filepath.Join(t.TempDir(), "export.json")

	cmd := cli.RootCmd
	cmd.SetArgs([]string{"export", "--format", "json", "--output", outputPath, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}

	if !capturedForce {
		t.Error("confirmExport should receive force=true when --yes is set")
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(data) == 0 {
		t.Error("export produced empty output")
	}
}

func setupTestVault(t *testing.T, searchWorkers int) *cli.VaultService {
	t.Helper()
	vaultDir := t.TempDir()
	passphrase := "test-passphrase"
	cfg := config.Default()
	if cfg.Vault == nil {
		cfg.Vault = &config.VaultConfig{}
	}
	cfg.Vault.SearchWorkers = searchWorkers
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, []byte(passphrase), cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	origVault := cli.Vault
	cli.Vault = vaultDir
	t.Cleanup(func() { cli.Vault = origVault })
	t.Setenv("SYMVAULT_PASSPHRASE", passphrase)

	v, err := cli.UnlockVault(vaultDir, true)
	if err != nil {
		t.Fatalf("unlock vault: %v", err)
	}
	return cli.NewVaultService(v, nil)
}

func seedVaultEntries(t *testing.T, vs *cli.VaultService) {
	t.Helper()
	entries := map[string]map[string]any{
		"aaa/first":  {"password": "pass1", "username": "user1"},
		"bbb/second": {"token": "tok2", "host": "host2"},
		"ccc/third":  {"password": "pass3", "extra": "data3", "note": "note3"},
	}
	for path, data := range entries {
		if err := vs.SetFields(path, data); err != nil {
			t.Fatalf("set entry %s: %v", path, err)
		}
	}
}

func runExport(t *testing.T, format, outputPath string) []byte {
	t.Helper()
	origConfirm := confirmExport
	confirmExport = func(_ string, _ bool) (bool, error) { return true, nil }
	t.Cleanup(func() { confirmExport = origConfirm })

	cmd := cli.RootCmd
	cmd.SetArgs([]string{"export", "--format", format, "--output", outputPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	return data
}

func buildExpectedJSON(t *testing.T, vs *cli.VaultService) []byte {
	t.Helper()
	listEntries, err := vs.ListEntries("")
	if err != nil {
		t.Fatalf("list entries: %v", err)
	}
	var exportEntries []exporter.ExportEntry
	for _, path := range listEntries {
		entry, readErr := vs.GetEntry(path)
		if readErr != nil {
			t.Fatalf("get entry %s: %v", path, readErr)
		}
		exportEntries = append(exportEntries, exporter.ExportEntry{
			Path: path,
			Data: entry.Data,
		})
	}
	var buf bytes.Buffer
	exp := &exporter.JSONExporter{}
	if err := exp.Export(&buf, exportEntries, nil); err != nil {
		t.Fatalf("batch export: %v", err)
	}
	return buf.Bytes()
}

func buildExpectedCSV(t *testing.T, vs *cli.VaultService) []byte {
	t.Helper()
	listEntries, err := vs.ListEntries("")
	if err != nil {
		t.Fatalf("list entries: %v", err)
	}
	var exportEntries []exporter.ExportEntry
	for _, path := range listEntries {
		entry, readErr := vs.GetEntry(path)
		if readErr != nil {
			t.Fatalf("get entry %s: %v", path, readErr)
		}
		exportEntries = append(exportEntries, exporter.ExportEntry{
			Path: path,
			Data: entry.Data,
		})
	}
	var buf bytes.Buffer
	exp := &exporter.CSVExporter{}
	if err := exp.Export(&buf, exportEntries, nil); err != nil {
		t.Fatalf("batch export: %v", err)
	}
	return buf.Bytes()
}

func TestExport_Parallel_JSON_ByteIdentical(t *testing.T) {
	vs := setupTestVault(t, 4)
	seedVaultEntries(t, vs)

	expected := buildExpectedJSON(t, vs)
	outputPath := filepath.Join(t.TempDir(), "export.json")
	actual := runExport(t, "json", outputPath)

	if !bytes.Equal(actual, expected) {
		t.Errorf("JSON output not byte-identical.\nexpected:\n%s\nactual:\n%s", expected, actual)
	}
}

func TestExport_Parallel_CSV_ByteIdentical(t *testing.T) {
	vs := setupTestVault(t, 4)
	seedVaultEntries(t, vs)

	expected := buildExpectedCSV(t, vs)
	outputPath := filepath.Join(t.TempDir(), "export.csv")
	actual := runExport(t, "csv", outputPath)

	if !bytes.Equal(actual, expected) {
		t.Errorf("CSV output not byte-identical.\nexpected:\n%s\nactual:\n%s", expected, actual)
	}
}

func TestExport_Parallel_JSON_OrderingPreserved(t *testing.T) {
	vs := setupTestVault(t, 2)
	seedVaultEntries(t, vs)

	outputPath := filepath.Join(t.TempDir(), "export.json")
	actual := runExport(t, "json", outputPath)

	var result []map[string]any
	if err := json.Unmarshal(actual, &result); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}

	listEntries, err := vs.ListEntries("")
	if err != nil {
		t.Fatalf("list entries: %v", err)
	}

	if len(result) != len(listEntries) {
		t.Fatalf("got %d entries, want %d", len(result), len(listEntries))
	}

	for i, want := range listEntries {
		if got := result[i]["path"].(string); got != want {
			t.Errorf("entry %d path = %q, want %q", i, got, want)
		}
	}
}

func TestExport_Parallel_SearchWorkersConfig(t *testing.T) {
	vs := setupTestVault(t, 8)
	seedVaultEntries(t, vs)

	outputPath := filepath.Join(t.TempDir(), "export.json")
	actual := runExport(t, "json", outputPath)

	if len(actual) == 0 {
		t.Error("export produced empty output")
	}

	var result []map[string]any
	if err := json.Unmarshal(actual, &result); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}
	if len(result) != 3 {
		t.Errorf("got %d entries, want 3", len(result))
	}
}
