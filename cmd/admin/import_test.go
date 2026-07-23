package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/importer"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestDetectFormatFromExt(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     importer.Format
		wantErr  bool
	}{
		{"csv", "export.csv", importer.FormatCSV, false},
		{"csv with path", "/path/to/file.csv", importer.FormatCSV, false},
		{"json", "backup.json", "json", false},
		{"json with path", "/home/user/export.json", "json", false},
		{"yaml", "config.yaml", "yaml", false},
		{"yml", "config.yml", "yaml", false},
		{"yaml with path", "/exports/data.yaml", "yaml", false},
		{"yml with path", "/exports/data.yml", "yaml", false},
		{"unknown extension", "data.txt", "", true},
		{"no extension", "data", "", true},
		{"uppercase CSV", "export.CSV", importer.FormatCSV, false},
		{"uppercase JSON", "export.JSON", "json", false},
		{"uppercase YAML", "export.YAML", "yaml", false},
		{"uppercase YML", "export.YML", "yaml", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := detectFormatFromExt(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("detectFormatFromExt(%q) error = %v, wantErr %v", tt.filename, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("detectFormatFromExt(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestDetectFormatFromExtErrorMessage(t *testing.T) {
	_, err := detectFormatFromExt("backup.txt")
	if err == nil {
		t.Fatal("expected error for unknown extension")
	}
	if !strings.Contains(err.Error(), "cannot detect format from file extension") {
		t.Errorf("error = %v, want message about unsupported extension", err)
	}
	if !strings.Contains(err.Error(), "--format") {
		t.Errorf("error = %v, want message suggesting --format flag", err)
	}
}

func TestIsSupportedImportFormat(t *testing.T) {
	tests := []struct {
		format importer.Format
		want   bool
	}{
		{importer.FormatCSV, true},
		{importer.Format1Password, true},
		{importer.FormatBitwarden, true},
		{importer.FormatPass, true},
		{"json", false},
		{"yaml", false},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			if got := isSupportedImportFormat(tt.format); got != tt.want {
				t.Errorf("isSupportedImportFormat(%q) = %v, want %v", tt.format, got, tt.want)
			}
		})
	}
}

func TestImportCommandAutoDetectCSV(t *testing.T) {
	tmpDir := t.TempDir()
	csvFile := filepath.Join(tmpDir, "export.csv")
	if err := os.WriteFile(csvFile, []byte("title,username,password\ngithub,user,pass123\n"), 0o600); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	vaultDir := t.TempDir()
	passphrase := "test-passphrase"
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, []byte(passphrase), config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	origVault := cli.Vault
	cli.Vault = vaultDir
	t.Cleanup(func() { cli.Vault = origVault })
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
	t.Setenv("SYMVAULT_PASSPHRASE", passphrase)

	// Reset global flags
	oldFormat := ImportFormat
	oldDryRun := ImportDryRun
	defer func() {
		ImportFormat = oldFormat
		ImportDryRun = oldDryRun
	}()
	ImportFormat = ""
	ImportDryRun = true

	cmd := cli.RootCmd
	cmd.SetArgs([]string{"import", csvFile})
	err := cmd.Execute()
	if err != nil {
		t.Errorf("import with auto-detect CSV failed: %v", err)
	}
}

func TestImportCommandExplicitFormatOverride(t *testing.T) {
	tmpDir := t.TempDir()
	csvFile := filepath.Join(tmpDir, "data.csv")
	if err := os.WriteFile(csvFile, []byte("title,username,password\ngithub,user,pass123\n"), 0o600); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	vaultDir := t.TempDir()
	passphrase := "test-passphrase"
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, []byte(passphrase), config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	origVault := cli.Vault
	cli.Vault = vaultDir
	t.Cleanup(func() { cli.Vault = origVault })
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
	t.Setenv("SYMVAULT_PASSPHRASE", passphrase)

	// Reset global flags
	oldFormat := ImportFormat
	oldDryRun := ImportDryRun
	defer func() {
		ImportFormat = oldFormat
		ImportDryRun = oldDryRun
	}()
	ImportFormat = ""
	ImportDryRun = true

	// Explicit --format should override auto-detection
	cmd := cli.RootCmd
	cmd.SetArgs([]string{"import", "--format", "csv", csvFile})
	err := cmd.Execute()
	if err != nil {
		t.Errorf("import with explicit --format failed: %v", err)
	}
}

func TestImportCommandUnknownExtensionNoFormat(t *testing.T) {
	tmpDir := t.TempDir()
	txtFile := filepath.Join(tmpDir, "export.txt")
	if err := os.WriteFile(txtFile, []byte("some content"), 0o600); err != nil {
		t.Fatalf("write txt: %v", err)
	}

	// Reset global flags
	oldFormat := ImportFormat
	oldDryRun := ImportDryRun
	defer func() {
		ImportFormat = oldFormat
		ImportDryRun = oldDryRun
	}()
	ImportFormat = ""
	ImportDryRun = true

	cmd := cli.RootCmd
	cmd.SetArgs([]string{"import", txtFile})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown extension without --format")
	}
}

func TestImportCommandUnsupportedFormat(t *testing.T) {
	tmpDir := t.TempDir()
	jsonFile := filepath.Join(tmpDir, "data.json")
	if err := os.WriteFile(jsonFile, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write json: %v", err)
	}

	// Reset global flags
	oldFormat := ImportFormat
	oldDryRun := ImportDryRun
	defer func() {
		ImportFormat = oldFormat
		ImportDryRun = oldDryRun
	}()
	ImportFormat = ""
	ImportDryRun = true

	// .json auto-detects to "json" which is not a supported import format
	cmd := cli.RootCmd
	cmd.SetArgs([]string{"import", jsonFile})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unsupported auto-detected format")
	}
	if !strings.Contains(err.Error(), "unsupported import format") {
		t.Errorf("error = %v, want unsupported format error", err)
	}
}
