package cli

import (
	"os"
	"path/filepath"
	"testing"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
)

func TestExpandVaultDir_TildeOnly(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot get home dir: %v", err)
	}

	got, err := ExpandVaultDir("~")
	if err != nil {
		t.Fatalf("ExpandVaultDir(\"~\") error = %v", err)
	}
	if got != home {
		t.Errorf("ExpandVaultDir(\"~\") = %q, want %q", got, home)
	}
}

func TestExpandVaultDir_TildeSlash(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot get home dir: %v", err)
	}

	got, err := ExpandVaultDir("~/my-vault")
	if err != nil {
		t.Fatalf("ExpandVaultDir(\"~/my-vault\") error = %v", err)
	}
	want := filepath.Join(home, "my-vault")
	if got != want {
		t.Errorf("ExpandVaultDir(\"~/my-vault\") = %q, want %q", got, want)
	}
}

func TestExpandVaultDir_AbsolutePath(t *testing.T) {
	got, err := ExpandVaultDir("/tmp/test-vault")
	if err != nil {
		t.Fatalf("ExpandVaultDir(\"/tmp/test-vault\") error = %v", err)
	}
	if got != "/tmp/test-vault" {
		t.Errorf("ExpandVaultDir(\"/tmp/test-vault\") = %q, want /tmp/test-vault", got)
	}
}

func TestExpandVaultDir_RelativePath(t *testing.T) {
	got, err := ExpandVaultDir("relative/path")
	if err != nil {
		t.Fatalf("ExpandVaultDir(\"relative/path\") error = %v", err)
	}
	// Should be cleaned to relative path
	if got != "relative/path" {
		t.Errorf("ExpandVaultDir(\"relative/path\") = %q, want relative/path", got)
	}
}

func TestExpandVaultDir_EmptyString(t *testing.T) {
	got, err := ExpandVaultDir("")
	if err != nil {
		t.Fatalf("ExpandVaultDir(\"\") error = %v", err)
	}
	if got != "." {
		t.Errorf("ExpandVaultDir(\"\") = %q, want .", got)
	}
}

func TestIsDefaultVaultFlagValue_Empty(t *testing.T) {
	if !isDefaultVaultFlagValue("") {
		t.Error("isDefaultVaultFlagValue(\"\") = false, want true")
	}
}

func TestIsDefaultVaultFlagValue_Default(t *testing.T) {
	if !isDefaultVaultFlagValue("~/" + configpkg.DefaultVaultSubdir) {
		t.Errorf("isDefaultVaultFlagValue(%q) = false, want true", "~/"+configpkg.DefaultVaultSubdir)
	}
}

func TestIsDefaultVaultFlagValue_NonDefault(t *testing.T) {
	if isDefaultVaultFlagValue("/custom/path") {
		t.Error("isDefaultVaultFlagValue(\"/custom/path\") = true, want false")
	}
}

func TestIsDefaultVaultFlagValue_WhitespaceOnly(t *testing.T) {
	if !isDefaultVaultFlagValue("   ") {
		t.Error("isDefaultVaultFlagValue(\"   \") = false, want true (whitespace trims to empty)")
	}
}

func TestVaultExists_ConfigYaml(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("vaultDir: ."), 0600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	if !vaultExists(dir) {
		t.Error("vaultExists() = false for dir with config.yaml, want true")
	}
}

func TestVaultExists_IdentityAge(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "identity.age"), []byte("key"), 0600); err != nil {
		t.Fatalf("write identity.age: %v", err)
	}

	if !vaultExists(dir) {
		t.Error("vaultExists() = false for dir with identity.age, want true")
	}
}

func TestVaultExists_NoFiles(t *testing.T) {
	dir := t.TempDir()

	if vaultExists(dir) {
		t.Error("vaultExists() = true for empty dir, want false")
	}
}

func TestVaultExists_DirectoryNotFile(t *testing.T) {
	dir := t.TempDir()
	// Create a directory named config.yaml (not a file)
	if err := os.MkdirAll(filepath.Join(dir, "config.yaml"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if vaultExists(dir) {
		t.Error("vaultExists() = true when config.yaml is a directory, want false")
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("content"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if !fileExists(path) {
		t.Errorf("fileExists(%q) = false, want true", path)
	}
}

func TestFileExists_NonExistent(t *testing.T) {
	if fileExists("/nonexistent/path/file.txt") {
		t.Error("fileExists() = true for non-existent file, want false")
	}
}

func TestFileExists_Directory(t *testing.T) {
	dir := t.TempDir()

	if fileExists(dir) {
		t.Error("fileExists() = true for directory, want false")
	}
}

func TestGetVaultDir_FallbackToDataDir(t *testing.T) {
	// When VaultPath() fails (no config, no vault dir), GetVaultDir should
	// fall back to the data dir from the config resolver.
	dir := GetVaultDir()
	if dir == "" {
		t.Error("GetVaultDir() returned empty string")
	}
}
