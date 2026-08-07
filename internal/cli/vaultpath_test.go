package cli

import (
	"os"
	"path/filepath"
	"runtime"
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
	if runtime.GOOS == "windows" {
		t.Skip("Test uses Unix-style absolute paths")
	}
	got, err := ExpandVaultDir("/tmp/test-vault")
	if err != nil {
		t.Fatalf("ExpandVaultDir(\"/tmp/test-vault\") error = %v", err)
	}
	if got != "/tmp/test-vault" {
		t.Errorf("ExpandVaultDir(\"/tmp/test-vault\") = %q, want /tmp/test-vault", got)
	}
}

func TestExpandVaultDir_RelativePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Test uses Unix-style path separators")
	}
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

func TestGetVaultDir_FallbackToDataDir(t *testing.T) {
	// When VaultPath() fails (no config, no vault dir), GetVaultDir should
	// fall back to the data dir from the config resolver.
	dir := GetVaultDir()
	if dir == "" {
		t.Error("GetVaultDir() returned empty string")
	}
}
