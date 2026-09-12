package admin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigratePathsPreviewIsNonMutating(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	legacy := filepath.Join(home, ".symvault")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "config.yaml"), []byte("vault: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newMigratePathsCmd()
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("preview command failed: %v", err)
	}
	for _, path := range []string{
		filepath.Join(home, "config"),
		filepath.Join(home, "data"),
		filepath.Join(home, "cache"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("preview created %s", path)
		}
	}
}
