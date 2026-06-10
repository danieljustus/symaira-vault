package secureedit

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestEditEntrySecurelyDeletesTempFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell editor fixture is Unix-only")
	}

	origCreateTemp := CreateTemp
	var tmpPath string
	CreateTemp = func(dir, pattern string) (*os.File, error) {
		f, err := origCreateTemp(dir, pattern)
		if err == nil {
			tmpPath = f.Name()
		}
		return f, err
	}
	t.Cleanup(func() { CreateTemp = origCreateTemp })

	editor := filepath.Join(t.TempDir(), "editor")
	script := `#!/bin/sh
cat > "$1" <<'EOF'
{"data":{"password":"edited"}}
EOF
`
	if err := os.WriteFile(editor, []byte(script), 0o755); err != nil {
		t.Fatalf("write editor: %v", err)
	}

	edited, err := EditEntry(&vaultpkg.Entry{Data: map[string]any{"password": "original"}}, editor, Streams{})
	if err != nil {
		t.Fatalf("EditEntry() error = %v", err)
	}
	if edited.Data["password"] != "edited" {
		t.Fatalf("password = %v, want edited", edited.Data["password"])
	}
	if tmpPath == "" {
		t.Fatal("temp path was not captured")
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("temp file still exists after edit: %v", err)
	}
}
