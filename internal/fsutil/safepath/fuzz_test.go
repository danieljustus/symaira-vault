package safepath

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzSafeWriteFile(f *testing.F) {
	f.Add("testfile", []byte("hello"))
	f.Add("subdir/testfile", []byte("world"))
	f.Add("testfile", []byte(""))

	f.Fuzz(func(t *testing.T, name string, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, name)

		parent := filepath.Dir(path)
		if parent != dir {
			if err := os.MkdirAll(parent, 0o700); err != nil {
				t.Skip()
			}
		}

		err := DefaultManager.WriteFile(path, data, 0o600)
		if err != nil {
			if os.IsNotExist(err) {
				t.Skip()
			}
			return
		}

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read after write: %v", err)
		}
		if string(content) != string(data) {
			t.Fatalf("content mismatch: got %q, want %q", content, data)
		}
	})
}

func FuzzSafeRemove(f *testing.F) {
	f.Add("testfile")
	f.Add("subdir/testfile")

	f.Fuzz(func(t *testing.T, name string) {
		dir := t.TempDir()
		path := filepath.Join(dir, name)

		parent := filepath.Dir(path)
		if parent != dir {
			if err := os.MkdirAll(parent, 0o700); err != nil {
				t.Skip()
			}
		}

		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Skip()
		}

		err := DefaultManager.Remove(path)
		if err != nil {
			if os.IsNotExist(err) {
				return
			}
			t.Fatalf("remove: %v", err)
		}

		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("file still exists after remove")
		}
	})
}
