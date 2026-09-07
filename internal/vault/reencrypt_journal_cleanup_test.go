package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupUnjournaledReencryptArtifactsPreservesUserEntries(t *testing.T) {
	vaultDir := t.TempDir()
	if err := os.MkdirAll(entriesDir(vaultDir), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(entriesDir(vaultDir), "foo.reencrypt-note.age")
	want := []byte("legitimate user ciphertext")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cleanupUnjournaledReencryptArtifacts(vaultDir, &reencryptJournal{}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("legitimate entry was removed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("legitimate entry changed: got %q want %q", got, want)
	}
}
