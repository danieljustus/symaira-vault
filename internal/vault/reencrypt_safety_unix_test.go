//go:build !windows

package vault

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/testutil"
)

func TestReencryptAll_SpecialFileRejected(t *testing.T) {
	vaultDir, identity := initTestVault(t)
	fifo := filepath.Join(entriesDir(vaultDir), "special.age")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("FIFO unavailable: %v", err)
	}
	defer os.Remove(fifo)
	if err := ReencryptAll(vaultDir, identity, []*age.X25519Recipient{testutil.TempIdentity(t).Recipient()}); err == nil {
		t.Fatal("ReencryptAll accepted special-file entry")
	}
}

func TestReencryptAll_AncestorReplacementDetected(t *testing.T) {
	vaultDir, identity := initTestVault(t)
	if err := WriteEntry(vaultDir, "nested/one", &Entry{Data: map[string]any{"value": "one"}}, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	FlushManifestUpdates()
	restoreReencryptHooks(t)
	original := reencryptCommit
	reencryptCommit = func(item *reencryptStaged) error {
		parent := filepath.Dir(item.candidate.path)
		moved := parent + ".raced-original"
		if err := os.Rename(parent, moved); err != nil {
			return err
		}
		if err := os.Symlink(t.TempDir(), parent); err != nil {
			return err
		}
		return original(item)
	}
	if err := ReencryptAll(vaultDir, identity, []*age.X25519Recipient{testutil.TempIdentity(t).Recipient()}); err == nil {
		t.Fatal("ReencryptAll accepted ancestor replacement race")
	}
}
