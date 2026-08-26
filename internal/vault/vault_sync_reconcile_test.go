package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

// TestOpenFilesystemSyncReconcilesConflicts verifies that opening a
// filesystem-synced vault (e.g. iCloud Drive) deterministically resolves two
// .age files for the same logical entry by EntryMetadata.Version and preserves
// the losing copy as a conflict copy rather than deleting or clobbering data.
func TestOpenFilesystemSyncReconcilesConflicts(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	cfg := config.Default()
	cfg.Vault = &config.VaultConfig{
		Sync: &config.SyncConfig{Method: config.SyncMethodICloudDrive},
	}

	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Device A writes login/example at version 1.
	if err := WriteEntry(vaultDir, "login/example", &Entry{
		Path:     "login/example",
		Data:     map[string]any{"username": "a@example.com"},
		Metadata: EntryMetadata{Version: 1},
	}, identity); err != nil {
		t.Fatalf("WriteEntry v1: %v", err)
	}

	// Simulate Device B's older copy of the same entry arriving via the sync
	// engine as a conflict-named file (it must be preserved, not deleted).
	canonical := entryFilePath(vaultDir, "login/example")
	conflict := canonical + ".conflict-20200101T000000.age"
	data, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatalf("read canonical v1: %v", err)
	}
	if err := os.WriteFile(conflict, data, 0o600); err != nil {
		t.Fatalf("write conflict copy: %v", err)
	}

	// Device A then writes the newer version 2, overwriting the canonical file.
	if err := WriteEntry(vaultDir, "login/example", &Entry{
		Path:     "login/example",
		Data:     map[string]any{"username": "b@example.com"},
		Metadata: EntryMetadata{Version: 2},
	}, identity); err != nil {
		t.Fatalf("WriteEntry v2: %v", err)
	}

	// Reopen: reconciliation must keep version 2 as canonical and preserve the
	// version-1 conflict copy losslessly.
	v, err := Open(vaultDir, identity)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if v.SyncReport == nil || v.SyncReport.Method != config.SyncMethodICloudDrive {
		t.Fatalf("expected SyncReport with iCloud method, got %+v", v.SyncReport)
	}

	got, err := GetEntryMetadata(vaultDir, "login/example", identity)
	if err != nil {
		t.Fatalf("GetEntryMetadata: %v", err)
	}

	matches, err := filepath.Glob(canonical + ".conflict-*.age")
	if err != nil {
		t.Fatalf("glob conflict copies: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected a preserved conflict copy of the losing version, found none")
	}
	lost, err := readConflictVersion(matches[0], identity)
	if err != nil {
		t.Fatalf("read conflict copy: %v", err)
	}
	// The canonical entry must be strictly newer than the preserved loser, and
	// the loser must be preserved (never deleted) — lossless deterministic LWW.
	if got.Version <= lost {
		t.Fatalf("canonical version %d must be greater than preserved conflict version %d", got.Version, lost)
	}
}

// readConflictVersion decrypts a specific .age file (e.g. a conflict copy) and
// returns its EntryMetadata.Version. It does not resolve by logical path, so
// it reads the conflict file's own content rather than the canonical entry.
func readConflictVersion(path string, identity *age.X25519Identity) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	plaintext, err := crypto.Decrypt(raw, identity)
	if err != nil {
		return 0, err
	}
	var entry Entry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		return 0, err
	}
	return entry.Metadata.Version, nil
}
