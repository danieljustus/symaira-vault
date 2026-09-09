package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/testutil"
)

// TestManifestSequenceContract freezes the observable manifest sequencing
// oracle used by the Rust store port. Each case is intentionally named so a
// differential runner can execute and report the same contract rows.
func TestManifestSequenceContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("manifest sequence contract uses age crypto unavailable on windows")
	}

	run := func(t *testing.T, id string, test func(*testing.T)) {
		t.Run(id, func(t *testing.T) {
			t.Logf("CASE %s", id)
			test(t)
		})
	}

	run(t, "WRITE-MANIFEST-001", func(t *testing.T) {
		vaultDir, identity := newManifestSequenceVault(t)
		if err := WriteEntry(vaultDir, "alpha", &Entry{Data: map[string]any{"value": "one"}}, identity); err != nil {
			t.Fatalf("WriteEntry: %v", err)
		}
		manifest := mustLoadManifestSequence(t, vaultDir, identity)
		entry := manifest.Entries["alpha"]
		if manifest.Version != 1 || manifest.Generation != 1 {
			t.Fatalf("manifest version/generation = %d/%d, want 1/1", manifest.Version, manifest.Generation)
		}
		if manifest.Created.IsZero() || manifest.Updated.IsZero() || entry.MTime.IsZero() {
			t.Fatal("write did not populate UTC manifest and entry timestamps")
		}
		if manifest.Created.After(manifest.Updated) {
			t.Fatalf("manifest Created %s is after Updated %s", manifest.Created, manifest.Updated)
		}
		if entry.Size <= 0 || len(entry.SHA256) != 64 {
			t.Fatalf("manifest entry integrity metadata = size %d, sha %q", entry.Size, entry.SHA256)
		}
		written, err := ReadEntry(vaultDir, "alpha", identity)
		if err != nil {
			t.Fatalf("ReadEntry: %v", err)
		}
		if written.Metadata.Version != 1 || written.Metadata.Created.IsZero() || written.Metadata.Updated.IsZero() {
			t.Fatalf("entry metadata after first write = version %d created %s updated %s", written.Metadata.Version, written.Metadata.Created, written.Metadata.Updated)
		}
	})

	run(t, "WRITE-MANIFEST-002", func(t *testing.T) {
		vaultDir, identity := newManifestSequenceVault(t)
		if err := WriteEntry(vaultDir, "alpha", &Entry{Data: map[string]any{"value": "one"}}, identity); err != nil {
			t.Fatalf("first WriteEntry: %v", err)
		}
		firstManifest := mustLoadManifestSequence(t, vaultDir, identity)
		firstCiphertext := mustReadManifestEntryFile(t, vaultDir, identity, "alpha")

		if err := WriteEntry(vaultDir, "alpha", &Entry{Data: map[string]any{"value": "two"}}, identity); err != nil {
			t.Fatalf("second WriteEntry: %v", err)
		}
		secondManifest := mustLoadManifestSequence(t, vaultDir, identity)
		secondCiphertext := mustReadManifestEntryFile(t, vaultDir, identity, "alpha")
		secondEntry, err := ReadEntry(vaultDir, "alpha", identity)
		if err != nil {
			t.Fatalf("second ReadEntry: %v", err)
		}
		if secondManifest.Generation != firstManifest.Generation+1 {
			t.Fatalf("manifest generation = %d after rewrite, want %d", secondManifest.Generation, firstManifest.Generation+1)
		}
		if !secondManifest.Created.Equal(firstManifest.Created) {
			t.Fatalf("manifest Created changed from %s to %s", firstManifest.Created, secondManifest.Created)
		}
		if bytes.Equal(firstCiphertext, secondCiphertext) {
			t.Fatal("rewrite did not replace ciphertext")
		}
		if secondEntry.Data["value"] != "two" || secondEntry.Metadata.Version != 1 || secondEntry.Metadata.Created.IsZero() || secondEntry.Metadata.Updated.IsZero() {
			t.Fatalf("entry rewrite state = data %v version %d created %s updated %s", secondEntry.Data, secondEntry.Metadata.Version, secondEntry.Metadata.Created, secondEntry.Metadata.Updated)
		}
	})

	run(t, "DELETE-MANIFEST-001", func(t *testing.T) {
		vaultDir, identity := newManifestSequenceVault(t)
		if err := WriteEntry(vaultDir, "alpha", &Entry{Data: map[string]any{"value": "one"}}, identity); err != nil {
			t.Fatalf("WriteEntry: %v", err)
		}
		before := mustLoadManifestSequence(t, vaultDir, identity)
		entryPath := mustManifestEntryPath(t, vaultDir, identity, "alpha")
		if err := DeleteEntry(vaultDir, "alpha", identity); err != nil {
			t.Fatalf("DeleteEntry: %v", err)
		}
		after := mustLoadManifestSequence(t, vaultDir, identity)
		if after.Generation != before.Generation+1 || !after.Created.Equal(before.Created) {
			t.Fatalf("delete manifest metadata = generation %d Created %s, want generation %d and preserved Created", after.Generation, after.Created, before.Generation+1)
		}
		if _, ok := after.Entries["alpha"]; ok {
			t.Fatal("deleted entry remains in manifest")
		}
		if _, err := os.Stat(entryPath); !os.IsNotExist(err) {
			t.Fatalf("entry ciphertext stat error = %v, want not-exist", err)
		}
	})

	run(t, "MANIFEST-MISSING-001", func(t *testing.T) {
		vaultDir, identity := newManifestSequenceVault(t)
		if err := UpdateManifestEntry(vaultDir, "alpha", []byte("ciphertext"), identity); err != nil {
			t.Fatalf("UpdateManifestEntry on missing manifest: %v", err)
		}
		manifest := mustLoadManifestSequence(t, vaultDir, identity)
		if manifest.Version != 1 || manifest.Generation != 1 || len(manifest.Entries) != 1 {
			t.Fatalf("created manifest = version %d generation %d entries %d, want 1/1/1", manifest.Version, manifest.Generation, len(manifest.Entries))
		}
		if _, ok := manifest.Entries["alpha"]; !ok {
			t.Fatal("direct manifest update did not create alpha")
		}
	})

	run(t, "MANIFEST-MISSING-002", func(t *testing.T) {
		vaultDir, identity := newManifestSequenceVault(t)
		if err := RemoveManifestEntry(vaultDir, "alpha", identity); err != nil {
			t.Fatalf("RemoveManifestEntry on missing manifest: %v", err)
		}
		if _, err := os.Stat(filepath.Join(vaultDir, manifestFileName)); !os.IsNotExist(err) {
			t.Fatalf("manifest stat error after missing remove = %v, want not-exist", err)
		}
	})

	run(t, "MANIFEST-MALFORMED-001", func(t *testing.T) {
		vaultDir, identity := newManifestSequenceVault(t)
		malformed := []byte("malformed manifest bytes")
		manifestPath := filepath.Join(vaultDir, manifestFileName)
		mustWriteSequenceFile(t, manifestPath, malformed)
		if err := UpdateManifestEntry(vaultDir, "alpha", []byte("ciphertext"), identity); err == nil {
			t.Fatal("UpdateManifestEntry accepted malformed manifest")
		}
		if got := mustReadSequenceFile(t, manifestPath); !bytes.Equal(got, malformed) {
			t.Fatalf("direct malformed update changed manifest bytes")
		}
		if err := WriteEntry(vaultDir, "alpha", &Entry{Data: map[string]any{"value": "one"}}, identity); err != nil {
			t.Fatalf("high-level WriteEntry: %v", err)
		}
		if _, err := ReadEntry(vaultDir, "alpha", identity); err != nil {
			t.Fatalf("high-level write did not persist entry: %v", err)
		}
		if got := mustReadSequenceFile(t, manifestPath); !bytes.Equal(got, malformed) {
			t.Fatalf("high-level write changed malformed manifest bytes")
		}
	})

	run(t, "MANIFEST-MALFORMED-002", func(t *testing.T) {
		vaultDir, identity := newManifestSequenceVault(t)
		if err := WriteEntry(vaultDir, "alpha", &Entry{Data: map[string]any{"value": "one"}}, identity); err != nil {
			t.Fatalf("initial WriteEntry: %v", err)
		}
		manifestPath := filepath.Join(vaultDir, manifestFileName)
		malformed := []byte("malformed manifest bytes")
		mustWriteSequenceFile(t, manifestPath, malformed)
		if err := RemoveManifestEntry(vaultDir, "alpha", identity); err == nil {
			t.Fatal("RemoveManifestEntry accepted malformed manifest")
		}
		if got := mustReadSequenceFile(t, manifestPath); !bytes.Equal(got, malformed) {
			t.Fatalf("direct malformed remove changed manifest bytes")
		}
		if err := DeleteEntry(vaultDir, "alpha", identity); err != nil {
			t.Fatalf("high-level DeleteEntry: %v", err)
		}
		if _, err := ReadEntry(vaultDir, "alpha", identity); !errors.Is(err, os.ErrNotExist) && !os.IsNotExist(err) {
			t.Fatalf("high-level delete entry read error = %v, want not-exist", err)
		}
		if got := mustReadSequenceFile(t, manifestPath); !bytes.Equal(got, malformed) {
			t.Fatalf("high-level delete changed malformed manifest bytes")
		}
	})
}

func newManifestSequenceVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	// Kept below as a concrete helper wrapper so every case gets an isolated
	// root and an identity whose recipient is the only configured recipient.
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	if err := Init(vaultDir, identity, testConfig(vaultDir)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return vaultDir, identity
}

func mustLoadManifestSequence(t *testing.T, vaultDir string, identity *age.X25519Identity) *Manifest {
	t.Helper()
	manifest, err := LoadManifest(vaultDir, identity)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	return manifest
}

func mustManifestEntryPath(t *testing.T, vaultDir string, identity *age.X25519Identity, path string) string {
	t.Helper()
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return entryStoragePath(vaultDir, path, identity, cfg)
}

func mustReadManifestEntryFile(t *testing.T, vaultDir string, identity *age.X25519Identity, path string) []byte {
	t.Helper()
	return mustReadSequenceFile(t, mustManifestEntryPath(t, vaultDir, identity, path))
}

func mustWriteSequenceFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustReadSequenceFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
