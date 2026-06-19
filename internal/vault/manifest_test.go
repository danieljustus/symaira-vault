package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

func testConfig(vaultDir string) *config.Config {
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	return cfg
}

func TestDetectOutOfBandEntries_EmptyManifest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: manifest uses cgo age crypto")
	}
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	if _, err := InitWithPassphrase(vaultDir, []byte("test-passphrase"), testConfig(vaultDir)); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(vaultDir, manifestFileName)); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}

	_, err := DetectOutOfBandEntries(vaultDir, id, testConfig(vaultDir))
	if err == nil {
		t.Fatal("expected os.IsNotExist when manifest is missing, got nil")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected os.IsNotExist, got: %v", err)
	}
}

func TestDetectOutOfBandEntries_NoneOutOfBand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: manifest uses cgo age crypto")
	}
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	if _, err := InitWithPassphrase(vaultDir, []byte("test-passphrase"), testConfig(vaultDir)); err != nil {
		t.Fatalf("init: %v", err)
	}

	if err := WriteEntry(vaultDir, "alpha", &Entry{Data: map[string]any{"v": "a"}}, id); err != nil {
		t.Fatalf("write alpha: %v", err)
	}
	FlushManifestUpdates()

	unknown, err := DetectOutOfBandEntries(vaultDir, id, testConfig(vaultDir))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(unknown) != 0 {
		t.Errorf("expected no out-of-band entries, got %v", unknown)
	}
}

// TestDetectOutOfBandEntries_OutOfBandViaSync simulates the live #515 failure:
// entries are added to disk (e.g. by a git pull or rsync) without going through
// the normal write path, so the manifest is left behind. The detector must
// report those files so callers can trigger a rebuild.
func TestDetectOutOfBandEntries_OutOfBandViaSync(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: manifest uses cgo age crypto")
	}
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	if _, err := InitWithPassphrase(vaultDir, []byte("test-passphrase"), testConfig(vaultDir)); err != nil {
		t.Fatalf("init: %v", err)
	}

	if err := WriteEntry(vaultDir, "alpha", &Entry{Data: map[string]any{"v": "a"}}, id); err != nil {
		t.Fatalf("write alpha: %v", err)
	}
	FlushManifestUpdates()

	// Add three more entries, but the manifest lags behind — this is exactly
	// what happens when a git pull drops new .age files into a working tree
	// whose manifest is older than the new entries.
	for _, name := range []string{"beta", "gamma", "delta"} {
		if err := WriteEntry(vaultDir, name, &Entry{Data: map[string]any{"v": name}}, id); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	FlushManifestUpdates()

	// Sanity: every entry was added through the write path, so the manifest
	// knows about all four entries. To reproduce the out-of-band scenario, we
	// need a manifest that's behind the disk. Easiest: write a file directly
	// without going through WriteEntry.
	extra := filepath.Join(vaultDir, entriesDirName, "extra.age")
	if err := os.WriteFile(extra, []byte("sneaked-in"), 0o600); err != nil {
		t.Fatalf("write extra: %v", err)
	}

	unknown, err := DetectOutOfBandEntries(vaultDir, id, testConfig(vaultDir))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	sort.Strings(unknown)
	want := []string{"extra.age"}
	if len(unknown) != len(want) {
		t.Fatalf("expected %d out-of-band entries, got %d: %v", len(want), len(unknown), unknown)
	}
	if unknown[0] != want[0] {
		t.Errorf("unknown[0] = %q, want %q", unknown[0], want[0])
	}
}

// TestOpen_RebuildsOnOutOfBandEntries verifies that Vault.Open detects
// out-of-band .age files (the #515 bug) and rebuilds the manifest, so
// subsequent list/search calls see them.
func TestOpen_RebuildsOnOutOfBandEntries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: manifest uses cgo age crypto")
	}
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	if _, err := InitWithPassphrase(vaultDir, []byte("test-passphrase"), testConfig(vaultDir)); err != nil {
		t.Fatalf("init: %v", err)
	}

	if err := WriteEntry(vaultDir, "tracked", &Entry{Data: map[string]any{"v": "t"}}, id); err != nil {
		t.Fatalf("write tracked: %v", err)
	}
	FlushManifestUpdates()

	// Add an out-of-band entry directly to the entries dir.
	if err := os.MkdirAll(filepath.Join(vaultDir, entriesDirName), 0o700); err != nil {
		t.Fatalf("mkdir entries: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, entriesDirName, "out-of-band.age"), []byte("sneaked-in"), 0o600); err != nil {
		t.Fatalf("write out-of-band: %v", err)
	}

	mBefore, err := LoadManifest(vaultDir, id)
	if err != nil {
		t.Fatalf("load before: %v", err)
	}
	if _, ok := mBefore.Entries["out-of-band"]; ok {
		t.Fatal("test setup: manifest should not yet know about out-of-band file")
	}

	// Open should detect the out-of-band file and rebuild the manifest.
	if _, err := Open(vaultDir, id); err != nil {
		t.Fatalf("open: %v", err)
	}

	mAfter, err := LoadManifest(vaultDir, id)
	if err != nil {
		t.Fatalf("load after: %v", err)
	}
	if _, ok := mAfter.Entries["out-of-band"]; !ok {
		t.Errorf("manifest was not rebuilt: out-of-band entry still missing (entries: %v)", keysOf(mAfter.Entries))
	}
}

func keysOf(m map[string]ManifestEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
