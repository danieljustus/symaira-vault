package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/testutil"
)

func TestConcurrentWriteEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: concurrent cgo calls can trigger access violations in age crypto")
	}
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	var wg sync.WaitGroup
	wg.Add(2)

	writeWithLock := func(value string) {
		defer wg.Done()
		err := WriteEntry(vaultDir, "test/entry", &Entry{
			Data: map[string]any{"value": value},
		}, id)
		if err != nil {
			t.Errorf("concurrent write %s: %v", value, err)
		}
	}

	go writeWithLock("first")
	go writeWithLock("second")

	wg.Wait()

	// Verify the entry exists and data is not corrupted
	got, err := ReadEntry(vaultDir, "test/entry", id)
	if err != nil {
		t.Fatalf("read after concurrent writes: %v", err)
	}

	val, ok := got.Data["value"]
	if !ok {
		t.Fatal("entry missing 'value' field after concurrent writes")
	}

	// Both writers must have complete, one of their values survives
	if val != "first" && val != "second" {
		t.Errorf("unexpected value after concurrent writes: %q", val)
	}
}

func TestConcurrentMergeEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: concurrent cgo calls can trigger access violations in age crypto")
	}
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	entry := &Entry{
		Data: map[string]any{
			"base": "initial",
		},
	}
	if err := WriteEntry(vaultDir, "test/merge", entry, id); err != nil {
		t.Fatalf("write initial entry: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(3)

	// Concurrent merges adding different fields
	fields := []map[string]any{
		{"field_a": "value_a"},
		{"field_b": "value_b"},
		{"field_c": "value_c"},
	}

	for _, f := range fields {
		go func() {
			defer wg.Done()

			_, err := MergeEntry(vaultDir, "test/merge", f, id)
			if err != nil {
				t.Errorf("concurrent merge: %v", err)
			}
		}()
	}

	wg.Wait()

	// Verify all fields are present (no lost updates)
	got, err := ReadEntry(vaultDir, "test/merge", id)
	if err != nil {
		t.Fatalf("read after concurrent merges: %v", err)
	}

	if got.Data["base"] != "initial" {
		t.Errorf("base field lost: got %v", got.Data["base"])
	}
	if got.Data["field_a"] != "value_a" {
		t.Errorf("field_a missing: got %v", got.Data["field_a"])
	}
	if got.Data["field_b"] != "value_b" {
		t.Errorf("field_b missing: got %v", got.Data["field_b"])
	}
	if got.Data["field_c"] != "value_c" {
		t.Errorf("field_c missing: got %v", got.Data["field_c"])
	}
}

func TestAcquireWriteLockDefaultTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: LockFileEx can trigger access violations in CI")
	}
	if DefaultLockTimeout != 30*time.Second {
		t.Errorf("DefaultLockTimeout = %v, want 30s", DefaultLockTimeout)
	}
}

func TestLockFileIsCreated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: LockFileEx can trigger access violations in CI")
	}
	vaultDir := t.TempDir()

	lockFile, err := AcquireWriteLock(vaultDir, time.Second)
	if err != nil {
		t.Fatalf("acquire lock: %v", err)
	}

	// Verify lock file exists
	lockPath := filepath.Join(vaultDir, lockFileName)
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file not created at %s: %v", lockPath, err)
	}

	if err := ReleaseLock(lockFile); err != nil {
		t.Fatalf("release lock: %v", err)
	}
}

func TestAcquireWriteLockNonEmptyVaultDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: LockFileEx can trigger access violations in CI")
	}
	vaultDir := t.TempDir()

	lockFile, err := AcquireWriteLock(vaultDir, time.Second)
	if err != nil {
		t.Fatalf("acquire lock: %v", err)
	}
	if err := ReleaseLock(lockFile); err != nil {
		t.Fatalf("release lock: %v", err)
	}
}

func TestAcquireWriteLockCustomTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: LockFileEx can trigger access violations in CI")
	}
	vaultDir := t.TempDir()

	lockFile, err := AcquireWriteLock(vaultDir, 5*time.Second)
	if err != nil {
		t.Fatalf("acquire lock: %v", err)
	}
	if err := ReleaseLock(lockFile); err != nil {
		t.Fatalf("release lock: %v", err)
	}
}

func TestDeferredManifestUpdate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: LockFileEx access violation")
	}
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	if err := WriteEntry(vaultDir, "test/entry", &Entry{
		Data: map[string]any{"key": "value"},
	}, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	FlushManifestUpdates()

	m, err := LoadManifest(vaultDir, id)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if _, ok := m.Entries["test/entry"]; !ok {
		t.Fatal("manifest missing test/entry after flush")
	}

	if err := DeleteEntry(vaultDir, "test/entry", id); err != nil {
		t.Fatalf("delete entry: %v", err)
	}
	FlushManifestUpdates()

	m, err = LoadManifest(vaultDir, id)
	if err != nil {
		t.Fatalf("load manifest after delete: %v", err)
	}
	if _, ok := m.Entries["test/entry"]; ok {
		t.Fatal("manifest still has test/entry after delete and flush")
	}
}

func TestConcurrentWriteDifferentEntries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: concurrent cgo calls can trigger access violations in age crypto")
	}
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	const numEntries = 10
	var wg sync.WaitGroup
	wg.Add(numEntries)

	for i := 0; i < numEntries; i++ {
		name := fmt.Sprintf("entry-%d", i)
		go func() {
			defer wg.Done()
			err := WriteEntry(vaultDir, name, &Entry{
				Data: map[string]any{"idx": name},
			}, id)
			if err != nil {
				t.Errorf("write %s: %v", name, err)
			}
		}()
	}

	wg.Wait()

	for i := 0; i < numEntries; i++ {
		name := fmt.Sprintf("entry-%d", i)
		got, err := ReadEntry(vaultDir, name, id)
		if err != nil {
			t.Fatalf("read %s after concurrent writes: %v", name, err)
		}
		if got.Data["idx"] != name {
			t.Errorf("%s: got idx=%v, want %s", name, got.Data["idx"], name)
		}
	}

	FlushManifestUpdates()
	m, err := LoadManifest(vaultDir, id)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	for i := 0; i < numEntries; i++ {
		name := fmt.Sprintf("entry-%d", i)
		if _, ok := m.Entries[name]; !ok {
			t.Errorf("manifest missing %s after concurrent writes", name)
		}
	}
}

func TestRebuildManifest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: LockFileEx access violation")
	}
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	entries := []string{"alpha", "beta", "gamma"}
	for _, name := range entries {
		if err := WriteEntry(vaultDir, name, &Entry{
			Data: map[string]any{"name": name},
		}, id); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	FlushManifestUpdates()

	manifestPath := filepath.Join(vaultDir, manifestFileName)
	if err := os.Remove(manifestPath); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}

	if err := RebuildManifest(vaultDir, id); err != nil {
		t.Fatalf("rebuild manifest: %v", err)
	}

	m, err := LoadManifest(vaultDir, id)
	if err != nil {
		t.Fatalf("load rebuilt manifest: %v", err)
	}
	for _, name := range entries {
		if _, ok := m.Entries[name]; !ok {
			t.Errorf("rebuilt manifest missing %s", name)
		}
	}
	if len(m.Entries) != len(entries) {
		t.Errorf("rebuilt manifest has %d entries, want %d", len(m.Entries), len(entries))
	}
}
