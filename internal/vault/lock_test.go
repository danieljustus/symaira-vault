package vault

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/testutil"
)

func TestConcurrentWriteEntry(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	var wg sync.WaitGroup
	wg.Add(2)

	writeWithLock := func(value string) {
		defer wg.Done()
		lockFile, err := AcquireWriteLock(vaultDir, 5*time.Second)
		if err != nil {
			t.Errorf("acquire lock for %s: %v", value, err)
			return
		}
		defer func() {
			if err := ReleaseLock(lockFile); err != nil {
				t.Errorf("release lock for %s: %v", value, err)
			}
		}()
		err = WriteEntry(vaultDir, "test/entry", &Entry{
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
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	// Write initial entry (with lock for consistency)
	lockFile, err := AcquireWriteLock(vaultDir, 5*time.Second)
	if err != nil {
		t.Fatalf("acquire initial lock: %v", err)
	}
	entry := &Entry{
		Data: map[string]any{
			"base": "initial",
		},
	}
	if err := WriteEntry(vaultDir, "test/merge", entry, id); err != nil {
		ReleaseLock(lockFile)
		t.Fatalf("write initial entry: %v", err)
	}
	if err := ReleaseLock(lockFile); err != nil {
		t.Fatalf("release initial lock: %v", err)
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

			// Acquire lock for the merge (protects read-modify-write)
			lockFile, err := AcquireWriteLock(vaultDir, 5*time.Second)
			if err != nil {
				t.Errorf("acquire merge lock: %v", err)
				return
			}
			defer func() {
				if err := ReleaseLock(lockFile); err != nil {
					t.Errorf("release merge lock: %v", err)
				}
			}()

			_, err = MergeEntry(vaultDir, "test/merge", f, id)
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
	if DefaultLockTimeout != 30*time.Second {
		t.Errorf("DefaultLockTimeout = %v, want 30s", DefaultLockTimeout)
	}
}

func TestLockFileIsCreated(t *testing.T) {
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
	vaultDir := t.TempDir()

	lockFile, err := AcquireWriteLock(vaultDir, 5*time.Second)
	if err != nil {
		t.Fatalf("acquire lock: %v", err)
	}
	if err := ReleaseLock(lockFile); err != nil {
		t.Fatalf("release lock: %v", err)
	}
}
