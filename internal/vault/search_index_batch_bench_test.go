package vault

import (
	"fmt"
	"path/filepath"
	"testing"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
)

// BenchmarkEncryptedIndexUpdateEntry_1kEntries measures the cost of a single
// incremental UpdateEntry on a 1k-entry vault: each call decrypts, re-marshals,
// re-encrypts, and re-persists the whole index document.
func BenchmarkEncryptedIndexUpdateEntry_1kEntries(b *testing.B) {
	benchmarkIndexUpdateEntry(b, 1000, false)
}

// BenchmarkEncryptedIndexUpdateEntryCached_1kEntries measures the same write
// with the opt-in decrypted index cache enabled.
func BenchmarkEncryptedIndexUpdateEntryCached_1kEntries(b *testing.B) {
	benchmarkIndexUpdateEntry(b, 1000, true)
}

// BenchmarkEncryptedIndexUpdateEntry_2kEntries measures the per-write cost on
// a 2k-entry vault, showing the O(N) growth that makes bulk imports O(N²).
func BenchmarkEncryptedIndexUpdateEntry_2kEntries(b *testing.B) {
	benchmarkIndexUpdateEntry(b, 2000, false)
}

// BenchmarkEncryptedIndexBatchUpdate_1kEntries_100Writes measures a batch of
// 100 writes on a 1k-entry vault with Suspend/Resume: one full index build
// total instead of 100 per-write re-encryptions. Reports builds/op == 1.
func BenchmarkEncryptedIndexBatchUpdate_1kEntries_100Writes(b *testing.B) {
	benchmarkIndexBatchUpdate(b, 1000, 100)
}

// BenchmarkEncryptedIndexBatchUpdate_2kEntries_100Writes is the 2k-entry
// variant of the batch benchmark.
func BenchmarkEncryptedIndexBatchUpdate_2kEntries_100Writes(b *testing.B) {
	benchmarkIndexBatchUpdate(b, 2000, 100)
}

// BenchmarkEncryptedIndexRemoveEntry_2kEntries measures an incremental
// RemoveEntry, whose token cleanup now uses the reverse path→tokens map
// instead of scanning every token in the index.
func BenchmarkEncryptedIndexRemoveEntry_2kEntries(b *testing.B) {
	benchmarkIndexRemoveEntry(b, 2000)
}

func benchmarkIndexUpdateEntry(b *testing.B, numEntries int, cacheEnabled bool) {
	vaultDir := b.TempDir()
	identity := generateTestIdentity(b)
	createTestEntries(b, vaultDir, identity, numEntries)
	if cacheEnabled {
		cfg := vaultconfig.Default()
		cfg.VaultDir = vaultDir
		cfg.Vault = &vaultconfig.VaultConfig{SearchIndexCache: true}
		if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
			b.Fatalf("save cache config: %v", err)
		}
	}

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		b.Fatalf("Build failed: %v", err)
	}

	target := fmt.Sprintf("service-%d/entry-%05d", 0, 0)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if err := idx.UpdateEntry(vaultDir, target, identity); err != nil {
			b.Fatalf("UpdateEntry failed: %v", err)
		}
	}
}

func benchmarkIndexBatchUpdate(b *testing.B, numEntries, numWrites int) {
	vaultDir := b.TempDir()
	identity := generateTestIdentity(b)
	createTestEntries(b, vaultDir, identity, numEntries)

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		b.Fatalf("Build failed: %v", err)
	}

	paths := make([]string, 0, numWrites)
	for i := 0; i < numWrites; i++ {
		paths = append(paths, fmt.Sprintf("service-%d/entry-%05d", i/100, i))
	}

	buildsBefore := indexBuildCounter.Load()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		idx.Suspend()
		for _, p := range paths {
			if err := idx.UpdateEntry(vaultDir, p, identity); err != nil {
				b.Fatalf("UpdateEntry failed: %v", err)
			}
		}
		if err := idx.Resume(vaultDir, identity); err != nil {
			b.Fatalf("Resume failed: %v", err)
		}
	}

	b.StopTimer()
	buildsPerOp := float64(indexBuildCounter.Load()-buildsBefore) / float64(b.N)
	b.ReportMetric(buildsPerOp, "builds/op")
	if buildsPerOp != 1 {
		b.Fatalf("batch of %d writes triggered %f index builds per batch, want exactly 1", numWrites, buildsPerOp)
	}
}

func benchmarkIndexRemoveEntry(b *testing.B, numEntries int) {
	vaultDir := b.TempDir()
	identity := generateTestIdentity(b)
	createTestEntries(b, vaultDir, identity, numEntries)

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		b.Fatalf("Build failed: %v", err)
	}

	target := fmt.Sprintf("service-%d/entry-%05d", 0, 0)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		idx.RemoveEntry(target, identity)
		// Re-add so the next iteration measures a real removal again.
		if err := idx.UpdateEntry(vaultDir, target, identity); err != nil {
			b.Fatalf("UpdateEntry failed: %v", err)
		}
	}
}
