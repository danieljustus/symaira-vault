package vault

import (
	"fmt"
	"testing"

	"filippo.io/age"
)

func BenchmarkList_100Entries(b *testing.B) {
	benchmarkList(b, 100)
}

func BenchmarkList_1kEntries(b *testing.B) {
	benchmarkList(b, 1000)
}

func BenchmarkList_10kEntries(b *testing.B) {
	benchmarkList(b, 10000)
}

func BenchmarkFind_100Entries_PathOnly(b *testing.B) {
	benchmarkFindPathOnly(b, 100)
}

func BenchmarkFind_1kEntries_PathOnly(b *testing.B) {
	benchmarkFindPathOnly(b, 1000)
}

func BenchmarkFind_10kEntries_PathOnly(b *testing.B) {
	benchmarkFindPathOnly(b, 10000)
}

func BenchmarkFind_100Entries_FieldSearch(b *testing.B) {
	benchmarkFindFieldSearch(b, 100)
}

func BenchmarkFind_1kEntries_FieldSearch(b *testing.B) {
	benchmarkFindFieldSearch(b, 1000)
}

func BenchmarkFind_10kEntries_FieldSearch(b *testing.B) {
	benchmarkFindFieldSearch(b, 10000)
}

func BenchmarkFind_50kEntries_PathOnly(b *testing.B) {
	benchmarkFindPathOnly(b, 50000)
}

func BenchmarkFind_50kEntries_FieldSearch(b *testing.B) {
	benchmarkFindFieldSearch(b, 50000)
}

// BenchmarkFindWithOptions_* benchmarks with varying worker counts and vault sizes
func BenchmarkFindWithOptions_100_Entries_1_Worker(b *testing.B) {
	benchmarkFindWithOptions(b, 100, 1)
}

func BenchmarkFindWithOptions_100_Entries_2_Workers(b *testing.B) {
	benchmarkFindWithOptions(b, 100, 2)
}

func BenchmarkFindWithOptions_100_Entries_4_Workers(b *testing.B) {
	benchmarkFindWithOptions(b, 100, 4)
}

func BenchmarkFindWithOptions_100_Entries_8_Workers(b *testing.B) {
	benchmarkFindWithOptions(b, 100, 8)
}

func BenchmarkFindWithOptions_1k_Entries_1_Worker(b *testing.B) {
	benchmarkFindWithOptions(b, 1000, 1)
}

func BenchmarkFindWithOptions_1k_Entries_2_Workers(b *testing.B) {
	benchmarkFindWithOptions(b, 1000, 2)
}

func BenchmarkFindWithOptions_1k_Entries_4_Workers(b *testing.B) {
	benchmarkFindWithOptions(b, 1000, 4)
}

func BenchmarkFindWithOptions_1k_Entries_8_Workers(b *testing.B) {
	benchmarkFindWithOptions(b, 1000, 8)
}

func BenchmarkFindWithOptions_10k_Entries_1_Worker(b *testing.B) {
	benchmarkFindWithOptions(b, 10000, 1)
}

func BenchmarkFindWithOptions_10k_Entries_2_Workers(b *testing.B) {
	benchmarkFindWithOptions(b, 10000, 2)
}

func BenchmarkFindWithOptions_10k_Entries_4_Workers(b *testing.B) {
	benchmarkFindWithOptions(b, 10000, 4)
}

func BenchmarkFindWithOptions_10k_Entries_8_Workers(b *testing.B) {
	benchmarkFindWithOptions(b, 10000, 8)
}

// BenchmarkFindWithOptions_10k_Entries_DefaultWorkers uses default worker count (0=sequential)
func BenchmarkFindWithOptions_10k_Entries_DefaultWorkers(b *testing.B) {
	benchmarkFindWithOptions(b, 10000, 0)
}

func benchmarkList(b *testing.B, numEntries int) {
	vaultDir := b.TempDir()
	identity := generateTestIdentity(b)
	createTestEntries(b, vaultDir, identity, numEntries)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		paths, err := List(vaultDir, "")
		if err != nil {
			b.Fatalf("List failed: %v", err)
		}
		if len(paths) != numEntries {
			b.Fatalf("expected %d entries, got %d", numEntries, len(paths))
		}
	}
}

func benchmarkFindPathOnly(b *testing.B, numEntries int) {
	vaultDir := b.TempDir()
	identity := generateTestIdentity(b)
	createTestEntries(b, vaultDir, identity, numEntries)
	rememberSearchIdentity(identity)

	// Find a path number that exists in all vault sizes (use 50 for 100-entry vaults)
	pathQuery := fmt.Sprintf("entry-%05d", min(50, numEntries-1))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Query that matches path - uses fast path (no decryption)
		matches, err := FindWithOptions(vaultDir, pathQuery, FindOptions{MaxWorkers: 0})
		if err != nil {
			b.Fatalf("Find failed: %v", err)
		}
		if len(matches) != 1 {
			b.Fatalf("expected 1 match, got %d", len(matches))
		}
	}
}

func benchmarkFindFieldSearch(b *testing.B, numEntries int) {
	vaultDir := b.TempDir()
	identity := generateTestIdentity(b)
	createTestEntries(b, vaultDir, identity, numEntries)
	rememberSearchIdentity(identity)

	fieldQuery := fmt.Sprintf("secret-password-%05d", min(50, numEntries-1))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		matches, err := FindWithOptions(vaultDir, fieldQuery, FindOptions{MaxWorkers: 0})
		if err != nil {
			b.Fatalf("Find failed: %v", err)
		}
		if len(matches) != 1 {
			b.Fatalf("expected 1 match, got %d", len(matches))
		}
	}
}

func benchmarkFindWithOptions(b *testing.B, numEntries int, maxWorkers int) {
	vaultDir := b.TempDir()
	identity := generateTestIdentity(b)
	createTestEntries(b, vaultDir, identity, numEntries)
	rememberSearchIdentity(identity)

	fieldQuery := fmt.Sprintf("secret-password-%05d", min(50, numEntries-1))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		matches, err := FindWithOptions(vaultDir, fieldQuery, FindOptions{MaxWorkers: maxWorkers})
		if err != nil {
			b.Fatalf("FindWithOptions failed: %v", err)
		}
		if len(matches) != 1 {
			b.Fatalf("expected 1 match, got %d", len(matches))
		}
	}
}

// BenchmarkEncryptedIndexBuild_100Entries measures index build time for 100 entries.
func BenchmarkEncryptedIndexBuild_100Entries(b *testing.B) {
	benchmarkIndexBuild(b, 100)
}

// BenchmarkEncryptedIndexBuild_1kEntries measures index build time for 1k entries.
func BenchmarkEncryptedIndexBuild_1kEntries(b *testing.B) {
	benchmarkIndexBuild(b, 1000)
}

// BenchmarkFind_1kEntries_FieldSearch_IndexHot measures field search with a
// pre-built index on a 1k entry vault.
func BenchmarkFind_1kEntries_FieldSearch_IndexHot(b *testing.B) {
	benchmarkFindFieldSearchIndexHot(b, 1000)
}

// BenchmarkFind_10kEntries_FieldSearch_IndexHot measures field search with a
// pre-built index on a 10k entry vault.
func BenchmarkFind_10kEntries_FieldSearch_IndexHot(b *testing.B) {
	benchmarkFindFieldSearchIndexHot(b, 10000)
}

// benchmarkIndexBuild builds the encrypted search index for the given number
// of entries and reports the time taken.
func benchmarkIndexBuild(b *testing.B, numEntries int) {
	vaultDir := b.TempDir()
	identity := generateTestIdentity(b)
	createTestEntries(b, vaultDir, identity, numEntries)
	rememberSearchIdentity(identity)
	b.Cleanup(func() { searchIdentity.Store(nil) })

	// Pre-warm list cache by listing once
	_, err := List(vaultDir, "")
	if err != nil {
		b.Fatalf("List failed: %v", err)
	}

	idx := &EncryptedIndex{}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if err := idx.Build(vaultDir, identity); err != nil {
			b.Fatalf("Build failed: %v", err)
		}
	}
}

// benchmarkFindFieldSearchIndexHot measures the time for FindWithOptions on a
// vault with a pre-built hot index. The first search builds the index; we
// measure only subsequent searches where the index is already hot.
func benchmarkFindFieldSearchIndexHot(b *testing.B, numEntries int) {
	vaultDir := b.TempDir()
	identity := generateTestIdentity(b)
	createTestEntries(b, vaultDir, identity, numEntries)
	rememberSearchIdentity(identity)
	b.Cleanup(func() { searchIdentity.Store(nil) })

	fieldQuery := fmt.Sprintf("secret-password-%05d", min(50, numEntries-1))

	// First search warms the index (build + search)
	_, err := FindWithOptions(vaultDir, fieldQuery, FindOptions{MaxWorkers: 0})
	if err != nil {
		b.Fatalf("Warmup FindWithOptions failed: %v", err)
	}

	globalIndex.Invalidate()

	// Rebuild index explicitly (so we measure hot-index search, not build)
	if err := globalIndex.Build(vaultDir, identity); err != nil {
		b.Fatalf("Build failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		matches, err := FindWithOptions(vaultDir, fieldQuery, FindOptions{MaxWorkers: 0})
		if err != nil {
			b.Fatalf("FindWithOptions failed: %v", err)
		}
		if len(matches) != 1 {
			b.Fatalf("expected 1 match, got %d", len(matches))
		}
	}
}

func createTestEntries(b *testing.B, vaultDir string, identity *age.X25519Identity, count int) {
	b.Helper()
	for i := 0; i < count; i++ {
		path := fmt.Sprintf("service-%d/entry-%05d", i/100, i)
		data := map[string]interface{}{
			"username": fmt.Sprintf("user-%05d", i),
			"password": fmt.Sprintf("secret-password-%05d", i),
			"url":      fmt.Sprintf("https://service-%d.example.com", i),
		}
		if err := WriteEntry(vaultDir, path, &Entry{Data: data}, identity); err != nil {
			b.Fatalf("WriteEntry(%s) failed: %v", path, err)
		}
	}
}

func generateTestIdentity(b *testing.B) *age.X25519Identity {
	b.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		b.Fatalf("GenerateX25519Identity failed: %v", err)
	}
	return identity
}
