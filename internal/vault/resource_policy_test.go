package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

func TestResourcePolicyAdmissionBoundsActualEntryReads(t *testing.T) {
	identity := testutil.TempIdentity(t)
	ciphertext, err := vaultcrypto.Encrypt([]byte(`{"data":{"fixture":"value"}}`), identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("vault:\n  search_index_cache: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteEntry(root, "control", &Entry{Data: map[string]any{"fixture": "capacity-control-token"}}, identity); err != nil {
		t.Fatal(err)
	}
	index := searchIndexForVault(root)
	if err := index.Build(root, identity); err != nil {
		t.Fatal(err)
	}
	if !index.docValid {
		t.Fatal("cached-index reproduction is not using the cached document")
	}
	blocked := make(chan struct{})
	gate := blocked
	done := make(chan error, maxActiveVaultReads+maxPendingVaultReads)
	defer func() {
		if blocked != nil {
			close(blocked)
		}
	}()
	startRead := func() {
		go func() {
			entry, err := readEntryFileWith(identity, func() ([]byte, error) {
				<-gate
				return ciphertext, nil
			})
			if err == nil && entry.Data["fixture"] != "value" {
				err = errors.New("decryption control changed")
			}
			done <- err
		}()
	}
	waitFor := func(active, pending int) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			vaultReadAdmission.mu.Lock()
			a, p := vaultReadAdmission.active, vaultReadAdmission.pending
			vaultReadAdmission.mu.Unlock()
			if a == active && p == pending {
				return
			}
			if !time.Now().Before(deadline) {
				t.Fatalf("admission state %d/%d, want %d/%d", a, p, active, pending)
			}
			runtime.Gosched()
		}
	}
	for i := 0; i < maxActiveVaultReads; i++ {
		startRead()
	}
	waitFor(maxActiveVaultReads, 0)
	for i := 0; i < maxPendingVaultReads; i++ {
		startRead()
	}
	waitFor(maxActiveVaultReads, maxPendingVaultReads)
	called := false
	_, err = readEntryFileWith(identity, func() ([]byte, error) { called = true; return ciphertext, nil })
	if !errors.Is(err, ErrVaultResourceBusy) || called {
		t.Fatalf("excess read reached file allocation: %v, called=%v", err, called)
	}
	if _, err := GetEntryMetadata(root, "control", identity); !errors.Is(err, ErrVaultResourceBusy) {
		t.Fatalf("metadata bypassed admission: %v", err)
	}
	if err := index.UpdateEntry(root, "control", identity); !errors.Is(err, ErrVaultResourceBusy) {
		t.Fatalf("busy incremental index update: %v", err)
	}
	if index.IsBuilt() {
		t.Fatal("busy update published an incomplete searchable index")
	}
	if _, err := os.Stat(indexFilePath(root)); !os.IsNotExist(err) {
		t.Fatalf("stale index survived invalidation: %v", err)
	}
	close(blocked)
	blocked = nil
	for i := 0; i < maxActiveVaultReads+maxPendingVaultReads; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("read lease leaked")
		}
	}
	waitFor(0, 0)
	found, err := FindWithOptions(root, "capacity-control-token", FindOptions{}, identity)
	if err != nil || len(found) != 1 || found[0].Path != "control" {
		t.Fatalf("search lost the value after capacity recovery: %v %v", found, err)
	}
}

func TestResourcePolicyBatchStopsBeforeDecryptAndCacheStaysBounded(t *testing.T) {
	identity := testutil.TempIdentity(t)
	ciphertext, err := vaultcrypto.Encrypt([]byte(`{"data":{"fixture":"value"}}`), identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	batch := &vaultReadBatch{ciphertextBytes: maxVaultBatchCiphertextBytes - len(ciphertext)}
	called := 0
	read := func(b *vaultReadBatch) ([]byte, error) {
		called++
		if budgetErr := b.consume(len(ciphertext)); budgetErr != nil {
			return nil, budgetErr
		}
		return ciphertext, nil
	}
	if _, err := readEntryFileWithBudget(identity, read, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := readEntryFileWithBudget(identity, read, batch); !errors.Is(err, ErrVaultResourceLimit) {
		t.Fatalf("over-budget read: %v", err)
	}
	if _, err := readEntryFileWithBudget(identity, read, batch); !errors.Is(err, ErrVaultResourceLimit) || called != 2 {
		t.Fatalf("exhausted batch reached reader: %v, calls=%d", err, called)
	}
	cache := NewVaultCache(VaultCacheConfig{})
	for i := 0; i < defaultListCacheVaults*2; i++ {
		root := t.TempDir()
		data := map[string]any{"title": strings.Repeat("public-fixture", 20_000)}
		cache.storePseudonymizedListCache(root, identity, []string{"fixture"}, map[string]map[string]any{"fixture": data})
	}
	total := 0
	for _, entry := range cache.pseudonymItems {
		total += entry.retainedBytes
	}
	if total > maxPseudonymCacheBytes || len(cache.pseudonymItems) > defaultListCacheVaults {
		t.Fatal("listing cache retained an unbounded batch")
	}
	if total == 0 {
		t.Fatal("ordinary cache entries were all discarded")
	}
}

func TestResourcePolicyCountsUnknownRawKeysAndManifestAliases(t *testing.T) {
	for _, count := range []int{maxEntryEnvelopeKeys, maxEntryEnvelopeKeys + 1} {
		raw := []byte("{" + strings.TrimSuffix(strings.Repeat(`"future":null,`, count), ",") + "}")
		err := validateEntryEnvelope(raw)
		if count == maxEntryEnvelopeKeys && err != nil {
			t.Fatal(err)
		}
		if count > maxEntryEnvelopeKeys && !errors.Is(err, ErrVaultResourceLimit) {
			t.Fatalf("raw key guard: %v", err)
		}
	}
	if err := validateManifestEntryCount([]byte(`{"entries":{"a":{}},"Entries":{"b":{}}}`)); err == nil {
		t.Fatal("manifest entries aliases were merged past preflight")
	}
	if err := validateManifestEntryCount([]byte(`{"Entries":{"a":{}}}`)); err != nil {
		t.Fatal(err)
	}
}

func TestResourcePolicyCoversWholeEnvelopeMetadata(t *testing.T) {
	for _, count := range []int{maxEntryArrayItems, maxEntryArrayItems + 1} {
		tags := make([]string, count)
		for i := range tags {
			tags[i] = "public-fixture"
		}
		raw, err := json.Marshal(map[string]any{"data": map[string]any{}, "meta": map[string]any{"tags": tags}})
		if err != nil {
			t.Fatal(err)
		}
		entry, err := decodeEntryBounded(raw)
		if count == maxEntryArrayItems {
			if err != nil || len(entry.Metadata.Tags) != count {
				t.Fatalf("valid metadata rejected: %v", err)
			}
		} else if err == nil {
			t.Fatal("metadata array bypassed the shared entry shape budget")
		}
	}
}

func TestResourcePolicySharedWriterCannotPublishUnreadableEntry(t *testing.T) {
	root := t.TempDir()
	identity := testutil.TempIdentity(t)
	entry := &Entry{Data: map[string]any{"public_fixture": strings.Repeat("x", maxEntryValueBytes+1)}}
	err := WriteEntryWithRecipients(root, "over-limit", entry, identity)
	if err == nil {
		t.Fatal("shared-recipient writer published an entry rejected by the normal reader")
	}
	if _, err := os.Stat(filepath.Join(root, "entries", "over-limit.age")); !os.IsNotExist(err) {
		t.Fatal("rejected write mutated the vault")
	}
	valid := &Entry{Data: map[string]any{"public_fixture": "ordinary value"}}
	if err := WriteEntryWithRecipients(root, "control", valid, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEntry(root, "control", identity); err != nil {
		t.Fatal(err)
	}
}

func TestResourcePolicyFailedIndexPreservesFileAndFindFallsBack(t *testing.T) {
	root := t.TempDir()
	identity := testutil.TempIdentity(t)
	if err := WriteEntry(root, "control", &Entry{Data: map[string]any{"public_fixture": "ordinary-control"}}, identity); err != nil {
		t.Fatal(err)
	}
	index := &EncryptedIndex{}
	if err := index.Build(root, identity); err != nil {
		t.Fatal(err)
	}
	previous, err := os.ReadFile(filepath.Join(root, ".search-index"))
	if err != nil {
		t.Fatal(err)
	}
	var words strings.Builder
	for i := 0; i < 50_000; i++ {
		fmt.Fprintf(&words, "public_token_%05d ", i)
	}
	entry := &Entry{Data: map[string]any{"public_fixture": words.String()}}
	if words.Len() > maxEntryValueBytes {
		t.Fatal("test entry exceeds ordinary reader's string limit")
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := vaultcrypto.Encrypt(raw, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "entries", "large.age"), ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RebuildManifest(root, identity); err != nil {
		t.Fatal(err)
	}
	if err := index.Build(root, identity); !errors.Is(err, ErrVaultResourceLimit) {
		t.Fatalf("oversized index admitted: %v", err)
	}
	retained, err := os.ReadFile(filepath.Join(root, ".search-index"))
	if err != nil || !bytes.Equal(previous, retained) {
		t.Fatalf("failed index build replaced prior file: %v", err)
	}
	matches, err := FindWithOptions(root, "public_token_49999", FindOptions{MaxWorkers: 4}, identity)
	if err != nil || len(matches) != 1 || matches[0].Path != "large" {
		t.Fatalf("ordinary fallback lost valid entry: %v, matches=%v", err, matches)
	}
}

func TestResourcePolicyReservationsRejectBeforeActualEntryDecryptAndStayFailed(t *testing.T) {
	root := t.TempDir()
	identity := testutil.TempIdentity(t)
	if err := WriteEntry(root, "control", &Entry{Data: map[string]any{"public_fixture": "ordinary-control"}}, identity); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "entries", "control.age")
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	batch := &vaultReadBatch{ciphertextBytes: maxVaultBatchCiphertextBytes - int(info.Size())}
	if _, err := readEntryInner(root, "control", identity, nil, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := readEntryInner(root, "control", identity, nil, batch); !errors.Is(err, ErrVaultResourceLimit) {
		t.Fatalf("ciphertext reservation: %v", err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := readEntryInner(root, "control", identity, nil, batch); !errors.Is(err, ErrVaultResourceLimit) {
		t.Fatalf("failed scope performed file lookup: %v", err)
	}
	expanded := &vaultReadBatch{decodedBytes: maxVaultBatchCiphertextBytes - 256}
	if _, err := decodeEntryBounded([]byte("null"), expanded); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEntryBounded([]byte("null"), expanded); !errors.Is(err, ErrVaultResourceLimit) {
		t.Fatalf("decoded reservation: %v", err)
	}
	if err := expanded.consume(0); !errors.Is(err, ErrVaultResourceLimit) {
		t.Fatal("decoded exhaustion admitted more I/O")
	}
}

func TestResourcePolicyLegacyBackupCodeStringsStayBounded(t *testing.T) {
	for _, count := range []int{maxEntryArrayItems, maxEntryArrayItems + 1} {
		raw, err := json.Marshal(map[string]any{"data": map[string]any{"backup_codes": strings.Repeat("public-code\n", count)}})
		if err != nil {
			t.Fatal(err)
		}
		entry, err := decodeEntryBounded(raw)
		if count > maxEntryArrayItems {
			if !errors.Is(err, ErrVaultResourceLimit) {
				t.Fatalf("legacy normalization bypassed array limit: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			MigrateBackupCodes(entry)
			if len(BackupCodes(entry)) != count {
				t.Fatal("ordinary normalization changed")
			}
		}
	}
	raw := []byte(`{"data":{"backup_codes":"` + strings.Repeat(`\n`, 50_000) + `"}}`)
	entry, err := decodeEntryBounded(raw)
	if err != nil {
		t.Fatal(err)
	}
	MigrateBackupCodes(entry)
	if len(BackupCodes(entry)) != 0 {
		t.Fatal("blank lines became recovery codes")
	}
}

func TestResourcePolicyIntegrityStreamsAboveGenericRootLimit(t *testing.T) {
	root := t.TempDir()
	identity := testutil.TempIdentity(t)
	if err := WriteEntry(root, "control", &Entry{Data: map[string]any{"public_fixture": "value"}}, identity); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(root, "entries", "large.age"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(17 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RebuildManifest(root, identity); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(root, identity)
	if err != nil || manifest.Entries["large"].Size != 17*1024*1024 {
		t.Fatalf("streaming manifest used generic root cap: %v", err)
	}
	result, err := VerifyManifestIntegrity(root, identity)
	if err != nil || len(result.Tampered) != 0 || len(result.Missing) != 0 {
		t.Fatalf("integrity verification rejected admissible ciphertext: %v", err)
	}
}

func TestResourcePolicyRecoveryRejectsOversizeBeforeMutation(t *testing.T) {
	root := t.TempDir()
	identity := testutil.TempIdentity(t)
	if err := WriteEntry(root, "control", &Entry{Data: map[string]any{"fixture": "ordinary-control"}}, identity); err != nil {
		t.Fatal(err)
	}
	entryPath := filepath.Join(root, "entries", "control.age")
	before, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	oversized := func(path string, size int64) {
		t.Helper()
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := file.Truncate(size); err != nil {
			t.Fatal(err)
		}
	}
	journalPath := reencryptJournalPath(root)
	oversized(journalPath, maxEntryPlaintextBytesV1+1)
	if err := recoverReencryptJournal(root, identity); !errors.Is(err, ErrVaultResourceLimit) {
		t.Fatalf("oversized journal: %v", err)
	}
	if err := os.Remove(journalPath); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, manifestFileName)
	oversized(manifestPath, maxEntryPlaintextBytesV1+1)
	if err := ReencryptAll(root, identity, []*age.X25519Recipient{identity.Recipient()}); !errors.Is(err, ErrVaultResourceLimit) {
		t.Fatalf("oversized manifest snapshot: %v", err)
	}
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Fatal("manifest failure started a transaction")
	}
	after, err := os.ReadFile(entryPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("resource rejection changed entry ciphertext")
	}
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "entries", "large.age")
	backup := filepath.Join(root, "entries", ".large.age.backup")
	oversized(target, maxEntryCiphertextBytesV1+1)
	if err := os.WriteFile(backup, before, 0o600); err != nil {
		t.Fatal(err)
	}
	journal := &reencryptJournal{Version: 1, Entries: []reencryptJournalEntry{{Path: target, Backup: backup, Digest: strings.Repeat("0", 64)}}}
	if err := journal.persist(root); err != nil {
		t.Fatal(err)
	}
	if err := recoverReencryptJournal(root, identity); !errors.Is(err, ErrVaultResourceLimit) {
		t.Fatalf("oversized journal target: %v", err)
	}
	if got, err := os.ReadFile(backup); err != nil || !bytes.Equal(got, before) {
		t.Fatal("failed recovery dropped original backup")
	}
	if _, err := os.Stat(journalPath); err != nil {
		t.Fatal("failed recovery dropped its journal")
	}
}
