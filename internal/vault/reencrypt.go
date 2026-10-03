package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/fsutil"
)

// reencryptCandidate is a validated, capability-backed entry discovered during
// the read-only preflight. platform contains an open parent directory on Unix
// and the equivalent checked path state on Windows.
type reencryptCandidate struct {
	path            string
	logical         string
	raw             []byte
	mode            os.FileMode
	mtime           time.Time
	platform        any
	journal         *reencryptJournal
	journalVaultDir string
	digest          string
}

type reencryptStaged struct {
	candidate *reencryptCandidate
	platform  any
	committed bool
}

// These seams are deliberately package-local. They make staging, committing,
// and manifest failures deterministic in tests without changing production
// defaults or the public API.
var (
	reencryptStage           = stageReencryptFile
	reencryptCommit          = commitReencryptFile
	reencryptRollback        = rollbackReencryptFile
	reencryptCleanup         = cleanupReencryptFile
	reencryptRebuildManifest = rebuildManifestStrict
)

// ReencryptAll rotates every regular .age entry transactionally. The vault
// write lock covers discovery, staging, commit, manifest replacement, and
// cleanup, so SafeWriteFile writers cannot overwrite a newer ciphertext.
// A durable journal makes a crash recoverable before the next vault operation.
//
//nolint:gocyclo // Transactional recovery intentionally keeps all failure phases together.
func ReencryptAll(vaultDir string, identity *age.X25519Identity, recipients []*age.X25519Recipient) (retErr error) {
	if identity == nil {
		return vaultcrypto.ErrNilIdentity
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients provided for re-encryption")
	}
	vaultDir, err := filepath.Abs(vaultDir)
	if err != nil {
		return fmt.Errorf("resolve vault directory: %w", err)
	}
	// Drain deferred manifest writes before taking the lock. The worker also
	// uses this lock, so no stale SafeWriteFile can overtake the transaction.
	FlushManifestUpdates()

	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := ReleaseLock(lockFile); releaseErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release vault write lock: %w", releaseErr))
		}
	}()

	if recoveryErr := recoverReencryptJournalLocked(vaultDir, identity); recoveryErr != nil {
		return fmt.Errorf("recover prior re-encryption: %w", recoveryErr)
	}

	batch := &vaultReadBatch{}
	candidates, err := collectReencryptCandidates(entriesDir(vaultDir), batch)
	if err != nil {
		return fmt.Errorf("preflight entries: %w", err)
	}
	if len(candidates) == 0 {
		return nil
	}
	defer closeReencryptCandidates(candidates)

	manifestBackup, err := snapshotReencryptManifest(vaultDir, batch)
	if err != nil {
		return fmt.Errorf("snapshot manifest: %w", err)
	}

	journal := newReencryptJournal(vaultDir, candidates)
	if err := journal.persist(vaultDir); err != nil {
		return fmt.Errorf("start re-encryption journal: %w", err)
	}
	journalActive := true

	staged := make([]*reencryptStaged, 0, len(candidates))
	cleanup := func() error {
		var firstErr error
		for _, item := range staged {
			if err := reencryptCleanup(item); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	fail := func(operationErr error) error {
		rollbackBatch := &vaultReadBatch{}
		var rollbackErr error
		for i := len(staged) - 1; i >= 0; i-- {
			if staged[i].committed {
				if err := reencryptRollback(staged[i], rollbackBatch); err != nil && rollbackErr == nil {
					rollbackErr = err
				}
			}
		}
		if err := restoreReencryptManifest(vaultDir, manifestBackup); err != nil && rollbackErr == nil {
			rollbackErr = err
		}
		if err := syncReencryptDirectory(vaultDir); err != nil && rollbackErr == nil {
			rollbackErr = err
		}
		cleanupErr := cleanup()
		if cleanupErr != nil && rollbackErr == nil {
			rollbackErr = cleanupErr
		}
		if rollbackErr == nil && journalActive {
			if err := journal.remove(vaultDir); err != nil {
				rollbackErr = err
			} else {
				journalActive = false
			}
		}
		if rollbackErr != nil {
			return fmt.Errorf("%w (rollback: %w)", operationErr, rollbackErr)
		}
		return operationErr
	}

	// Encrypt and stage every replacement before any target is changed.
	for _, candidate := range candidates {
		ciphertext, err := ReencryptBytes(candidate.raw, identity, recipients)
		if err != nil {
			return fail(fmt.Errorf("re-encrypt %s: %w", candidate.path, err))
		}
		item, err := reencryptStage(candidate, ciphertext)
		vaultcrypto.Wipe(ciphertext)
		if err != nil {
			return fail(fmt.Errorf("stage %s: %w", candidate.path, err))
		}
		staged = append(staged, item)
	}

	for _, item := range staged {
		if err := reencryptCommit(item); err != nil {
			return fail(fmt.Errorf("commit %s: %w", item.candidate.path, err))
		}
		item.committed = true
	}

	if err := reencryptRebuildManifest(vaultDir, identity, batch); err != nil {
		return fail(fmt.Errorf("rebuild manifest: %w", err))
	}

	if err := cleanup(); err != nil {
		return fmt.Errorf("cleanup re-encryption files: %w (journal retained for recovery)", err)
	}
	if journalActive {
		if err := journal.remove(vaultDir); err != nil {
			return fmt.Errorf("remove re-encryption journal: %w", err)
		}
		journalActive = false
	}
	return nil
}

// ReencryptBytes decrypts one age envelope and encrypts its plaintext for the
// supplied recipients. It never writes a vault file or updates a manifest.
func ReencryptBytes(raw []byte, identity *age.X25519Identity, recipients []*age.X25519Recipient) ([]byte, error) {
	release, err := vaultReadAdmission.acquire()
	if err != nil {
		return nil, err
	}
	defer release()
	if identity == nil {
		return nil, vaultcrypto.ErrNilIdentity
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients provided for re-encryption")
	}
	if len(raw) > maxEntryCiphertextBytesV1 {
		return nil, fmt.Errorf("%w: ciphertext", errEntryReadLimit)
	}

	plaintext, err := decryptEntryBounded(raw, identity, maxEntryPlaintextBytesV1)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	defer vaultcrypto.Wipe(plaintext)

	ciphertext, err := vaultcrypto.EncryptWithRecipients(plaintext, recipients...)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	return ciphertext, nil
}

func collectReencryptCandidates(entriesPath string, budgets ...*vaultReadBatch) ([]*reencryptCandidate, error) {
	var candidates []*reencryptCandidate
	batch := &vaultReadBatch{}
	if len(budgets) != 0 {
		batch = budgets[0]
	}
	pathBytes := 0
	err := walkVaultEntriesBounded(entriesPath, func(path string, d os.DirEntry) error {
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe symlink entry %q", path)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsafe special-file entry %q", path)
		}
		// The on-disk format is canonical: only lowercase .age is an entry.
		if filepath.Ext(info.Name()) != entryExtAge {
			return nil
		}
		if validationErr := addVaultPathBytes(&pathBytes, path); validationErr != nil {
			return validationErr
		}
		release, err := vaultReadAdmission.acquire()
		if err != nil {
			return err
		}
		candidate, err := prepareReencryptCandidate(entriesPath, path, info, batch)
		release()
		if err != nil {
			return err
		}
		candidates = append(candidates, candidate)
		return nil
	})
	if err != nil {
		closeReencryptCandidates(candidates)
		return nil, err
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].path < candidates[j].path })
	return candidates, nil
}

func rebuildManifestStrict(vaultDir string, identity *age.X25519Identity, budgets ...*vaultReadBatch) error {
	batch := &vaultReadBatch{}
	if len(budgets) != 0 {
		batch = budgets[0]
	}
	manifest := &Manifest{Version: 1, Created: time.Now().UTC(), Entries: make(map[string]ManifestEntry)}
	pathBytes := 0
	err := walkVaultEntriesBounded(entriesDir(vaultDir), func(path string, d os.DirEntry) error {
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("unsafe entry file")
		}
		if info.IsDir() || filepath.Ext(path) != entryExtAge {
			return nil
		}
		rel, err := filepath.Rel(entriesDir(vaultDir), path)
		if err != nil {
			return err
		}
		logical := filepath.ToSlash(rel[:len(rel)-len(entryExtAge)])
		if pathErr := addVaultPathBytes(&pathBytes, logical); pathErr != nil {
			return pathErr
		}
		digest, size, mtime, err := hashVaultEntry(vaultDir, path, batch)
		if err != nil {
			return err
		}
		manifest.Entries[logical] = ManifestEntry{SHA256: digest, Size: size, MTime: mtime}
		return nil
	})
	if err != nil {
		return err
	}
	return writeManifest(vaultDir, manifest, identity)
}

// snapshotReencryptManifest captures the exact pre-operation manifest so an
// injected or partial manifest write can be rolled back as well.
type reencryptManifestBackup struct {
	exists bool
	data   []byte
	mode   os.FileMode
}

func snapshotReencryptManifest(vaultDir string, budgets ...*vaultReadBatch) (reencryptManifestBackup, error) {
	release, err := vaultReadAdmission.acquire()
	if err != nil {
		return reencryptManifestBackup{}, err
	}
	defer release()
	var backup reencryptManifestBackup
	err = withRootedFile(vaultDir, manifestFileName, func(file *os.File, _ string) error {
		info, statErr := file.Stat()
		if statErr != nil {
			return statErr
		}
		if !info.Mode().IsRegular() {
			return ErrVaultResourceLimit
		}
		data, readErr := readEntryStreamLimited(file, file.Name(), maxEntryPlaintextBytesV1, budgets...)
		if readErr != nil {
			return readErr
		}
		backup = reencryptManifestBackup{exists: true, data: data, mode: info.Mode().Perm()}
		return nil
	})
	if os.IsNotExist(err) {
		return reencryptManifestBackup{}, nil
	}
	return backup, err
}

func restoreReencryptManifest(vaultDir string, backup reencryptManifestBackup) error {
	path := filepath.Join(vaultDir, manifestFileName)
	if !backup.exists {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
		return fsutil.SafeRemove(path)
	}
	return fsutil.SafeWriteFile(path, backup.data, backup.mode)
}
