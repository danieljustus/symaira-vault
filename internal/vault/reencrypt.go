package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/fsutil"
)

// reencryptCandidate is a validated, capability-backed entry discovered during
// the read-only preflight. platform contains an open parent directory on Unix
// and the equivalent checked path state on Windows.
type reencryptCandidate struct {
	path     string
	logical  string
	raw      []byte
	mode     os.FileMode
	mtime    time.Time
	platform any
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

// ReencryptAll rotates every regular .age entry transactionally. All entries
// are securely read, decrypted, and staged before the first target is changed.
// Any commit or manifest failure restores every changed entry and the manifest
// byte-for-byte, then removes all temporary files and backups.
func ReencryptAll(vaultDir string, identity *age.X25519Identity, recipients []*age.X25519Recipient) error {
	if identity == nil {
		return vaultcrypto.ErrNilIdentity
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients provided for re-encryption")
	}

	candidates, err := collectReencryptCandidates(entriesDir(vaultDir))
	if err != nil {
		return fmt.Errorf("preflight entries: %w", err)
	}
	if len(candidates) == 0 {
		return nil
	}
	defer closeReencryptCandidates(candidates)

	manifestBackup, err := snapshotReencryptManifest(vaultDir)
	if err != nil {
		return fmt.Errorf("snapshot manifest: %w", err)
	}

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
		var rollbackErr error
		for i := len(staged) - 1; i >= 0; i-- {
			if staged[i].committed {
				if err := reencryptRollback(staged[i]); err != nil && rollbackErr == nil {
					rollbackErr = err
				}
			}
		}
		if err := restoreReencryptManifest(vaultDir, manifestBackup); err != nil && rollbackErr == nil {
			rollbackErr = err
		}
		if err := cleanup(); err != nil && rollbackErr == nil {
			rollbackErr = err
		}
		if rollbackErr != nil {
			return fmt.Errorf("%w (rollback: %w)", operationErr, rollbackErr)
		}
		return operationErr
	}

	// Encrypt and stage every replacement before any rename occurs.
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

	if err := reencryptRebuildManifest(vaultDir, identity); err != nil {
		return fail(fmt.Errorf("rebuild manifest: %w", err))
	}

	if err := cleanup(); err != nil {
		return fmt.Errorf("cleanup re-encryption files: %w", err)
	}
	return nil
}

// ReencryptBytes decrypts one age envelope and encrypts its plaintext for the
// supplied recipients. It never writes a vault file or updates a manifest.
func ReencryptBytes(raw []byte, identity *age.X25519Identity, recipients []*age.X25519Recipient) ([]byte, error) {
	if identity == nil {
		return nil, vaultcrypto.ErrNilIdentity
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients provided for re-encryption")
	}

	plaintext, err := vaultcrypto.Decrypt(raw, identity)
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

func collectReencryptCandidates(entriesPath string) ([]*reencryptCandidate, error) {
	var candidates []*reencryptCandidate
	err := filepath.Walk(entriesPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
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
		if !strings.EqualFold(filepath.Ext(info.Name()), entryExtAge) {
			return nil
		}
		candidate, err := prepareReencryptCandidate(entriesPath, path, info)
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
	return candidates, nil
}

func rebuildManifestStrict(vaultDir string, identity *age.X25519Identity) error {
	candidates, err := collectReencryptCandidates(entriesDir(vaultDir))
	if err != nil {
		return fmt.Errorf("collect entries: %w", err)
	}
	defer closeReencryptCandidates(candidates)

	manifest := &Manifest{
		Version: 1,
		Created: time.Now().UTC(),
		Entries: make(map[string]ManifestEntry, len(candidates)),
	}
	for _, candidate := range candidates {
		hash := sha256.Sum256(candidate.raw)
		manifest.Entries[candidate.logical] = ManifestEntry{
			SHA256: hex.EncodeToString(hash[:]),
			Size:   int64(len(candidate.raw)),
			MTime:  candidate.mtime,
		}
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

func snapshotReencryptManifest(vaultDir string) (reencryptManifestBackup, error) {
	path := filepath.Join(vaultDir, manifestFileName)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return reencryptManifestBackup{}, nil
	}
	if err != nil {
		return reencryptManifestBackup{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return reencryptManifestBackup{}, fmt.Errorf("manifest is not a regular file")
	}
	f, err := os.Open(path) // #nosec G304 -- path is vaultDir plus fixed manifest name
	if err != nil {
		return reencryptManifestBackup{}, err
	}
	openedInfo, statErr := f.Stat()
	if statErr != nil {
		_ = f.Close()
		return reencryptManifestBackup{}, statErr
	}
	if !os.SameFile(info, openedInfo) {
		_ = f.Close()
		return reencryptManifestBackup{}, fmt.Errorf("manifest changed during snapshot")
	}
	data, readErr := io.ReadAll(f)
	closeErr := f.Close()
	if readErr != nil {
		return reencryptManifestBackup{}, readErr
	}
	if closeErr != nil {
		return reencryptManifestBackup{}, closeErr
	}
	return reencryptManifestBackup{exists: true, data: data, mode: info.Mode().Perm()}, nil
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
