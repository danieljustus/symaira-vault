package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/fsutil"
)

const reencryptJournalFileName = ".reencrypt.journal"

type reencryptJournal struct {
	Version int                     `json:"version"`
	Entries []reencryptJournalEntry `json:"entries"`
}

type reencryptJournalEntry struct {
	Path      string `json:"path"`
	Temp      string `json:"temp,omitempty"`
	Backup    string `json:"backup,omitempty"`
	Digest    string `json:"digest"`
	Installed bool   `json:"installed"`
}

func reencryptJournalPath(vaultDir string) string {
	return filepath.Join(vaultDir, reencryptJournalFileName)
}

func newReencryptJournal(vaultDir string, candidates []*reencryptCandidate) *reencryptJournal {
	journal := &reencryptJournal{Version: 1, Entries: make([]reencryptJournalEntry, len(candidates))}
	for i, candidate := range candidates {
		journal.Entries[i] = reencryptJournalEntry{Path: candidate.path}
		candidate.journal = journal
		candidate.journalVaultDir = vaultDir
	}
	return journal
}

func (j *reencryptJournal) persist(vaultDir string) error {
	if j == nil {
		return errors.New("nil re-encryption journal")
	}
	data, err := json.Marshal(j)
	if err != nil {
		return fmt.Errorf("marshal re-encryption journal: %w", err)
	}
	if err := fsutil.AtomicWriteFile(reencryptJournalPath(vaultDir), data, 0o600); err != nil {
		return fmt.Errorf("write re-encryption journal: %w", err)
	}
	if err := syncReencryptDirectory(vaultDir); err != nil {
		return fmt.Errorf("sync re-encryption journal directory: %w", err)
	}
	return nil
}

func (j *reencryptJournal) remove(vaultDir string) error {
	if err := os.Remove(reencryptJournalPath(vaultDir)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncReencryptDirectory(vaultDir)
}

func (j *reencryptJournal) entryFor(path string) (*reencryptJournalEntry, error) {
	for i := range j.Entries {
		if j.Entries[i].Path == path {
			return &j.Entries[i], nil
		}
	}
	return nil, fmt.Errorf("journal entry %q not found", path)
}

func recordReencryptStage(item *reencryptStaged, ciphertext []byte) error {
	if item == nil || item.candidate == nil || item.candidate.journal == nil {
		return nil
	}
	temp, backup := reencryptArtifactPaths(item)
	entry, err := item.candidate.journal.entryFor(item.candidate.path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(ciphertext)
	entry.Temp = temp
	entry.Backup = backup
	entry.Digest = hex.EncodeToString(sum[:])
	item.candidate.digest = entry.Digest
	return item.candidate.journal.persist(item.candidate.journalVaultDir)
}

func recordReencryptBackup(item *reencryptStaged) error {
	if item == nil || item.candidate == nil || item.candidate.journal == nil {
		return nil
	}
	_, backup := reencryptArtifactPaths(item)
	entry, err := item.candidate.journal.entryFor(item.candidate.path)
	if err != nil {
		return err
	}
	entry.Backup = backup
	return item.candidate.journal.persist(item.candidate.journalVaultDir)
}

func recordReencryptInstalled(item *reencryptStaged) error {
	if item == nil || item.candidate == nil || item.candidate.journal == nil {
		return nil
	}
	entry, err := item.candidate.journal.entryFor(item.candidate.path)
	if err != nil {
		return err
	}
	entry.Temp = ""
	entry.Installed = true
	return item.candidate.journal.persist(item.candidate.journalVaultDir)
}

func loadReencryptJournal(vaultDir string) (*reencryptJournal, error) {
	data, err := os.ReadFile(reencryptJournalPath(vaultDir))
	if err != nil {
		return nil, err
	}
	var journal reencryptJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return nil, fmt.Errorf("parse re-encryption journal: %w", err)
	}
	if journal.Version != 1 {
		return nil, fmt.Errorf("unsupported re-encryption journal version %d", journal.Version)
	}
	for _, entry := range journal.Entries {
		if entry.Path == "" || !filepath.IsAbs(entry.Path) {
			return nil, fmt.Errorf("invalid re-encryption journal entry")
		}
		if entry.Digest == "" {
			if entry.Temp != "" || entry.Backup != "" {
				return nil, fmt.Errorf("journal artifact has no ciphertext digest")
			}
			continue
		}
		for _, artifact := range []string{entry.Temp, entry.Backup} {
			if artifact == "" || !filepath.IsAbs(artifact) {
				continue
			}
			if filepath.Dir(artifact) != filepath.Dir(entry.Path) {
				return nil, fmt.Errorf("journal artifact escapes target directory")
			}
		}
	}
	return &journal, nil
}

func recoverReencryptJournal(vaultDir string, identity *age.X25519Identity) error {
	absolute, err := filepath.Abs(vaultDir)
	if err != nil {
		return err
	}
	vaultDir = absolute
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		return err
	}
	defer func() { _ = ReleaseLock(lockFile) }()
	return recoverReencryptJournalLocked(vaultDir, identity)
}

func recoverReencryptJournalLocked(vaultDir string, identity *age.X25519Identity) error {
	journal, err := loadReencryptJournal(vaultDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := recoverReencryptArtifacts(vaultDir, journal); err != nil {
		return fmt.Errorf("recover re-encryption artifacts: %w", err)
	}
	if err := cleanupUnjournaledReencryptArtifacts(vaultDir, journal); err != nil {
		return fmt.Errorf("clean unjournaled re-encryption artifacts: %w", err)
	}
	if err := rebuildManifestStrict(vaultDir, identity); err != nil {
		return fmt.Errorf("rebuild manifest after re-encryption recovery: %w", err)
	}
	if err := journal.remove(vaultDir); err != nil {
		return fmt.Errorf("remove recovered re-encryption journal: %w", err)
	}
	return nil
}

func verifyReencryptDigest(path, want string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("re-encryption artifact target is not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(data)
	return strings.EqualFold(hex.EncodeToString(sum[:]), want), nil
}
