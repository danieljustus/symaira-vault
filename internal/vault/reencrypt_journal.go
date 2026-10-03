package vault

import (
	"bytes"
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
	if err := validateJournalEntries(j.Entries); err != nil {
		return err
	}
	data, err := json.Marshal(j)
	if err != nil {
		return fmt.Errorf("marshal re-encryption journal: %w", err)
	}
	if err := validateRetainedJSON(data, maxEntryPlaintextBytesV1, maxEntryPlaintextBytesV1); err != nil {
		return err
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

func loadReencryptJournal(vaultDir string, budgets ...*vaultReadBatch) (*reencryptJournal, error) {
	release, err := vaultReadAdmission.acquire()
	if err != nil {
		return nil, err
	}
	defer release()
	data, err := readRootedFileLimited(vaultDir, reencryptJournalFileName, maxEntryPlaintextBytesV1, budgets...)
	if err != nil {
		return nil, err
	}
	if err := validateRetainedJSON(data, maxEntryPlaintextBytesV1, maxEntryPlaintextBytesV1); err != nil {
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
	batch := &vaultReadBatch{}
	journal, err := loadReencryptJournal(vaultDir, batch)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := recoverReencryptArtifacts(vaultDir, journal, batch); err != nil {
		return fmt.Errorf("recover re-encryption artifacts: %w", err)
	}
	if err := cleanupUnjournaledReencryptArtifacts(vaultDir, journal); err != nil {
		return fmt.Errorf("clean unjournaled re-encryption artifacts: %w", err)
	}
	if err := rebuildManifestStrict(vaultDir, identity, batch); err != nil {
		return fmt.Errorf("rebuild manifest after re-encryption recovery: %w", err)
	}
	if err := cleanupRecoveredReencryptBackups(vaultDir, journal); err != nil {
		return err
	}
	if err := journal.remove(vaultDir); err != nil {
		return fmt.Errorf("remove recovered re-encryption journal: %w", err)
	}
	return nil
}

func verifyReencryptDigestAtRoot(vaultDir, path, want string, batch *vaultReadBatch) (bool, error) {
	digest, _, _, err := hashVaultEntry(vaultDir, path, batch)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.EqualFold(digest, want), nil
}

func validateJournalEntries(entries []reencryptJournalEntry) error {
	if len(entries) > maxVaultEntryCount {
		return ErrVaultResourceLimit
	}
	paths, cost := 0, 0
	for _, entry := range entries {
		for _, path := range []string{entry.Path, entry.Temp, entry.Backup} {
			if pathErr := addVaultPathBytes(&paths, path); pathErr != nil {
				return pathErr
			}
		}
		// Bounds retained strings and serialized escape expansion before Marshal.
		if len(entry.Digest) > maxEntryValueBytes {
			return ErrVaultResourceLimit
		}
		entryCost := 4096 + 6*(len(entry.Path)+len(entry.Temp)+len(entry.Backup)+len(entry.Digest))
		if entryCost > maxEntryPlaintextBytesV1-cost {
			return ErrVaultResourceLimit
		}
		cost += entryCost
	}
	return nil
}

// Bound the entry slice before retaining synchronized journal objects.
func (j *reencryptJournal) UnmarshalJSON(raw []byte) error {
	var fields struct {
		Version int             `json:"version"`
		Entries json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	j.Version = fields.Version
	if len(fields.Entries) == 0 || bytes.Equal(fields.Entries, []byte("null")) {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(fields.Entries))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('[') {
		return errors.New("invalid journal entries")
	}
	paths := 0
	for decoder.More() {
		if len(j.Entries) >= maxVaultEntryCount {
			return ErrVaultResourceLimit
		}
		var entry reencryptJournalEntry
		if decodeErr := decoder.Decode(&entry); decodeErr != nil {
			return decodeErr
		}
		for _, path := range []string{entry.Path, entry.Temp, entry.Backup} {
			if pathErr := addVaultPathBytes(&paths, path); pathErr != nil {
				return pathErr
			}
		}
		j.Entries = append(j.Entries, entry)
	}
	_, err = decoder.Token()
	return err
}

func cleanupRecoveredReencryptBackups(vaultDir string, journal *reencryptJournal) error {
	batch := &vaultReadBatch{}
	for _, entry := range journal.Entries {
		if entry.Backup == "" {
			continue
		}
		if err := validateReencryptJournalPath(vaultDir, entry.Backup); err != nil {
			return err
		}
		matches, err := verifyReencryptDigestAtRoot(vaultDir, entry.Path, entry.Digest, batch)
		if err != nil {
			return err
		}
		if matches {
			if err := removeReencryptArtifact(entry.Backup); err != nil {
				return err
			}
		}
	}
	return nil
}
