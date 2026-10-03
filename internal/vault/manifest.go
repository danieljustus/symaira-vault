package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"filippo.io/age"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/fsutil"
)

// ManifestEntry stores integrity metadata for a single vault entry.
type ManifestEntry struct {
	SHA256 string    `json:"sha256"`
	Size   int64     `json:"size"`
	MTime  time.Time `json:"mtime"`
}

// Manifest tracks integrity of all .age entry files in the vault.
type Manifest struct {
	Version    int                      `json:"version"`
	Generation int                      `json:"generation"`
	Created    time.Time                `json:"created"`
	Updated    time.Time                `json:"updated"`
	Entries    map[string]ManifestEntry `json:"entries"`
}

// ManifestVerifyResult contains the outcome of a full manifest integrity check.
type ManifestVerifyResult struct {
	Missing  []string `json:"missing"`
	Tampered []string `json:"tampered"`
	Unknown  []string `json:"unknown"`
	OK       int      `json:"ok"`
}

const manifestFileName = "manifest.age"

// LoadManifest reads manifest.age from the vault root, decrypts it with the
// provided identity, and unmarshals the JSON content. Returns nil + os.IsNotExist
// error if the file does not exist.
func LoadManifest(vaultDir string, identity *age.X25519Identity) (*Manifest, error) {
	release, err := vaultReadAdmission.acquire()
	if err != nil {
		return nil, err
	}
	defer release()
	manifestPath := filepath.Join(vaultDir, manifestFileName)
	raw, err := readVaultEntryBounded(vaultDir, manifestPath)
	if err != nil {
		return nil, err
	}
	// Rust's root-file reader caps manifest.age at MAX_FILE_BYTES (16 MiB).
	// Keep the same accepted ciphertext range even though entry files allow
	// extra room for Age framing.
	if int64(len(raw)) > maxEntryPlaintextBytesV1 {
		return nil, fmt.Errorf("%w: manifest ciphertext", errEntryReadLimit)
	}

	plaintext, err := decryptEntryBounded(raw, identity, maxEntryPlaintextBytesV1)
	if err != nil {
		return nil, fmt.Errorf("decrypt manifest: %w", err)
	}
	defer vaultcrypto.Wipe(plaintext)
	if err := validateManifestEntryCount(plaintext); err != nil {
		return nil, err
	}

	var m Manifest
	if err := json.Unmarshal(plaintext, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}
	if m.Entries == nil {
		m.Entries = make(map[string]ManifestEntry)
	}
	return &m, nil
}

func validateManifestEntryCount(plaintext []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	start, parseErr := decoder.Token()
	if parseErr != nil {
		return parseErr
	}
	if start != json.Delim('{') {
		return nil
	}
	seen, entries, pathBytes := false, 0, 0
	for decoder.More() {
		token, keyErr := decoder.Token()
		if keyErr != nil {
			return keyErr
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("manifest object key is not a string")
		}
		if !strings.EqualFold(key, "entries") {
			var ignored json.RawMessage
			if ignoredErr := decoder.Decode(&ignored); ignoredErr != nil {
				return ignoredErr
			}
			continue
		}
		if seen {
			return errors.New("manifest has duplicate entries fields")
		}
		seen = true
		mapStart, mapErr := decoder.Token()
		if mapErr != nil {
			return mapErr
		}
		if mapStart == nil {
			continue
		}
		if mapStart != json.Delim('{') {
			return errors.New("manifest entries must be an object or null")
		}
		for decoder.More() {
			entryToken, entryErr := decoder.Token()
			if entryErr != nil {
				return entryErr
			}
			entryKey, ok := entryToken.(string)
			if !ok {
				return errors.New("manifest entry key is not a string")
			}
			entries++
			if entries > maxVaultEntryCount {
				return errManifestEntryLimit
			}
			if budgetErr := addVaultPathBytes(&pathBytes, entryKey); budgetErr != nil {
				return budgetErr
			}
			var ignored json.RawMessage
			if valueErr := decoder.Decode(&ignored); valueErr != nil {
				return valueErr
			}
		}
		if _, endErr := decoder.Token(); endErr != nil {
			return endErr
		}
	}
	_, parseErr = decoder.Token()
	return parseErr
}

// walkVaultEntriesBounded applies the same traversal limits as Rust's
// entry_candidates: count every descendant filesystem item, and do not enter
// paths deeper than the shared logical-path limit.
func walkVaultEntriesBounded(root string, visit func(path string, d os.DirEntry) error, counters ...*int) error {
	rootCap, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = rootCap.Close() }()

	visited := 0
	visitedCount := &visited
	if len(counters) != 0 {
		visitedCount = counters[0]
	}
	var walk func(relative string, depth int) error
	walk = func(relative string, depth int) error {
		directory, err := rootCap.Open(relative)
		if err != nil {
			return err
		}
		defer func() { _ = directory.Close() }()
		info, err := directory.Stat()
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("vault scan expected directory: %q", relative)
		}
		for {
			// Fixed-size chunks also bound retained directory names at each
			// recursion level, including wide trees whose first child is deep.
			entries, readErr := directory.ReadDir(128)
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return readErr
			}
			for _, d := range entries {
				*visitedCount++
				if *visitedCount > maxVaultEntryCount {
					return errEntryEnumerationLimit
				}
				childDepth := depth + 1
				if childDepth > maxVaultEntryPathDepth {
					return ErrVaultResourceLimit
				}
				child := filepath.Join(relative, d.Name())
				path := filepath.Join(root, child)
				if d.IsDir() {
					if visitErr := visit(path, d); visitErr != nil {
						if errors.Is(visitErr, filepath.SkipDir) {
							continue
						}
						return visitErr
					}
					if walkErr := walk(child, childDepth); walkErr != nil {
						return walkErr
					}
					continue
				}
				if visitErr := visit(path, d); visitErr != nil {
					return visitErr
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
		}
		return nil
	}
	return walk(".", 0)
}

// writeManifest marshals the manifest to JSON, encrypts it for all recipients,
// and writes it atomically to manifest.age.
func writeManifest(vaultDir string, m *Manifest, identity *age.X25519Identity) error {
	if len(m.Entries) > maxVaultEntryCount {
		return errManifestEntryLimit
	}
	if m.Version == 0 {
		m.Version = 1
	}
	m.Generation++
	m.Updated = time.Now().UTC()

	plaintext, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	defer vaultcrypto.Wipe(plaintext)
	if len(plaintext) > maxEntryPlaintextBytesV1 {
		return fmt.Errorf("%w: manifest plaintext", errEntryReadLimit)
	}

	v := &Vault{Dir: vaultDir, Identity: identity}
	recipients, err := v.GetAllRecipientsForEncryption()
	if err != nil {
		return fmt.Errorf("get recipients for manifest: %w", err)
	}

	ciphertext, err := vaultcrypto.EncryptWithRecipients(plaintext, recipients...)
	if err != nil {
		return fmt.Errorf("encrypt manifest: %w", err)
	}
	if len(ciphertext) > maxEntryPlaintextBytesV1 {
		vaultcrypto.Wipe(ciphertext)
		return fmt.Errorf("%w: manifest ciphertext", errEntryReadLimit)
	}

	manifestPath := filepath.Join(vaultDir, manifestFileName)
	if err := fsutil.AtomicWriteFile(manifestPath, ciphertext, 0o600); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	return nil
}

// UpdateManifestEntry loads the manifest (or creates a new one), adds or
// updates the entry for the given logical path, and writes it back.
func UpdateManifestEntry(vaultDir, path string, ciphertext []byte, identity *age.X25519Identity) error {
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		return err
	}
	defer func() { _ = ReleaseLock(lockFile) }()
	m, err := LoadManifest(vaultDir, identity)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("load manifest: %w", err)
		}
		m = &Manifest{
			Version: 1,
			Created: time.Now().UTC(),
			Entries: make(map[string]ManifestEntry),
		}
	}

	hash := sha256.Sum256(ciphertext)
	entry := ManifestEntry{
		SHA256: hex.EncodeToString(hash[:]),
		Size:   int64(len(ciphertext)),
		MTime:  time.Now().UTC(),
	}

	m.Entries[path] = entry

	return writeManifest(vaultDir, m, identity)
}

// RemoveManifestEntry removes an entry from the manifest. If the manifest
// does not exist, this is a no-op.
func RemoveManifestEntry(vaultDir, path string, identity *age.X25519Identity) error {
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		return err
	}
	defer func() { _ = ReleaseLock(lockFile) }()
	m, err := LoadManifest(vaultDir, identity)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("load manifest: %w", err)
	}

	delete(m.Entries, path)

	return writeManifest(vaultDir, m, identity)
}

// VerifyManifestIntegrity checks that all entries in the manifest match their
// corresponding files on disk, and reports any discrepancies.
func VerifyManifestIntegrity(vaultDir string, identity *age.X25519Identity) (*ManifestVerifyResult, error) {
	m, err := LoadManifest(vaultDir, identity)
	if err != nil {
		return nil, err
	}

	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		return nil, err
	}
	result := &ManifestVerifyResult{}
	storagePaths := make(map[string]bool)

	var pseudoKey []byte
	if identity != nil && isPseudonymizeEnabled(cfg) {
		pseudoKey = derivePseudonymizationKey(identity)
	}

	batch := &vaultReadBatch{}
	for logicalPath, manifestEntry := range m.Entries {
		filePath := entryStoragePathCached(vaultDir, logicalPath, pseudoKey)
		storagePaths[filePath] = true

		hashStr, _, _, err := hashVaultEntry(vaultDir, filePath, batch)
		if os.IsNotExist(err) {
			result.Missing = append(result.Missing, logicalPath)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filePath, err)
		}

		if hashStr != manifestEntry.SHA256 {
			result.Tampered = append(result.Tampered, logicalPath)
		} else {
			result.OK++
		}
	}

	entriesPath := entriesDir(vaultDir)
	if err := walkVaultEntriesBounded(entriesPath, func(path string, d os.DirEntry) error {
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".age") {
			return nil
		}
		if !storagePaths[path] {
			rel, _ := filepath.Rel(entriesPath, path)
			result.Unknown = append(result.Unknown, rel)
		}
		return nil
	}); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return result, nil
}

// DetectOutOfBandEntries returns the .age files under the vault's entries
// directory that are not tracked by the manifest (typical after a git/rsync
// sync that brings new entries in without updating the manifest). It does not
// hash entries; callers that need a tamper check should call
// VerifyManifestIntegrity. Returns os.IsNotExist if no manifest exists yet.
func DetectOutOfBandEntries(vaultDir string, identity *age.X25519Identity, cfg *vaultconfig.Config) ([]string, error) {
	m, err := LoadManifest(vaultDir, identity)
	if err != nil {
		return nil, err
	}

	expected := make(map[string]bool, len(m.Entries))
	var pseudoKey []byte
	if identity != nil && isPseudonymizeEnabled(cfg) {
		pseudoKey = derivePseudonymizationKey(identity)
	}
	for logicalPath := range m.Entries {
		expected[entryStoragePathCached(vaultDir, logicalPath, pseudoKey)] = true
	}

	var outOfBand []string
	entriesPath := entriesDir(vaultDir)
	if err := walkVaultEntriesBounded(entriesPath, func(path string, d os.DirEntry) error {
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".age") {
			return nil
		}
		if !expected[path] {
			rel, relErr := filepath.Rel(entriesPath, path)
			if relErr == nil {
				outOfBand = append(outOfBand, rel)
			}
		}
		return nil
	}); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return outOfBand, nil
}

// RebuildManifest walks all .age entry files in the vault and regenerates the
// manifest from scratch. It acquires the same write lock as entry writers.
func RebuildManifest(vaultDir string, identity *age.X25519Identity) error {
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		return err
	}
	defer func() { _ = ReleaseLock(lockFile) }()
	return rebuildManifestUnlocked(vaultDir, identity)
}

func rebuildManifestUnlocked(vaultDir string, identity *age.X25519Identity) error {
	m := &Manifest{
		Version: 1,
		Created: time.Now().UTC(),
		Entries: make(map[string]ManifestEntry),
	}

	entriesPath := entriesDir(vaultDir)

	// Reuse the capability-rooted, chunked traversal rather than asking
	// filepath.Walk to allocate and sort an entire directory first.
	paths, err := pseudonymizedEntryFiles(vaultDir)
	if err != nil {
		return fmt.Errorf("walk entries for manifest rebuild: %w", err)
	}

	// Second pass: compute SHA-256 hashes in parallel with auto-scaled workers.
	type result struct {
		logicalPath string
		entry       ManifestEntry
		err         error
	}

	pathCh := make(chan string, maxActiveVaultReads)
	resultCh := make(chan result, maxActiveVaultReads)
	batch := &vaultReadBatch{}
	var wg sync.WaitGroup
	numWorkers := SearchWorkerCount(0)
	if len(paths) < numWorkers {
		numWorkers = len(paths)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathCh {
				digest, size, mtime, err := hashVaultEntry(vaultDir, path, batch)
				if err != nil {
					resultCh <- result{err: err}
					continue
				}
				rel, err := filepath.Rel(entriesPath, path)
				if err != nil {
					continue
				}
				logicalPath := strings.TrimSuffix(filepath.ToSlash(rel), ".age")

				resultCh <- result{
					logicalPath: logicalPath,
					entry: ManifestEntry{
						SHA256: digest,
						Size:   size,
						MTime:  mtime,
					},
				}
			}
		}()
	}

	go func() {
		for _, path := range paths {
			pathCh <- path
		}
		close(pathCh)
		wg.Wait()
		close(resultCh)
	}()

	var firstErr error
	for r := range resultCh {
		if r.err != nil {
			if errors.Is(r.err, ErrVaultResourceLimit) || errors.Is(r.err, ErrVaultResourceBusy) {
				if firstErr == nil {
					firstErr = r.err
				}
			}
			continue
		}
		m.Entries[r.logicalPath] = r.entry
	}
	if firstErr != nil {
		return firstErr
	}

	return writeManifest(vaultDir, m, identity)
}
