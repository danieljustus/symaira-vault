package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/fileutil"
)

// ManifestEntry stores integrity metadata for a single vault entry.
type ManifestEntry struct {
	SHA256 string    `json:"sha256"`
	Size   int64     `json:"size"`
	MTime  time.Time `json:"mtime"`
}

// Manifest tracks integrity of all .age entry files in the vault.
type Manifest struct {
	Version int                      `json:"version"`
	Created time.Time                `json:"created"`
	Updated time.Time                `json:"updated"`
	Entries map[string]ManifestEntry `json:"entries"`
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
	manifestPath := filepath.Join(vaultDir, manifestFileName)
	raw, err := os.ReadFile(manifestPath) //#nosec G304 -- vaultDir is controlled
	if err != nil {
		return nil, err
	}

	plaintext, err := vaultcrypto.Decrypt(raw, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt manifest: %w", err)
	}
	defer vaultcrypto.Wipe(plaintext)

	var m Manifest
	if err := json.Unmarshal(plaintext, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}
	if m.Entries == nil {
		m.Entries = make(map[string]ManifestEntry)
	}
	return &m, nil
}

// writeManifest marshals the manifest to JSON, encrypts it for all recipients,
// and writes it atomically to manifest.age.
func writeManifest(vaultDir string, m *Manifest, identity *age.X25519Identity) error {
	if m.Version == 0 {
		m.Version = 1
	}
	m.Updated = time.Now().UTC()

	plaintext, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	defer vaultcrypto.Wipe(plaintext)

	v := &Vault{Dir: vaultDir, Identity: identity}
	recipients, err := v.GetAllRecipientsForEncryption()
	if err != nil {
		return fmt.Errorf("get recipients for manifest: %w", err)
	}

	ciphertext, err := vaultcrypto.EncryptWithRecipients(plaintext, recipients...)
	if err != nil {
		return fmt.Errorf("encrypt manifest: %w", err)
	}

	manifestPath := filepath.Join(vaultDir, manifestFileName)
	if err := fileutil.AtomicWriteFile(manifestPath, ciphertext, 0o600); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	return nil
}

// UpdateManifestEntry loads the manifest (or creates a new one), adds or
// updates the entry for the given logical path, and writes it back.
func UpdateManifestEntry(vaultDir, path string, ciphertext []byte, identity *age.X25519Identity) error {
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

	for logicalPath, manifestEntry := range m.Entries {
		filePath := entryStoragePath(vaultDir, logicalPath, identity, cfg)
		storagePaths[filePath] = true

		data, err := os.ReadFile(filePath) //#nosec G304 -- path derived from manifest entries
		if os.IsNotExist(err) {
			result.Missing = append(result.Missing, logicalPath)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filePath, err)
		}

		hash := sha256.Sum256(data)
		hashStr := hex.EncodeToString(hash[:])

		if hashStr != manifestEntry.SHA256 {
			result.Tampered = append(result.Tampered, logicalPath)
		} else {
			result.OK++
		}
	}

	entriesPath := entriesDir(vaultDir)
	_ = filepath.Walk(entriesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".age") {
			return nil
		}
		if !storagePaths[path] {
			rel, _ := filepath.Rel(entriesPath, path)
			result.Unknown = append(result.Unknown, rel)
		}
		return nil
	})

	return result, nil
}
