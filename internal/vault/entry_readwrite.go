package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/vault/taint"
)

// EntryReadBudgetV1 keeps Go and Rust entry reads on the same allocation
// envelope. Ciphertext allows room for Age armor and framing around the full
// plaintext budget.
const (
	maxEntryCiphertextBytesV1 = 24 * 1024 * 1024
	maxEntryPlaintextBytesV1  = 16 * 1024 * 1024
	maxEntryFields            = 1024
	maxEntryDepth             = 32
	maxEntryValueBytes        = 1024 * 1024
	maxEntryArrayItems        = 1024
	maxVaultEntryCount        = 100_000
	maxVaultEntryPathDepth    = 64
)

var errEntryReadLimit = errors.New("entry exceeds read size limit")
var errEntryEnumerationLimit = errors.New("vault entry enumeration exceeds limit")
var errManifestEntryLimit = errors.New("manifest entry count exceeds limit")

func loadVaultConfig(vaultDir string) (*vaultconfig.Config, error) {
	cache := listCacheFor(vaultDir)
	configPath := filepath.Join(vaultDir, "config.yaml")
	mtime := time.Time{}
	if info, err := os.Stat(configPath); err == nil {
		mtime = info.ModTime()
	}
	cache.configMu.RLock()
	entry, ok := cache.configItems[vaultDir]
	cache.configMu.RUnlock()
	if ok && entry.mtime.Equal(mtime) && entry.cfg != nil {
		cache.configMu.Lock()
		entry.accessedAt = time.Now()
		cache.configItems[vaultDir] = entry
		cache.configMu.Unlock()
		return entry.cfg, nil
	}
	cfg, err := vaultconfig.Load(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return vaultconfig.Default(), nil
		}
		return nil, fmt.Errorf("load vault config: %w", err)
	}
	cache.configMu.Lock()
	cache.evictOldestConfigLocked()
	cache.configItems[vaultDir] = configCacheEntry{cfg: cfg, mtime: mtime, accessedAt: time.Now()}
	cache.configMu.Unlock()
	return cfg, nil
}

// ReadEntry reads and decrypts an entry from the vault
func ReadEntry(vaultDir, path string, identity *age.X25519Identity) (*Entry, error) {
	if identity == nil {
		return nil, errors.New("nil identity")
	}
	if err := validateEntryPath(vaultDir, path); err != nil {
		return nil, err
	}
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		return nil, err
	}
	filePath := entryStoragePath(vaultDir, path, identity, cfg)
	raw, err := readVaultEntryBounded(vaultDir, filePath)
	if os.IsNotExist(err) && canUseLegacyEntryPath(path) {
		// A vault may still hold entries under their plaintext names while
		// pseudonymize_paths is already enabled — an interrupted or previously
		// buggy migration leaves exactly that state. Reading must fall back to
		// the entries/<plain>.age layout, not only to the pre-entries/ legacy
		// root, or the entries become unreachable even though they exist.
		raw, err = readVaultEntryBounded(vaultDir, entryFilePath(vaultDir, path))
	}
	if os.IsNotExist(err) && canUseLegacyEntryPath(path) {
		if legacyErr := validateLegacyEntryPath(vaultDir, path); legacyErr != nil {
			return nil, legacyErr
		}
		raw, err = readVaultEntryBounded(vaultDir, legacyEntryFilePath(vaultDir, path))
	}
	if err != nil {
		return nil, err
	}
	start := time.Now()
	plaintext, err := decryptEntryBounded(raw, identity, maxEntryPlaintextBytesV1)
	recordDuration("decrypt", time.Since(start))
	if err != nil {
		return nil, err
	}
	entry, err := decodeEntryBounded(plaintext)
	vaultcrypto.Wipe(plaintext)
	if err != nil {
		return nil, err
	}
	MigrateBackupCodes(entry)
	return entry, nil
}

func readEntryInner(vaultDir, path string, identity *age.X25519Identity, pseudoKey []byte) (*Entry, error) {
	if identity == nil {
		return nil, errors.New("nil identity")
	}

	if err := validateEntryPath(vaultDir, path); err != nil {
		return nil, err
	}

	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		return nil, err
	}

	var filePath string
	if pseudoKey != nil {
		filePath = entryStoragePathCached(vaultDir, path, pseudoKey)
	} else {
		filePath = entryStoragePath(vaultDir, path, identity, cfg)
	}
	raw, err := readVaultEntryBounded(vaultDir, filePath)
	if os.IsNotExist(err) && canUseLegacyEntryPath(path) {
		// See ReadEntry: an entry may still live under its plaintext name in
		// entries/ while pseudonymize_paths is enabled.
		raw, err = readVaultEntryBounded(vaultDir, entryFilePath(vaultDir, path))
	}
	if os.IsNotExist(err) && canUseLegacyEntryPath(path) {
		if legacyErr := validateLegacyEntryPath(vaultDir, path); legacyErr != nil {
			return nil, legacyErr
		}
		raw, err = readVaultEntryBounded(vaultDir, legacyEntryFilePath(vaultDir, path))
	}
	if err != nil {
		return nil, err
	}

	start := time.Now()
	plaintext, err := decryptEntryBounded(raw, identity, maxEntryPlaintextBytesV1)
	recordDuration("decrypt", time.Since(start))
	if err != nil {
		return nil, err
	}
	entry, err := decodeEntryBounded(plaintext)
	vaultcrypto.Wipe(plaintext)
	if err != nil {
		return nil, err
	}
	MigrateBackupCodes(entry)
	return entry, nil
}

func decryptEntryBounded(ciphertext []byte, identity *age.X25519Identity, limit int64) ([]byte, error) {
	if identity == nil {
		return nil, errors.New("nil identity")
	}
	if len(ciphertext) == 0 {
		return nil, vaultcrypto.ErrEmptyCiphertext
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", vaultcrypto.ErrDecryptionFailed, err)
	}
	plaintext, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		vaultcrypto.Wipe(plaintext)
		return nil, fmt.Errorf("read decrypted entry: %w", err)
	}
	if int64(len(plaintext)) > limit {
		vaultcrypto.Wipe(plaintext)
		return nil, fmt.Errorf("%w: plaintext", errEntryReadLimit)
	}
	return plaintext, nil
}

func decodeEntryBounded(plaintext []byte) (*Entry, error) {
	if err := validateEntryPlaintext(plaintext); err != nil {
		return nil, err
	}
	var entry Entry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		return nil, err
	}
	if entry.Data == nil {
		entry.Data = map[string]any{}
	}
	return &entry, nil
}

func validateEntryPlaintext(plaintext []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	start, err := decoder.Token()
	if err != nil {
		return err
	}
	if start == nil { // JSON null has the same zero-value behavior as Entry decoding.
		return nil
	}
	delim, ok := start.(json.Delim)
	if !ok || delim != '{' {
		return nil // Entry decoding returns the authoritative shape error.
	}
	var data json.RawMessage
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("entry object key is not a string")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
		// encoding/json matches struct fields case-insensitively and processes
		// duplicate members in order, so the last matching Data value wins.
		if strings.EqualFold(key, "data") {
			data = raw
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("entry has trailing JSON")
		}
		return err
	}
	if data != nil {
		return validateEntryDataJSON(data)
	}
	return nil
}

func validateEntryDataJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	start, err := decoder.Token()
	if err != nil {
		return err
	}
	if start == nil {
		return nil
	}
	delim, ok := start.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("entry data must be an object or null")
	}
	var nestedFields int
	topLevelFields := 0
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("entry object key is not a string")
		}
		topLevelFields++
		if topLevelFields > maxEntryFields {
			return fmt.Errorf("entry has too many top-level fields (limit %d)", maxEntryFields)
		}
		if len(key) > maxEntryValueBytes {
			return fmt.Errorf("entry field name exceeds %d bytes", maxEntryValueBytes)
		}
		if err := validateEntryJSONValue(decoder, 1, &nestedFields); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("entry data has trailing JSON")
		}
		return err
	}
	return nil
}

func validateEntryJSONValue(decoder *json.Decoder, depth int, fields *int) error {
	if depth > maxEntryDepth {
		return fmt.Errorf("entry nesting depth exceeds %d", maxEntryDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case string:
		if len(value) > maxEntryValueBytes {
			return fmt.Errorf("entry string exceeds %d bytes", maxEntryValueBytes)
		}
	case json.Delim:
		switch value {
		case '[':
			items := 0
			for decoder.More() {
				items++
				if items > maxEntryArrayItems {
					return fmt.Errorf("entry array exceeds %d items", maxEntryArrayItems)
				}
				if err := validateEntryJSONValue(decoder, depth+1, fields); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
		case '{':
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("entry object key is not a string")
				}
				if len(key) > maxEntryValueBytes {
					return fmt.Errorf("entry field name exceeds %d bytes", maxEntryValueBytes)
				}
				(*fields)++
				if *fields > maxEntryFields {
					return fmt.Errorf("entry has too many nested fields (limit %d)", maxEntryFields)
				}
				if err := validateEntryJSONValue(decoder, depth+1, fields); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return err
	}
	return nil
}

func validateEntryData(data map[string]any) error {
	if len(data) > maxEntryFields {
		return fmt.Errorf("entry has too many top-level fields (limit %d)", maxEntryFields)
	}
	fields := 0
	for key, value := range data {
		if len(key) > maxEntryValueBytes {
			return fmt.Errorf("entry field name exceeds %d bytes", maxEntryValueBytes)
		}
		if err := validateEntryValue(value, 1, &fields); err != nil {
			return err
		}
	}
	return nil
}

func validateEntryValue(value any, depth int, fields *int) error {
	if depth > maxEntryDepth {
		return fmt.Errorf("entry nesting depth exceeds %d", maxEntryDepth)
	}
	switch value := value.(type) {
	case string:
		if len(value) > maxEntryValueBytes {
			return fmt.Errorf("entry string exceeds %d bytes", maxEntryValueBytes)
		}
	case []any:
		if len(value) > maxEntryArrayItems {
			return fmt.Errorf("entry array exceeds %d items", maxEntryArrayItems)
		}
		for _, item := range value {
			if err := validateEntryValue(item, depth+1, fields); err != nil {
				return err
			}
		}
	case map[string]any:
		*fields += len(value)
		if *fields > maxEntryFields {
			return fmt.Errorf("entry has too many nested fields (limit %d)", maxEntryFields)
		}
		for key, item := range value {
			if len(key) > maxEntryValueBytes {
				return fmt.Errorf("entry field name exceeds %d bytes", maxEntryValueBytes)
			}
			if err := validateEntryValue(item, depth+1, fields); err != nil {
				return err
			}
		}
	}
	return nil
}

func readVaultEntryBounded(vaultDir, filePath string) ([]byte, error) {
	relative, err := filepath.Rel(vaultDir, filePath)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("entry path escapes vault root: %q", filePath)
	}
	return readEntryRootedBounded(vaultDir, relative)
}

// InferClassification scans all string values in entry.Data.
func InferClassification(entry *Entry) taint.Classification {
	if entry == nil || entry.Data == nil {
		if entry != nil {
			return entry.Classification
		}
		return taint.Public
	}
	maxClass := entry.Classification
	for _, v := range entry.Data {
		str, ok := v.(string)
		if !ok {
			continue
		}
		secretType := DetectSecretType(str)
		if class := classifySecretType(secretType); class > maxClass {
			maxClass = class
		}
	}
	return maxClass
}

func classifySecretType(t SecretType) taint.Classification {
	switch t {
	case SecretTypeSSHKey, SecretTypeCertificate, SecretTypeTOTPSeed:
		return taint.Restricted
	case SecretTypeBearerToken, SecretTypeAPIKey, SecretTypeBasicAuth, SecretTypeDatabaseURL:
		return taint.Secret
	default:
		return taint.Confidential
	}
}

func writeEntryLocked(vaultDir, path string, entry *Entry, identity *age.X25519Identity, cfg *vaultconfig.Config) ([]byte, error) {
	now := time.Now().UTC()
	copyEntry := PrepareEntryForWrite(entry, now, path, isPseudonymizeEnabled(cfg))
	copyEntry.Classification = InferClassification(copyEntry)
	if err := validateEntryData(copyEntry.Data); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(copyEntry)
	if err != nil {
		return nil, err
	}
	defer vaultcrypto.Wipe(plaintext)
	if len(plaintext) > maxEntryPlaintextBytesV1 {
		return nil, fmt.Errorf("%w: plaintext", errEntryReadLimit)
	}
	if err := validateEntryPlaintext(plaintext); err != nil {
		return nil, err
	}
	start := time.Now()
	ciphertext, err := vaultcrypto.Encrypt(plaintext, identity.Recipient())
	recordDuration("encrypt", time.Since(start))
	if err != nil {
		return nil, err
	}
	if len(ciphertext) > maxEntryCiphertextBytesV1 {
		vaultcrypto.Wipe(ciphertext)
		return nil, fmt.Errorf("%w: ciphertext", errEntryReadLimit)
	}
	filePath := entryStoragePath(vaultDir, path, identity, cfg)
	if err := SafeMkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		return nil, err
	}
	if err := SafeWriteFile(filePath, ciphertext, 0o600); err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// WriteEntry encrypts and writes an entry to the vault.
func WriteEntry(vaultDir, path string, entry *Entry, identity *age.X25519Identity) error {
	if entry == nil {
		return errors.New("nil entry")
	}
	if identity == nil {
		return errors.New("nil identity")
	}
	if err := validateEntryPath(vaultDir, path); err != nil {
		return err
	}
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		return err
	}
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		return err
	}
	defer func() {
		if lockFile != nil {
			_ = ReleaseLock(lockFile)
		}
	}()
	ciphertext, err := writeEntryLocked(vaultDir, path, entry, identity, cfg)
	if err != nil {
		return err
	}
	if cfg.Vault != nil {
		cfg.Vault.ManifestGeneration++
	}
	if err := ReleaseLock(lockFile); err != nil {
		return err
	}
	lockFile = nil
	queueManifestUpdate(vaultDir, path, ciphertext, identity)
	FlushManifestUpdates()
	_ = searchIndexForVault(vaultDir).UpdateEntry(vaultDir, path, identity)
	listCacheFor(vaultDir).Invalidate()
	return nil
}

// ReadEntryFile decrypts one entry directly from its file inside the vault.
//
// Migration walks the entries/ tree, where the file name no longer identifies
// the entry once paths are pseudonymized; only the ciphertext's embedded
// logical path does. Callers that need to migrate a file whose name is not
// (or no longer) derivable from a logical path must read it this way.
// ReadEntryFile reads an entry file through a capability rooted at vaultDir.
// It is intended for vault-internal callers that have discovered a file path
// and need the logical path stored in its ciphertext.
func ReadEntryFile(vaultDir, filePath string, identity *age.X25519Identity) (*Entry, error) {
	return readEntryFileWith(identity, func() ([]byte, error) {
		return readVaultEntryBounded(vaultDir, filePath)
	})
}

func readEntryFileWith(identity *age.X25519Identity, read func() ([]byte, error)) (*Entry, error) {
	if identity == nil {
		return nil, errors.New("nil identity")
	}
	raw, err := read()
	if err != nil {
		return nil, err
	}
	start := time.Now()
	plaintext, err := decryptEntryBounded(raw, identity, maxEntryPlaintextBytesV1)
	recordDuration("decrypt", time.Since(start))
	if err != nil {
		return nil, err
	}
	entry, err := decodeEntryBounded(plaintext)
	vaultcrypto.Wipe(plaintext)
	if err != nil {
		return nil, err
	}
	MigrateBackupCodes(entry)
	return entry, nil
}

// DeleteEntry removes an entry from the vault
func DeleteEntry(vaultDir, path string, identity *age.X25519Identity) error {
	if err := validateEntryPath(vaultDir, path); err != nil {
		return err
	}
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		return err
	}
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		return err
	}
	defer func() {
		if lockFile != nil {
			_ = ReleaseLock(lockFile)
		}
	}()
	filePath := entryStoragePath(vaultDir, path, identity, cfg)
	if err := SafeRemove(filePath); err != nil {
		if !os.IsNotExist(err) || !canUseLegacyEntryPath(path) {
			return err
		}
		if legacyErr := validateLegacyEntryPath(vaultDir, path); legacyErr != nil {
			return legacyErr
		}
		if err := SafeRemove(legacyEntryFilePath(vaultDir, path)); err != nil {
			return err
		}
		if cfg.Vault != nil {
			cfg.Vault.ManifestGeneration++
		}
		if err := ReleaseLock(lockFile); err != nil {
			return err
		}
		lockFile = nil
		queueManifestRemove(vaultDir, path, identity)
		FlushManifestUpdates()
		searchIndexForVault(vaultDir).RemoveEntry(path, identity)
		listCacheFor(vaultDir).Invalidate()
		return nil
	}
	if canUseLegacyEntryPath(path) {
		if legacyErr := validateLegacyEntryPath(vaultDir, path); legacyErr != nil {
			return legacyErr
		}
		if err := SafeRemove(legacyEntryFilePath(vaultDir, path)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if cfg.Vault != nil {
		cfg.Vault.ManifestGeneration++
	}
	if err := ReleaseLock(lockFile); err != nil {
		return err
	}
	lockFile = nil
	queueManifestRemove(vaultDir, path, identity)
	FlushManifestUpdates()
	searchIndexForVault(vaultDir).RemoveEntry(path, identity)
	listCacheFor(vaultDir).Invalidate()
	return nil
}

// MergeEntry merges partial data into an existing entry.
func MergeEntry(vaultDir, path string, partialData map[string]any, identity *age.X25519Identity) (*Entry, error) {
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if lockFile != nil {
			_ = ReleaseLock(lockFile)
		}
	}()
	entry, err := ReadEntry(vaultDir, path, identity)
	if err != nil {
		return nil, err
	}
	if entry.Data == nil {
		entry.Data = map[string]any{}
	}
	mergeMaps(entry.Data, partialData)
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		return nil, err
	}
	ciphertext, err := writeEntryLocked(vaultDir, path, entry, identity, cfg)
	if err != nil {
		return nil, err
	}
	if err := ReleaseLock(lockFile); err != nil {
		return nil, err
	}
	lockFile = nil
	queueManifestUpdate(vaultDir, path, ciphertext, identity)
	_ = searchIndexForVault(vaultDir).UpdateEntry(vaultDir, path, identity)
	listCacheFor(vaultDir).Invalidate()
	return ReadEntry(vaultDir, path, identity)
}

// GetEntryMetadata reads only the metadata from an entry.
func GetEntryMetadata(vaultDir, path string, identity *age.X25519Identity) (*EntryMetadata, error) {
	if identity == nil {
		return nil, errors.New("nil identity")
	}
	if err := validateEntryPath(vaultDir, path); err != nil {
		return nil, err
	}
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		return nil, err
	}
	raw, err := readVaultEntryBounded(vaultDir, entryStoragePath(vaultDir, path, identity, cfg))
	if os.IsNotExist(err) && canUseLegacyEntryPath(path) {
		if legacyErr := validateLegacyEntryPath(vaultDir, path); legacyErr != nil {
			return nil, legacyErr
		}
		raw, err = readVaultEntryBounded(vaultDir, legacyEntryFilePath(vaultDir, path))
	}
	if err != nil {
		return nil, err
	}
	start := time.Now()
	plaintext, err := decryptEntryBounded(raw, identity, maxEntryPlaintextBytesV1)
	recordDuration("decrypt", time.Since(start))
	if err != nil {
		return nil, err
	}
	defer vaultcrypto.Wipe(plaintext)
	if err := validateEntryPlaintext(plaintext); err != nil {
		return nil, err
	}
	var entry struct {
		Metadata EntryMetadata `json:"meta"`
	}
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		return nil, err
	}
	return &entry.Metadata, nil
}

func cloneEntry(entry *Entry) *Entry {
	if entry == nil {
		return nil
	}
	clone := &Entry{
		Metadata:       entry.Metadata,
		SecretMetadata: entry.SecretMetadata,
		Classification: entry.Classification,
		Canary:         entry.Canary,
	}
	if entry.SecretMetadata.ExpiresAt != nil {
		expiresAt := *entry.SecretMetadata.ExpiresAt
		clone.SecretMetadata.ExpiresAt = &expiresAt
	}
	if entry.Data != nil {
		if cloned, ok := deepCloneMap(entry.Data).(map[string]any); ok {
			clone.Data = cloned
		}
	}
	if len(entry.Metadata.WriteHistory) > 0 {
		clone.Metadata.WriteHistory = make([]WriteRecord, len(entry.Metadata.WriteHistory))
		copy(clone.Metadata.WriteHistory, entry.Metadata.WriteHistory)
	}
	if entry.PendingWrite != nil {
		record := *entry.PendingWrite
		clone.PendingWrite = &record
	}
	return clone
}

func deepCloneMap(m map[string]any) any {
	clone := make(map[string]any, len(m))
	for k, v := range m {
		clone[k] = deepCloneValue(v)
	}
	return clone
}

func deepCloneValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		return deepCloneMap(typed)
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			out[i] = deepCloneValue(typed[i])
		}
		return out
	default:
		return typed
	}
}

func mergeMaps(dst, src map[string]any) {
	for k, v := range src {
		if existing, ok := dst[k]; ok {
			dstMap, dstIsMap := existing.(map[string]any)
			srcMap, srcIsMap := v.(map[string]any)
			if dstIsMap && srcIsMap {
				mergeMaps(dstMap, srcMap)
				dst[k] = dstMap
				continue
			}
		}
		dst[k] = deepCloneValue(v)
	}
}
