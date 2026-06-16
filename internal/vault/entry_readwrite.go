package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	"github.com/danieljustus/symaira-vault/internal/vault/taint"
)

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
	if cache.configMaxSize > 0 && len(cache.configItems) >= cache.configMaxSize {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range cache.configItems {
			if oldestTime.IsZero() || v.accessedAt.Before(oldestTime) {
				oldestTime = v.accessedAt
				oldestKey = k
			}
		}
		if oldestKey != "" {
			delete(cache.configItems, oldestKey)
		}
	}
	cache.configItems[vaultDir] = configCacheEntry{cfg: cfg, mtime: mtime, accessedAt: time.Now()}
	cache.configMu.Unlock()
	return cfg, nil
}

// ReadEntry reads and decrypts an entry from the vault
func ReadEntry(vaultDir, path string, identity *age.X25519Identity) (*Entry, error) {
	if identity == nil {
		return nil, errors.New("nil identity")
	}
	_, span := metrics.StartSpan(context.Background(), "vault.ReadEntry",
		attribute.String("operation", "read"),
		attribute.String("vault.entry.path", metrics.HashEntryPath(path)),
	)
	defer span.End()
	if err := validateEntryPath(vaultDir, path); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	filePath := entryStoragePath(vaultDir, path, identity, cfg)
	// #nosec G304
	raw, err := os.ReadFile(filePath)
	if os.IsNotExist(err) && canUseLegacyEntryPath(path) {
		if legacyErr := validateLegacyEntryPath(vaultDir, path); legacyErr != nil {
			span.SetStatus(codes.Error, legacyErr.Error())
			return nil, legacyErr
		}
		raw, err = os.ReadFile(legacyEntryFilePath(vaultDir, path))
	}
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	start := time.Now()
	plaintext, err := vaultcrypto.Decrypt(raw, identity)
	metrics.RecordVaultOperationDuration("decrypt", time.Since(start))
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	var entry Entry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		vaultcrypto.Wipe(plaintext)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	vaultcrypto.Wipe(plaintext)
	if entry.Data == nil {
		entry.Data = map[string]any{}
	}
	return &entry, nil
}

func readEntryInner(vaultDir, path string, identity *age.X25519Identity, pseudoKey []byte) (*Entry, error) {
	if identity == nil {
		return nil, errors.New("nil identity")
	}

	_, span := metrics.StartSpan(context.Background(), "vault.ReadEntry",
		attribute.String("operation", "read"),
		attribute.String("vault.entry.path", metrics.HashEntryPath(path)),
	)
	defer span.End()

	if err := validateEntryPath(vaultDir, path); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	var filePath string
	if pseudoKey != nil {
		filePath = entryStoragePathCached(vaultDir, path, pseudoKey)
	} else {
		filePath = entryStoragePath(vaultDir, path, identity, cfg)
	}
	// #nosec G304 -- filePath is constructed by entryStoragePath from validated vaultDir and path
	raw, err := os.ReadFile(filePath)
	if os.IsNotExist(err) && canUseLegacyEntryPath(path) {
		if legacyErr := validateLegacyEntryPath(vaultDir, path); legacyErr != nil {
			span.SetStatus(codes.Error, legacyErr.Error())
			return nil, legacyErr
		}
		raw, err = os.ReadFile(legacyEntryFilePath(vaultDir, path))
	}
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	start := time.Now()
	plaintext, err := vaultcrypto.Decrypt(raw, identity)
	metrics.RecordVaultOperationDuration("decrypt", time.Since(start))
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	var entry Entry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		vaultcrypto.Wipe(plaintext)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	vaultcrypto.Wipe(plaintext)
	if entry.Data == nil {
		entry.Data = map[string]any{}
	}
	return &entry, nil
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
	copyEntry := cloneEntry(entry)
	if copyEntry.Metadata.Created.IsZero() {
		copyEntry.Metadata.Created = now
	}
	copyEntry.Metadata.Updated = now
	copyEntry.Metadata.Version++
	if copyEntry.Data == nil {
		copyEntry.Data = map[string]any{}
	}
	if copyEntry.PendingWrite != nil {
		record := *copyEntry.PendingWrite
		record.Timestamp = now
		copyEntry.Metadata.WriteHistory = append(copyEntry.Metadata.WriteHistory, record)
		copyEntry.PendingWrite = nil
	}
	copyEntry.Classification = InferClassification(copyEntry)
	if isPseudonymizeEnabled(cfg) {
		copyEntry.Path = path
	}
	plaintext, err := json.Marshal(copyEntry)
	if err != nil {
		return nil, err
	}
	defer vaultcrypto.Wipe(plaintext)
	start := time.Now()
	ciphertext, err := vaultcrypto.Encrypt(plaintext, identity.Recipient())
	metrics.RecordVaultOperationDuration("encrypt", time.Since(start))
	if err != nil {
		return nil, err
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
	_, span := metrics.StartSpan(context.Background(), "vault.WriteEntry",
		attribute.String("operation", "write"),
		attribute.String("vault.entry.path", metrics.HashEntryPath(path)),
	)
	defer span.End()
	if err := validateEntryPath(vaultDir, path); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer func() {
		if lockFile != nil {
			_ = ReleaseLock(lockFile)
		}
	}()
	ciphertext, err := writeEntryLocked(vaultDir, path, entry, identity, cfg)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	queueManifestUpdate(vaultDir, path, ciphertext, identity)
	if cfg.Vault != nil {
		cfg.Vault.ManifestGeneration++
	}
	FlushManifestUpdates()
	if err := ReleaseLock(lockFile); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	lockFile = nil
	if err := globalIndex.UpdateEntry(vaultDir, path, identity); err != nil {
		span.SetStatus(codes.Error, err.Error())
	}
	listCacheFor(vaultDir).Invalidate()
	return nil
}

// DeleteEntry removes an entry from the vault
func DeleteEntry(vaultDir, path string, identity *age.X25519Identity) error {
	_, span := metrics.StartSpan(context.Background(), "vault.DeleteEntry",
		attribute.String("operation", "delete"),
		attribute.String("vault.entry.path", metrics.HashEntryPath(path)),
	)
	defer span.End()
	if err := validateEntryPath(vaultDir, path); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
			span.SetStatus(codes.Error, err.Error())
			return err
		}
		if legacyErr := validateLegacyEntryPath(vaultDir, path); legacyErr != nil {
			span.SetStatus(codes.Error, legacyErr.Error())
			return legacyErr
		}
		if err := SafeRemove(legacyEntryFilePath(vaultDir, path)); err != nil {
			span.SetStatus(codes.Error, err.Error())
			return err
		}
		queueManifestRemove(vaultDir, path, identity)
		if cfg.Vault != nil {
			cfg.Vault.ManifestGeneration++
		}
		FlushManifestUpdates()
		if err := ReleaseLock(lockFile); err != nil {
			span.SetStatus(codes.Error, err.Error())
			return err
		}
		lockFile = nil
		globalIndex.RemoveEntry(path, identity)
		listCacheFor(vaultDir).Invalidate()
		return nil
	}
	if canUseLegacyEntryPath(path) {
		if legacyErr := validateLegacyEntryPath(vaultDir, path); legacyErr != nil {
			span.SetStatus(codes.Error, legacyErr.Error())
			return legacyErr
		}
		if err := SafeRemove(legacyEntryFilePath(vaultDir, path)); err != nil && !os.IsNotExist(err) {
			span.SetStatus(codes.Error, err.Error())
			return err
		}
	}
	queueManifestRemove(vaultDir, path, identity)
	if cfg.Vault != nil {
		cfg.Vault.ManifestGeneration++
	}
	FlushManifestUpdates()
	if err := ReleaseLock(lockFile); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	lockFile = nil
	globalIndex.RemoveEntry(path, identity)
	listCacheFor(vaultDir).Invalidate()
	return nil
}

// MergeEntry merges partial data into an existing entry.
func MergeEntry(vaultDir, path string, partialData map[string]any, identity *age.X25519Identity) (*Entry, error) {
	_, span := metrics.StartSpan(context.Background(), "vault.MergeEntry",
		attribute.String("operation", "merge"),
		attribute.String("vault.entry.path", metrics.HashEntryPath(path)),
	)
	defer span.End()
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	defer func() {
		if lockFile != nil {
			_ = ReleaseLock(lockFile)
		}
	}()
	entry, err := ReadEntry(vaultDir, path, identity)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if entry.Data == nil {
		entry.Data = map[string]any{}
	}
	mergeMaps(entry.Data, partialData)
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	ciphertext, err := writeEntryLocked(vaultDir, path, entry, identity, cfg)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if err := ReleaseLock(lockFile); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	lockFile = nil
	queueManifestUpdate(vaultDir, path, ciphertext, identity)
	if err := globalIndex.UpdateEntry(vaultDir, path, identity); err != nil {
		span.SetStatus(codes.Error, err.Error())
	}
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
	raw, err := os.ReadFile(entryStoragePath(vaultDir, path, identity, cfg))
	if os.IsNotExist(err) && canUseLegacyEntryPath(path) {
		if legacyErr := validateLegacyEntryPath(vaultDir, path); legacyErr != nil {
			return nil, legacyErr
		}
		raw, err = os.ReadFile(legacyEntryFilePath(vaultDir, path))
	}
	if err != nil {
		return nil, err
	}
	start := time.Now()
	plaintext, err := vaultcrypto.Decrypt(raw, identity)
	metrics.RecordVaultOperationDuration("decrypt", time.Since(start))
	if err != nil {
		return nil, err
	}
	defer vaultcrypto.Wipe(plaintext)
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
