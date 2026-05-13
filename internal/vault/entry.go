package vault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	vaultconfig "github.com/danieljustus/OpenPass/internal/config"
	vaultcrypto "github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/pathutil"
	"github.com/danieljustus/OpenPass/internal/vault/taint"
)

// Entry represents a vault entry with flexible data storage using map[string]any.
type Entry struct {
	Path           string         `json:"path,omitempty"`
	Data           map[string]any `json:"data"`
	Metadata       EntryMetadata  `json:"meta"`
	SecretMetadata SecretMetadata `json:"secret_meta,omitempty"`
}

// EntryMetadata contains metadata about an entry
type EntryMetadata struct {
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
	Version int       `json:"version"`
	Tags    []string  `json:"tags,omitempty"`
}

// SecretMetadata contains semantic metadata about a secret for AI agent usage.
type SecretMetadata struct {
	Type       SecretType `json:"type,omitempty"`
	UsageHint  string     `json:"usage_hint,omitempty"`
	AutoRotate bool       `json:"auto_rotate,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for Entry
func (e Entry) MarshalJSON() ([]byte, error) {
	type alias Entry
	return json.Marshal(alias(e))
}

// UnmarshalJSON implements custom JSON unmarshaling for Entry
func (e *Entry) UnmarshalJSON(data []byte) error {
	type alias Entry
	var v alias
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*e = Entry(v)
	if e.Data == nil {
		e.Data = map[string]any{}
	}
	return nil
}

// TagWeakPassword is the tag applied to entries whose password is assessed as weak.
const TagWeakPassword = "weak-password"

// HasTag returns true if the entry has the given tag.
func (e *Entry) HasTag(tag string) bool {
	for _, t := range e.Metadata.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// AddTag adds a tag to the entry if not already present.
func (e *Entry) AddTag(tag string) {
	if !e.HasTag(tag) {
		e.Metadata.Tags = append(e.Metadata.Tags, tag)
	}
}

// RemoveTag removes a tag from the entry if present.
func (e *Entry) RemoveTag(tag string) {
	for i, t := range e.Metadata.Tags {
		if t == tag {
			e.Metadata.Tags = append(e.Metadata.Tags[:i], e.Metadata.Tags[i+1:]...)
			return
		}
	}
}

// validateEntryPath ensures the entry path stays within the vault directory.
// Returns an error if path traversal is detected.
func validateEntryPath(vaultDir, path string) error {
	if err := validateRawEntryPath(path); err != nil {
		return err
	}

	filePath := entryFilePath(vaultDir, path)
	cleanPath := filepath.Clean(filePath)
	entriesDirClean := filepath.Clean(entriesDir(vaultDir))
	if !strings.HasPrefix(cleanPath, entriesDirClean+string(filepath.Separator)) && cleanPath != entriesDirClean {
		return fmt.Errorf("entry path %q escapes vault directory", path)
	}
	return nil
}

func validateRawEntryPath(path string) error {
	path = strings.TrimSpace(path)

	// Use centralized path validation from pathutil
	if err := pathutil.ValidatePath(path); err != nil {
		return fmt.Errorf("entry path %q: %w", path, err)
	}

	// Additional entry-specific validation: reject "." segments
	normalized := strings.ReplaceAll(path, "\\", "/")
	for _, segment := range strings.Split(normalized, "/") {
		if segment == "." {
			return fmt.Errorf("entry path %q contains invalid path segment \".\"", path)
		}
	}

	return nil
}

func validateLegacyEntryPath(vaultDir, path string) error {
	if err := validateRawEntryPath(path); err != nil {
		return err
	}

	filePath := legacyEntryFilePath(vaultDir, path)
	cleanPath := filepath.Clean(filePath)
	vaultDirClean := filepath.Clean(vaultDir)
	if !strings.HasPrefix(cleanPath, vaultDirClean+string(filepath.Separator)) || cleanPath == filepath.Join(vaultDirClean, "identity.age") {
		return fmt.Errorf("legacy entry path %q escapes vault entry namespace", path)
	}
	return nil
}

// configCache memoizes parsed vault configs per vaultDir, keyed by the
// config file's mtime. It avoids re-parsing config.yaml on every entry
// read during a search — the hot path for large vaults.
var configCache struct {
	mu    sync.RWMutex
	items map[string]configCacheEntry
}

type configCacheEntry struct {
	cfg   *vaultconfig.Config
	mtime time.Time
}

func init() {
	configCache.items = make(map[string]configCacheEntry)
}

// InvalidateConfigCache drops the cached config for vaultDir. Callers should
// invoke this after writing config.yaml so the next load sees the new value.
func InvalidateConfigCache(vaultDir string) {
	configCache.mu.Lock()
	delete(configCache.items, vaultDir)
	configCache.mu.Unlock()
}

func loadVaultConfig(vaultDir string) (*vaultconfig.Config, error) {
	configPath := filepath.Join(vaultDir, "config.yaml")
	mtime := time.Time{}
	if info, err := os.Stat(configPath); err == nil {
		mtime = info.ModTime()
	}

	configCache.mu.RLock()
	entry, ok := configCache.items[vaultDir]
	configCache.mu.RUnlock()
	if ok && entry.mtime.Equal(mtime) && entry.cfg != nil {
		return entry.cfg, nil
	}

	cfg, err := vaultconfig.Load(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return vaultconfig.Default(), nil
		}
		return nil, fmt.Errorf("load vault config: %w", err)
	}

	configCache.mu.Lock()
	configCache.items[vaultDir] = configCacheEntry{cfg: cfg, mtime: mtime}
	configCache.mu.Unlock()
	return cfg, nil
}

// ReadEntry reads and decrypts an entry from the vault
func ReadEntry(vaultDir, path string, identity *age.X25519Identity) (*Entry, error) {
	if identity == nil {
		return nil, errors.New("nil identity")
	}
	rememberSearchIdentity(identity)

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
	defer vaultcrypto.Wipe(plaintext)

	var entry Entry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if entry.Data == nil {
		entry.Data = map[string]any{}
	}
	return &entry, nil
}

// writeEntryLocked performs the full entry write (prep, encrypt, file ops, manifest
// update) assuming the caller already holds the per-vaultDir exclusive lock.
func writeEntryLocked(vaultDir, path string, entry *Entry, identity *age.X25519Identity, cfg *vaultconfig.Config) error {
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

	if isPseudonymizeEnabled(cfg) {
		copyEntry.Path = path
	}

	plaintext, err := json.Marshal(copyEntry)
	if err != nil {
		return err
	}

	start := time.Now()
	ciphertext, err := vaultcrypto.Encrypt(plaintext, identity.Recipient())
	metrics.RecordVaultOperationDuration("encrypt", time.Since(start))
	if err != nil {
		return err
	}

	filePath := entryStoragePath(vaultDir, path, identity, cfg)
	if err := SafeMkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		return err
	}
	// Symlink-hardened write: O_NOFOLLOW + fstat verification prevents writing through symlinks
	if err := SafeWriteFile(filePath, ciphertext, 0o600); err != nil {
		return err
	}
	if err := UpdateManifestEntry(vaultDir, path, ciphertext, identity); err != nil {
		return fmt.Errorf("update manifest: %w", err)
	}
	return nil
}

// WriteEntry encrypts and writes an entry to the vault.
// It acquires a per-vaultDir exclusive lock before writing.
func WriteEntry(vaultDir, path string, entry *Entry, identity *age.X25519Identity) error {
	if entry == nil {
		return errors.New("nil entry")
	}
	if identity == nil {
		return errors.New("nil identity")
	}
	rememberSearchIdentity(identity)

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

	// Acquire per-vaultDir exclusive lock before writing entry and updating manifest
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer func() { _ = ReleaseLock(lockFile) }()

	if err := writeEntryLocked(vaultDir, path, entry, identity, cfg); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
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

	// Acquire per-vaultDir exclusive lock before deleting entry and updating manifest
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer func() { _ = ReleaseLock(lockFile) }()

	filePath := entryStoragePath(vaultDir, path, identity, cfg)
	// Symlink-hardened remove: O_NOFOLLOW + fstat verification prevents removing through symlinks
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
		if err := RemoveManifestEntry(vaultDir, path, identity); err != nil {
			span.SetStatus(codes.Error, err.Error())
			return fmt.Errorf("remove from manifest: %w", err)
		}
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
	if err := RemoveManifestEntry(vaultDir, path, identity); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("remove from manifest: %w", err)
	}
	return nil
}

const entriesDirName = "entries"

func entriesDir(vaultDir string) string {
	return filepath.Join(vaultDir, entriesDirName)
}

func canUseLegacyEntryPath(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	return clean != "identity" && clean != entriesDirName && !strings.HasPrefix(clean, entriesDirName+"/")
}

func legacyEntryFilePath(vaultDir, path string) string {
	return filepath.Join(vaultDir, filepath.FromSlash(path)+".age")
}

func migrateLegacyEntries(vaultDir string) error {
	vaultDirClean := filepath.Clean(vaultDir)
	entriesDirClean := filepath.Clean(entriesDir(vaultDir))
	// Symlink-hardened mkdir: validates each component to prevent following symlinks
	if err := SafeMkdirAll(entriesDirClean, 0o700); err != nil {
		return err
	}

	return filepath.Walk(vaultDirClean, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == vaultDirClean {
			return nil
		}
		if info.IsDir() {
			cleanPath := filepath.Clean(path)
			if cleanPath == entriesDirClean || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".age" { //nolint:goconst // file extension literal
			return nil
		}

		rel, err := filepath.Rel(vaultDirClean, path)
		if err != nil {
			return err
		}
		if filepath.ToSlash(rel) == "identity.age" { //nolint:goconst // filename literal
			return nil
		}

		target := filepath.Join(entriesDirClean, rel)
		if _, err := os.Stat(target); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := SafeMkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return os.Rename(path, target) // #nosec G122 -- both paths are within the user's own vault directory (internally generated by filepath.Walk)
	})
}

// MergeEntry merges partial data into an existing entry.
// It acquires a per-vaultDir exclusive lock so the read-merge-write is atomic.
func MergeEntry(vaultDir, path string, partialData map[string]any, identity *age.X25519Identity) (*Entry, error) {
	_, span := metrics.StartSpan(context.Background(), "vault.MergeEntry",
		attribute.String("operation", "merge"),
		attribute.String("vault.entry.path", metrics.HashEntryPath(path)),
	)
	defer span.End()

	// Acquire per-vaultDir exclusive lock so the entire read-merge-write is atomic
	lockFile, err := AcquireWriteLock(vaultDir, 0)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	defer func() { _ = ReleaseLock(lockFile) }()

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

	if err := writeEntryLocked(vaultDir, path, entry, identity, cfg); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return ReadEntry(vaultDir, path, identity)
}

// entryFilePath returns the filesystem path for an entry
func entryFilePath(vaultDir, path string) string {
	return filepath.Join(entriesDir(vaultDir), filepath.FromSlash(path)+".age")
}

// derivePseudonymizationKey derives a deterministic HMAC key from the vault identity.
// Uses sha256 of the identity string so the same vault always produces the same hashes.
func derivePseudonymizationKey(identity *age.X25519Identity) []byte {
	h := sha256.Sum256([]byte(identity.String()))
	return h[:]
}

// pseudonymizePath computes the HMAC-SHA256 hash of a path using the given key
// and returns it as a hex-encoded string.
func pseudonymizePath(path string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(path))
	return hex.EncodeToString(mac.Sum(nil))
}

// entryStoragePath returns the filesystem path for an entry, respecting pseudonymization.
// When pseudonymization is enabled, entries are stored at entries/<hash[:2]>/<hash>.age.
// Otherwise, falls back to the plaintext path under entries/.
func entryStoragePath(vaultDir, path string, identity *age.X25519Identity, cfg *vaultconfig.Config) string {
	if identity != nil && isPseudonymizeEnabled(cfg) {
		key := derivePseudonymizationKey(identity)
		hash := pseudonymizePath(path, key)
		return filepath.Join(entriesDir(vaultDir), hash[:2], hash+".age")
	}
	return entryFilePath(vaultDir, path)
}

// isPseudonymizeEnabled returns whether path pseudonymization is enabled based on the given config.
// Callers should pass the vault config to avoid redundant disk I/O.
func isPseudonymizeEnabled(cfg *vaultconfig.Config) bool {
	return cfg != nil && cfg.Vault != nil && cfg.Vault.PseudonymizePaths
}

// cloneEntry creates a deep copy of an entry
func cloneEntry(entry *Entry) *Entry {
	if entry == nil {
		return nil
	}
	clone := &Entry{
		Metadata:       entry.Metadata,
		SecretMetadata: entry.SecretMetadata,
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
	return clone
}

// deepCloneMap creates a deep copy of a map
func deepCloneMap(m map[string]any) any {
	clone := make(map[string]any, len(m))
	for k, v := range m {
		clone[k] = deepCloneValue(v)
	}
	return clone
}

// deepCloneValue creates a deep copy of a value
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

// mergeMaps merges source map into destination map
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

// ExtractTOTP extracts TOTP configuration from entry data.
// Returns the secret, algorithm, digits, period, and a boolean indicating
// whether a valid TOTP configuration was found.
func ExtractTOTP(data map[string]any) (secret, algorithm string, digits, period int, hasTOTP bool) {
	totpData, ok := data["totp"].(map[string]any)
	if !ok {
		return "", "", 0, 0, false
	}

	secretVal, ok := totpData["secret"].(string)
	if !ok || secretVal == "" {
		return "", "", 0, 0, false
	}

	algorithm = "SHA1"
	if v, ok := totpData["algorithm"].(string); ok && v != "" {
		algorithm = v
	}

	digits = 6
	if v, ok := totpData["digits"].(float64); ok {
		digits = int(v)
	}

	period = 30
	if v, ok := totpData["period"].(float64); ok {
		period = int(v)
	}

	return secretVal, algorithm, digits, period, true
}

// GetField retrieves a field value from the entry's data map.
func (e *Entry) GetField(name string) (any, bool) {
	if e.Data == nil {
		return nil, false
	}
	val, ok := e.Data[name]
	return val, ok
}

// fieldString converts a Data field value to a string representation.
func fieldString(v any) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	default:
		return fmt.Sprint(v)
	}
}

// FieldUntrusted returns a field value wrapped as taint.Untrusted with
// provenance tracking. Returns (Untrusted{}, false) if the field does
// not exist.
func (e *Entry) FieldUntrusted(name string) (taint.Untrusted, bool) {
	val, ok := e.GetField(name)
	if !ok {
		return taint.Untrusted{}, false
	}
	return taint.Wrap(fieldString(val), taint.Provenance{
		Source:    "vault.field",
		EntryPath: e.Path,
		FieldName: name,
	}), true
}

// TagsUntrusted returns all entry tags as Untrusted values with
// provenance tracking. Returns an empty slice (not nil) for entries
// with no tags.
func (e *Entry) TagsUntrusted() []taint.Untrusted {
	if len(e.Metadata.Tags) == 0 {
		return []taint.Untrusted{}
	}
	result := make([]taint.Untrusted, len(e.Metadata.Tags))
	for i, tag := range e.Metadata.Tags {
		result[i] = taint.Wrap(tag, taint.Provenance{
			Source:    "vault.tag",
			EntryPath: e.Path,
		})
	}
	return result
}

// UsageHintUntrusted returns the entry's UsageHint as an Untrusted value
// with provenance tracking. Returns an empty Untrusted if no UsageHint
// is set.
func (e *Entry) UsageHintUntrusted() taint.Untrusted {
	return taint.Wrap(e.SecretMetadata.UsageHint, taint.Provenance{
		Source:    "vault.usage_hint",
		EntryPath: e.Path,
	})
}

// Handles returns a SecretHandle for each field in the entry's Data map.
// The path parameter is used as the handle path (typically e.Path).
func (e *Entry) Handles(path string) []taint.SecretHandle {
	if len(e.Data) == 0 {
		return nil
	}
	result := make([]taint.SecretHandle, 0, len(e.Data))
	for field := range e.Data {
		result = append(result, taint.SecretHandle{
			Path:  path,
			Field: field,
		})
	}
	return result
}

// GetEntryMetadata reads only the metadata from an entry without decrypting the full entry.
// This is useful for cache validation where only freshness information is needed.
// Returns the metadata and a boolean indicating if the entry exists.
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

	// Only unmarshal the metadata portion for efficiency
	var entry struct {
		Metadata EntryMetadata `json:"meta"`
	}
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		return nil, err
	}

	return &entry.Metadata, nil
}

// SetField sets a field value in the entry's data map
func (e *Entry) SetField(name string, value any) {
	if e.Data == nil {
		e.Data = make(map[string]any)
	}
	e.Data[name] = value
}

// HasField checks if a field exists in the entry
func (e *Entry) HasField(name string) bool {
	if e.Data == nil {
		return false
	}
	_, ok := e.Data[name]
	return ok
}
