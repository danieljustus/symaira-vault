package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/fsutil"
)

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
	if err := fsutil.ValidatePath(path); err != nil {
		return fmt.Errorf("entry path %q: %w", path, err)
	}
	// Reject "." segments
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
	if err := SafeMkdirAll(entriesDirClean, 0o700); err != nil {
		return err
	}
	return filepath.Walk(vaultDirClean, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
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
		if filepath.Ext(path) != ".age" {
			return nil
		}
		rel, err := filepath.Rel(vaultDirClean, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		if relSlash == "identity.age" || relSlash == "manifest.age" {
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
		return os.Rename(path, target)
	})
}

func entryFilePath(vaultDir, path string) string {
	return filepath.Join(entriesDir(vaultDir), filepath.FromSlash(path)+".age")
}

func derivePseudonymizationKey(identity *age.X25519Identity) []byte {
	h := sha256.Sum256([]byte(identity.String()))
	return h[:]
}

func pseudonymizePath(path string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(path))
	return hex.EncodeToString(mac.Sum(nil))
}

func entryStoragePath(vaultDir, path string, identity *age.X25519Identity, cfg *vaultconfig.Config) string {
	if identity != nil && isPseudonymizeEnabled(cfg) {
		key := derivePseudonymizationKey(identity)
		hash := pseudonymizePath(path, key)
		return filepath.Join(entriesDir(vaultDir), hash[:2], hash+".age")
	}
	return entryFilePath(vaultDir, path)
}


func entryStoragePathCached(vaultDir, path string, cfg *vaultconfig.Config, pseudoKey []byte) string {
	if pseudoKey != nil {
		hash := pseudonymizePath(path, pseudoKey)
		return filepath.Join(entriesDir(vaultDir), hash[:2], hash+".age")
	}
	return entryFilePath(vaultDir, path)
}

func isPseudonymizeEnabled(cfg *vaultconfig.Config) bool {
	return cfg != nil && cfg.Vault != nil && cfg.Vault.PseudonymizePaths
}
