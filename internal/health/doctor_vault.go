package health

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func checkVaultInitialized(vaultDir string, _ Options) Result {
	r := Result{ID: "vault.initialized", Name: "Vault initialized"}
	if vault.IsInitialized(vaultDir) {
		r.Status = StatusOK
		r.Message = "config.yaml and identity.age present"
	} else {
		r.Status = StatusFail
		r.Message = "vault not initialized at " + vaultDir
		r.Hint = "run `openpass init` or `openpass setup`"
	}
	return r
}

func checkVaultConfigParses(vaultDir string, _ Options) Result {
	r := Result{ID: "vault.config.parses", Name: "Vault config parses"}
	cfgPath := filepath.Join(vaultDir, "config.yaml")
	if _, err := configpkg.Load(cfgPath); err != nil {
		r.Status = StatusFail
		r.Message = "config.yaml parse error: " + err.Error()
		r.Hint = "inspect " + cfgPath + " for YAML syntax errors"
		return r
	}
	r.Status = StatusOK
	r.Message = "config.yaml loads without errors"
	return r
}

func checkVaultIdentityEncrypted(vaultDir string, _ Options) Result {
	r := Result{ID: "vault.identity.encrypted", Name: "Identity encrypted"}
	identityPath := filepath.Join(vaultDir, "identity.age")
	data, err := os.ReadFile(identityPath) //#nosec G304 -- vaultDir is controlled
	if err != nil {
		if os.IsNotExist(err) {
			r.Status = StatusFail
			r.Message = "identity.age not found"
			r.Hint = "run `openpass init` to create an encrypted identity"
			return r
		}
		r.Status = StatusFail
		r.Message = "cannot read identity.age: " + err.Error()
		return r
	}
	// age files start with "age-encryption.org/v1" (binary) or the PEM armor header.
	s := string(data)
	if strings.HasPrefix(s, "age-encryption.org/v1") || strings.Contains(s, "AGE ENCRYPTED FILE") {
		r.Status = StatusOK
		r.Message = "identity.age is age-encrypted"
	} else {
		r.Status = StatusFail
		r.Message = "identity.age does not appear to be age-encrypted"
		r.Hint = "the file may be corrupted; re-initialize with `openpass init`"
	}
	return r
}

func checkVaultPermissions(vaultDir string, _ Options) Result {
	r := Result{ID: "vault.permissions", Name: "File permissions"}

	// Unix file permission semantics do not apply on Windows.
	if runtime.GOOS == "windows" {
		r.Status = StatusOK
		r.Message = "not applicable on Windows"
		return r
	}
	r.Fixable = true
	r.Fix = func() error {
		if FixDryRun {
			return nil
		}
		// #nosec G302 -- directory needs execute bit
		if err := os.Chmod(filepath.Join(vaultDir, "entries"), 0o700); err != nil {
			return fmt.Errorf("chmod entries: %w", err)
		}
		// #nosec G302 -- identity file intentionally restricted
		if err := os.Chmod(filepath.Join(vaultDir, "identity.age"), 0o600); err != nil {
			return fmt.Errorf("chmod identity.age: %w", err)
		}
		return nil
	}
	var issues []string

	entriesDir := filepath.Join(vaultDir, "entries")
	if info, err := os.Stat(entriesDir); err == nil {
		perm := info.Mode().Perm()
		if perm&0o077 != 0 {
			issues = append(issues, fmt.Sprintf("entries/ has mode %o (expected 0700)", perm))
		}
	}

	identityPath := filepath.Join(vaultDir, "identity.age")
	if info, err := os.Stat(identityPath); err == nil {
		perm := info.Mode().Perm()
		if perm&0o177 != 0 {
			issues = append(issues, fmt.Sprintf("identity.age has mode %o (expected 0600)", perm))
		}
	}

	if len(issues) > 0 {
		r.Status = StatusWarn
		r.Message = strings.Join(issues, "; ")
		r.Hint = "run `chmod 0700 " + entriesDir + " && chmod 0600 " + identityPath + "`"
	} else {
		r.Status = StatusOK
		r.Message = "entries/=0700, identity.age=0600"
	}
	return r
}

func checkManifestIntegrity(vaultDir string, _ Options) Result {
	r := Result{ID: "vault.manifest.intact", Name: "Entry manifest integrity"}

	manifestPath := filepath.Join(vaultDir, "manifest.age")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		r.Status = StatusWarn
		r.Message = "no manifest.age — entry integrity not tracked"
		r.Hint = "run `openpass verify` to create and verify a manifest"
		return r
	}

	identity := vault.CurrentSearchIdentity()
	if identity == nil {
		r.Status = StatusWarn
		r.Message = msgSessionNeeded
		r.Hint = "run `openpass unlock` to decrypt your identity for manifest verification"
		return r
	}

	result, err := vault.VerifyManifestIntegrity(vaultDir, identity)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot verify manifest: " + err.Error()
		r.Hint = "run `openpass verify` to regenerate manifest"
		return r
	}

	var issues []string
	if len(result.Tampered) > 0 {
		issues = append(issues, fmt.Sprintf("%d tampered: %s", len(result.Tampered), strings.Join(result.Tampered, ", ")))
	}
	if len(result.Missing) > 0 {
		issues = append(issues, fmt.Sprintf("%d missing: %s", len(result.Missing), strings.Join(result.Missing, ", ")))
	}
	if len(result.Unknown) > 0 {
		issues = append(issues, fmt.Sprintf("%d unknown: %s", len(result.Unknown), strings.Join(result.Unknown, ", ")))
	}

	if len(issues) > 0 {
		if len(result.Tampered) > 0 {
			r.Status = StatusFail
		} else {
			r.Status = StatusWarn
		}
		r.Message = strings.Join(issues, "; ")
		r.Hint = "run `openpass verify` to regenerate manifest"
		return r
	}

	r.Status = StatusOK
	r.Message = fmt.Sprintf("all %d entries verified", result.OK)
	return r
}

func checkVaultSize(vaultDir string, _ Options) Result {
	r := Result{ID: "vault.size", Name: "Vault size"}
	entriesDir := filepath.Join(vaultDir, "entries")
	var count int
	var totalBytes int64
	err := filepath.Walk(entriesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil //nolint:nilerr // best-effort walk
		}
		if !info.IsDir() {
			count++
			totalBytes += info.Size()
		}
		return nil
	})
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot walk entries directory: " + err.Error()
		return r
	}
	r.Status = StatusOK
	r.Message = fmt.Sprintf("%d entries, %.2f MB", count, float64(totalBytes)/1024/1024)
	return r
}

func checkPassphraseRotation(vaultDir string, _ Options) Result {
	r := Result{ID: "auth.passphrase.rotation", Name: "Passphrase rotation"}

	cfgPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(cfgPath)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot load config: " + err.Error()
		return r
	}

	if cfg.Vault == nil || cfg.Vault.LastRotated.IsZero() {
		r.Status = StatusWarn
		r.Message = "passphrase never rotated — rotation is recommended for security hygiene"
		r.Hint = "run `openpass auth rotate-passphrase` to rotate"
		return r
	}

	age := time.Since(cfg.Vault.LastRotated)
	if age > 365*24*time.Hour {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("last rotated %s ago (recommended: every 365 days)", age.Round(24*time.Hour))
		r.Hint = "run `openpass auth rotate-passphrase` to rotate"
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("last rotated %s ago", age.Round(24*time.Hour))
	}
	return r
}
