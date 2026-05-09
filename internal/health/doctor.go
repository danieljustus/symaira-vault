// Package health provides the openpass doctor health checks.
package health

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/danieljustus/OpenPass/internal/audit"
	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/git"
	"github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/session"
	"github.com/danieljustus/OpenPass/internal/update"
	"github.com/danieljustus/OpenPass/internal/vault"
)

// Status represents the outcome of a single check.
type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
)

// Result is the outcome of one health check.
type Result struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

// Options controls which checks are run.
type Options struct {
	NoNetwork bool
}

// RunChecks runs all doctor checks against vaultDir and returns the results.
func RunChecks(vaultDir string, opts Options) []Result {
	checks := []func(string, Options) Result{
		checkVaultInitialized,
		checkVaultConfigParses,
		checkVaultIdentityEncrypted,
		checkVaultPermissions,
		checkAuthMethod,
		checkSessionCache,
		checkGitRepo,
		checkGitRemote,
		checkGitignoreProtects,
		checkGitLastSync,
		checkRecipients,
		checkMCPTokens,
		checkAuditLog,
		checkUpdateAvailable,
		checkVaultSize,
	}

	if opts.NoNetwork {
		checks = []func(string, Options) Result{
			checkVaultInitialized,
			checkVaultConfigParses,
			checkVaultIdentityEncrypted,
			checkVaultPermissions,
			checkAuthMethod,
			checkSessionCache,
			checkGitRepo,
			checkGitRemote,
			checkGitignoreProtects,
			checkRecipients,
			checkMCPTokens,
			checkAuditLog,
			checkVaultSize,
		}
	}

	results := make([]Result, 0, len(checks))
	for _, fn := range checks {
		results = append(results, fn(vaultDir, opts))
	}
	return results
}

// Score returns counts of ok, warn, and fail from a result set.
func Score(results []Result) (ok, warn, fail int) {
	for _, r := range results {
		switch r.Status {
		case StatusOK:
			ok++
		case StatusWarn:
			warn++
		case StatusFail:
			fail++
		}
	}
	return
}

// --- DOC-2: Vault checks ---

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

// --- DOC-3: Auth checks ---

func checkAuthMethod(vaultDir string, _ Options) Result {
	r := Result{ID: "auth.method", Name: "Auth method"}
	cfgPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(cfgPath)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot load config to determine auth method"
		return r
	}
	method := cfg.EffectiveAuthMethod()
	if method == configpkg.AuthMethodTouchID {
		if session.BiometricAvailable() {
			r.Status = StatusOK
			r.Message = "passphrase + Touch ID active"
		} else {
			r.Status = StatusWarn
			r.Message = "configured as Touch ID but biometric not available on this system"
			r.Hint = "run `openpass auth set passphrase` to switch to passphrase-only"
		}
	} else {
		r.Status = StatusOK
		r.Message = "auth method: " + method
	}
	return r
}

func checkSessionCache(vaultDir string, _ Options) Result {
	r := Result{ID: "session.cache", Name: "Session cache"}
	status := session.GetCacheStatus()
	r.Status = StatusOK
	if status.Backend == "memory" || status.Backend == "" {
		r.Status = StatusWarn
		r.Message = "session cache uses in-memory backend (not persistent)"
		r.Hint = "install a system keyring (macOS Keychain, GNOME Keyring, KWallet) for persistent sessions"
	} else {
		r.Message = fmt.Sprintf("backend: %s, persistent: %v", status.Backend, status.Persistent)
	}
	return r
}

// --- DOC-4: Git local checks ---

func checkGitRepo(vaultDir string, _ Options) Result {
	r := Result{ID: "git.repo", Name: "Git repository"}
	gitDir := filepath.Join(vaultDir, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		r.Status = StatusOK
		r.Message = ".git directory present"
	} else {
		r.Status = StatusWarn
		r.Message = "no git repository in vault directory"
		r.Hint = "run `openpass git init` to enable version history and sync"
	}
	return r
}

func checkGitRemote(vaultDir string, _ Options) Result {
	r := Result{ID: "git.remote", Name: "Git remote"}
	has, err := git.HasRemote(vaultDir, "origin")
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot determine git remote: " + err.Error()
		return r
	}
	if has {
		r.Status = StatusOK
		r.Message = "remote 'origin' configured"
	} else {
		r.Status = StatusWarn
		r.Message = "no remote 'origin' — vault is local-only"
		r.Hint = "run `openpass git remote add origin <url>` to enable sync"
	}
	return r
}

func checkGitignoreProtects(vaultDir string, _ Options) Result {
	r := Result{ID: "git.gitignore.protects", Name: ".gitignore protects sensitive files"}
	gitignorePath := filepath.Join(vaultDir, ".gitignore")
	data, err := os.ReadFile(gitignorePath) //#nosec G304 -- vaultDir is controlled
	if err != nil {
		if os.IsNotExist(err) {
			r.Status = StatusWarn
			r.Message = ".gitignore missing"
			r.Hint = "run `openpass git init` to create a protective .gitignore"
			return r
		}
		r.Status = StatusWarn
		r.Message = "cannot read .gitignore: " + err.Error()
		return r
	}
	content := string(data)
	required := []string{"identity.age", "mcp-token", "mcp-tokens.json"}
	var missing []string
	for _, entry := range required {
		if !strings.Contains(content, entry) {
			missing = append(missing, entry)
		}
	}
	if len(missing) > 0 {
		r.Status = StatusWarn
		r.Message = ".gitignore missing entries: " + strings.Join(missing, ", ")
		r.Hint = "add missing entries to " + gitignorePath
	} else {
		r.Status = StatusOK
		r.Message = "identity.age, mcp-token, mcp-tokens.json are gitignored"
	}
	return r
}

// --- DOC-5: Git network checks ---

func checkGitLastSync(vaultDir string, _ Options) Result {
	r := Result{ID: "git.lastsync.fresh", Name: "Last sync fresh"}
	t, err := git.LastSyncTime(vaultDir)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot determine last sync time: " + err.Error()
		return r
	}
	if t.IsZero() {
		r.Status = StatusWarn
		r.Message = "no sync recorded yet"
		r.Hint = "run `openpass git push` to sync your vault"
		return r
	}
	age := time.Since(t).Round(time.Hour)
	if age > 7*24*time.Hour {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("last sync %s ago", age)
		r.Hint = "run `openpass git pull` to sync latest changes"
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("last sync %s ago", age)
	}
	return r
}

// --- DOC-6: Recipients check ---

func checkRecipients(vaultDir string, _ Options) Result {
	r := Result{ID: "recipients.count", Name: "Recipients"}
	rm := vault.NewRecipientsManager(vaultDir)
	recipients, err := rm.ListRecipients()
	if err != nil {
		if !rm.RecipientsFileExists() {
			r.Status = StatusWarn
			r.Message = "no recipients file — single-device risk"
			r.Hint = "add a backup recipient: `openpass recipients add <age1...>`"
			return r
		}
		r.Status = StatusWarn
		r.Message = "cannot read recipients: " + err.Error()
		return r
	}
	count := len(recipients)
	if count <= 1 {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("%d recipient (self only) — if identity is lost, vault is unrecoverable", count)
		r.Hint = "add a backup recipient: `openpass recipients add <age1...>`"
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("%d recipients configured", count)
	}
	return r
}

// --- DOC-7: MCP token checks ---

func checkMCPTokens(vaultDir string, _ Options) Result {
	r := Result{ID: "mcp.tokens", Name: "MCP tokens"}
	reg, _, err := mcp.LoadTokenSystem(vaultDir)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot load MCP token registry: " + err.Error()
		return r
	}
	tokens := reg.List()
	if len(tokens) == 0 {
		r.Status = StatusOK
		r.Message = "no MCP tokens configured"
		return r
	}

	const rotationThreshold = 90 * 24 * time.Hour
	var old, expired int
	for _, t := range tokens {
		if t.IsExpired() {
			expired++
		} else if time.Since(t.CreatedAt) > rotationThreshold {
			old++
		}
	}

	active := len(tokens) - expired
	if old > 0 || expired > 0 {
		r.Status = StatusWarn
		parts := []string{fmt.Sprintf("%d active", active)}
		if old > 0 {
			parts = append(parts, fmt.Sprintf("%d older than 90d", old))
		}
		if expired > 0 {
			parts = append(parts, fmt.Sprintf("%d expired/revoked", expired))
		}
		r.Message = strings.Join(parts, ", ")
		r.Hint = "rotate old tokens with `openpass mcp-token-rotate`"
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("%d active token(s), all within rotation policy", active)
	}
	return r
}

// --- DOC-8: Audit log checks ---

func checkAuditLog(vaultDir string, _ Options) Result {
	r := Result{ID: "audit.log", Name: "Audit log"}
	// Find audit log files: ~/.openpass/audit-*.log
	pattern := filepath.Join(vaultDir, "audit-*.log")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		r.Status = StatusOK
		r.Message = "no audit logs (MCP not used yet)"
		return r
	}

	// HMAC key is shared across all audit logs in the vault directory.
	hmacKeyPath := filepath.Join(vaultDir, "audit-hmac-key")
	var issues []string
	var totalSize int64
	for _, logPath := range matches {
		info, statErr := os.Stat(logPath)
		if statErr == nil {
			totalSize += info.Size()
		}
		result, verErr := audit.VerifyLog(logPath, hmacKeyPath)
		if verErr != nil {
			issues = append(issues, fmt.Sprintf("%s: verify error: %v", filepath.Base(logPath), verErr))
			continue
		}
		if result != nil && !result.Valid {
			issues = append(issues, fmt.Sprintf("%s: integrity check failed", filepath.Base(logPath)))
		}
	}

	auditCfg := audit.GetConfig()
	if totalSize >= auditCfg.MaxFileSize {
		issues = append(issues, fmt.Sprintf("total audit size %.1f MB at limit", float64(totalSize)/1024/1024))
	}

	if len(issues) > 0 {
		r.Status = StatusWarn
		r.Message = strings.Join(issues, "; ")
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("%d log file(s), total %.1f MB, integrity OK", len(matches), float64(totalSize)/1024/1024)
	}
	return r
}

// --- DOC-9: Update check ---

func checkUpdateAvailable(vaultDir string, _ Options) Result {
	r := Result{ID: "update.available", Name: "Update check"}
	checker := update.NewChecker(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get current version from build info.
	const currentVersion = "0.0.0" // replaced by build-time injection
	result, err := checker.Check(ctx, currentVersion)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot check for updates: " + err.Error()
		return r
	}
	if !result.Checkable {
		r.Status = StatusOK
		r.Message = "update check not available (dev build)"
		return r
	}
	if result.UpdateAvailable {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("%s → %s available", result.CurrentVersion, result.LatestVersion)
		r.Hint = result.ReleaseURL
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("up to date (%s)", result.CurrentVersion)
	}
	return r
}

// --- DOC-10: Vault size summary ---

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
