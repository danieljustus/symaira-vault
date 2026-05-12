// Package health provides the openpass doctor health checks.
package health

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/audit"
	configpkg "github.com/danieljustus/OpenPass/internal/config"
	vaultcrypto "github.com/danieljustus/OpenPass/internal/crypto"
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
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Status  Status       `json:"status"`
	Message string       `json:"message"`
	Hint    string       `json:"hint,omitempty"`
	Fixable bool         `json:"fixable"`         // set to true by checks with a fix
	Fix     func() error `json:"-"`               // closure, nil for non-fixable checks
	Fixed   bool         `json:"fixed,omitempty"` // set to true after successful fix
}

// Options controls which checks are run.
type Options struct {
	NoNetwork bool
	Version   string
	Only      []string
	Exclude   []string
}

// matchesAny returns true if name matches any pattern via path.Match.
func matchesAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
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
		checkRecipientsRecovery,
		checkMCPTokens,
		checkAuditLog,
		checkUpdateAvailable,
		checkVaultSize,
		checkScryptBenchmark,
		checkKDFModern,
		checkManifestIntegrity,
		checkPassphraseRotation,
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
			checkRecipientsRecovery,
			checkMCPTokens,
			checkAuditLog,
			checkVaultSize,
			checkScryptBenchmark,
			checkKDFModern,
			checkManifestIntegrity,
			checkPassphraseRotation,
		}
	}

	results := make([]Result, 0, len(checks))
	for _, fn := range checks {
		results = append(results, fn(vaultDir, opts))
	}

	if len(opts.Only) > 0 {
		filtered := make([]Result, 0, len(results))
		for _, r := range results {
			if matchesAny(opts.Only, r.ID) {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	if len(opts.Exclude) > 0 {
		filtered := make([]Result, 0, len(results))
		for _, r := range results {
			if !matchesAny(opts.Exclude, r.ID) {
				filtered = append(filtered, r)
			}
		}
		results = filtered
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

	// Unix file permission semantics do not apply on Windows.
	if runtime.GOOS == "windows" {
		r.Status = StatusOK
		r.Message = "not applicable on Windows"
		return r
	}
	r.Fixable = true
	r.Fix = func() error {
		if err := os.Chmod(filepath.Join(vaultDir, "entries"), 0o700); err != nil { //#nosec G302 -- directory needs execute bit
			return fmt.Errorf("chmod entries: %w", err)
		}
		if err := os.Chmod(filepath.Join(vaultDir, "identity.age"), 0o600); err != nil { //#nosec G302 -- identity file intentionally restricted
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
	r.Fixable = true
	r.Fix = func() error {
		return git.Init(vaultDir)
	}
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
	r.Fixable = true
	r.Fix = func() error {
		gitignorePath := filepath.Join(vaultDir, ".gitignore")
		var existing []string
		if data, err := os.ReadFile(gitignorePath); err == nil { //#nosec G304 -- vaultDir is controlled
			existing = strings.Split(strings.TrimSpace(string(data)), "\n")
		}
		required := []string{"identity.age", "mcp-token", "mcp-tokens.json"}
		var toAdd []string
		for _, entry := range required {
			found := false
			for _, e := range existing {
				if strings.TrimSpace(e) == entry {
					found = true
					break
				}
			}
			if !found {
				toAdd = append(toAdd, entry)
			}
		}
		if len(toAdd) == 0 {
			return nil
		}
		existing = append(existing, toAdd...)
		//#nosec G703 -- gitignorePath is derived from trusted vaultDir
		return os.WriteFile(gitignorePath, []byte(strings.Join(existing, "\n")+"\n"), 0o600)
	}
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

const recipientsListHint = "run `openpass recipients list`"

func checkRecipientsRecovery(vaultDir string, _ Options) Result {
	r := Result{ID: "recipients.recovery", Name: "Recipient decrypt test"}

	rm := vault.NewRecipientsManager(vaultDir)

	if !rm.RecipientsFileExists() {
		r.Status = StatusOK
		r.Message = "no external recipients to test"
		return r
	}

	rawStrings, err := rm.LoadRecipientStrings()
	if err != nil {
		r.Status = StatusFail
		r.Message = "cannot read recipients: " + err.Error()
		r.Hint = recipientsListHint
		return r
	}

	if len(rawStrings) == 0 {
		r.Status = StatusOK
		r.Message = "no external recipients to test"
		return r
	}

	recipients := make([]*age.X25519Recipient, 0, len(rawStrings))
	for _, rs := range rawStrings {
		rec, recErr := vaultcrypto.ValidateRecipient(rs)
		if recErr != nil {
			r.Status = StatusFail
			r.Message = fmt.Sprintf("invalid recipient: %s (%s)", rs, recErr.Error())
			r.Hint = recipientsListHint
			return r
		}
		recipients = append(recipients, rec)
	}

	testIdentity, err := vaultcrypto.GenerateIdentity()
	if err != nil {
		r.Status = StatusFail
		r.Message = "generate test identity: " + err.Error()
		r.Hint = recipientsListHint
		return r
	}

	allRecipients := make([]*age.X25519Recipient, 0, 1+len(recipients))
	allRecipients = append(allRecipients, testIdentity.Recipient())
	allRecipients = append(allRecipients, recipients...)

	testBlob := make([]byte, 32)
	if _, randErr := rand.Read(testBlob); randErr != nil {
		r.Status = StatusFail
		r.Message = "generate test data: " + randErr.Error()
		r.Hint = recipientsListHint
		return r
	}

	ciphertext, err := vaultcrypto.EncryptWithRecipients(testBlob, allRecipients...)
	if err != nil {
		r.Status = StatusFail
		r.Message = "encryption failed: " + err.Error()
		r.Hint = recipientsListHint
		return r
	}

	decrypted, err := vaultcrypto.Decrypt(ciphertext, testIdentity)
	if err != nil {
		r.Status = StatusFail
		r.Message = "decryption failed: " + err.Error()
		r.Hint = recipientsListHint
		return r
	}

	if !bytes.Equal(decrypted, testBlob) {
		r.Status = StatusFail
		r.Message = "decrypted data does not match original"
		r.Hint = recipientsListHint
		return r
	}

	// Count stanzas (lines starting with "-> X25519" before "---")
	lines := strings.Split(string(ciphertext), "\n")
	stanzaCount := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "---") {
			break
		}
		if strings.HasPrefix(line, "-> X25519") {
			stanzaCount++
		}
	}

	expectedCount := len(allRecipients)
	if stanzaCount != expectedCount {
		r.Status = StatusFail
		r.Message = fmt.Sprintf("expected %d stanzas, got %d", expectedCount, stanzaCount)
		r.Hint = recipientsListHint
		return r
	}

	r.Status = StatusOK
	r.Message = fmt.Sprintf("all %d recipients can participate in encryption", len(recipients))
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
	ks := audit.NewKeystore(vaultDir)
	key, keyErr := ks.LoadHMACKey()
	if keyErr != nil {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("cannot read hmac key: %v", keyErr)
		return r
	}

	var issues []string
	var totalSize int64
	for _, logPath := range matches {
		info, statErr := os.Stat(logPath)
		if statErr == nil {
			totalSize += info.Size()
		}
		result, verErr := audit.VerifyLog(logPath, key)
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

func checkUpdateAvailable(vaultDir string, opts Options) Result {
	r := Result{ID: "update.available", Name: "Update check"}
	checker := update.NewChecker(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get current version from build info.
	result, err := checker.Check(ctx, opts.Version)
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

func checkScryptBenchmark(vaultDir string, _ Options) Result {
	r := Result{ID: "crypto.scrypt.benchmark", Name: "Scrypt KDF performance"}
	wf, elapsed, err := vaultcrypto.BenchmarkScryptWorkFactor(250 * time.Millisecond)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "scrypt benchmark failed: " + err.Error()
		return r
	}

	current := vaultcrypto.DefaultScryptWorkFactor
	if cfg, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml")); err == nil && cfg.Vault != nil && cfg.Vault.ScryptWorkFactor > 0 {
		current = cfg.Vault.ScryptWorkFactor
	}
	switch {
	case wf == current:
		r.Status = StatusOK
		r.Message = fmt.Sprintf("config work factor %d matches recommendation (%d, %.0fms)", current, wf, elapsed.Seconds()*1000)
	case wf > current:
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("config work factor %d is below recommended %d (%.0fms)", current, wf, elapsed.Seconds()*1000)
		r.Hint = fmt.Sprintf("set vault.scrypt_work_factor: %d in config.yaml for better security", wf)
	default:
		r.Status = StatusOK
		r.Message = fmt.Sprintf("config work factor %d exceeds recommendation (benchmark: %d, %.0fms)", current, wf, elapsed.Seconds()*1000)
	}
	return r
}

// checkKDFModern checks whether the vault uses a modern KDF (argon2id, format v2+)
// versus legacy scrypt (format v1).
func checkKDFModern(vaultDir string, _ Options) Result {
	r := Result{ID: "crypto.kdf.modern", Name: "KDF modernity"}

	cfgPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(cfgPath)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot check KDF version"
		return r
	}

	if cfg.Vault == nil || cfg.Vault.FormatVersion < 2 {
		r.Status = StatusWarn
		r.Message = "using scrypt KDF (format v1) — argon2id is recommended for 2025+"
		r.Hint = "run `openpass migrate kdf` after backing up your vault"
	} else {
		r.Status = StatusOK
		r.Message = "using argon2id KDF (format v2)"
	}
	return r
}

// --- DOC-11: Manifest integrity check ---

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
		r.Message = "no active session — run `openpass unlock` first"
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

// --- DOC-12: Passphrase rotation check ---

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
