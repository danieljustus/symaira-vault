// Package health provides the openpass doctor health checks.
package health

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
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

const (
	osDarwin = "darwin"
	osLinux  = "linux"

	msgSessionNeeded  = "no active session — run `openpass unlock` first"
	hintSessionNeeded = "run `openpass unlock` to decrypt entries for password strength analysis"
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
	Tags    []string     `json:"tags,omitempty"`
	Fixable bool         `json:"fixable"`         // set to true by checks with a fix
	Fix     func() error `json:"-"`               // closure, nil for non-fixable checks
	Fixed   bool         `json:"fixed,omitempty"` // set to true after successful fix
}

// Options controls which checks are run.
type Options struct {
	NoNetwork bool
	Quick     bool
	Version   string
	Only      []string
	Exclude   []string
}

// FixDryRun controls whether fix closures should skip actual modifications.
// Set to true to log intent without applying changes.
var FixDryRun bool

// matchesAny returns true if name matches any pattern via path.Match.
func matchesAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// hasTag returns true if tags contains the target string.
func hasTag(tags []string, target string) bool {
	for _, t := range tags {
		if t == target {
			return true
		}
	}
	return false
}

// checkDef pairs a check function with its tags for filtering.
type checkDef struct {
	fn   func(string, Options) Result
	tags []string
}

// allChecks is the single source of truth for all doctor health checks.
// Each checkDef pairs a check function with tags for filtering (e.g., "network", "slow").
var allChecks = []checkDef{
	{fn: checkVaultInitialized},
	{fn: checkVaultConfigParses},
	{fn: checkVaultIdentityEncrypted},
	{fn: checkVaultPermissions},
	{fn: checkAuthMethod},
	{fn: checkSessionCache},
	{fn: checkGitRepo},
	{fn: checkGitRemote},
	{fn: checkGitignoreProtects},
	{fn: checkGitLastSync, tags: []string{"network"}},
	{fn: checkRecipients},
	{fn: checkRecipientsRecovery},
	{fn: checkMCPTokens},
	{fn: checkAuditLog},
	{fn: checkUpdateAvailable, tags: []string{"network", "slow"}},
	{fn: checkVaultSize},
	{fn: checkScryptBenchmark, tags: []string{"slow"}},
	{fn: checkKDFModern},
	{fn: checkManifestIntegrity},
	{fn: checkPassphraseRotation},
	{fn: checkAutoTypeBackend},
	{fn: checkClipboardBackend},
	{fn: checkDaemonStatus},
	{fn: checkMCPServer, tags: []string{"network"}},
	{fn: checkDynamicSecretEngines},
	{fn: checkMCPAgents},
	{fn: checkSecureUI},
	{fn: checkPreCommitHooks},
	{fn: checkSessionKeyring},
	{fn: checkPasswordStrength, tags: []string{"slow"}},
	{fn: checkPasswordReuse, tags: []string{"slow"}},
}

// RunChecks runs all doctor checks against vaultDir and returns the results.
func RunChecks(vaultDir string, opts Options) []Result {
	checks := allChecks

	if opts.NoNetwork {
		filtered := make([]checkDef, 0, len(checks))
		for _, c := range checks {
			if !hasTag(c.tags, "network") {
				filtered = append(filtered, c)
			}
		}
		checks = filtered
	}

	if opts.Quick {
		filtered := make([]checkDef, 0, len(checks))
		for _, c := range checks {
			if !hasTag(c.tags, "slow") {
				filtered = append(filtered, c)
			}
		}
		checks = filtered
	}

	results := make([]Result, 0, len(checks))
	for _, c := range checks {
		results = append(results, c.fn(vaultDir, opts))
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
		if FixDryRun {
			return nil
		}
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
		if FixDryRun {
			return nil
		}
		gitignorePath := filepath.Join(vaultDir, ".gitignore")
		var existing []string
		// #nosec G304 -- vaultDir is controlled
		if data, err := os.ReadFile(gitignorePath); err == nil {
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

// --- DOC-13: Auto-type backend check ---

func checkAutoTypeBackend(_ string, _ Options) Result {
	r := Result{ID: "tooling.autotype.backend", Name: "Auto-type backend"}
	switch runtime.GOOS {
	case osDarwin:
		if _, err := exec.LookPath("osascript"); err != nil {
			r.Status = StatusWarn
			r.Message = "osascript not found — autotype unavailable on macOS"
			r.Hint = "install Xcode command line tools: xcode-select --install"
		} else {
			r.Status = StatusOK
			r.Message = "osascript available"
		}
	case osLinux:
		if _, err := exec.LookPath("xdotool"); err != nil {
			r.Status = StatusWarn
			r.Message = "xdotool not found — autotype unavailable on X11"
			r.Hint = "install xdotool (apt install xdotool, dnf install xdotool)"
		} else {
			r.Status = StatusOK
			r.Message = "xdotool available"
		}
	default:
		r.Status = StatusOK
		r.Message = "not applicable on " + runtime.GOOS
	}
	return r
}

// --- DOC-14: Clipboard backend check ---

func checkClipboardBackend(_ string, _ Options) Result {
	r := Result{ID: "tooling.clipboard.backend", Name: "Clipboard backend"}
	switch runtime.GOOS {
	case osDarwin:
		if _, err := exec.LookPath("pbcopy"); err != nil {
			r.Status = StatusWarn
			r.Message = "pbcopy not found — clipboard unavailable"
		} else {
			r.Status = StatusOK
			r.Message = "pbcopy available"
		}
	case osLinux:
		for _, name := range []string{"xclip", "wl-copy"} {
			if _, err := exec.LookPath(name); err == nil {
				r.Status = StatusOK
				r.Message = name + " available"
				return r
			}
		}
		r.Status = StatusWarn
		r.Message = "no clipboard tool found (xclip or wl-clipboard)"
		r.Hint = "install xclip (apt install xclip) or wl-clipboard (apt install wl-clipboard)"
	default:
		r.Status = StatusOK
		r.Message = "not applicable on " + runtime.GOOS
	}
	return r
}

// --- DOC-15: Daemon status check ---

func checkDaemonStatus(_ string, _ Options) Result {
	r := Result{ID: "daemon.status", Name: "Daemon status"}
	home, err := os.UserHomeDir()
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot determine home directory"
		return r
	}
	var svcPath string
	switch runtime.GOOS {
	case osDarwin:
		svcPath = filepath.Join(home, "Library", "LaunchAgents", "com.openpass.mcp.plist")
	case osLinux:
		svcPath = filepath.Join(home, ".config", "systemd", "user", "openpass-mcp.service")
	default:
		r.Status = StatusOK
		r.Message = "daemon not supported on " + runtime.GOOS
		return r
	}
	info, err := os.Stat(svcPath)
	if err != nil {
		if os.IsNotExist(err) {
			r.Status = StatusOK
			r.Message = "daemon not installed"
			return r
		}
		r.Status = StatusWarn
		r.Message = "cannot stat daemon file: " + err.Error()
		return r
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("daemon file has mode %o (expected 0600)", perm)
		r.Hint = "run chmod 0600 " + svcPath
	} else {
		r.Status = StatusOK
		r.Message = "daemon installed with correct permissions"
	}
	return r
}

// --- DOC-16: MCP server reachability check ---

func checkMCPServer(vaultDir string, _ Options) Result {
	r := Result{ID: "mcp.server.reachable", Name: "MCP server reachable"}
	cfgPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(cfgPath)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot load config: " + err.Error()
		return r
	}
	port := 8080
	if cfg.MCP != nil && cfg.MCP.Port > 0 {
		port = cfg.MCP.Port
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/health", port)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot create request: " + err.Error()
		return r
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "MCP server not reachable at " + url
		r.Hint = "start the server with `openpass serve --port " + strconv.Itoa(port) + "`"
		return r
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("MCP server returned HTTP %d", resp.StatusCode)
		return r
	}
	r.Status = StatusOK
	r.Message = "server reachable at " + url
	// Check token presence for HTTP auth
	tokenPath := filepath.Join(vaultDir, "mcp-token")
	if _, err := os.Stat(tokenPath); err == nil {
		r.Message += ", token present"
	} else {
		r.Message += ", no token file"
		r.Hint = "generate an MCP token with `openpass mcp token create`"
	}
	return r
}

// --- DOC-17: Dynamic secret engines check ---

func checkDynamicSecretEngines(vaultDir string, _ Options) Result {
	r := Result{ID: "mcp.dynamic.engines", Name: "Dynamic secret engines"}
	cfgPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(cfgPath)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot load config: " + err.Error()
		return r
	}
	var configured bool
	for _, profile := range cfg.Agents {
		if len(profile.DynamicProviders) > 0 {
			configured = true
			break
		}
	}
	if !configured {
		r.Status = StatusOK
		r.Message = "no dynamic providers configured"
		return r
	}
	r.Status = StatusWarn
	r.Message = "dynamic providers configured but engines not registered"
	r.Hint = "dynamic provider engines were never wired to the MCP server"
	return r
}

// --- DOC-18: MCP agents check ---

func checkMCPAgents(vaultDir string, _ Options) Result {
	r := Result{ID: "mcp.agents", Name: "MCP agents configured"}
	cfgPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(cfgPath)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot load config: " + err.Error()
		return r
	}
	knownAgents := []string{"claude-code", "codex", "opencode", "hermes", "openclaw"}
	var found []string
	for _, agent := range knownAgents {
		if _, ok := cfg.Agents[agent]; ok {
			found = append(found, agent)
		}
	}
	if len(found) > 0 {
		r.Status = StatusOK
		r.Message = strings.Join(found, ", ") + " configured"
	} else {
		r.Status = StatusOK
		r.Message = "no AI agent MCP configs found"
		r.Hint = "run `openpass mcp-config <agent>` to generate config"
	}
	return r
}

// --- DOC-19: Secure input UI check ---

func checkSecureUI(_ string, _ Options) Result {
	r := Result{ID: "tooling.secureui", Name: "Secure input UI"}
	switch runtime.GOOS {
	case osDarwin:
		if _, err := exec.LookPath("osascript"); err != nil {
			r.Status = StatusWarn
			r.Message = "osascript not found — secure input dialogs unavailable"
		} else {
			r.Status = StatusOK
			r.Message = "osascript available (GUI dialogs)"
		}
	case osLinux:
		var found string
		for _, name := range []string{"zenity", "kdialog"} {
			if _, err := exec.LookPath(name); err == nil {
				found = name
				break
			}
		}
		if found != "" {
			r.Status = StatusOK
			r.Message = found + " available (GUI dialogs)"
		} else {
			r.Status = StatusWarn
			r.Message = "no GUI dialog tool found (zenity or kdialog)"
			r.Hint = "install zenity (apt install zenity) or kdialog"
		}
	default:
		r.Status = StatusOK
		r.Message = "no GUI secure input available on " + runtime.GOOS
	}
	return r
}

// --- DOC-20: Pre-commit hooks check ---

func checkPreCommitHooks(_ string, _ Options) Result {
	r := Result{ID: "tooling.precommit", Name: "Pre-commit hooks"}
	cwd, err := os.Getwd()
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot determine working directory"
		return r
	}
	preCommitPath := filepath.Join(cwd, ".pre-commit-config.yaml")
	if _, statErr := os.Stat(preCommitPath); os.IsNotExist(statErr) {
		r.Status = StatusOK
		r.Message = "no .pre-commit-config.yaml (not a dev environment)"
		return r
	}
	gitDir := filepath.Join(cwd, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	if _, statErr := os.Stat(hooksDir); os.IsNotExist(statErr) {
		r.Status = StatusWarn
		r.Message = ".pre-commit-config.yaml exists but not a git repository"
		return r
	}
	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot read hooks directory: " + err.Error()
		return r
	}
	var hookCount int
	for _, e := range entries {
		if !e.IsDir() && e.Name() != ".gitignore" {
			hookCount++
		}
	}
	if hookCount == 0 {
		r.Status = StatusWarn
		r.Message = "pre-commit hooks not installed"
		r.Hint = "run `pre-commit install` to activate hooks"
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("%d hook(s) installed", hookCount)
	}
	return r
}

// --- DOC-21: Session keyring roundtrip check ---

func checkSessionKeyring(vaultDir string, _ Options) Result {
	r := Result{ID: "session.keyring", Name: "Session keyring roundtrip"}
	testData := "openpass-doctor-test"

	saveDone := make(chan error, 1)
	go func() {
		saveDone <- session.SavePassphrase(vaultDir, []byte(testData), 10*time.Second)
	}()
	select {
	case err := <-saveDone:
		if err != nil {
			r.Status = StatusWarn
			r.Message = "cannot write to keyring: " + err.Error()
			r.Hint = "check OS keyring availability (macOS Keychain, GNOME Keyring, etc.)"
			return r
		}
	case <-time.After(5 * time.Second):
		r.Status = StatusWarn
		r.Message = "save to keyring timed out — keyring unavailable in this environment"
		return r
	}

	loadDone := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data, err := session.LoadPassphrase(vaultDir)
		loadDone <- struct {
			data []byte
			err  error
		}{data, err}
	}()
	var loaded []byte
	select {
	case res := <-loadDone:
		if res.err != nil {
			r.Status = StatusFail
			r.Message = "keyring roundtrip failed: " + res.err.Error()
			_ = session.ClearSession(vaultDir)
			return r
		}
		loaded = res.data
	case <-time.After(5 * time.Second):
		r.Status = StatusWarn
		r.Message = "load from keyring timed out — keyring unavailable in this environment"
		_ = session.ClearSession(vaultDir)
		return r
	}

	if string(loaded) != testData {
		r.Status = StatusFail
		r.Message = "keyring returned corrupted data"
		_ = session.ClearSession(vaultDir)
		return r
	}
	_ = session.ClearSession(vaultDir)
	r.Status = StatusOK
	r.Message = "keyring encrypt/decrypt roundtrip OK"
	return r
}

// --- DOC-22: Password strength check ---

func checkPasswordStrength(vaultDir string, _ Options) Result {
	r := Result{ID: "password.strength", Name: "Weak password detection"}

	identity := vault.CurrentSearchIdentity()
	if identity == nil {
		r.Status = StatusWarn
		r.Message = msgSessionNeeded
		r.Hint = hintSessionNeeded
		return r
	}

	paths, err := vault.List(vaultDir, "")
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot list entries: " + err.Error()
		return r
	}

	var weakCount int
	var examplePaths []string
	for _, path := range paths {
		entry, err := vault.ReadEntry(vaultDir, path, identity)
		if err != nil {
			continue
		}
		pwd, ok := entry.GetField("password")
		if !ok {
			continue
		}
		pwdStr, ok := pwd.(string)
		if !ok || pwdStr == "" {
			continue
		}
		s := vaultcrypto.AssessPasswordStrength(pwdStr)
		if s.Weak {
			weakCount++
			if len(examplePaths) < 5 {
				examplePaths = append(examplePaths, path)
			}
		}
	}

	if weakCount > 0 {
		examples := strings.Join(examplePaths, ", ")
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("%d entries with weak passwords", weakCount)
		r.Hint = fmt.Sprintf("review and strengthen: %s", examples)
	} else {
		r.Status = StatusOK
		r.Message = "all entries meet password strength requirements"
	}
	return r
}

// --- DOC-23: Password reuse check ---

func checkPasswordReuse(vaultDir string, _ Options) Result {
	r := Result{ID: "password.reuse", Name: "Password reuse detection"}

	identity := vault.CurrentSearchIdentity()
	if identity == nil {
		r.Status = StatusWarn
		r.Message = msgSessionNeeded
		r.Hint = "run `openpass unlock` to decrypt entries for password reuse analysis"
		return r
	}

	paths, err := vault.List(vaultDir, "")
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot list entries: " + err.Error()
		return r
	}

	hashToPaths := make(map[string][]string)
	for _, path := range paths {
		entry, err := vault.ReadEntry(vaultDir, path, identity)
		if err != nil {
			continue
		}
		pwd, ok := entry.GetField("password")
		if !ok {
			continue
		}
		pwdStr, ok := pwd.(string)
		if !ok || pwdStr == "" {
			continue
		}
		h := sha256.Sum256([]byte(pwdStr))
		hashHex := hex.EncodeToString(h[:])
		hashToPaths[hashHex] = append(hashToPaths[hashHex], path)
	}

	var reusedGroups [][]string
	for _, ec := range hashToPaths {
		if len(ec) > 1 {
			reusedGroups = append(reusedGroups, ec)
		}
	}

	if len(reusedGroups) > 0 {
		sort.Slice(reusedGroups, func(i, j int) bool {
			return len(reusedGroups[i]) > len(reusedGroups[j])
		})
		r.Status = StatusWarn
		if len(reusedGroups) == 1 {
			sort.Strings(reusedGroups[0])
			r.Message = fmt.Sprintf("%d entries share the same password", len(reusedGroups[0]))
			r.Hint = fmt.Sprintf("entries: %s", strings.Join(reusedGroups[0], ", "))
		} else {
			r.Message = fmt.Sprintf("%d sets of entries with shared passwords", len(reusedGroups))
			if len(reusedGroups) > 3 {
				r.Hint = fmt.Sprintf("top groups: %s", formatReuseGroups(reusedGroups[:3]))
			} else {
				r.Hint = formatReuseGroups(reusedGroups)
			}
		}
	} else {
		r.Status = StatusOK
		r.Message = "no reused passwords detected"
	}
	return r
}

func formatReuseGroups(groups [][]string) string {
	var parts []string
	for _, g := range groups {
		sort.Strings(g)
		entries := strings.Join(g, ", ")
		if len(g) > 5 {
			entries = strings.Join(g[:5], ", ") + fmt.Sprintf(", ... (%d total)", len(g))
		}
		parts = append(parts, fmt.Sprintf("%d entries: %s", len(g), entries))
	}
	return strings.Join(parts, "; ")
}
