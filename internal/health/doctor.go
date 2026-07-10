// Package health provides the symvault doctor health checks.
package health

import (
	"path"
)

const (
	osDarwin = "darwin"
	osLinux  = "linux"

	msgSessionNeeded  = "no active session — run `symvault unlock` first"
	hintSessionNeeded = "run `symvault unlock` to decrypt entries for password strength analysis"
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
	{fn: checkVaultConfigValidates},
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
	{fn: checkSearchIndexPersistence},
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
	{fn: checkEnvPassphrase},
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
