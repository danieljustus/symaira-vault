package health_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/health"
	"github.com/danieljustus/symaira-vault/internal/session"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

func TestRunChecks_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	// vault.initialized should be fail for an empty dir.
	var found bool
	for _, r := range results {
		if r.ID == "vault.initialized" {
			found = true
			if r.Status != health.StatusFail {
				t.Errorf("expected vault.initialized=fail, got %s", r.Status)
			}
		}
	}
	if !found {
		t.Error("vault.initialized check not found")
	}
}

func TestRunChecks_InitializedVault(t *testing.T) {
	dir := t.TempDir()
	// Write minimal vault structure.
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("vaultDir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Write a fake age-encrypted identity file.
	ageContent := "age-encryption.org/v1\n-> scrypt fakesalt\nfakebody\n"
	if err := os.WriteFile(filepath.Join(dir, "identity.age"), []byte(ageContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatal(err)
	}

	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}

	if r := byID["vault.initialized"]; r.Status != health.StatusOK {
		t.Errorf("vault.initialized: expected ok, got %s: %s", r.Status, r.Message)
	}
	if r := byID["vault.identity.encrypted"]; r.Status != health.StatusOK {
		t.Errorf("vault.identity.encrypted: expected ok, got %s: %s", r.Status, r.Message)
	}
}

func TestScore(t *testing.T) {
	results := []health.Result{
		{Status: health.StatusOK},
		{Status: health.StatusOK},
		{Status: health.StatusWarn},
		{Status: health.StatusFail},
	}
	ok, warn, fail := health.Score(results)
	if ok != 2 || warn != 1 || fail != 1 {
		t.Errorf("Score: got ok=%d warn=%d fail=%d", ok, warn, fail)
	}
}

func TestRunChecks_NoNetwork_SkipsGitRemoteReachable(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	for _, r := range results {
		if r.ID == "git.remote.reachable" || r.ID == "update.available" {
			t.Errorf("expected check %s to be skipped with --no-network", r.ID)
		}
	}
}

func TestRunChecks_WithNetwork_IncludesGitLastSync(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{NoNetwork: false})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	// git.lastsync.fresh should be present when NoNetwork=false.
	if _, found := byID["git.lastsync.fresh"]; !found {
		t.Error("expected git.lastsync.fresh check when NoNetwork=false")
	}
	// update.available should be present when NoNetwork=false.
	if _, found := byID["update.available"]; !found {
		t.Error("expected update.available check when NoNetwork=false")
	}
}

func TestRunChecks_GitLastSync_NoGitRepo(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{NoNetwork: false})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	r, found := byID["git.lastsync.fresh"]
	if !found {
		t.Fatal("expected git.lastsync.fresh check")
	}
	// Without a git repo, expect warn (cannot determine last sync time or no sync).
	if r.Status != health.StatusWarn {
		t.Errorf("expected warn for git.lastsync.fresh without git repo, got %s: %s", r.Status, r.Message)
	}
}

func TestRunChecks_VaultIdentityEncrypted_Missing(t *testing.T) {
	dir := t.TempDir()
	// Write config but no identity.age.
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("vaultDir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	r := byID["vault.identity.encrypted"]
	if r.Status != health.StatusFail {
		t.Errorf("expected fail for missing identity.age, got %s: %s", r.Status, r.Message)
	}
}

func TestRunChecks_VaultIdentityEncrypted_NotEncrypted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("vaultDir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Write a non-encrypted identity file.
	if err := os.WriteFile(filepath.Join(dir, "identity.age"), []byte("not-encrypted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	r := byID["vault.identity.encrypted"]
	if r.Status != health.StatusFail {
		t.Errorf("expected fail for non-encrypted identity, got %s: %s", r.Status, r.Message)
	}
}

func TestRunChecks_GitignoreProtects_MissingEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("vaultDir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ageContent := "age-encryption.org/v1\n-> scrypt fakesalt\nfakebody\n"
	if err := os.WriteFile(filepath.Join(dir, "identity.age"), []byte(ageContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Write .gitignore missing required entries.
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*.tmp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	r := byID["git.gitignore.protects"]
	if r.Status != health.StatusWarn {
		t.Errorf("expected warn for gitignore missing entries, got %s: %s", r.Status, r.Message)
	}
}

func TestRunChecks_GitignoreProtects_Complete(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("vaultDir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ageContent := "age-encryption.org/v1\n-> scrypt fakesalt\nfakebody\n"
	if err := os.WriteFile(filepath.Join(dir, "identity.age"), []byte(ageContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatal(err)
	}
	gitignore := "identity.age\nmcp-token\nmcp-tokens.json\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(gitignore), 0o600); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	r := byID["git.gitignore.protects"]
	if r.Status != health.StatusOK {
		t.Errorf("expected ok for complete gitignore, got %s: %s", r.Status, r.Message)
	}
}

func TestRunChecks_AuditLog_WithIntegrityOK(t *testing.T) {
	dir := t.TempDir()
	// Write an audit log file — without an HMAC key, verify will error → warn.
	logPath := filepath.Join(dir, "audit-2026.log")
	if err := os.WriteFile(logPath, []byte(`{"event":"test"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	r := byID["audit.log"]
	// Verify error (no HMAC key) → warn.
	if r.Status == health.StatusFail {
		t.Errorf("unexpected fail for audit.log: %s", r.Message)
	}
}

func TestRunChecks_VaultSize_WithEntries(t *testing.T) {
	dir := t.TempDir()
	entriesDir := filepath.Join(dir, "entries")
	if err := os.MkdirAll(entriesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		p := filepath.Join(entriesDir, fmt.Sprintf("entry%d.age", i))
		if err := os.WriteFile(p, []byte("fake-entry-data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	r := byID["vault.size"]
	if r.Status != health.StatusOK {
		t.Errorf("expected ok for vault.size, got %s: %s", r.Status, r.Message)
	}
}

func TestRunChecks_VaultPermissions_InsecureIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions not enforced on Windows")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("vaultDir: "+dir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ageContent := "age-encryption.org/v1\n-> scrypt fakesalt\nfakebody\n"
	// Write identity with insecure permissions.
	identityPath := filepath.Join(dir, "identity.age")
	if err := os.WriteFile(identityPath, []byte(ageContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	r := byID["vault.permissions"]
	if r.Status != health.StatusWarn {
		t.Errorf("expected warn for insecure permissions, got %s: %s", r.Status, r.Message)
	}
}

func TestRunChecks_GitRemote_WithGitRepo(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	r := byID["git.repo"]
	if r.Status != health.StatusOK {
		t.Errorf("expected ok for git.repo with .git dir, got %s: %s", r.Status, r.Message)
	}
}

func TestRunChecks_GitLastSync_WithRecentSync(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Write FETCH_HEAD to simulate a recent sync.
	fetchHead := filepath.Join(gitDir, "FETCH_HEAD")
	if err := os.WriteFile(fetchHead, []byte("abc123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Set mtime to recent.
	now := time.Now()
	if err := os.Chtimes(fetchHead, now, now); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{NoNetwork: false})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	r, found := byID["git.lastsync.fresh"]
	if !found {
		t.Fatal("expected git.lastsync.fresh check")
	}
	// Recent FETCH_HEAD → either ok or warn (depends on git.LastSyncTime impl).
	if r.Status == health.StatusFail {
		t.Errorf("unexpected fail for git.lastsync.fresh: %s", r.Message)
	}
}

func TestRunChecks_AuthMethod_Passphrase(t *testing.T) {
	dir := t.TempDir()
	// Write a minimal config that sets passphrase auth.
	cfg := []byte("auth_method: passphrase\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	r, found := byID["auth.method"]
	if !found {
		t.Fatal("expected auth.method check")
	}
	if r.Status == health.StatusFail {
		t.Errorf("unexpected fail for auth.method: %s", r.Message)
	}
}

func TestRunChecks_SessionCache_Unknown(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	if _, found := byID["session.cache"]; !found {
		t.Fatal("expected session.cache check")
	}
}

func TestRunChecks_Recipients_NoRecipients(t *testing.T) {
	dir := t.TempDir()
	// No recipients file — should warn or fail.
	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	if _, found := byID["recipients.count"]; !found {
		t.Fatal("expected recipients.count check")
	}
}

func TestFix_VaultPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions not enforced on Windows")
	}
	vaultDir := t.TempDir()
	entriesDir := filepath.Join(vaultDir, "entries")
	identityPath := filepath.Join(vaultDir, "identity.age")

	// Setup: create entries/ with 0755 and identity.age with 0644
	if err := os.MkdirAll(entriesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityPath, []byte("fake identity"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Run check — should get StatusWarn because perms are wrong
	results := health.RunChecks(vaultDir, health.Options{Only: []string{"vault.permissions"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("no results from RunChecks")
	}
	r := results[0]
	if r.Status != health.StatusWarn {
		t.Fatalf("expected StatusWarn, got %s", r.Status)
	}
	if !r.Fixable {
		t.Fatal("expected Fixable=true for vault.permissions")
	}
	if r.Fix == nil {
		t.Fatal("expected Fix!=nil for vault.permissions")
	}

	// Apply fix
	if err := r.Fix(); err != nil {
		t.Fatalf("Fix() error = %v", err)
	}

	// Verify permissions were fixed
	if info, err := os.Stat(entriesDir); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o700 {
		t.Errorf("entries/ mode = %o, want 0700", info.Mode().Perm())
	}
	if info, err := os.Stat(identityPath); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Errorf("identity.age mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestFix_GitignoreProtects(t *testing.T) {
	vaultDir := t.TempDir()

	// Setup: create all required dirs/files for RunChecks NOT to skip this check
	if err := os.MkdirAll(filepath.Join(vaultDir, "entries"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Run check — should get StatusWarn because .gitignore is missing
	results := health.RunChecks(vaultDir, health.Options{Only: []string{"git.gitignore.protects"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("no results from RunChecks")
	}
	r := results[0]
	if r.Status != health.StatusWarn {
		t.Fatalf("expected StatusWarn, got %s: %s", r.Status, r.Message)
	}
	if !r.Fixable {
		t.Fatal("expected Fixable=true for git.gitignore.protects")
	}
	if r.Fix == nil {
		t.Fatal("expected Fix!=nil for git.gitignore.protects")
	}

	// Apply fix
	if err := r.Fix(); err != nil {
		t.Fatalf("Fix() error = %v", err)
	}

	// Verify .gitignore was created with required entries
	gitignorePath := filepath.Join(vaultDir, ".gitignore")
	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatalf("ReadFile(.gitignore) error = %v", err)
	}
	content := string(data)
	for _, entry := range []string{"identity.age", "mcp-token", "mcp-tokens.json"} {
		if !strings.Contains(content, entry) {
			t.Errorf(".gitignore should contain %q", entry)
		}
	}
}

func TestFix_GitRepo(t *testing.T) {
	vaultDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(vaultDir, "entries"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Run check — no .git dir, should be StatusWarn
	results := health.RunChecks(vaultDir, health.Options{Only: []string{"git.repo"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("no results from RunChecks")
	}
	r := results[0]
	if r.Status != health.StatusWarn {
		t.Fatalf("expected StatusWarn, got %s", r.Status)
	}
	if !r.Fixable {
		t.Fatal("expected Fixable=true for git.repo")
	}
	if r.Fix == nil {
		t.Fatal("expected Fix!=nil for git.repo")
	}

	// Apply fix
	if err := r.Fix(); err != nil {
		t.Fatalf("Fix() error = %v", err)
	}

	// Verify .git dir exists
	gitDir := filepath.Join(vaultDir, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		t.Error("expected .git directory to exist after fix")
	}
}

func TestFix_NonFixableChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("vault.permissions not fixable on Windows (chmod not enforced)")
	}
	vaultDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(vaultDir, "entries"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Run ALL checks (no Only filter)
	results := health.RunChecks(vaultDir, health.Options{NoNetwork: true})

	// All checks that ARE fixable should have Fixable=true and Fix!=nil
	nonFixable := map[string]bool{
		"vault.permissions":      true, // IT IS fixable
		"git.repo":               true, // IT IS fixable
		"git.gitignore.protects": true, // IT IS fixable
	}
	// Everything else should NOT be fixable
	for _, r := range results {
		if nonFixable[r.ID] {
			if !r.Fixable {
				t.Errorf("%s should be Fixable=true", r.ID)
			}
		} else {
			if r.Fixable {
				t.Errorf("%s should have Fixable=false", r.ID)
			}
			if r.Fix != nil {
				t.Errorf("%s should have Fix=nil", r.ID)
			}
		}
	}
}

func TestRunChecks_ManifestIntegrity_Missing(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"vault.manifest.intact"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	r := results[0]
	if r.Status != health.StatusWarn {
		t.Errorf("expected warn for missing manifest, got %s: %s", r.Status, r.Message)
	}
}

func TestRunChecks_ManifestIntegrity_NoIdentity(t *testing.T) {
	dir := t.TempDir()
	// Write a minimal manifest.age (identity is nil, so we won't try to decrypt)
	if err := os.WriteFile(filepath.Join(dir, "manifest.age"), []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{Only: []string{"vault.manifest.intact"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	r := results[0]
	if r.Status != health.StatusWarn {
		t.Errorf("expected warn for no identity, got %s: %s", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "no active session") {
		t.Errorf("expected message about active session, got: %s", r.Message)
	}
}

func testPlatformCheck(t *testing.T, checkID, name string) {
	t.Helper()
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{checkID}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatalf("expected %s check result", name)
	}
	r := results[0]
	if r.ID != checkID {
		t.Errorf("expected %s, got %s", checkID, r.ID)
	}
	switch runtime.GOOS {
	case "darwin", "linux":
		if r.Status != health.StatusOK && r.Status != health.StatusWarn {
			t.Errorf("expected ok or warn on %s, got %s", runtime.GOOS, r.Status)
		}
	default:
		if r.Status != health.StatusOK {
			t.Errorf("expected ok on %s, got %s: %s", runtime.GOOS, r.Status, r.Message)
		}
	}
}

func TestRunChecks_AutoTypeBackend_Runs(t *testing.T) {
	testPlatformCheck(t, "tooling.autotype.backend", "auto-type backend")
}
func TestRunChecks_ClipboardBackend_Runs(t *testing.T) {
	testPlatformCheck(t, "tooling.clipboard.backend", "clipboard backend")
}

func TestRunChecks_DaemonStatus_Runs(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"daemon.status"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected daemon status check result")
	}
	r := results[0]
	if r.ID != "daemon.status" {
		t.Errorf("expected daemon.status, got %s", r.ID)
	}
	switch runtime.GOOS {
	case "darwin", "linux":
		if r.Status == health.StatusFail {
			t.Errorf("unexpected fail for daemon.status: %s", r.Message)
		}
	default:
		if r.Status != health.StatusOK {
			t.Errorf("expected ok on %s, got %s: %s", runtime.GOOS, r.Status, r.Message)
		}
	}
}

func TestRunChecks_SecureUI_Runs(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"tooling.secureui"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected secure UI check result")
	}
	r := results[0]
	if r.ID != "tooling.secureui" {
		t.Errorf("expected tooling.secureui, got %s", r.ID)
	}
	switch runtime.GOOS {
	case "darwin", "linux":
		if r.Status != health.StatusOK && r.Status != health.StatusWarn {
			t.Errorf("expected ok or warn on %s, got %s", runtime.GOOS, r.Status)
		}
	default:
		if r.Status != health.StatusOK {
			t.Errorf("expected ok on %s, got %s: %s", runtime.GOOS, r.Status, r.Message)
		}
	}
}

func TestRunChecks_PreCommitHooks_Runs(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"tooling.precommit"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected pre-commit hooks check result")
	}
	r := results[0]
	if r.ID != "tooling.precommit" {
		t.Errorf("expected tooling.precommit, got %s", r.ID)
	}
	// Uses os.Getwd(), not vaultDir — verify it runs without panicking on any OS.
}

func TestRunChecks_SessionKeyring_Run(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"session.keyring"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected session keyring check result")
	}
	r := results[0]
	if r.ID != "session.keyring" {
		t.Errorf("expected session.keyring, got %s", r.ID)
	}
	// Timed-out operations return StatusWarn in headless CI envs.
	if r.Status == health.StatusFail {
		t.Errorf("unexpected fail for session.keyring: %s", r.Message)
	}
}

func TestRunChecks_MCPTokens_Runs(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"mcp.tokens"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected MCP tokens check result")
	}
	r := results[0]
	if r.ID != "mcp.tokens" {
		t.Errorf("expected mcp.tokens, got %s", r.ID)
	}
	if r.Status == health.StatusFail {
		t.Errorf("unexpected fail for mcp.tokens: %s", r.Message)
	}
}

func TestRunChecks_RecipientsRecovery_NoRecipients(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"recipients.recovery"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected recipients recovery check result")
	}
	r := results[0]
	if r.ID != "recipients.recovery" {
		t.Errorf("expected recipients.recovery, got %s", r.ID)
	}
	if r.Status == health.StatusFail {
		t.Errorf("unexpected fail for recipients.recovery: %s", r.Message)
	}
}

func TestRunChecks_DynamicSecretEngines_Runs(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"mcp.dynamic.engines"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected dynamic secret engines check result")
	}
	r := results[0]
	if r.ID != "mcp.dynamic.engines" {
		t.Errorf("expected mcp.dynamic.engines, got %s", r.ID)
	}
	if r.Status == health.StatusFail {
		t.Errorf("unexpected fail for mcp.dynamic.engines: %s", r.Message)
	}
}

func TestRunChecks_MCPAgents_Runs(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"mcp.agents"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected MCP agents check result")
	}
	r := results[0]
	if r.ID != "mcp.agents" {
		t.Errorf("expected mcp.agents, got %s", r.ID)
	}
	if r.Status == health.StatusFail {
		t.Errorf("unexpected fail for mcp.agents: %s", r.Message)
	}
}

func TestRunChecks_KDFModern_NoVault(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"crypto.kdf.modern"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected KDF modernity check result")
	}
	r := results[0]
	if r.ID != "crypto.kdf.modern" {
		t.Errorf("expected crypto.kdf.modern, got %s", r.ID)
	}
	if r.Status != health.StatusWarn {
		t.Errorf("expected warn without vault config, got %s: %s", r.Status, r.Message)
	}
}

// writeKDFModernityVaultFixture writes a config.yaml + identity.age with the
// requested KDF/format-version combination so checkKDFModern can be exercised
// in every state the real check needs to distinguish.
func writeKDFModernityVaultFixture(t *testing.T, kdf string, formatVersion int) string {
	t.Helper()
	dir := t.TempDir()
	cfg := fmt.Sprintf("vaultDir: %s\nvault:\n  format_version: %d\n", dir, formatVersion)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var identity string
	switch kdf {
	case "scrypt":
		identity = "age-encryption.org/v1\n-> scrypt fakesalt\nfakebody\n"
	case "argon2id":
		identity = "age-encryption.org/v1\n-> argon2id fakesalt t=1,m=64,p=1\nfakebody\n"
	default:
		t.Fatalf("unknown KDF %q", kdf)
	}
	if err := os.WriteFile(filepath.Join(dir, "identity.age"), []byte(identity), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	return dir
}

func runKDFModern(t *testing.T, dir string) health.Result {
	t.Helper()
	results := health.RunChecks(dir, health.Options{Only: []string{"crypto.kdf.modern"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected KDF modernity result")
	}
	return results[0]
}

func TestRunChecks_KDFModern_Argon2idMatchesV2(t *testing.T) {
	dir := writeKDFModernityVaultFixture(t, "argon2id", 2)
	r := runKDFModern(t, dir)
	if r.Status != health.StatusOK {
		t.Errorf("expected OK for argon2id+v2, got %s: %s", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "argon2id") {
		t.Errorf("message should mention argon2id, got %q", r.Message)
	}
}

func TestRunChecks_KDFModern_ScryptMatchesV1(t *testing.T) {
	dir := writeKDFModernityVaultFixture(t, "scrypt", 1)
	r := runKDFModern(t, dir)
	if r.Status != health.StatusWarn {
		t.Errorf("expected warn for scrypt+v1, got %s: %s", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "scrypt") {
		t.Errorf("message should mention scrypt, got %q", r.Message)
	}
}

func TestRunChecks_KDFModern_DesyncScryptFileV2Config(t *testing.T) {
	dir := writeKDFModernityVaultFixture(t, "scrypt", 2)
	r := runKDFModern(t, dir)
	if r.Status != health.StatusWarn {
		t.Errorf("expected desync warn for scrypt file + v2 config, got %s: %s", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "out of sync") {
		t.Errorf("message should mention desync, got %q", r.Message)
	}
}

func TestRunChecks_KDFModern_DesyncArgon2idFileV1Config(t *testing.T) {
	dir := writeKDFModernityVaultFixture(t, "argon2id", 1)
	r := runKDFModern(t, dir)
	if r.Status != health.StatusWarn {
		t.Errorf("expected desync warn for argon2id file + v1 config, got %s: %s", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "out of sync") {
		t.Errorf("message should mention desync, got %q", r.Message)
	}
}

func TestRunChecks_Quick_SkipsSlow(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Quick: true, NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	if _, found := byID["crypto.scrypt.benchmark"]; found {
		t.Error("expected crypto.scrypt.benchmark to be skipped with --quick")
	}
	if _, found := byID["vault.initialized"]; !found {
		t.Error("expected vault.initialized check when --quick")
	}
}

func TestRunChecks_Exclude_FiltersOutCheck(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Exclude: []string{"vault.size"}, NoNetwork: true})
	for _, r := range results {
		if r.ID == "vault.size" {
			t.Error("expected vault.size to be excluded")
		}
	}
	var found bool
	for _, r := range results {
		if r.ID == "vault.initialized" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected other checks to remain after exclusion")
	}
}

func TestRunChecks_Only_FiltersToSingleCheck(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"vault.initialized"}, NoNetwork: true})
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 result with Only filter, got %d", len(results))
	}
	if results[0].ID != "vault.initialized" {
		t.Errorf("expected vault.initialized, got %s", results[0].ID)
	}
}

func TestRunChecks_OnlyAndExcludeConflict(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{
		Only:      []string{"vault.initialized", "vault.size"},
		Exclude:   []string{"vault.size"},
		NoNetwork: true,
	})
	for _, r := range results {
		if r.ID == "vault.size" {
			t.Error("expected vault.size to be excluded even with Only")
		}
	}
}

func TestRunChecks_PassphraseRotation_WithConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf("vault:\n  last_rotated: %s\n", time.Now().Add(-30*24*time.Hour).Format(time.RFC3339))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{Only: []string{"auth.passphrase.rotation"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected passphrase rotation check result")
	}
	r := results[0]
	if r.ID != "auth.passphrase.rotation" {
		t.Errorf("expected auth.passphrase.rotation, got %s", r.ID)
	}
	if r.Status == health.StatusFail {
		t.Errorf("unexpected fail: %s", r.Message)
	}
}

func TestRunChecks_AuthMethod_TouchIDConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := "auth_method: touchid\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{Only: []string{"auth.method"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected auth method check result")
	}
	r := results[0]
	if r.ID != "auth.method" {
		t.Errorf("expected auth.method, got %s", r.ID)
	}
	if r.Status == health.StatusFail {
		t.Errorf("unexpected fail: %s", r.Message)
	}
}

func TestRunChecks_ManifestIntegrity_AllOK(t *testing.T) {
	dir := t.TempDir()

	// Create minimal config.yaml (needed by vault.OpenWithCachedIdentity).
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vaultDir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Generate a real age identity.
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	// Create entries directory.
	entriesDir := filepath.Join(dir, "entries")
	if err := os.MkdirAll(entriesDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Write an entry file (simulating an encrypted vault entry).
	entryContent := []byte("fake-ciphertext-data-for-testing")
	entryFile := filepath.Join(entriesDir, "test-entry.age")
	if err := os.WriteFile(entryFile, entryContent, 0o600); err != nil {
		t.Fatal(err)
	}

	// Cache identity by opening vault.
	if _, err := vault.OpenWithCachedIdentity(dir, identity); err != nil {
		t.Fatal(err)
	}

	// Save identity to session so the health check can load it.
	if err := session.SaveIdentity(dir, identity.String(), 15*time.Minute); err != nil {
		t.Fatal(err)
	}

	// Create encrypted manifest with matching entry hash.
	if err := vault.UpdateManifestEntry(dir, "test-entry", entryContent, identity); err != nil {
		t.Fatal(err)
	}

	// Run the manifest integrity check only.
	results := health.RunChecks(dir, health.Options{Only: []string{"vault.manifest.intact"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	r := results[0]
	if r.Status != health.StatusOK {
		t.Errorf("expected ok, got %s: %s", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "verified") {
		t.Errorf("expected 'verified' in message, got: %s", r.Message)
	}
}

func TestRunChecks_UpdateCheck_DevBuild(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Version: "", NoNetwork: false})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	r, found := byID["update.available"]
	if !found {
		t.Fatal("expected update.available check")
	}
	if r.Status == health.StatusFail {
		t.Errorf("unexpected fail for update.available: %s", r.Message)
	}
}

func TestRunChecks_Recipients_WithRecipientsFile(t *testing.T) {
	dir := t.TempDir()
	recipientsDir := filepath.Join(dir, "recipients")
	if err := os.MkdirAll(recipientsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recFile := filepath.Join(recipientsDir, "default")
	if err := os.WriteFile(recFile, []byte(identity.Recipient().String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{Only: []string{"recipients.count"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected recipients count check result")
	}
	r := results[0]
	if r.ID != "recipients.count" {
		t.Errorf("expected recipients.count, got %s", r.ID)
	}
	if r.Status == health.StatusFail {
		t.Errorf("unexpected fail for recipients.count: %s", r.Message)
	}
}

func TestRunChecks_PassphraseRotation_NoRotation(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vault:\n  scrypt_work_factor: 12\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := health.RunChecks(dir, health.Options{Only: []string{"auth.passphrase.rotation"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected passphrase rotation check result")
	}
	r := results[0]
	if r.ID != "auth.passphrase.rotation" {
		t.Errorf("expected auth.passphrase.rotation, got %s", r.ID)
	}
	if r.Status != health.StatusWarn {
		t.Errorf("expected warn for no rotation, got %s: %s", r.Status, r.Message)
	}
}

// TestRunChecks_ManifestIntegrity_HintPointsAtRebuild verifies that the
// doctor hint for the "no manifest" case points at the real rebuild command
// (the previous hint told users to run `symvault verify`, which is read-only
// and would not create a manifest).
func TestRunChecks_ManifestIntegrity_HintPointsAtRebuild(t *testing.T) {
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"vault.manifest.intact"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	r := results[0]
	if !strings.Contains(r.Hint, "verify --rebuild") {
		t.Errorf("expected hint to point at `symvault verify --rebuild`, got: %q", r.Hint)
	}
}

// TestRunChecks_ManifestIntegrity_OutOfBandIsFixable verifies that when the
// manifest has Unknown entries (i.e. .age files on disk not tracked by the
// manifest, the #515 bug) the doctor marks the check as fixable and a Fix
// call rebuilds the manifest so the unknown entries are picked up.
func TestRunChecks_ManifestIntegrity_OutOfBandIsFixable(t *testing.T) {
	dir := t.TempDir()

	// Set up an initialized vault with one tracked entry, then drop an
	// out-of-band .age file directly into entries/. This mirrors the live
	// failure mode (git pull brings new entries in but the manifest lags).
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vaultDir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	entriesDir := filepath.Join(dir, "entries")
	if err := os.MkdirAll(entriesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tracked := []byte("tracked-ciphertext")
	if err := os.WriteFile(filepath.Join(entriesDir, "tracked.age"), tracked, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := vault.UpdateManifestEntry(dir, "tracked", tracked, identity); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entriesDir, "out-of-band.age"), []byte("sneaked-in"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := session.SaveIdentity(dir, identity.String(), 15*time.Minute); err != nil {
		t.Fatal(err)
	}

	results := health.RunChecks(dir, health.Options{Only: []string{"vault.manifest.intact"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	r := results[0]
	if r.Status != health.StatusWarn {
		t.Fatalf("expected warn for out-of-band, got %s: %s", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "unknown") {
		t.Errorf("expected 'unknown' in message, got: %s", r.Message)
	}
	if !r.Fixable {
		t.Errorf("expected Fixable=true for out-of-band entries, got false")
	}
	if r.Fix == nil {
		t.Fatal("expected Fix function for out-of-band entries, got nil")
	}
	if !strings.Contains(r.Hint, "verify --rebuild") {
		t.Errorf("expected hint to point at `symvault verify --rebuild`, got: %q", r.Hint)
	}

	// Apply the fix and confirm the manifest now knows about the out-of-band
	// entry. We invoke Fix directly (bypassing the --fix CLI plumbing) so
	// the test exercises the rebuild path.
	if err := r.Fix(); err != nil {
		t.Fatalf("Fix() failed: %v", err)
	}

	m, err := vault.LoadManifest(dir, identity)
	if err != nil {
		t.Fatalf("load manifest after fix: %v", err)
	}
	if _, ok := m.Entries["out-of-band"]; !ok {
		t.Errorf("manifest after fix should include 'out-of-band' entry, got entries: %v", m.Entries)
	}
}

func TestRunChecks_SearchIndexPersistence_NoFailureRecorded(t *testing.T) {
	dir := t.TempDir()

	results := health.RunChecks(dir, health.Options{NoNetwork: true})
	byID := map[string]health.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}

	r, ok := byID["vault.search_index.persistence"]
	if !ok {
		t.Fatal("expected vault.search_index.persistence check to run")
	}
	if r.Status != health.StatusOK {
		t.Errorf("expected ok for vault.search_index.persistence with no prior build, got %s: %s", r.Status, r.Message)
	}
}

func TestRunChecks_EnvPassphrase_Absent(t *testing.T) {
	t.Setenv("SYMVAULT_PASSPHRASE", "")
	t.Setenv("OPENPASS_PASSPHRASE", "")
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"security.env_passphrase"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected security.env_passphrase result")
	}
	r := results[0]
	if r.Status != health.StatusOK {
		t.Errorf("expected StatusOK when env passphrase absent, got %s: %s", r.Status, r.Message)
	}
}

func TestRunChecks_EnvPassphrase_Present(t *testing.T) {
	secretValue := "SUPER_SECRET_TEST_PASSPHRASE_12345"
	t.Setenv("SYMVAULT_PASSPHRASE", secretValue)
	dir := t.TempDir()
	results := health.RunChecks(dir, health.Options{Only: []string{"security.env_passphrase"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected security.env_passphrase result")
	}
	r := results[0]
	if r.Status != health.StatusWarn {
		t.Errorf("expected StatusWarn when env passphrase present, got %s: %s", r.Status, r.Message)
	}
	if strings.Contains(r.Message, secretValue) || strings.Contains(r.Hint, secretValue) {
		t.Errorf("SECURITY RISK: doctor output exposed passphrase value!")
	}
	if !strings.Contains(r.Message, "SYMVAULT_PASSPHRASE") {
		t.Errorf("expected message to reference variable name, got %q", r.Message)
	}
}

func TestRunChecks_EnvPassphrase_UnsafeSourceFile(t *testing.T) {
	t.Setenv("SYMVAULT_PASSPHRASE", "")
	t.Setenv("OPENPASS_PASSPHRASE", "")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("SYMVAULT_PASSPHRASE=secret_in_file\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	foundPath, perm, hasUnsafePerm := health.InspectPassphraseSourceFilesForTest([]string{envFile})
	if foundPath != envFile {
		t.Errorf("expected foundPath %s, got %s", envFile, foundPath)
	}
	if perm != 0o644 {
		t.Errorf("expected perm 0644, got %o", perm)
	}
	if !hasUnsafePerm {
		t.Errorf("expected hasUnsafePerm=true for mode 0644")
	}
}

func TestRunChecks_EnvPassphrase_SafeSourceFile(t *testing.T) {
	t.Setenv("SYMVAULT_PASSPHRASE", "")
	t.Setenv("OPENPASS_PASSPHRASE", "")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("SYMVAULT_PASSPHRASE=secret_in_file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	foundPath, perm, hasUnsafePerm := health.InspectPassphraseSourceFilesForTest([]string{envFile})
	if foundPath != envFile {
		t.Errorf("expected foundPath %s, got %s", envFile, foundPath)
	}
	if perm != 0o600 {
		t.Errorf("expected perm 0600, got %o", perm)
	}
	if hasUnsafePerm {
		t.Errorf("expected hasUnsafePerm=false for mode 0600")
	}
}

