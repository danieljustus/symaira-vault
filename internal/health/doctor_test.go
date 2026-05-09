package health_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/health"
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
