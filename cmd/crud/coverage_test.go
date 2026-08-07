package crud

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// Coverage-recovery tests for the cmd/crud command layer (issue #747):
// constructors and helper paths that the existing suite does not execute.

func TestFindCmd_PrintsMatchPath(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "work/aws", map[string]any{"password": "secret-2"})

	cmd := newFindCmd()
	cmd.SetArgs([]string{"aws"})
	var err error
	out := captureStdout(t, func() {
		err = cmd.Execute()
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(out, "work/aws") {
		t.Errorf("stdout = %q, want it to contain work/aws", out)
	}
}

func TestFindCmd_NoMatches(t *testing.T) {
	setupTestVault(t)

	cmd := newFindCmd()
	cmd.SetArgs([]string{"definitely-not-present"})
	var err error
	errOut := captureStderr(t, func() {
		err = cmd.Execute()
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(errOut, "No matches found") {
		t.Errorf("stderr = %q, want 'No matches found'", errOut)
	}
}

func TestFindCmd_JSONOutput(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "secret-3"})
	setJSONOutput(t)

	cmd := newFindCmd()
	cmd.SetArgs([]string{"github"})
	var err error
	out := captureStdout(t, func() {
		err = cmd.Execute()
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(out, `"matches"`) || !strings.Contains(out, "github") {
		t.Errorf("stdout = %q, want JSON matches containing github", out)
	}
}

func TestGetCmd_PrintField(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "print-me-42"})

	cmd := newGetCmd()
	cmd.SetArgs([]string{"github.password", "--print"})
	var err error
	out := captureStdout(t, func() {
		err = cmd.Execute()
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(out, "print-me-42") {
		t.Errorf("stdout = %q, want it to contain print-me-42", out)
	}
}

func TestGetCmd_FieldNotFound(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "x"})

	cmd := newGetCmd()
	cmd.SetArgs([]string{"github.nosuchfield", "--print"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() expected error for missing field")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v, want not-found message", err)
	}
}

func TestGetAutoClearDuration_Defaults(t *testing.T) {
	// No resolvable vault dir: fall back to the default.
	origVault := cli.Vault
	cli.Vault = filepath.Join(t.TempDir(), "does-not-exist")
	defer func() { cli.Vault = origVault }()

	if got := GetAutoClearDuration(); got != 30 {
		t.Errorf("GetAutoClearDuration() = %d, want 30", got)
	}
}

func TestGetAutoClearDuration_NoClipboardConfig(t *testing.T) {
	// Valid vault dir but no config.yaml: fall back to the default.
	vaultDir := t.TempDir()
	origVault := cli.Vault
	cli.Vault = vaultDir
	defer func() { cli.Vault = origVault }()

	if got := GetAutoClearDuration(); got != 30 {
		t.Errorf("GetAutoClearDuration() = %d, want 30", got)
	}
}

func TestGetAutoClearDuration_Configured(t *testing.T) {
	vaultDir := t.TempDir()
	cfg := "clipboard:\n  auto_clear_duration: 45\n"
	if err := os.WriteFile(filepath.Join(vaultDir, "config.yaml"), []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	origVault := cli.Vault
	cli.Vault = vaultDir
	defer func() { cli.Vault = origVault }()

	if got := GetAutoClearDuration(); got != 45 {
		t.Errorf("GetAutoClearDuration() = %d, want 45", got)
	}
}

func TestSetCmd_ValueCreatesField(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "old"})

	cmd := newSetCmd()
	cmd.SetArgs([]string{"github.token", "--value", "new-token-abc"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	entry := getTestEntry(t, "github")
	if got, _ := entry.GetField("token"); got != "new-token-abc" {
		t.Errorf("token = %q, want new-token-abc", got)
	}
}

func TestSetCmd_StdinValue(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "old"})

	withStdin(t, "from-stdin-77\n", func() {
		cmd := newSetCmd()
		cmd.SetArgs([]string{"github.password", "--stdin-value"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})
	entry := getTestEntry(t, "github")
	if got, _ := entry.GetField("password"); got != "from-stdin-77" {
		t.Errorf("password = %q, want from-stdin-77", got)
	}
}

func TestBuildFormDefaults(t *testing.T) {
	resetAddFlags(t)
	AddUsername = "octocat"
	AddURL = "https://github.com"
	AddNotes = "primary"
	AddType = "api_key"
	AddUsageHint = "CI token"
	AddAutoRotate = true
	AddTOTPSecret = "JBSWY3DPEHPK3PXP"
	AddTOTPIssuer = "GitHub"
	AddTOTPAccount = "octocat@example.com"

	defaults := buildFormDefaults()
	if defaults["username"] != "octocat" {
		t.Errorf("username = %v, want octocat", defaults["username"])
	}
	if defaults["url"] != "https://github.com" {
		t.Errorf("url = %v, want https://github.com", defaults["url"])
	}
	if defaults["notes"] != "primary" {
		t.Errorf("notes = %v, want primary", defaults["notes"])
	}
	if defaults["_secret_type"] != "api_key" {
		t.Errorf("_secret_type = %v, want api_key", defaults["_secret_type"])
	}
	if defaults["_usage_hint"] != "CI token" {
		t.Errorf("_usage_hint = %v, want CI token", defaults["_usage_hint"])
	}
	if defaults["_auto_rotate"] != true {
		t.Errorf("_auto_rotate = %v, want true", defaults["_auto_rotate"])
	}
	totp, ok := defaults["totp"].(map[string]any)
	if !ok {
		t.Fatalf("totp = %v, want map", defaults["totp"])
	}
	if totp["secret"] != "JBSWY3DPEHPK3PXP" || totp["issuer"] != "GitHub" || totp["account_name"] != "octocat@example.com" {
		t.Errorf("totp defaults = %v, want full TOTP sub-map", totp)
	}
}

func TestBuildFormDefaults_Empty(t *testing.T) {
	resetAddFlags(t)
	defaults := buildFormDefaults()
	if len(defaults) != 0 {
		t.Errorf("buildFormDefaults() = %v, want empty map", defaults)
	}
}

func TestAddNonReaderFields(t *testing.T) {
	resetAddFlags(t)
	AddURL = "https://example.com"
	AddNotes = "note-1"
	AddTOTPSecret = "JBSWY3DPEHPK3PXP"
	AddTOTPIssuer = "Issuer"
	AddTOTPAccount = "acct"

	data := map[string]any{"password": "x"}
	addNonReaderFields(data)
	if data["url"] != "https://example.com" {
		t.Errorf("url = %v, want https://example.com", data["url"])
	}
	if data["notes"] != "note-1" {
		t.Errorf("notes = %v, want note-1", data["notes"])
	}
	totp, ok := data["totp"].(map[string]any)
	if !ok {
		t.Fatalf("totp = %v, want map", data["totp"])
	}
	if totp["secret"] != "JBSWY3DPEHPK3PXP" || totp["issuer"] != "Issuer" || totp["account_name"] != "acct" {
		t.Errorf("totp = %v, want full TOTP sub-map", totp)
	}
}

func TestAddNonReaderFields_Empty(t *testing.T) {
	resetAddFlags(t)
	data := map[string]any{"password": "x"}
	addNonReaderFields(data)
	if len(data) != 1 {
		t.Errorf("data = %v, want unchanged single-field map", data)
	}
}

func TestApplySecretMetaFlags(t *testing.T) {
	resetAddFlags(t)
	AddType = "api_key"
	AddUsageHint = "explicit hint"
	AddAutoRotate = true

	meta := applySecretMetaFlags(vaultpkg.SecretMetadata{})
	if meta.Type != vaultpkg.SecretTypeAPIKey {
		t.Errorf("Type = %q, want api_key", meta.Type)
	}
	if meta.UsageHint != "explicit hint" {
		t.Errorf("UsageHint = %q, want explicit hint", meta.UsageHint)
	}
	if !meta.AutoRotate {
		t.Error("AutoRotate = false, want true")
	}
}

func TestApplySecretMetaFlags_UsageHintDerivedFromType(t *testing.T) {
	resetAddFlags(t)
	AddType = "ssh_key"
	AddUsageHint = ""

	meta := applySecretMetaFlags(vaultpkg.SecretMetadata{})
	if meta.Type != vaultpkg.SecretTypeSSHKey {
		t.Errorf("Type = %q, want ssh_key", meta.Type)
	}
	if meta.UsageHint == "" {
		t.Error("UsageHint = empty, want type-derived hint")
	}
}

func TestApplySecretMetaFlags_ExpiresAt(t *testing.T) {
	resetAddFlags(t)
	AddExpiresAt = "2030-01-02T03:04:05Z"

	meta := applySecretMetaFlags(vaultpkg.SecretMetadata{})
	if meta.ExpiresAt == nil {
		t.Fatal("ExpiresAt = nil, want parsed timestamp")
	}
	want := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if !meta.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", meta.ExpiresAt, want)
	}
}

func TestApplySecretMetaFlags_InvalidExpiresAtIgnored(t *testing.T) {
	resetAddFlags(t)
	AddExpiresAt = "not-a-time"

	meta := applySecretMetaFlags(vaultpkg.SecretMetadata{})
	if meta.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil for unparseable value", meta.ExpiresAt)
	}
}

func TestWarnArgvExposure_ValueOnTerminal(t *testing.T) {
	orig := cli.IsTerminalFunc
	cli.IsTerminalFunc = func(int) bool { return true }
	defer func() { cli.IsTerminalFunc = orig }()

	errOut := captureStderr(t, func() {
		warnArgvExposure("visible-secret", "", false)
	})
	if !strings.Contains(errOut, "--value is visible in process listings") {
		t.Errorf("stderr = %q, want --value exposure warning", errOut)
	}
}

func TestWarnArgvExposure_TOTPOnTerminal(t *testing.T) {
	orig := cli.IsTerminalFunc
	cli.IsTerminalFunc = func(int) bool { return true }
	defer func() { cli.IsTerminalFunc = orig }()

	errOut := captureStderr(t, func() {
		warnArgvExposure("", "totp-secret-1", false)
	})
	if !strings.Contains(errOut, "--totp-secret is visible in process listings") {
		t.Errorf("stderr = %q, want --totp-secret exposure warning", errOut)
	}
}

func TestWarnArgvExposure_TOTPFromStdinNoWarning(t *testing.T) {
	orig := cli.IsTerminalFunc
	cli.IsTerminalFunc = func(int) bool { return true }
	defer func() { cli.IsTerminalFunc = orig }()

	errOut := captureStderr(t, func() {
		warnArgvExposure("", "totp-secret-2", true)
	})
	if strings.Contains(errOut, "--totp-secret is visible") {
		t.Errorf("stderr = %q, want no warning for stdin-provided TOTP", errOut)
	}
}
