package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
)

func writeBrokenConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func stubConfirm(t *testing.T, responses ...bool) {
	t.Helper()
	orig := ConfirmInteractive
	t.Cleanup(func() { ConfirmInteractive = orig })
	idx := 0
	ConfirmInteractive = func(prompt string, force bool) (bool, error) {
		if idx >= len(responses) {
			t.Fatalf("unexpected confirm call %d (only %d responses stubbed); prompt=%q", idx+1, len(responses), prompt)
		}
		r := responses[idx]
		idx++
		return r, nil
	}
}

func TestInteractiveFixConfig_FixesWhitespaceVaultDir(t *testing.T) {
	// "  " is preserved by Load (only empty string is replaced) and
	// rejected by Validate, so this is the case the auto-fix must handle.
	path := writeBrokenConfig(t, "vaultDir: \"  \"\n")

	cfg, err := configpkg.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	valErr := cfg.Validate()
	if valErr == nil || !strings.Contains(valErr.Error(), "vaultDir: must not be empty") {
		t.Fatalf("expected vaultDir validation error, got: %v", valErr)
	}

	stubConfirm(t, true)

	fixed, err := InteractiveFixConfig(path, nil, cfg, valErr)
	if err != nil {
		t.Fatalf("InteractiveFixConfig: %v", err)
	}
	if fixed == nil {
		t.Fatal("expected non-nil fixed config")
	}
	if strings.TrimSpace(fixed.VaultDir) == "" {
		t.Errorf("VaultDir not fixed: %q", fixed.VaultDir)
	}

	reloaded, err := configpkg.Load(path)
	if err != nil {
		t.Fatalf("reload after fix: %v", err)
	}
	if reloaded.Validate() != nil {
		t.Errorf("expected validation to pass after fix, got: %v", reloaded.Validate())
	}
}

func TestInteractiveFixConfig_FallsThroughToEditorOnLoadError(t *testing.T) {
	// invalid approvalMode is a Load() error and cfg is nil, so the
	// auto-fix cannot run. Verify the function falls through to the
	// editor prompt (which the stub will decline).
	path := writeBrokenConfig(t, "agents:\n  myagent:\n    approvalMode: nonsense\n")

	stubConfirm(t, false) // decline the editor prompt

	_, err := InteractiveFixConfig(path, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "aborted by user") {
		t.Errorf("expected abort error when load fails, got: %v", err)
	}
}

func TestInteractiveFixConfig_LeavesAlreadyValidConfigUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := configpkg.Default()
	if err := cfg.SaveTo(path); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	originalBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	reloaded, err := configpkg.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if valErr := reloaded.Validate(); valErr != nil {
		t.Fatalf("unexpected validation error on default config: %v", valErr)
	}

	stubConfirm(t, false)

	_, err = InteractiveFixConfig(path, nil, reloaded, nil)
	// With valErr == nil, the auto-fix block is skipped and the function
	// asks to open the editor; the user (stub) declined, so the function
	// returns "configuration fix aborted by user".
	if err == nil || !strings.Contains(err.Error(), "aborted by user") {
		t.Errorf("expected abort error, got: %v", err)
	}

	afterBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(originalBytes, afterBytes) {
		t.Errorf("file was modified by InteractiveFixConfig on a valid config")
	}
}
