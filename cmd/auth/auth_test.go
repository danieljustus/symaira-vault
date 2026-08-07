package auth

import (
	"encoding/json"
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/session"
)

// installTestBiometricStore swaps the process-wide biometric passphrase store
// for the recording fake so auth set/status tests can exercise the
// Touch ID branches deterministically.
func installTestBiometricStore(t *testing.T, available bool) *testBiometricStore {
	t.Helper()
	store := &testBiometricStore{available: available}
	old := session.DefaultBiometricPassphraseStore()
	session.SetBiometricPassphraseStore(store)
	t.Cleanup(func() { session.SetBiometricPassphraseStore(old) })
	return store
}

func TestAuthStatus_TextOutput(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)
	// The darwin build installs a real Touch ID store in init(); pin the
	// fake (unavailable) store so the text branch is deterministic.
	installTestBiometricStore(t, false)

	out := captureStdout(t, func() {
		if err := AuthStatusCmd.RunE(AuthStatusCmd, nil); err != nil {
			t.Fatalf("auth status error = %v", err)
		}
	})

	for _, want := range []string{
		"Vault: ",
		"Auth method: passphrase",
		"Touch ID available: false",
		"Session cache: os-keyring (persistent: true)",
		"Keyring health: available",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestAuthStatus_KeyringUnavailableBranch(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, false)

	out := captureStdout(t, func() {
		if err := AuthStatusCmd.RunE(AuthStatusCmd, nil); err != nil {
			t.Fatalf("auth status error = %v", err)
		}
	})

	if !strings.Contains(out, "Keyring health: unavailable") {
		t.Errorf("output missing keyring-unavailable health:\n%s", out)
	}
	if !strings.Contains(out, "Session cache: memory (persistent: false)") {
		t.Errorf("output missing memory cache status:\n%s", out)
	}
}

func TestAuthStatus_TouchIDAvailableFlag(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)
	installTestBiometricStore(t, true)

	out := captureStdout(t, func() {
		if err := AuthStatusCmd.RunE(AuthStatusCmd, nil); err != nil {
			t.Fatalf("auth status error = %v", err)
		}
	})

	if !strings.Contains(out, "Touch ID available: true") {
		t.Errorf("output missing Touch ID availability:\n%s", out)
	}
}

func TestAuthStatus_JSONFlag(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	oldJSON := AuthStatusJSON
	AuthStatusJSON = true
	t.Cleanup(func() { AuthStatusJSON = oldJSON })

	out := captureStdout(t, func() {
		if err := AuthStatusCmd.RunE(AuthStatusCmd, nil); err != nil {
			t.Fatalf("auth status error = %v", err)
		}
	})

	var parsed map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput: %s", err, out)
	}
	for _, key := range []string{"vault", "method", "touchIDAvailable", "cache", "keyringHealth"} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("JSON missing key %q: %v", key, parsed)
		}
	}
	if parsed["keyringHealth"] != "available" {
		t.Errorf("keyringHealth = %v, want available", parsed["keyringHealth"])
	}
	if parsed["method"] != configpkg.AuthMethodPassphrase {
		t.Errorf("method = %v, want %q", parsed["method"], configpkg.AuthMethodPassphrase)
	}
}

func TestAuthStatus_JSONOutputFormatGlobalFlag(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, false)
	setOutputFormat(t, "json")

	oldJSON := AuthStatusJSON
	AuthStatusJSON = false
	t.Cleanup(func() { AuthStatusJSON = oldJSON })

	out := captureStdout(t, func() {
		if err := AuthStatusCmd.RunE(AuthStatusCmd, nil); err != nil {
			t.Fatalf("auth status error = %v", err)
		}
	})

	var parsed map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput: %s", err, out)
	}
	if parsed["keyringHealth"] != "unavailable" {
		t.Errorf("keyringHealth = %v, want unavailable", parsed["keyringHealth"])
	}
	cache, ok := parsed["cache"].(map[string]any)
	if !ok {
		t.Fatalf("cache = %v (%T), want object", parsed["cache"], parsed["cache"])
	}
	if cache["persistent"] != false {
		t.Errorf("cache.persistent = %v, want false", cache["persistent"])
	}
	if cache["backend"] != session.CacheBackendMemory {
		t.Errorf("cache.backend = %v, want %q", cache["backend"], session.CacheBackendMemory)
	}
}

func TestAuthStatus_QuietModeSuppressesOutput(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)
	setQuietMode(t, true)

	out := captureStdout(t, func() {
		if err := AuthStatusCmd.RunE(AuthStatusCmd, nil); err != nil {
			t.Fatalf("auth status error = %v", err)
		}
	})
	if strings.TrimSpace(out) != "" {
		t.Errorf("quiet mode should suppress status output, got %q", out)
	}
}

func TestAuthStatus_VaultNotInitialized(t *testing.T) {
	// Point at an empty temp dir with no vault.
	cli.Vault = t.TempDir()
	err := AuthStatusCmd.RunE(AuthStatusCmd, nil)
	if err == nil {
		t.Fatal("expected error for uninitialized vault, got nil")
	}
	if !strings.Contains(err.Error(), "vault not initialized") {
		t.Errorf("error = %v, want vault-not-initialized", err)
	}
}

func TestAuthSet_PassphraseUpdatesConfig(t *testing.T) {
	vaultDir, _ := setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)
	// Pin the fake store so ClearBiometricPassphrase stays hermetic.
	installTestBiometricStore(t, false)

	// First switch to touchid so the passphrase path must clear biometrics.
	cfg, err := configpkg.Load(vaultDir + "/config.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := cfg.SetAuthMethod(configpkg.AuthMethodTouchID); err != nil {
		t.Fatalf("SetAuthMethod: %v", err)
	}
	if err := cfg.SaveTo(vaultDir + "/config.yaml"); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	out := captureStdout(t, func() {
		if err := AuthSetCmd.RunE(AuthSetCmd, []string{"passphrase"}); err != nil {
			t.Fatalf("auth set passphrase error = %v", err)
		}
	})
	if !strings.Contains(out, "Auth method set to passphrase") {
		t.Errorf("output = %q, want passphrase confirmation", out)
	}

	loaded, err := configpkg.Load(vaultDir + "/config.yaml")
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if got := loaded.EffectiveAuthMethod(); got != configpkg.AuthMethodPassphrase {
		t.Errorf("auth method = %q, want %q", got, configpkg.AuthMethodPassphrase)
	}
}

func TestAuthSet_TouchIDHappyPath(t *testing.T) {
	vaultDir, passphrase := setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)
	store := installTestBiometricStore(t, true)
	saveTestSession(t, vaultDir, passphrase)

	out := captureStdout(t, func() {
		if err := AuthSetCmd.RunE(AuthSetCmd, []string{"touchid"}); err != nil {
			t.Fatalf("auth set touchid error = %v", err)
		}
	})
	if !strings.Contains(out, "Auth method set to touchid") {
		t.Errorf("output = %q, want touchid confirmation", out)
	}
	if string(store.saved) != string(passphrase) {
		t.Errorf("saved biometric passphrase = %q, want %q", store.saved, passphrase)
	}

	loaded, err := configpkg.Load(vaultDir + "/config.yaml")
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if got := loaded.EffectiveAuthMethod(); got != configpkg.AuthMethodTouchID {
		t.Errorf("auth method = %q, want %q", got, configpkg.AuthMethodTouchID)
	}
}

func TestAuthSet_TouchIDUnavailable(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)
	// Explicitly report Touch ID as unavailable (darwin registers a real
	// store in init(), so the noop fallback is never active there).
	installTestBiometricStore(t, false)

	err := AuthSetCmd.RunE(AuthSetCmd, []string{"touchid"})
	if err == nil {
		t.Fatal("expected error when Touch ID is unavailable, got nil")
	}
	if !strings.Contains(err.Error(), "touch ID is not available") {
		t.Errorf("error = %v, want touch-ID-unavailable message", err)
	}
}

func TestAuthSet_TouchIDRejectsInvalidPassphrase(t *testing.T) {
	_, passphrase := setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)
	installTestBiometricStore(t, true)

	// Remove the env passphrase so the command falls through to stdin, and
	// re-set it afterwards because passphraseForBiometricSetup unsets it.
	restoreStdin := pipeStdin(t, "wrong-passphrase\n")
	defer restoreStdin()

	t.Setenv("SYMVAULT_PASSPHRASE", "")

	err := AuthSetCmd.RunE(AuthSetCmd, []string{"touchid"})
	if err == nil {
		t.Fatal("expected error for invalid passphrase, got nil")
	}
	if !strings.Contains(err.Error(), "open vault") {
		t.Errorf("error = %v, want open-vault failure", err)
	}

	// passphraseForBiometricSetup unsets the env passphrase; restore it so
	// later tests in this process keep working.
	t.Setenv("SYMVAULT_PASSPHRASE", string(passphrase))
}

func TestAuthSet_InvalidMethod(t *testing.T) {
	setupTestVault(t)

	err := AuthSetCmd.RunE(AuthSetCmd, []string{"bogus"})
	if err == nil {
		t.Fatal("expected error for invalid auth method, got nil")
	}
	if !strings.Contains(err.Error(), "invalid authMethod") {
		t.Errorf("error = %v, want invalid-authMethod message", err)
	}
}

func TestAuthSet_ArgsValidation(t *testing.T) {
	set := newAuthSetCmd()

	err := set.Args(set, nil)
	if err == nil {
		t.Fatal("expected error for missing argument, got nil")
	}
	if !strings.Contains(err.Error(), "requires exactly 1 argument") {
		t.Errorf("error = %v, want exactly-1-argument message", err)
	}

	if err := set.Args(set, []string{"passphrase"}); err != nil {
		t.Errorf("Args with one argument returned error: %v", err)
	}
}

func TestAuthSet_NotInitialized(t *testing.T) {
	cli.Vault = t.TempDir()
	err := AuthSetCmd.RunE(AuthSetCmd, []string{"passphrase"})
	if err == nil {
		t.Fatal("expected error for uninitialized vault, got nil")
	}
	// loadAuthConfig wraps the not-initialized check in a plain error.
	if !strings.Contains(err.Error(), "vault not initialized") {
		t.Errorf("error = %v, want vault-not-initialized message", err)
	}
}
