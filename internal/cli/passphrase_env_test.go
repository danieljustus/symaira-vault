package cli

import (
	"os"
	"sync"
	"testing"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
)

func TestHasCachedEnvPassphrase_Empty(t *testing.T) {
	// Clear the cache first
	cachedEnvPassphrase = nil

	if HasCachedEnvPassphrase() {
		t.Error("HasCachedEnvPassphrase() = true for empty cache, want false")
	}
}

func TestHasCachedEnvPassphrase_Set(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() { cachedEnvPassphrase = orig })

	cachedEnvPassphrase = []byte("test-passphrase")
	if !HasCachedEnvPassphrase() {
		t.Error("HasCachedEnvPassphrase() = false after set, want true")
	}
}

func TestSetCachedEnvPassphrase(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() { cachedEnvPassphrase = orig })

	SetCachedEnvPassphrase([]byte("new-passphrase"))
	if !HasCachedEnvPassphrase() {
		t.Error("HasCachedEnvPassphrase() = false after SetCachedEnvPassphrase, want true")
	}
	if string(cachedEnvPassphrase) != "new-passphrase" {
		t.Errorf("cachedEnvPassphrase = %q, want new-passphrase", string(cachedEnvPassphrase))
	}
}

func TestConsumeCachedEnvPassphrase_ReturnsValue(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() { cachedEnvPassphrase = orig })

	cachedEnvPassphrase = []byte("consumed-passphrase")
	result := ConsumeCachedEnvPassphrase()

	if string(result) != "consumed-passphrase" {
		t.Errorf("ConsumeCachedEnvPassphrase() = %q, want consumed-passphrase", string(result))
	}
}

func TestConsumeCachedEnvPassphrase_ClearsCache(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() { cachedEnvPassphrase = orig })

	cachedEnvPassphrase = []byte("to-be-consumed")
	_ = ConsumeCachedEnvPassphrase()

	if HasCachedEnvPassphrase() {
		t.Error("cache should be cleared after ConsumeCachedEnvPassphrase")
	}
}

func TestConsumeCachedEnvPassphrase_EmptyCache(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() { cachedEnvPassphrase = orig })

	cachedEnvPassphrase = nil
	result := ConsumeCachedEnvPassphrase()

	if result != nil {
		t.Errorf("ConsumeCachedEnvPassphrase() = %v, want nil for empty cache", result)
	}
}

func TestSniffAndClearEnvPassphrase_SetsCache(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() {
		cachedEnvPassphrase = orig
	})

	cachedEnvPassphraseOnce = sync.Once{}

	t.Setenv("SYMVAULT_PASSPHRASE", "env-secret")

	SniffAndClearEnvPassphrase()

	if !HasCachedEnvPassphrase() {
		t.Error("HasCachedEnvPassphrase() = false after SniffAndClearEnvPassphrase, want true")
	}
	if string(cachedEnvPassphrase) != "env-secret" {
		t.Errorf("cachedEnvPassphrase = %q, want env-secret", string(cachedEnvPassphrase))
	}
}

func TestSniffAndClearEnvPassphrase_LegacyEnvVar(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() {
		cachedEnvPassphrase = orig
	})

	cachedEnvPassphraseOnce = sync.Once{}

	t.Setenv("OPENPASS_PASSPHRASE", "legacy-secret")

	SniffAndClearEnvPassphrase()

	if string(cachedEnvPassphrase) != "legacy-secret" {
		t.Errorf("cachedEnvPassphrase = %q, want legacy-secret", string(cachedEnvPassphrase))
	}
}

func TestSniffAndClearEnvPassphrase_EmptyEnv(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() {
		cachedEnvPassphrase = orig
	})

	cachedEnvPassphraseOnce = sync.Once{}

	os.Unsetenv("SYMVAULT_PASSPHRASE")
	os.Unsetenv("OPENPASS_PASSPHRASE")

	SniffAndClearEnvPassphrase()

	if HasCachedEnvPassphrase() {
		t.Error("HasCachedEnvPassphrase() = true for empty env, want false")
	}
}

func TestSniffAndClearEnvPassphrase_UnsetsEnv(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() {
		cachedEnvPassphrase = orig
		os.Unsetenv("SYMVAULT_PASSPHRASE")
	})

	cachedEnvPassphraseOnce = sync.Once{}

	t.Setenv("SYMVAULT_PASSPHRASE", "to-be-unset")

	SniffAndClearEnvPassphrase()

	if v := os.Getenv("SYMVAULT_PASSPHRASE"); v != "" {
		t.Errorf("SYMVAULT_PASSPHRASE = %q after SniffAndClearEnvPassphrase, want empty", v)
	}
}

func TestSniffAndClearEnvPassphrase_SymvaultTakesPrecedence(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() {
		cachedEnvPassphrase = orig
		os.Unsetenv("SYMVAULT_PASSPHRASE")
		os.Unsetenv("OPENPASS_PASSPHRASE")
	})

	cachedEnvPassphraseOnce = sync.Once{}

	t.Setenv("SYMVAULT_PASSPHRASE", "symvault-secret")
	t.Setenv("OPENPASS_PASSPHRASE", "openpass-secret")

	SniffAndClearEnvPassphrase()

	// SYMVAULT_PASSPHRASE should take precedence
	if string(cachedEnvPassphrase) != "symvault-secret" {
		t.Errorf("cachedEnvPassphrase = %q, want symvault-secret (SYMVAULT should take precedence)", string(cachedEnvPassphrase))
	}
}

func TestConsumeCachedEnvPassphrase_OnlyConsumesOnce(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() {
		cachedEnvPassphrase = orig
	})

	cachedEnvPassphraseOnce = sync.Once{}
	cachedEnvPassphrase = []byte("single-use")

	first := ConsumeCachedEnvPassphrase()
	second := ConsumeCachedEnvPassphrase()

	if string(first) != "single-use" {
		t.Errorf("first ConsumeCachedEnvPassphrase() = %q, want single-use", string(first))
	}
	if second != nil {
		t.Errorf("second ConsumeCachedEnvPassphrase() = %v, want nil (already consumed)", second)
	}
}

func TestSetCachedEnvPassphrase_NilValue(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() { cachedEnvPassphrase = orig })

	SetCachedEnvPassphrase(nil)
	if HasCachedEnvPassphrase() {
		t.Error("HasCachedEnvPassphrase() = true after SetCachedEnvPassphrase(nil), want false")
	}
}

func TestSetCachedEnvPassphrase_EmptyBytes(t *testing.T) {
	orig := cachedEnvPassphrase
	t.Cleanup(func() { cachedEnvPassphrase = orig })

	SetCachedEnvPassphrase([]byte{})
	if HasCachedEnvPassphrase() {
		t.Error("HasCachedEnvPassphrase() = true after SetCachedEnvPassphrase([]), want false")
	}
}

func TestClearCachedEnvPassphrase_Zeroizes(t *testing.T) {
	buf := []byte("secret-to-zeroize")
	cachedEnvPassphrase = buf
	t.Cleanup(func() { cachedEnvPassphrase = nil })

	ClearCachedEnvPassphrase()

	if HasCachedEnvPassphrase() {
		t.Error("HasCachedEnvPassphrase() = true after ClearCachedEnvPassphrase, want false")
	}
	for i, b := range buf {
		if b != 0 {
			t.Errorf("buf[%d] = %d after ClearCachedEnvPassphrase, want 0", i, b)
		}
	}
}

func TestSetCachedEnvPassphrase_ZeroizesOldBytes(t *testing.T) {
	oldBuf := []byte("old-secret")
	cachedEnvPassphrase = oldBuf
	t.Cleanup(func() { cachedEnvPassphrase = nil })

	SetCachedEnvPassphrase([]byte("new-secret"))

	for i, b := range oldBuf {
		if b != 0 {
			t.Errorf("oldBuf[%d] = %d after replacement, want 0", i, b)
		}
	}
}

func TestIsEnvPassphraseAllowed_DefaultDeny(t *testing.T) {
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "")
	t.Setenv("OPENPASS_ALLOW_ENV_PASSPHRASE", "")

	if IsEnvPassphraseAllowed(nil) {
		t.Error("IsEnvPassphraseAllowed(nil) = true by default, want false (default-deny)")
	}
}

func TestIsEnvPassphraseAllowed_ConfigOptIn(t *testing.T) {
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "")
	t.Setenv("OPENPASS_ALLOW_ENV_PASSPHRASE", "")

	cfg := &configpkg.Config{
		Security: &configpkg.SecurityConfig{
			AllowEnvPassphrase: true,
		},
	}
	if !IsEnvPassphraseAllowed(cfg) {
		t.Error("IsEnvPassphraseAllowed(cfg) = false with AllowEnvPassphrase: true, want true")
	}
}

func TestIsEnvPassphraseAllowed_EnvOptIn(t *testing.T) {
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
	t.Setenv("OPENPASS_ALLOW_ENV_PASSPHRASE", "")

	if !IsEnvPassphraseAllowed(nil) {
		t.Error("IsEnvPassphraseAllowed(nil) = false with SYMVAULT_ALLOW_ENV_PASSPHRASE=1, want true")
	}
}

func TestIsEnvPassphraseAllowed_DisableOverridesAllow(t *testing.T) {
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")

	cfg := &configpkg.Config{
		Security: &configpkg.SecurityConfig{
			AllowEnvPassphrase:   true,
			DisableEnvPassphrase: true,
		},
	}
	if IsEnvPassphraseAllowed(cfg) {
		t.Error("IsEnvPassphraseAllowed(cfg) = true when DisableEnvPassphrase: true, want false")
	}
}
