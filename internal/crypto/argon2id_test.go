package crypto

import (
	"testing"
)

func TestArgon2idDeriveKey(t *testing.T) {
	salt, err := GenerateArgon2idSalt()
	if err != nil {
		t.Fatalf("GenerateArgon2idSalt() error = %v", err)
	}
	if len(salt) != SaltLen {
		t.Fatalf("salt length = %d, want %d", len(salt), SaltLen)
	}

	password := []byte("test-password")
	params := resolveArgon2idParams(Argon2idParams{})

	key, err := Argon2idDeriveKey(password, salt, params)
	if err != nil {
		t.Fatalf("Argon2idDeriveKey() error = %v", err)
	}
	if len(key) != Argon2idKeyLen {
		t.Fatalf("key length = %d, want %d", len(key), Argon2idKeyLen)
	}

	// Same inputs should produce same key
	key2, err := Argon2idDeriveKey(password, salt, params)
	if err != nil {
		t.Fatalf("Argon2idDeriveKey() second call error = %v", err)
	}
	if len(key2) != Argon2idKeyLen {
		t.Fatalf("second key length = %d, want %d", len(key2), Argon2idKeyLen)
	}
	for i := range key {
		if key[i] != key2[i] {
			t.Fatalf("keys differ at byte %d: deterministic derivation expected equal keys", i)
		}
	}

	// Different password should produce different key
	key3, err := Argon2idDeriveKey([]byte("different-password"), salt, params)
	if err != nil {
		t.Fatalf("Argon2idDeriveKey() different password error = %v", err)
	}
	if bytesEqual(key, key3) {
		t.Fatal("different passwords produced same key")
	}

	// Different salt should produce different key
	otherSalt, err := GenerateArgon2idSalt()
	if err != nil {
		t.Fatalf("GenerateArgon2idSalt() error = %v", err)
	}
	key4, err := Argon2idDeriveKey(password, otherSalt, params)
	if err != nil {
		t.Fatalf("Argon2idDeriveKey() different salt error = %v", err)
	}
	if bytesEqual(key, key4) {
		t.Fatal("different salts produced same key")
	}
}

func TestArgon2idDeriveKeyEmptyPassword(t *testing.T) {
	salt, err := GenerateArgon2idSalt()
	if err != nil {
		t.Fatalf("GenerateArgon2idSalt() error = %v", err)
	}
	_, err = Argon2idDeriveKey([]byte{}, salt, DefaultArgon2idParams())
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestArgon2idDeriveKeyEmptySalt(t *testing.T) {
	_, err := Argon2idDeriveKey([]byte("password"), []byte{}, DefaultArgon2idParams())
	if err == nil {
		t.Fatal("expected error for empty salt")
	}
}

func TestArgon2idParamsValidation(t *testing.T) {
	tests := []struct {
		name   string
		params Argon2idParams
		errMsg string
	}{
		{"zero time", Argon2idParams{Time: 0, Memory: 64, Threads: 1}, "time parameter must be > 0"},
		{"zero memory", Argon2idParams{Time: 1, Memory: 0, Threads: 1}, "memory parameter must be > 0"},
		{"zero threads", Argon2idParams{Time: 1, Memory: 64, Threads: 0}, "threads parameter must be > 0"},
		{"memory too low for threads", Argon2idParams{Time: 1, Memory: 3, Threads: 4}, "must be at least 4*threads"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateArgon2idParams(tt.params)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.errMsg) {
				t.Errorf("error = %q, want %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestArgon2idParamsValidCombinations(t *testing.T) {
	tests := []Argon2idParams{
		{Time: 1, Memory: 4, Threads: 1},
		{Time: 1, Memory: 64, Threads: 1},
		{Time: 1, Memory: 8, Threads: 2},
		{Time: 2, Memory: 64, Threads: 4},
		DefaultArgon2idParams(),
	}

	for i, p := range tests {
		if err := validateArgon2idParams(p); err != nil {
			t.Errorf("params[%d] %+v should be valid: %v", i, p, err)
		}
	}
}

func TestDefaultArgon2idParams(t *testing.T) {
	params := DefaultArgon2idParams()
	if params.Time != DefaultArgon2idTime {
		t.Errorf("Time = %d, want %d", params.Time, DefaultArgon2idTime)
	}
	if params.Memory != DefaultArgon2idMemory {
		t.Errorf("Memory = %d, want %d", params.Memory, DefaultArgon2idMemory)
	}
	if params.Threads != DefaultArgon2idThreads {
		t.Errorf("Threads = %d, want %d", params.Threads, DefaultArgon2idThreads)
	}
	if err := validateArgon2idParams(params); err != nil {
		t.Errorf("default params should be valid: %v", err)
	}
}

func TestGenerateArgon2idSalt(t *testing.T) {
	salt, err := GenerateArgon2idSalt()
	if err != nil {
		t.Fatalf("GenerateArgon2idSalt() error = %v", err)
	}
	if len(salt) != SaltLen {
		t.Errorf("salt length = %d, want %d", len(salt), SaltLen)
	}

	// Multiple calls should produce different salts
	salt2, err := GenerateArgon2idSalt()
	if err != nil {
		t.Fatalf("GenerateArgon2idSalt() second call error = %v", err)
	}
	if bytesEqual(salt, salt2) {
		t.Fatal("consecutive salt generations produced identical salts")
	}
}

func TestSetTestArgon2idParams(t *testing.T) {
	prev := testArgon2idParams.Load()

	params := Argon2idParams{Time: 42, Memory: 128, Threads: 2}
	restore := SetTestArgon2idParams(params)

	got := resolveArgon2idParams(Argon2idParams{})
	if got.Time != 42 || got.Memory != 128 || got.Threads != 2 {
		t.Errorf("test params not applied: got %+v, want %+v", got, params)
	}

	restore()
	restored := resolveArgon2idParams(Argon2idParams{})
	expected := *prev.(*Argon2idParams)
	if restored.Time != expected.Time || restored.Memory != expected.Memory || restored.Threads != expected.Threads {
		t.Errorf("params not restored: got %+v, want %+v", restored, expected)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsSubstring(s, substr)
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
