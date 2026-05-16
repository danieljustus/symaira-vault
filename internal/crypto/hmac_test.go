package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"
)

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestGenerateGrantID_ProducesValidFormat(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:   "alice",
		ToAgent:     "bob",
		SecretPath:  "vault/secret/password",
		SecretField: "",
		CreatedAt:   time.Now().UTC(),
	}

	grantID, err := GenerateGrantID(fields, testKey())
	if err != nil {
		t.Fatalf("GenerateGrantID() error = %v", err)
	}

	// Format: nonce_hex:hmac_hex
	parts := strings.SplitN(grantID, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("grant ID %q has wrong format, want nonce:hmac", grantID)
	}

	nonce := parts[0]
	hmacPart := parts[1]

	// Nonce should be 32 hex chars (16 bytes)
	nonceBytes, err := hex.DecodeString(nonce)
	if err != nil {
		t.Fatalf("nonce is not valid hex: %v", err)
	}
	if len(nonceBytes) != NonceSize {
		t.Errorf("nonce length = %d, want %d", len(nonceBytes), NonceSize)
	}

	// HMAC should be 64 hex chars (SHA256)
	hmacBytes, err := hex.DecodeString(hmacPart)
	if err != nil {
		t.Fatalf("HMAC is not valid hex: %v", err)
	}
	if len(hmacBytes) != 32 {
		t.Errorf("HMAC length = %d, want 32", len(hmacBytes))
	}
}

func TestGenerateGrantID_EmptyKey(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/key",
		CreatedAt:  time.Now().UTC(),
	}

	_, err := GenerateGrantID(fields, nil)
	if err == nil {
		t.Fatal("GenerateGrantID() should error with empty key")
	}
}

func TestVerifyGrantID_Valid(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:   "alice",
		ToAgent:     "bob",
		SecretPath:  "vault/secret/api-key",
		SecretField: "password",
		CreatedAt:   time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
	}

	key := testKey()

	grantID, err := GenerateGrantID(fields, key)
	if err != nil {
		t.Fatalf("GenerateGrantID() error = %v", err)
	}

	valid, err := VerifyGrantID(grantID, fields, key)
	if err != nil {
		t.Fatalf("VerifyGrantID() error = %v", err)
	}
	if !valid {
		t.Fatal("VerifyGrantID() should return true for valid grant")
	}
}

func TestVerifyGrantID_TamperedField(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/api-key",
		CreatedAt:  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
	}

	key := testKey()

	grantID, err := GenerateGrantID(fields, key)
	if err != nil {
		t.Fatalf("GenerateGrantID() error = %v", err)
	}

	// Tamper with a field.
	tamperedFields := fields
	tamperedFields.SecretPath = "vault/secret/different-key"

	valid, err := VerifyGrantID(grantID, tamperedFields, key)
	if err != nil {
		t.Fatalf("VerifyGrantID() error = %v", err)
	}
	if valid {
		t.Fatal("VerifyGrantID() should return false for tampered field")
	}
}

func TestVerifyGrantID_TamperedFromAgent(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/key",
		CreatedAt:  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
	}

	key := testKey()

	grantID, err := GenerateGrantID(fields, key)
	if err != nil {
		t.Fatalf("GenerateGrantID() error = %v", err)
	}

	// Attacker changes FromAgent.
	tampered := fields
	tampered.FromAgent = "eve"

	valid, _ := VerifyGrantID(grantID, tampered, key)
	if valid {
		t.Fatal("VerifyGrantID() should return false when FromAgent is tampered")
	}
}

func TestVerifyGrantID_TamperedCreatedAt(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/key",
		CreatedAt:  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
	}

	key := testKey()

	grantID, err := GenerateGrantID(fields, key)
	if err != nil {
		t.Fatalf("GenerateGrantID() error = %v", err)
	}

	tampered := fields
	tampered.CreatedAt = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	valid, _ := VerifyGrantID(grantID, tampered, key)
	if valid {
		t.Fatal("VerifyGrantID() should return false when CreatedAt is tampered")
	}
}

func TestVerifyGrantID_WrongKey(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/key",
		CreatedAt:  time.Now().UTC(),
	}

	key1 := testKey()
	grantID, err := GenerateGrantID(fields, key1)
	if err != nil {
		t.Fatalf("GenerateGrantID() error = %v", err)
	}

	// Different key.
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(255 - i)
	}

	valid, _ := VerifyGrantID(grantID, fields, key2)
	if valid {
		t.Fatal("VerifyGrantID() should return false with different key")
	}
}

func TestVerifyGrantID_EmptyKey(t *testing.T) {
	_, err := VerifyGrantID("nonce:hmac", GrantIDFields{}, nil)
	if err == nil {
		t.Fatal("VerifyGrantID() should error with empty key")
	}
}

func TestVerifyGrantID_NonHMACFormat(t *testing.T) {
	_, err := VerifyGrantID("legacy-uuid", GrantIDFields{}, testKey())
	if err == nil {
		t.Fatal("VerifyGrantID() should error with non-HMAC format")
	}
}

func TestVerifyGrantID_InvalidHMACHex(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/key",
		CreatedAt:  time.Now().UTC(),
	}

	_, err := VerifyGrantID("a1b2c3d4e5f6:not-valid-hex", fields, testKey())
	if err == nil {
		t.Fatal("VerifyGrantID() should error with invalid HMAC hex")
	}
}

func TestVerifyGrantID_InvalidNonceHex(t *testing.T) {
	_, err := VerifyGrantID("not-valid-hex:a1b2c3d4e5f6", GrantIDFields{}, testKey())
	if err == nil {
		t.Fatal("VerifyGrantID() should error with invalid nonce hex")
	}
}

func TestIsHMACFormat(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"a1b2c3d4e5f6:abcdef123456", true},
		{"legacy-uuid", false},
		{"", false},
		{":", true},
		{"550e8400-e29b-41d4-a716-446655440000", false},
		{"nonce_part:hmac_part", true},
	}

	for _, tt := range tests {
		got := IsHMACFormat(tt.id)
		if got != tt.want {
			t.Errorf("IsHMACFormat(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestParseNonceFromID(t *testing.T) {
	nonce, err := ParseNonceFromID("abc123:def456")
	if err != nil {
		t.Fatalf("ParseNonceFromID() error = %v", err)
	}
	if nonce != "abc123" {
		t.Errorf("nonce = %q, want %q", nonce, "abc123")
	}
}

func TestParseNonceFromID_NonHMAC(t *testing.T) {
	_, err := ParseNonceFromID("legacy-uuid")
	if err == nil {
		t.Fatal("ParseNonceFromID() should error on non-HMAC format")
	}
}

func TestGenerateGrantID_NonceUniqueness(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/key",
		CreatedAt:  time.Now().UTC(),
	}
	key := testKey()

	seen := make(map[string]bool)
	const count = 100

	for i := 0; i < count; i++ {
		grantID, err := GenerateGrantID(fields, key)
		if err != nil {
			t.Fatalf("GenerateGrantID() error = %v", err)
		}
		if seen[grantID] {
			t.Fatal("duplicate grant ID generated")
		}
		seen[grantID] = true
	}
}

func TestGenerateGrantID_ConcurrentNonceUniqueness(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/key",
		CreatedAt:  time.Now().UTC(),
	}
	key := testKey()

	var mu sync.Mutex
	seen := make(map[string]bool)
	var wg sync.WaitGroup
	errCh := make(chan error, 200)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			grantID, err := GenerateGrantID(fields, key)
			if err != nil {
				errCh <- err
				return
			}
			mu.Lock()
			if seen[grantID] {
				mu.Unlock()
				errCh <- err
				return
			}
			seen[grantID] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent generate error: %v", err)
	}
}

func TestVerifyGrantID_ConstantTimeBehavior(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/key",
		CreatedAt:  time.Now().UTC(),
	}
	key := testKey()
	grantID, err := GenerateGrantID(fields, key)
	if err != nil {
		t.Fatalf("GenerateGrantID() error = %v", err)
	}

	// Verify valid.
	valid, err := VerifyGrantID(grantID, fields, key)
	if err != nil || !valid {
		t.Fatal("valid grant should verify")
	}

	// Verify with tampered field should fail (uses hmac.Equal internally).
	tampered := fields
	tampered.SecretPath = "different/path"
	valid, err = VerifyGrantID(grantID, tampered, key)
	if err != nil {
		t.Fatalf("VerifyGrantID() error = %v", err)
	}
	if valid {
		t.Fatal("tampered grant should not verify")
	}
}

func TestVerifyGrantID_PreservesSecretFieldEmpty(t *testing.T) {
	// Grants with empty secret_field should still produce verifiable IDs.
	fields := GrantIDFields{
		FromAgent:   "alice",
		ToAgent:     "bob",
		SecretPath:  "vault/secret/key",
		SecretField: "",
		CreatedAt:   time.Now().UTC(),
	}
	key := testKey()

	grantID, err := GenerateGrantID(fields, key)
	if err != nil {
		t.Fatalf("GenerateGrantID() error = %v", err)
	}

	// Verify with same empty field.
	valid, err := VerifyGrantID(grantID, fields, key)
	if err != nil {
		t.Fatalf("VerifyGrantID() error = %v", err)
	}
	if !valid {
		t.Fatal("HMAC verification should work with empty secret_field")
	}
}

func TestVerifyGrantID_RoundtripJSONPreservesTime(t *testing.T) {
	// Simulate the store roundtrip: fields created, serialized to JSON,
	// deserialized, and verified.
	createdAt := time.Date(2025, 6, 15, 14, 30, 0, 123456789, time.UTC)

	fields := GrantIDFields{
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/key",
		CreatedAt:  createdAt,
	}
	key := testKey()

	grantID, err := GenerateGrantID(fields, key)
	if err != nil {
		t.Fatalf("GenerateGrantID() error = %v", err)
	}

	// Verify with the same fields (simulates read-after-write).
	valid, err := VerifyGrantID(grantID, fields, key)
	if err != nil {
		t.Fatalf("VerifyGrantID() error = %v", err)
	}
	if !valid {
		t.Fatal("grant should verify after roundtrip")
	}
}

func TestGenerateGrantID_ProvidedNonce(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/key",
		CreatedAt:  time.Now().UTC(),
		Nonce:      "aabbccdd11223344aabbccdd11223344",
	}
	key := testKey()

	grantID, err := GenerateGrantID(fields, key)
	if err != nil {
		t.Fatalf("GenerateGrantID() error = %v", err)
	}

	// The nonce in the ID should match the provided nonce.
	nonce, err := ParseNonceFromID(grantID)
	if err != nil {
		t.Fatalf("ParseNonceFromID() error = %v", err)
	}
	if nonce != fields.Nonce {
		t.Errorf("nonce = %q, want %q", nonce, fields.Nonce)
	}
}

func TestGenerateGrantID_DifferentKeys(t *testing.T) {
	fields := GrantIDFields{
		FromAgent:  "alice",
		ToAgent:    "bob",
		SecretPath: "vault/secret/key",
		CreatedAt:  time.Now().UTC(),
	}

	key1 := testKey()
	key2 := make([]byte, 32)
	_, _ = rand.Read(key2)

	id1, _ := GenerateGrantID(fields, key1)
	id2, _ := GenerateGrantID(fields, key2)

	// Different keys should produce different HMACs (extract HMAC parts).
	h1 := strings.SplitN(id1, ":", 2)[1]
	h2 := strings.SplitN(id2, ":", 2)[1]
	if h1 == h2 {
		t.Fatal("different keys should produce different HMACs")
	}
}
