package crypto

import (
	"fmt"
	"strings"
	"testing"
)

func TestGeneratePassword_Length(t *testing.T) {
	for _, length := range []int{1, 8, 16, 32, 64} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			password, err := GeneratePassword(length, true)
			if err != nil {
				t.Fatalf("GeneratePassword() error = %v", err)
			}
			if len(password) != length {
				t.Errorf("password length = %d, want %d", len(password), length)
			}
		})
	}
}

func TestGeneratePassword_ZeroLengthDefaultsTo16(t *testing.T) {
	password, err := GeneratePassword(0, true)
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}
	if len(password) != 16 {
		t.Errorf("password length = %d, want 16 (default)", len(password))
	}
}

func TestGeneratePassword_NegativeLengthDefaultsTo16(t *testing.T) {
	password, err := GeneratePassword(-5, true)
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}
	if len(password) != 16 {
		t.Errorf("password length = %d, want 16 (default)", len(password))
	}
}

func TestGeneratePassword_WithSymbols(t *testing.T) {
	password, err := GeneratePassword(50, true)
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}

	hasSymbol := false
	for _, c := range password {
		if strings.Contains("!@#$%^&*()_+-=[]{}|;:,.<>?", string(c)) {
			hasSymbol = true
			break
		}
	}
	if !hasSymbol {
		t.Error("expected password to contain at least one symbol")
	}
}

func TestGeneratePassword_WithoutSymbols(t *testing.T) {
	password, err := GeneratePassword(50, false)
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}

	for _, c := range password {
		if strings.Contains("!@#$%^&*()_+-=[]{}|;:,.<>?", string(c)) {
			t.Error("expected password to NOT contain symbols")
			break
		}
	}
}

func TestGeneratePassword_Randomness(t *testing.T) {
	password1, err := GeneratePassword(16, true)
	if err != nil {
		t.Fatalf("GeneratePassword() first call error = %v", err)
	}
	password2, err := GeneratePassword(16, true)
	if err != nil {
		t.Fatalf("GeneratePassword() second call error = %v", err)
	}
	if password1 == password2 {
		t.Error("expected different passwords on consecutive calls")
	}
}

func TestMaxPasswordLength(t *testing.T) {
	if MaxPasswordLength != 1024 {
		t.Errorf("MaxPasswordLength = %d, want 1024", MaxPasswordLength)
	}
}

func TestGeneratePassword_AtMaxLength(t *testing.T) {
	password, err := GeneratePassword(MaxPasswordLength, false)
	if err != nil {
		t.Fatalf("GeneratePassword(MaxPasswordLength) unexpected error: %v", err)
	}
	if len(password) != MaxPasswordLength {
		t.Errorf("password length = %d, want %d", len(password), MaxPasswordLength)
	}
}

func TestGeneratePassword_OverMaxLength(t *testing.T) {
	_, err := GeneratePassword(MaxPasswordLength+1, false)
	if err == nil {
		t.Fatal("GeneratePassword() error = nil, want error for length over maximum")
	}
}

func TestGeneratePassword_ErrorPath(t *testing.T) {
	failingReader := &errorReader{}
	_, err := generatePasswordWithReader(16, true, failingReader)
	if err == nil {
		t.Fatal("expected error from failing reader, got nil")
	}
	if !strings.Contains(err.Error(), "generate password:") {
		t.Errorf("expected error to contain 'generate password:', got %v", err)
	}
}

type errorReader struct{}

func (e *errorReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("mock reader error")
}

func TestValidatePasswordStrength_WeakShort(t *testing.T) {
	err := ValidatePasswordStrength("123")
	if err == nil {
		t.Error("expected error for short password, got nil")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("expected 'too short' error, got %v", err)
	}
}

func TestValidatePasswordStrength_WeakLowEntropy(t *testing.T) {
	err := ValidatePasswordStrength("abcdefghij")
	if err == nil {
		t.Error("expected error for low entropy password, got nil")
	}
	if !strings.Contains(err.Error(), "too weak") {
		t.Errorf("expected 'too weak' error, got %v", err)
	}
}

func TestValidatePasswordStrength_Strong(t *testing.T) {
	err := ValidatePasswordStrength("StrongP@ssw0rd123")
	if err != nil {
		t.Errorf("expected no error for strong password, got %v", err)
	}
}

func TestValidatePasswordStrength_Empty(t *testing.T) {
	err := ValidatePasswordStrength("")
	if err == nil {
		t.Error("expected error for empty password, got nil")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("expected 'too short' error, got %v", err)
	}
}

func TestValidatePasswordStrength_Unicode(t *testing.T) {
	err := ValidatePasswordStrength("HelloW0rld!日本語テスト")
	if err != nil {
		t.Errorf("expected unicode password with sufficient entropy to be valid, got %v", err)
	}
}

func TestAssessPasswordStrength_WeakShort(t *testing.T) {
	s := AssessPasswordStrength("123")
	if !s.Weak {
		t.Error("expected Weak=true for short password")
	}
	if !strings.Contains(s.Message, "too short") {
		t.Errorf("expected 'too short' message, got %q", s.Message)
	}
	if s.Entropy != 0 {
		t.Errorf("expected Entropy=0 for short password, got %f", s.Entropy)
	}
}

func TestAssessPasswordStrength_WeakLowEntropy(t *testing.T) {
	s := AssessPasswordStrength("abcdefghij")
	if !s.Weak {
		t.Error("expected Weak=true for low entropy password")
	}
	if !strings.Contains(s.Message, "too weak") {
		t.Errorf("expected 'too weak' message, got %q", s.Message)
	}
	if s.Entropy <= 0 {
		t.Errorf("expected positive entropy value, got %f", s.Entropy)
	}
}

func TestAssessPasswordStrength_Strong(t *testing.T) {
	s := AssessPasswordStrength("StrongP@ssw0rd123")
	if s.Weak {
		t.Errorf("expected Weak=false for strong password, got message: %s", s.Message)
	}
	if s.Entropy <= 60 {
		t.Errorf("expected entropy > 60 for strong password, got %f", s.Entropy)
	}
}

func TestAssessPasswordStrength_Empty(t *testing.T) {
	s := AssessPasswordStrength("")
	if !s.Weak {
		t.Error("expected Weak=true for empty password")
	}
	if !strings.Contains(s.Message, "too short") {
		t.Errorf("expected 'too short' message, got %q", s.Message)
	}
}

func TestAssessPasswordStrength_Unicode(t *testing.T) {
	s := AssessPasswordStrength("HelloW0rld!日本語テスト")
	if s.Weak {
		t.Errorf("expected Weak=false for unicode password with sufficient entropy, got %q", s.Message)
	}
}

func TestAssessPasswordStrength_ExactBoundary(t *testing.T) {
	// 10 chars, all lowercase = 10 * log2(26) ≈ 47 bits → weak
	s := AssessPasswordStrength("abcdefghij")
	if !s.Weak {
		t.Error("expected Weak=true for 10 lowercase chars (≈47 bits < 60)")
	}
}
