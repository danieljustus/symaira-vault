package vault

import (
	"strings"
	"testing"
)

func TestAllSecretTypes(t *testing.T) {
	types := AllSecretTypes()
	if len(types) != 9 {
		t.Errorf("AllSecretTypes() returned %d types, want 9", len(types))
	}
	// Should include all known types
	seen := make(map[SecretType]bool)
	for _, st := range types {
		seen[st] = true
	}
	for _, st := range []SecretType{
		SecretTypeAPIKey, SecretTypeBearerToken, SecretTypeBasicAuth,
		SecretTypeSSHKey, SecretTypePassword, SecretTypeCertificate,
		SecretTypeDatabaseURL, SecretTypeTOTPSeed, SecretTypeCustom,
	} {
		if !seen[st] {
			t.Errorf("AllSecretTypes() missing %q", st)
		}
	}
}

func TestSecretTypeFromString(t *testing.T) {
	tests := []struct {
		input string
		want  SecretType
	}{
		{"api_key", SecretTypeAPIKey},
		{"API_KEY", SecretTypeAPIKey},
		{"Api_Key", SecretTypeAPIKey},
		{"bearer_token", SecretTypeBearerToken},
		{"basic_auth", SecretTypeBasicAuth},
		{"ssh_key", SecretTypeSSHKey},
		{"password", SecretTypePassword},
		{"PASSWORD", SecretTypePassword},
		{"certificate", SecretTypeCertificate},
		{"database_url", SecretTypeDatabaseURL},
		{"totp_seed", SecretTypeTOTPSeed},
		{"custom", SecretTypeCustom},
		{"unknown", SecretTypeCustom},
		{"", SecretTypeCustom},
	}
	for _, tt := range tests {
		got := SecretTypeFromString(tt.input)
		if got != tt.want {
			t.Errorf("SecretTypeFromString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsValidSecretType(t *testing.T) {
	valid := []string{
		"api_key", "bearer_token", "basic_auth", "ssh_key",
		"password", "certificate", "database_url", "totp_seed", "custom",
		"API_KEY", "PASSWORD",
	}
	for _, s := range valid {
		if !IsValidSecretType(s) {
			t.Errorf("IsValidSecretType(%q) = false, want true", s)
		}
	}
	invalid := []string{"unknown", "", "invalid_type"}
	for _, s := range invalid {
		if IsValidSecretType(s) {
			t.Errorf("IsValidSecretType(%q) = true, want false", s)
		}
	}
}

func TestDetectSecretType(t *testing.T) {
	tests := []struct {
		value string
		want  SecretType
	}{
		{"", SecretTypePassword},
		{"  ", SecretTypePassword},
		// SSH keys
		{"-----BEGIN RSA PRIVATE KEY-----\n...", SecretTypeSSHKey},
		{"-----BEGIN EC PRIVATE KEY-----\n...", SecretTypeSSHKey},
		{"-----BEGIN OPENSSH PRIVATE KEY-----\n...", SecretTypeSSHKey},
		{"-----BEGIN DSA PRIVATE KEY-----\n...", SecretTypeSSHKey},
		// Certificates
		{"-----BEGIN CERTIFICATE-----\n...", SecretTypeCertificate},
		// Database URLs
		{"postgresql://user:pass@localhost:5432/db", SecretTypeDatabaseURL},
		{"mysql://user:pass@localhost:3306/db", SecretTypeDatabaseURL},
		{"mongodb+srv://user:pass@cluster.mongodb.net/db", SecretTypeDatabaseURL},
		{"redis://:password@localhost:6379", SecretTypeDatabaseURL},
		{"ghp_" + strings.Repeat("a", 36), SecretTypeBearerToken},
		{"github_pat_" + strings.Repeat("a", 22) + "_" + strings.Repeat("b", 59), SecretTypeBearerToken},
		{"gho_" + strings.Repeat("a", 36), SecretTypeBearerToken},
		{"ghs_" + strings.Repeat("a", 36), SecretTypeBearerToken},
		{"ghr_" + strings.Repeat("a", 36), SecretTypeBearerToken},
		// AWS access keys
		{"AKIA0123456789ABCDEF", SecretTypeAPIKey},
		// TOTP seeds
		{"JBSWY3DPEHPK3PXP", SecretTypeTOTPSeed},
		// JWT tokens
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3j5Z1O8T6Jw", SecretTypeBearerToken},
		// Basic auth
		{"user:password", SecretTypeBasicAuth},
		// Generic API keys (32+ alphanumeric)
		{"abcdefghijklmnopqrstuvwxyz0123456789", SecretTypeAPIKey},
		// Default to password
		{"simple-password", SecretTypePassword},
		{"short", SecretTypePassword},
	}
	for _, tt := range tests {
		got := DetectSecretType(tt.value)
		if got != tt.want {
			t.Errorf("DetectSecretType(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestUsageHintForType(t *testing.T) {
	tests := []struct {
		st   SecretType
		want string
	}{
		{SecretTypeAPIKey, "API-Key"},
		{SecretTypeBearerToken, "Bearer"},
		{SecretTypeBasicAuth, "basic"},
		{SecretTypeSSHKey, "chmod 600"},
		{SecretTypePassword, "password manager"},
		{SecretTypeCertificate, "TLS/SSL"},
		{SecretTypeDatabaseURL, "connection string"},
		{SecretTypeTOTPSeed, "TOTP generator"},
		{SecretTypeCustom, "specific integration"},
	}
	for _, tt := range tests {
		got := UsageHintForType(tt.st)
		if got == "" {
			t.Errorf("UsageHintForType(%q) returned empty", tt.st)
		}
	}
	// Unknown type should return empty
	if hint := UsageHintForType("unknown_type"); hint != "" {
		t.Errorf("UsageHintForType(unknown) = %q, want empty", hint)
	}
}

func TestSecretTypeIcon(t *testing.T) {
	if icon := SecretTypeIcon(SecretTypeAPIKey); icon == "" {
		t.Error("SecretTypeIcon(api_key) returned empty")
	}
	if icon := SecretTypeIcon("unknown_type"); icon == "" {
		t.Error("SecretTypeIcon(unknown) returned empty, want default")
	}
}
