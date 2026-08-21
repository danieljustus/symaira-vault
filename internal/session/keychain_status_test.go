package session

import (
	"errors"
	"strings"
	"testing"
)

func TestKeychainStatusError_Success(t *testing.T) {
	if err := keychainStatusError(errSecSuccess); err != nil {
		t.Fatalf("keychainStatusError(errSecSuccess) = %v, want nil", err)
	}
}

func TestKeychainStatusError_Mapping(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		wantSentinel  error
		wantContains  []string
		wantBiometric bool
	}{
		{
			name:         "duplicate item",
			status:       errSecDuplicateItem,
			wantSentinel: ErrKeychainDuplicateItem,
			wantContains: []string{"keychain item already exists", "keychain status -25299", "symvault doctor", "security list-keychains"},
		},
		{
			name:         "item not found",
			status:       errSecItemNotFound,
			wantSentinel: ErrKeychainItemNotFound,
			wantContains: []string{"keychain item not found", "keychain status -25300", "symvault doctor"},
		},
		{
			name:         "no such keychain",
			status:       errSecNoSuchKeychain,
			wantSentinel: ErrKeychainNoSuchKeychain,
			wantContains: []string{"keychain not found", "keychain status -25294", "symvault doctor"},
		},
		{
			name:         "invalid keychain",
			status:       errSecInvalidKeychain,
			wantSentinel: ErrKeychainInvalid,
			wantContains: []string{"invalid or corrupted", "keychain status -25295"},
		},
		{
			name:         "not available",
			status:       errSecNotAvailable,
			wantSentinel: ErrKeychainLocked,
			wantContains: []string{"locked or unavailable", "keychain status -25291", "security unlock-keychain"},
		},
		{
			name:         "read only",
			status:       errSecReadOnly,
			wantSentinel: ErrKeychainReadOnly,
			wantContains: []string{"read-only", "keychain status -25292"},
		},
		{
			name:         "interaction not allowed",
			status:       errSecInteractionNotAllowed,
			wantSentinel: ErrKeychainInteractionNotAllowed,
			wantContains: []string{"requires user interaction", "keychain status -25308", "security unlock-keychain"},
		},
		{
			name:         "missing entitlement",
			status:       errSecMissingEntitlement,
			wantSentinel: ErrKeychainMissingEntitlement,
			wantContains: []string{"access denied for this binary", "keychain status -34018"},
		},
		{
			name:         "decode failure",
			status:       errSecDecode,
			wantSentinel: ErrKeychainInvalid,
			wantContains: []string{"could not be decoded", "keychain status -26275", "symvault auth set touchid"},
		},
		{
			name:         "bad parameters",
			status:       errSecParam,
			wantSentinel: ErrKeychainInternal,
			wantContains: []string{"rejected the request parameters", "keychain status -50"},
		},
		{
			name:         "allocation failure",
			status:       errSecAllocate,
			wantSentinel: ErrKeychainInternal,
			wantContains: []string{"allocate memory", "keychain status -108"},
		},
		{
			name:         "unimplemented",
			status:       errSecUnimplemented,
			wantSentinel: ErrKeychainInternal,
			wantContains: []string{"not implemented", "keychain status -4"},
		},
		{
			name:          "authentication failed is biometric",
			status:        errSecAuthFailed,
			wantSentinel:  ErrBiometricFailed,
			wantContains:  []string{"biometric authentication failed", "keychain status -25293"},
			wantBiometric: true,
		},
		{
			name:          "user canceled is biometric",
			status:        errSecUserCanceled,
			wantSentinel:  ErrBiometricFailed,
			wantContains:  []string{"prompt was canceled", "keychain status -128"},
			wantBiometric: true,
		},
		{
			name:         "unknown status",
			status:       -12345,
			wantSentinel: ErrKeychainUnexpectedStatus,
			wantContains: []string{"unexpected keychain error", "keychain status -12345", "symvault doctor"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := keychainStatusError(tt.status)
			if err == nil {
				t.Fatalf("keychainStatusError(%d) = nil, want error", tt.status)
			}
			if !errors.Is(err, tt.wantSentinel) {
				t.Errorf("keychainStatusError(%d) = %v, want errors.Is(..., %v)", tt.status, err, tt.wantSentinel)
			}
			for _, want := range tt.wantContains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("keychainStatusError(%d) = %q, want it to contain %q", tt.status, err, want)
				}
			}
			if got := errors.Is(err, ErrBiometricFailed); got != tt.wantBiometric {
				t.Errorf("errors.Is(keychainStatusError(%d), ErrBiometricFailed) = %v, want %v", tt.status, got, tt.wantBiometric)
			}
		})
	}
}

// TestKeychainStatusError_NonBiometricStatusesAreNotBiometric guards the
// regression this mapping exists for: a keychain search list problem used
// to surface as "biometric authentication failed", which sent users
// looking for a Touch ID fault that was never there.
func TestKeychainStatusError_NonBiometricStatusesAreNotBiometric(t *testing.T) {
	for _, status := range []int{errSecDuplicateItem, errSecInteractionNotAllowed, errSecNoSuchKeychain} {
		err := keychainStatusError(status)
		if errors.Is(err, ErrBiometricFailed) {
			t.Errorf("keychainStatusError(%d) = %v, must not wrap ErrBiometricFailed", status, err)
		}
		if !strings.Contains(err.Error(), "keychain") {
			t.Errorf("keychainStatusError(%d) = %q, want a message naming the keychain", status, err)
		}
	}
}

// TestKeychainStatusError_SentinelsAreDistinct keeps callers able to tell
// the failure modes apart with errors.Is.
func TestKeychainStatusError_SentinelsAreDistinct(t *testing.T) {
	sentinels := map[string]error{
		"duplicate":     ErrKeychainDuplicateItem,
		"not found":     ErrKeychainItemNotFound,
		"no keychain":   ErrKeychainNoSuchKeychain,
		"invalid":       ErrKeychainInvalid,
		"locked":        ErrKeychainLocked,
		"read only":     ErrKeychainReadOnly,
		"interaction":   ErrKeychainInteractionNotAllowed,
		"entitlement":   ErrKeychainMissingEntitlement,
		"internal":      ErrKeychainInternal,
		"unexpected":    ErrKeychainUnexpectedStatus,
		"biometric":     ErrBiometricFailed,
		"notconfigured": ErrBiometricNotConfigured,
	}
	for nameA, a := range sentinels {
		for nameB, b := range sentinels {
			if nameA == nameB {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("sentinel %q matches %q; they must be distinct", nameA, nameB)
			}
		}
	}
}

// TestKeychainStatusError_HintsPointAtDoctor documents that the statuses
// doctor already diagnoses send the user there.
func TestKeychainStatusError_HintsPointAtDoctor(t *testing.T) {
	for _, status := range []int{errSecDuplicateItem, errSecItemNotFound, errSecNoSuchKeychain, errSecInvalidKeychain} {
		err := keychainStatusError(status)
		if !strings.Contains(err.Error(), "`symvault doctor`") {
			t.Errorf("keychainStatusError(%d) = %q, want it to point at `symvault doctor`", status, err)
		}
	}
}
