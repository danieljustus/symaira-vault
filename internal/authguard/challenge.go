// Package authguard provides identity verification challenges for critical
// configuration operations. It integrates the existing biometric (Touch ID /
// Face ID) authenticator from internal/session and provides a clear upgrade
// path for platforms that do not support biometrics.
package authguard

import (
	"context"
	"errors"
	"fmt"

	"github.com/danieljustus/symaira-vault/internal/session"
)

// ErrBiometryRequired is returned by policy evaluation when a rule matches
// with ActionRequireBiometry. Callers in the tool dispatch layer should catch
// this error, trigger a biometric challenge, and only proceed on success.
var ErrBiometryRequired = errors.New("biometric verification required by policy")

// OperationType classifies a critical configuration operation.
type OperationType string

const (
	OpTierUpgrade   OperationType = "agent_tier_upgrade"
	OpAuthMethodSet OperationType = "set_auth_method"
)

// CriticalMCPTools is the set of MCP tool names that perform critical
// configuration changes and therefore require biometric verification.
var CriticalMCPTools = map[string]bool{
	"set_auth_method": true,
}

// IsCriticalMCPTool reports whether toolName is a known critical-config MCP tool.
func IsCriticalMCPTool(toolName string) bool {
	return CriticalMCPTools[toolName]
}

// Challenger verifies the user's identity before a critical operation.
// It delegates to the platform's BiometricAuthenticator (Touch ID on macOS,
// noop on all other platforms).
type Challenger struct {
	// authenticator returns the current BiometricAuthenticator. Exposed as a
	// field (rather than hardcoding session.DefaultBiometricAuthenticator) so
	// tests can inject mocks.
	Authenticator func() session.BiometricAuthenticator
}

// DefaultChallenger returns a production-ready Challenger wired to the
// platform's real biometric authenticator.
func DefaultChallenger() *Challenger {
	return &Challenger{
		Authenticator: session.DefaultBiometricAuthenticator,
	}
}

// Available reports whether biometric verification is possible on this platform.
func (c *Challenger) Available() bool {
	if c == nil || c.Authenticator == nil {
		return false
	}
	return c.Authenticator().IsAvailable()
}

// Challenge triggers a biometric prompt and blocks until the user succeeds,
// fails, or cancels. It returns nil on success, or an error describing why
// verification could not be completed.
//
// The reason string is shown in the Touch ID system dialog on macOS. Keep it
// concise (≤ 128 chars) and include the specific operation details.
func (c *Challenger) Challenge(ctx context.Context, op OperationType, reason string) error {
	if c == nil || c.Authenticator == nil {
		return fmt.Errorf("biometric challenger not initialized")
	}

	auth := c.Authenticator()
	if !auth.IsAvailable() {
		return fmt.Errorf("%w: biometric authentication is not available on this platform", session.ErrBiometricNotAvailable)
	}

	if err := auth.Authenticate(ctx, reason); err != nil {
		return fmt.Errorf("biometric verification for %s failed: %w", op, err)
	}

	return nil
}

// String returns a short, user-visible label for an operation type.
func (op OperationType) String() string {
	switch op {
	case OpTierUpgrade:
		return "agent tier upgrade"
	case OpAuthMethodSet:
		return "auth method change"
	default:
		return string(op)
	}
}

// VerifyIdentity is a convenience helper that attempts biometric verification
// and returns an error explaining how to bypass it when biometric is unavailable.
// Callers should check the return value; on success (nil) the operation can
// proceed. On error the returned message is suitable for display to the user.
func VerifyIdentity(ctx context.Context, op OperationType, reason string) error {
	c := DefaultChallenger()
	if !c.Available() {
		return fmt.Errorf(
			"biometric verification is not available on this platform for %s.\n"+
				"Re-run with --no-biometric to bypass (not recommended for automated use).\n"+
				"For interactive use, re-enter your vault passphrase when prompted",
			op,
		)
	}
	return c.Challenge(ctx, op, reason)
}
