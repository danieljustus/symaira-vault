// Package errors provides structured error types for MCP tools.
package errors

import "fmt"

// MCPError represents a structured error response for MCP tools.
type MCPError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Hint    string         `json:"hint,omitempty"`
	Details map[string]any `json:"details,omitempty"`
	Doc     string         `json:"doc,omitempty"`
}

// Error implements the error interface.
func (e *MCPError) Error() string { return e.Message }

// Error codes as constants.
const (
	ErrAuthRequired          = "ERR_AUTH_REQUIRED"
	ErrPathForbidden         = "ERR_PATH_FORBIDDEN"
	ErrToolNotAllowed        = "ERR_TOOL_NOT_ALLOWED"
	ErrApprovalDenied        = "ERR_APPROVAL_DENIED"
	ErrApprovalTimeout       = "ERR_APPROVAL_TIMEOUT"
	ErrApprovalUnavailable   = "ERR_APPROVAL_UNAVAILABLE"
	ErrEntryNotFound         = "ERR_ENTRY_NOT_FOUND"
	ErrFieldNotFound         = "ERR_FIELD_NOT_FOUND"
	ErrFieldRedacted         = "ERR_FIELD_REDACTED"
	ErrQuotaExceeded         = "ERR_QUOTA_EXCEEDED"
	ErrTokenExpired          = "ERR_TOKEN_EXPIRED"
	ErrInvalidInput          = "ERR_INVALID_INPUT"
	ErrDryRun                = "ERR_DRY_RUN"
	ErrTierUpgradeNoTTY      = "ERR_TIER_UPGRADE_NO_TTY"
	ErrConfigExistsUnmanaged = "ERR_CONFIG_EXISTS_UNMANAGED"
	ErrToolNotFound          = "ERR_TOOL_NOT_FOUND"
)

// New creates a new MCPError with the given code and message.
func New(code, message string) *MCPError {
	return &MCPError{
		Code:    code,
		Message: message,
	}
}

// WithHint creates a new MCPError with a hint for the user.
func WithHint(code, message, hint string) *MCPError {
	return &MCPError{
		Code:    code,
		Message: message,
		Hint:    hint,
	}
}

// WithDetails creates a new MCPError with structured details.
func WithDetails(code, message string, details map[string]any) *MCPError {
	return &MCPError{
		Code:    code,
		Message: message,
		Details: details,
	}
}

// WithDoc creates a new MCPError with a documentation URL.
func WithDoc(code, message, docURL string) *MCPError {
	return &MCPError{
		Code:    code,
		Message: message,
		Doc:     docURL,
	}
}

// AuthRequired creates an authentication-required error.
func AuthRequired(msg string) *MCPError {
	return New(ErrAuthRequired, msg)
}

// PathForbidden creates a path-forbidden error with the path and allowed paths.
func PathForbidden(path string, allowed []string) *MCPError {
	return WithDetails(ErrPathForbidden, fmt.Sprintf("Path %q is not allowed", path), map[string]any{
		"path":             path,
		"allowed_for_path": allowed,
	})
}

// ToolNotAllowed creates a tool-not-allowed error indicating the required tier.
func ToolNotAllowed(tool, tier, upgradeCmd string) *MCPError {
	return WithDetails(ErrToolNotAllowed, fmt.Sprintf("Tool %q requires tier %q", tool, tier), map[string]any{
		"tool":            tool,
		"required_tier":   tier,
		"upgrade_command": upgradeCmd,
	})
}

// EntryNotFound creates an entry-not-found error for the given path.
func EntryNotFound(path string) *MCPError {
	return New(ErrEntryNotFound, fmt.Sprintf("Entry %q not found", path))
}

// QuotaExceeded creates a quota-exceeded error.
func QuotaExceeded(quotaType string, used, limit int) *MCPError {
	return WithDetails(ErrQuotaExceeded, fmt.Sprintf("Quota exceeded for %s: %d/%d", quotaType, used, limit), map[string]any{
		"quota_type": quotaType,
		"used":       used,
		"limit":      limit,
	})
}

// InvalidInput creates an invalid-input error for a specific field.
func InvalidInput(field, reason string) *MCPError {
	return WithDetails(ErrInvalidInput, fmt.Sprintf("Invalid input for %q: %s", field, reason), map[string]any{
		"field":  field,
		"reason": reason,
	})
}
