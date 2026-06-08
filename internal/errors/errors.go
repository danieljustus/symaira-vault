// Package errors provides centralized error handling for Symaira Vault CLI commands.
// It defines typed errors with exit codes and consistent error wrapping.
package errors

import (
	"errors"
	"fmt"
)

// ExitCode represents a process exit code for CLI commands.
//
// The exit code is part of Symaira Vault's public scripting contract: scripts
// rely on stable codes to distinguish between categories of failure (e.g. "is
// the entry missing?" vs "is the vault locked?"). New categories MUST be
// added at the end of the block, with the same numeric value, and documented
// in docs/cli-exit-codes.md.
type ExitCode int

const (
	// ExitSuccess indicates successful completion.
	ExitSuccess ExitCode = 0
	// ExitGeneralError indicates a general error. Use only when no more
	// specific category applies; prefer the typed constructors below.
	ExitGeneralError ExitCode = 1
	// ExitNotFound indicates the requested entry, field, or resource was
	// not found.
	ExitNotFound ExitCode = 2
	// ExitNotInitialized indicates the vault has not been initialized.
	ExitNotInitialized ExitCode = 3
	// ExitLocked indicates the vault is locked or passphrase is missing.
	ExitLocked ExitCode = 4
	// ExitPermissionDenied indicates a permission denied error.
	ExitPermissionDenied ExitCode = 5
	// ExitConfigError indicates a configuration validation or loading error.
	ExitConfigError ExitCode = 6
	// ExitDoctorWarn indicates doctor found warnings.
	ExitDoctorWarn ExitCode = 7
	// ExitDoctorFail indicates doctor found failures.
	ExitDoctorFail ExitCode = 8
	// ExitInvalidInput indicates user input failed validation (e.g. invalid
	// flag value, empty required argument, parse failure). Distinct from
	// ExitConfigError, which signals that the on-disk configuration is
	// malformed.
	ExitInvalidInput ExitCode = 9
	// ExitUpdateAvailable indicates a new version is available for download.
	ExitUpdateAvailable ExitCode = 10
)

// ErrorKind categorizes vault service errors for consistent mapping to CLI errors.
type ErrorKind int

const (
	ErrKindNone ErrorKind = iota
	ErrNotFound
	ErrFieldNotFound
	ErrReadFailed
	ErrWriteFailed
)

var (
	// ErrEntryNotFound is returned when a requested entry does not exist.
	ErrEntryNotFound = errors.New("entry not found")
	// ErrVaultNotInitialized is returned when the vault has not been initialized.
	ErrVaultNotInitialized = errors.New("vault not initialized")
	// ErrVaultLocked is returned when the vault is locked or passphrase is missing.
	ErrVaultLocked = errors.New("vault locked")
	// ErrPermissionDenied is returned when an operation is not permitted.
	ErrPermissionDenied = errors.New("permission denied")
)

// IsNotFound returns true if the error or any wrapped error is a not-found error.
func IsNotFound(err error) bool {
	var cliErr *CLIError
	if errors.As(err, &cliErr) {
		return cliErr.Kind == ErrNotFound || cliErr.Kind == ErrFieldNotFound
	}
	return false
}

// IsWriteError returns true if the error is a write failure.
func IsWriteError(err error) bool {
	var cliErr *CLIError
	if errors.As(err, &cliErr) {
		return cliErr.Kind == ErrWriteFailed
	}
	return false
}

// CLIError is a structured error with an exit code, user-friendly message,
// and optional remediation hint displayed to the user after the error.
type CLIError struct {
	Code    ExitCode
	Kind    ErrorKind
	Message string
	Cause   error
	Hint    string
}

// Error implements the error interface.
func (e *CLIError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying cause for errors.Is/errors.As support.
func (e *CLIError) Unwrap() error {
	return e.Cause
}

// NewCLIError creates a new CLIError with the given code, message, and optional cause.
func NewCLIError(code ExitCode, msg string, cause error) *CLIError {
	return &CLIError{
		Code:    code,
		Message: msg,
		Cause:   cause,
	}
}

// WithHint returns a new CLIError with the hint set.
func (e *CLIError) WithHint(hint string) *CLIError {
	e.Hint = hint
	return e
}

// HintForError returns a remediation hint for a known error type.
func HintForError(err error) string {
	var cliErr *CLIError
	if errors.As(err, &cliErr) && cliErr.Hint != "" {
		return cliErr.Hint
	}
	return ""
}

// ExitCodeFromError extracts the exit code from an error.
// It checks typed sentinel errors first, then falls back to *CLIError.
// If neither matches, it returns ExitGeneralError.
func ExitCodeFromError(err error) ExitCode {
	if err == nil {
		return ExitSuccess
	}
	if errors.Is(err, ErrEntryNotFound) {
		return ExitNotFound
	}
	if errors.Is(err, ErrVaultNotInitialized) {
		return ExitNotInitialized
	}
	if errors.Is(err, ErrVaultLocked) {
		return ExitLocked
	}
	if errors.Is(err, ErrPermissionDenied) {
		return ExitPermissionDenied
	}
	var cliErr *CLIError
	if errors.As(err, &cliErr) {
		return cliErr.Code
	}
	return ExitGeneralError
}

// Wrap creates a new CLIError with the given code, kind, cause, and formatted message.
func Wrap(code ExitCode, kind ErrorKind, cause error, format string, args ...any) *CLIError {
	return &CLIError{
		Code:    code,
		Kind:    kind,
		Message: fmt.Sprintf(format, args...),
		Cause:   cause,
	}
}

// NotFound creates a new CLIError with Code=ExitNotFound, Kind=ErrNotFound, and Cause=ErrEntryNotFound.
func NotFound(format string, args ...any) *CLIError {
	return &CLIError{
		Code:    ExitNotFound,
		Kind:    ErrNotFound,
		Message: fmt.Sprintf(format, args...),
		Cause:   ErrEntryNotFound,
		Hint:    "Try: symvault list to browse entries, or symvault find <term> to search by keyword.",
	}
}

// ReadFailed creates a new CLIError with Code=ExitGeneralError, Kind=ErrReadFailed, and the given cause.
func ReadFailed(cause error, format string, args ...any) *CLIError {
	return &CLIError{
		Code:    ExitGeneralError,
		Kind:    ErrReadFailed,
		Message: fmt.Sprintf(format, args...),
		Cause:   cause,
	}
}

// WriteFailed creates a new CLIError with Code=ExitGeneralError, Kind=ErrWriteFailed, and the given cause.
func WriteFailed(cause error, format string, args ...any) *CLIError {
	return &CLIError{
		Code:    ExitGeneralError,
		Kind:    ErrWriteFailed,
		Message: fmt.Sprintf(format, args...),
		Cause:   cause,
	}
}

// NotInitialized creates a new CLIError with Code=ExitNotInitialized and the
// sentinel ErrVaultNotInitialized as Cause.
func NotInitialized(format string, args ...any) *CLIError {
	return &CLIError{
		Code:    ExitNotInitialized,
		Kind:    ErrKindNone,
		Message: fmt.Sprintf(format, args...),
		Cause:   ErrVaultNotInitialized,
		Hint:    "Run: symvault init to initialize a new vault.",
	}
}

// Locked creates a new CLIError with Code=ExitLocked and the sentinel
// ErrVaultLocked as Cause.
func Locked(format string, args ...any) *CLIError {
	return &CLIError{
		Code:    ExitLocked,
		Kind:    ErrKindNone,
		Message: fmt.Sprintf(format, args...),
		Cause:   ErrVaultLocked,
		Hint:    "Run: symvault unlock to unlock the vault, or set a passphrase via 'symvault auth set passphrase'.",
	}
}

// PermissionDenied creates a new CLIError with Code=ExitPermissionDenied and
// the sentinel ErrPermissionDenied as Cause.
func PermissionDenied(format string, args ...any) *CLIError {
	return &CLIError{
		Code:    ExitPermissionDenied,
		Kind:    ErrKindNone,
		Message: fmt.Sprintf(format, args...),
		Cause:   ErrPermissionDenied,
	}
}

// InvalidInput creates a new CLIError with Code=ExitInvalidInput. Use this
// for user-facing validation errors (empty arguments, malformed values).
func InvalidInput(format string, args ...any) *CLIError {
	return &CLIError{
		Code:    ExitInvalidInput,
		Kind:    ErrKindNone,
		Message: fmt.Sprintf(format, args...),
	}
}

// ConfigError creates a new CLIError with Code=ExitConfigError. Use this for
// on-disk configuration problems (YAML parse failure, invalid values that
// pass flag validation).
func ConfigError(format string, args ...any) *CLIError {
	return &CLIError{
		Code:    ExitConfigError,
		Kind:    ErrKindNone,
		Message: fmt.Sprintf(format, args...),
	}
}

// Internal creates a new CLIError with Code=ExitGeneralError and no Kind.
// Use for unexpected internal failures where a more specific category does
// not apply.
func Internal(format string, args ...any) *CLIError {
	return &CLIError{
		Code:    ExitGeneralError,
		Kind:    ErrKindNone,
		Message: fmt.Sprintf(format, args...),
	}
}

// AlreadyExists creates a new CLIError with Code=ExitGeneralError. Use when
// an operation would clobber existing state (e.g. `add` against an existing
// entry, recipient add duplicates).
func AlreadyExists(format string, args ...any) *CLIError {
	return &CLIError{
		Code:    ExitGeneralError,
		Kind:    ErrKindNone,
		Message: fmt.Sprintf(format, args...),
	}
}
