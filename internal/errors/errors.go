// Package errors provides centralized error handling for OpenPass CLI commands.
// It defines typed errors with exit codes and consistent error wrapping.
package errors

import (
	"errors"
	"fmt"
)

// ExitCode represents a process exit code for CLI commands.
type ExitCode int

const (
	// ExitSuccess indicates successful completion.
	ExitSuccess ExitCode = 0
	// ExitGeneralError indicates a general error.
	ExitGeneralError ExitCode = 1
	// ExitNotFound indicates the requested entry was not found.
	ExitNotFound ExitCode = 2
	// ExitNotInitialized indicates the vault is not initialized.
	ExitNotInitialized ExitCode = 3
	// ExitLocked indicates the vault is locked or passphrase is missing.
	ExitLocked ExitCode = 4
	// ExitPermissionDenied indicates a permission denied error.
	ExitPermissionDenied ExitCode = 5
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

// CLIError is a structured error with an exit code and user-friendly message.
type CLIError struct {
	Code    ExitCode
	Kind    ErrorKind
	Message string
	Cause   error
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
