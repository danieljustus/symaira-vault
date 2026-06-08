package errors

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNewCLIError(t *testing.T) {
	err := NewCLIError(ExitLocked, "vault locked", errors.New("passphrase missing"))
	if err.Code != ExitLocked {
		t.Errorf("expected code %d, got %d", ExitLocked, err.Code)
	}
	if err.Message != "vault locked" {
		t.Errorf("expected message %q, got %q", "vault locked", err.Message)
	}
	if err.Cause == nil || err.Cause.Error() != "passphrase missing" {
		t.Error("expected cause to match")
	}
}

func TestCLIError_Error(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		err := NewCLIError(ExitGeneralError, "cannot list", fmt.Errorf("io error"))
		want := "cannot list: io error"
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := NewCLIError(ExitNotFound, "invalid argument", nil)
		want := "invalid argument"
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})
}

func TestExitCodeFromError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ExitCode
	}{
		{"nil error", nil, ExitSuccess},
		{"plain error", fmt.Errorf("plain"), ExitGeneralError},
		{"CLIError vault locked", NewCLIError(ExitLocked, "locked", nil), ExitLocked},
		{"wrapped CLIError", fmt.Errorf("outer: %w", NewCLIError(ExitNotInitialized, "not init", nil)), ExitNotInitialized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCodeFromError(tt.err); got != tt.want {
				t.Errorf("ExitCodeFromError() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestWrap(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		inner := fmt.Errorf("inner")
		err := Wrap(ExitGeneralError, ErrReadFailed, inner, "read failed: %v", inner)
		var cliErr *CLIError
		if !errors.As(err, &cliErr) {
			t.Fatal("expected *CLIError")
		}
		if cliErr.Code != ExitGeneralError {
			t.Errorf("code = %d, want %d", cliErr.Code, ExitGeneralError)
		}
		if cliErr.Kind != ErrReadFailed {
			t.Errorf("kind = %d, want %d", cliErr.Kind, ErrReadFailed)
		}
		if cliErr.Message != "read failed: inner" {
			t.Errorf("message = %q, want %q", cliErr.Message, "read failed: inner")
		}
		if !errors.Is(err, inner) {
			t.Error("expected wrapped error to be unwrappable")
		}
	})

	t.Run("with nil cause", func(t *testing.T) {
		err := Wrap(ExitNotFound, ErrFieldNotFound, nil, "field missing")
		var cliErr *CLIError
		if !errors.As(err, &cliErr) {
			t.Fatal("expected *CLIError")
		}
		if cliErr.Code != ExitNotFound {
			t.Errorf("code = %d, want %d", cliErr.Code, ExitNotFound)
		}
		if cliErr.Kind != ErrFieldNotFound {
			t.Errorf("kind = %d, want %d", cliErr.Kind, ErrFieldNotFound)
		}
		if cliErr.Cause != nil {
			t.Error("expected nil cause")
		}
	})
}

func TestNotFound(t *testing.T) {
	err := NotFound("entry not found: %s", "foo")
	if err.Code != ExitNotFound {
		t.Errorf("code = %d, want %d", err.Code, ExitNotFound)
	}
	if err.Kind != ErrNotFound {
		t.Errorf("kind = %d, want %d", err.Kind, ErrNotFound)
	}
	if err.Message != "entry not found: foo" {
		t.Errorf("message = %q, want %q", err.Message, "entry not found: foo")
	}
	if !errors.Is(err, ErrEntryNotFound) {
		t.Error("expected cause to be ErrEntryNotFound")
	}
}

func TestReadFailed(t *testing.T) {
	inner := fmt.Errorf("io error")
	err := ReadFailed(inner, "cannot read entry foo: %v", inner)
	if err.Code != ExitGeneralError {
		t.Errorf("code = %d, want %d", err.Code, ExitGeneralError)
	}
	if err.Kind != ErrReadFailed {
		t.Errorf("kind = %d, want %d", err.Kind, ErrReadFailed)
	}
	if err.Message != "cannot read entry foo: io error" {
		t.Errorf("message = %q, want %q", err.Message, "cannot read entry foo: io error")
	}
	if !errors.Is(err, inner) {
		t.Error("expected cause to be inner error")
	}
}

func TestWriteFailed(t *testing.T) {
	inner := fmt.Errorf("disk full")
	err := WriteFailed(inner, "cannot write entry bar: %v", inner)
	if err.Code != ExitGeneralError {
		t.Errorf("code = %d, want %d", err.Code, ExitGeneralError)
	}
	if err.Kind != ErrWriteFailed {
		t.Errorf("kind = %d, want %d", err.Kind, ErrWriteFailed)
	}
	if err.Message != "cannot write entry bar: disk full" {
		t.Errorf("message = %q, want %q", err.Message, "cannot write entry bar: disk full")
	}
	if !errors.Is(err, inner) {
		t.Error("expected cause to be inner error")
	}
}

func TestIsNotFound_True(t *testing.T) {
	err := NotFound("entry %q not found", "github")
	if !IsNotFound(err) {
		t.Error("expected IsNotFound=true for NotFound error")
	}
}

func TestIsNotFound_False(t *testing.T) {
	err := fmt.Errorf("some other error")
	if IsNotFound(err) {
		t.Error("expected IsNotFound=false for non-NotFound error")
	}
}

func TestIsNotFound_WriteError(t *testing.T) {
	err := WriteFailed(nil, "write error occurred")
	if IsNotFound(err) {
		t.Error("expected IsNotFound=false for WriteFailed error")
	}
}

func TestIsWriteError_True(t *testing.T) {
	err := WriteFailed(nil, "cannot write")
	if !IsWriteError(err) {
		t.Error("expected IsWriteError=true for WriteFailed error")
	}
}

func TestIsWriteError_False(t *testing.T) {
	err := fmt.Errorf("not a write error")
	if IsWriteError(err) {
		t.Error("expected IsWriteError=false for non-write error")
	}
}

func TestIsWriteError_NotFoundError(t *testing.T) {
	err := NotFound("entry %q not found", "github")
	if IsWriteError(err) {
		t.Error("expected IsWriteError=false for NotFound error")
	}
}

func TestNotFoundHasHint(t *testing.T) {
	err := NotFound("entry not found: foo")
	if err.Hint == "" {
		t.Error("expected NotFound error to have a hint")
	}
	if !strings.Contains(err.Hint, "symvault list") && !strings.Contains(err.Hint, "symvault find") {
		t.Errorf("expected hint to mention symvault list or symvault find, got: %s", err.Hint)
	}
}

func TestWithHint(t *testing.T) {
	err := NewCLIError(ExitGeneralError, "something went wrong", nil)
	err.WithHint("Run symvault doctor to check your configuration.")

	if err.Hint != "Run symvault doctor to check your configuration." {
		t.Errorf("hint = %q, want specific hint", err.Hint)
	}
}

func TestHintForError(t *testing.T) {
	err := NotFound("entry not found: foo")
	hint := HintForError(err)
	if hint == "" {
		t.Error("expected HintForError to return a hint for NotFound")
	}
}

func TestHintForError_NoHint(t *testing.T) {
	err := fmt.Errorf("plain error")
	hint := HintForError(err)
	if hint != "" {
		t.Errorf("expected empty hint for plain error, got: %s", hint)
	}
}

func TestCLIErrorWithoutHint(t *testing.T) {
	err := NewCLIError(ExitLocked, "vault is locked", nil)
	hint := HintForError(err)
	if hint != "" {
		t.Errorf("expected empty hint for CLIError without hint, got: %s", hint)
	}
}

func TestCLIErrorWithHintTakesPrecedence(t *testing.T) {
	err := NewCLIError(ExitPermissionDenied, "access denied", nil)
	err.WithHint("Check your agent's token scope: symvault mcp token list")

	hint := HintForError(err)
	if hint != "Check your agent's token scope: symvault mcp token list" {
		t.Errorf("hint = %q, want token scope hint", err.Hint)
	}
}

func TestNotInitialized(t *testing.T) {
	err := NotInitialized("vault at %s is not ready", "/tmp/vault")
	if err.Code != ExitNotInitialized {
		t.Errorf("code = %d, want %d", err.Code, ExitNotInitialized)
	}
	if !strings.Contains(err.Message, "/tmp/vault") {
		t.Errorf("message = %q, want path interpolated", err.Message)
	}
	if !errors.Is(err, ErrVaultNotInitialized) {
		t.Error("expected cause to be ErrVaultNotInitialized")
	}
	if err.Hint == "" {
		t.Error("expected NotInitialized to have a hint")
	}
}

func TestLocked(t *testing.T) {
	err := Locked("vault is locked: %s", "session expired")
	if err.Code != ExitLocked {
		t.Errorf("code = %d, want %d", err.Code, ExitLocked)
	}
	if !errors.Is(err, ErrVaultLocked) {
		t.Error("expected cause to be ErrVaultLocked")
	}
	if err.Hint == "" {
		t.Error("expected Locked to have a hint")
	}
}

func TestPermissionDenied(t *testing.T) {
	err := PermissionDenied("agent %s cannot write", "hermes")
	if err.Code != ExitPermissionDenied {
		t.Errorf("code = %d, want %d", err.Code, ExitPermissionDenied)
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Error("expected cause to be ErrPermissionDenied")
	}
	if ExitCodeFromError(err) != ExitPermissionDenied {
		t.Errorf("ExitCodeFromError = %d, want %d", ExitCodeFromError(err), ExitPermissionDenied)
	}
}

func TestInvalidInput(t *testing.T) {
	err := InvalidInput("flag --length must be > 0")
	if err.Code != ExitInvalidInput {
		t.Errorf("code = %d, want %d", err.Code, ExitInvalidInput)
	}
	if err.Kind != ErrKindNone {
		t.Errorf("kind = %d, want %d", err.Kind, ErrKindNone)
	}
	if ExitCodeFromError(err) != ExitInvalidInput {
		t.Errorf("ExitCodeFromError = %d, want %d", ExitCodeFromError(err), ExitInvalidInput)
	}
}

func TestConfigError(t *testing.T) {
	err := ConfigError("config.yaml: invalid value for %q", "sessionTimeout")
	if err.Code != ExitConfigError {
		t.Errorf("code = %d, want %d", err.Code, ExitConfigError)
	}
	if ExitCodeFromError(err) != ExitConfigError {
		t.Errorf("ExitCodeFromError = %d, want %d", ExitCodeFromError(err), ExitConfigError)
	}
}

func TestInternal(t *testing.T) {
	err := Internal("unexpected state: %s", "nil vault pointer")
	if err.Code != ExitGeneralError {
		t.Errorf("code = %d, want %d", err.Code, ExitGeneralError)
	}
	if ExitCodeFromError(err) != ExitGeneralError {
		t.Errorf("ExitCodeFromError = %d, want %d", ExitCodeFromError(err), ExitGeneralError)
	}
}

func TestAlreadyExists(t *testing.T) {
	err := AlreadyExists("entry %q already exists", "github")
	if err.Code != ExitGeneralError {
		t.Errorf("code = %d, want %d", err.Code, ExitGeneralError)
	}
	if err.Message != "entry \"github\" already exists" {
		t.Errorf("message = %q, want formatted message", err.Message)
	}
}
