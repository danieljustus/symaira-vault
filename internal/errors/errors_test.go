package errors

import (
	"errors"
	"fmt"
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
