package errors

import (
	"errors"
	"testing"

	clierrors "github.com/danieljustus/symaira-vault/internal/errors"
)

func TestMCPError_UnwrapsToCLIError(t *testing.T) {
	// EntryNotFound wraps ErrEntryNotFound sentinel
	mcpErr := EntryNotFound("test/path")
	if !errors.Is(mcpErr, clierrors.ErrEntryNotFound) {
		t.Error("EntryNotFound should unwrap to ErrEntryNotFound")
	}

	// FieldNotFound wraps CLIError with ErrFieldNotFound kind
	mcpErr = FieldNotFound("test/path", "password")
	var cliErr *clierrors.CLIError
	if !errors.As(mcpErr, &cliErr) {
		t.Fatal("FieldNotFound should unwrap to CLIError")
	}
	if cliErr.Kind != clierrors.ErrFieldNotFound {
		t.Errorf("kind = %d, want %d", cliErr.Kind, clierrors.ErrFieldNotFound)
	}
}

func TestMCPError_MCPSpecificErrorsHaveNilCause(t *testing.T) {
	mcpErr := AuthRequired("auth required")
	if mcpErr.Cause != nil {
		t.Error("AuthRequired should have nil Cause")
	}
	if mcpErr.Unwrap() != nil {
		t.Error("AuthRequired.Unwrap() should return nil")
	}
}
