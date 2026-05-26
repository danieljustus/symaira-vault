// Package secrets provides secret reference resolution and command execution
// with environment variable injection for the Secure Secret Execution Flow.
package secrets

import (
	"errors"
	"fmt"
	"os"
	"strings"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
	"github.com/danieljustus/symaira-vault/internal/vault/taint"
)

// HandleResolver resolves a SecretHandle to its actual secret value.
// Implementations wrap vault service Lookup/GetField to resolve op://
// references in MCP tool handlers.
type HandleResolver interface {
	// Resolve returns the secret value for the given handle.
	Resolve(h taint.SecretHandle) (string, error)
}

// ResolveSecretRef resolves a secret reference against the vault.
// The ref can be a bare entry path (e.g. "work/aws") which returns the full
// entry data, or a path.field reference (e.g. "work/aws.password") which
// returns a specific field value. The path.field syntax is only used if the
// candidate path and field actually exist in the vault.
func ResolveSecretRef(vault *vaultpkg.Vault, ref string) (string, error) {
	path := ref
	field := ""

	if idx := strings.LastIndex(ref, "."); idx > 0 {
		candidatePath := ref[:idx]
		candidateField := ref[idx+1:]

		entry, readErr := vaultpkg.ReadEntry(vault.Dir, candidatePath, vault.Identity)
		if readErr == nil {
			if _, ok := entry.Data[candidateField]; ok {
				path = candidatePath
				field = candidateField
			}
		}
	}

	entry, err := vaultpkg.ReadEntry(vault.Dir, path, vault.Identity)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("secret ref not found: %s", path)
		}
		return "", fmt.Errorf("cannot resolve secret ref %s: %w", ref, err)
	}

	if field != "" {
		val, ok := entry.Data[field]
		if !ok {
			return "", fmt.Errorf("field not found in secret ref %s.%s", path, field)
		}
		return fmt.Sprintf("%v", val), nil
	}

	return fmt.Sprintf("%v", entry.Data), nil
}
