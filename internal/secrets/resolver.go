// Package secrets provides secret reference resolution and command execution
// with environment variable injection for the Secure Secret Execution Flow.
package secrets

import (
	"errors"
	"fmt"
	"strings"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/vault/taint"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

// HandleResolver resolves a SecretHandle to its actual secret value.
// Implementations wrap vault service Lookup/GetField to resolve op://
// references in MCP tool handlers.
type HandleResolver interface {
	// Resolve returns the secret value for the given handle.
	Resolve(h taint.SecretHandle) (string, error)
}

// ResolveSecretRef resolves a secret reference against the vault service.
// The ref can be a bare entry path (e.g. "work/aws") which returns the full
// entry data, or a path.field reference (e.g. "work/aws.password") which
// returns a specific field value. The path.field syntax is only used if the
// candidate path and field actually exist in the vault.
func ResolveSecretRef(svc vaultsvc.Service, ref string) (string, error) {
	path := ref
	field := ""

	if idx := strings.LastIndex(ref, "."); idx > 0 {
		candidatePath := ref[:idx]
		candidateField := ref[idx+1:]

		if _, readErr := svc.GetField(candidatePath, candidateField); readErr == nil {
			path = candidatePath
			field = candidateField
		}
	}

	value, err := svc.GetField(path, field)
	if err != nil {
		var cliErr *errorspkg.CLIError
		if errors.As(err, &cliErr) {
			if cliErr.Kind == errorspkg.ErrNotFound {
				return "", fmt.Errorf("secret ref not found: %s", path)
			}
			if cliErr.Kind == errorspkg.ErrFieldNotFound {
				return "", fmt.Errorf("field not found in secret ref %s.%s", path, field)
			}
		}
		return "", fmt.Errorf("cannot resolve secret ref %s: %w", ref, err)
	}

	return fmt.Sprintf("%v", value), nil
}
