# vault:// Scripting Contract

This document defines the non-interactive scripting contract for
`symvault get`. Other tools (memory, eraseme, seek) call `symvault get` as
a subprocess to retrieve secrets; they depend on deterministic exit codes and
stdout/stderr behavior.

## Non-Interactive Detection

When stdin is not a TTY (piped or subprocess context), `symvault get` never
prompts for input. It uses `golang.org/x/term` (`term.IsTerminal`) to detect
whether stdin is a terminal. If stdin is not a terminal:

- The vault is unlocked non-interactively (session cache or env passphrase only).
- No passphrase prompt appears.
- If unlock fails, the process exits immediately with the appropriate code.

## Exit Codes

| Code | Constant              | Meaning                                                    |
| ---- | --------------------- | ---------------------------------------------------------- |
| 0    | `ExitSuccess`         | Secret retrieved successfully.                             |
| 1    | `ExitGeneralError`    | General error (decryption failure, I/O error, etc.).       |
| 2    | `ExitNotFound`        | Entry or field does not exist.                             |
| 3    | `ExitNotInitialized`  | Vault directory exists but has not been initialized.       |
| 4    | `ExitLocked`          | Vault is locked; no passphrase available non-interactively.|
| 5    | `ExitPermissionDenied`| Agent or user lacks permission for the operation.          |
| 6    | `ExitConfigError`     | On-disk configuration is malformed or invalid.             |
| 9    | `ExitInvalidInput`    | Invalid argument (empty path, malformed field syntax).     |

Full exit code reference: [cli-exit-codes.md](cli-exit-codes.md).

## stdout/stderr Guarantees

### `symvault get <path>.<field>` (field access)

| Condition       | stdout                              | stderr                | Exit Code      |
| --------------- | ----------------------------------- | --------------------- | -------------- |
| Success         | Secret value (one trailing newline) | Empty or hints        | 0              |
| Entry not found | Empty                               | Error message         | `ExitNotFound` |
| Vault locked    | Empty                               | Error message         | `ExitLocked`   |
| Uninitialized   | Empty                               | Error message         | `ExitNotInitialized` |

### `symvault get <path>` (whole entry)

| Condition       | stdout                              | stderr                | Exit Code      |
| --------------- | ----------------------------------- | --------------------- | ------------ly |
| Success         | Formatted entry (path, fields, …)   | TOTP codes if present | 0              |
| Entry not found | Empty                               | Error message         | `ExitNotFound` |
| Vault locked    | Empty                               | Error message         | `ExitLocked`   |
| Uninitialized   | Empty                               | Error message         | `ExitNotInitialized` |

### JSON output (`--output json`)

| Condition       | stdout                              | stderr                | Exit Code      |
| --------------- | ----------------------------------- | --------------------- | -------------- |
| Success         | JSON object                         | Empty                 | 0              |
| Entry not found | Empty                               | JSON error or message | `ExitNotFound` |
| Vault locked    | Empty                               | Error message         | `ExitLocked`   |

## Environment Variables

| Variable                | Purpose                                              |
| ----------------------- | ---------------------------------------------------- |
| `SYMVAULT_PASSPHRASE`   | Passphrase for non-interactive unlock (preferred).   |
| `OPENPASS_PASSPHRASE`   | Alias for `SYMVAULT_PASSPHRASE` (legacy compat).    |
| `SYMVAULT_NO_ENV_WARNING` | Set to `1` to suppress env passphrase warning.     |
| `SYMVAULT_NO_PIPE_WARNING` | Set to `1` to suppress pipe-read warning.         |

## Example: Go Integration with Timeout

```go
package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func getSecret(vaultDir, path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "symvault", "--vault", vaultDir, "get", path, "--print")
	out, err := cmd.CombinedOutput()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			switch exitErr.ExitCode() {
			case 4:
				return "", fmt.Errorf("vault locked: run 'symvault unlock' or set SYMVAULT_PASSPHRASE")
			case 2:
				return "", fmt.Errorf("entry not found: %s", path)
			default:
				return "", fmt.Errorf("symvault get failed (exit %d): %s", exitErr.ExitCode(), string(out))
			}
		}
		return "", fmt.Errorf("symvault get: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}
```

## Example: Shell Integration

```bash
#!/bin/sh
# Retrieve a secret non-interactively
SECRET=$(symvault get github.token --print 2>/dev/null)
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo "Got secret: ${SECRET}" ;;
  2) echo "Entry not found" >&2 ;;
  4) echo "Vault locked — run 'symvault unlock' first" >&2 ;;
  *) echo "Unexpected error (exit $EXIT_CODE)" >&2 ;;
esac
```

## Notes

- The `--print` flag forces output to stdout even on TTY (useful for scripting
  regardless of terminal detection).
- The `--output json` flag always outputs to stdout (never clipboard).
- On TTY, `symvault get <path>.field` defaults to clipboard copy. Use
  `--print` to override.
- The session cache has a 15-minute TTL. After expiry, the passphrase must be
  provided again via env var or `symvault unlock`.
