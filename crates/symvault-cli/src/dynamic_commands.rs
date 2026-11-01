//! `symvault dynamic generate` — Go oracle `cmd/dynamic.go` and
//! `internal/dynamicsecret`.
//!
//! The oracle's command opens the vault (`cli.WithVault`: initialization gate,
//! passphrase policy, unlock) and then asks `dynamicsecret.NewManager(v)` for the
//! requested engine. `NewManager` starts with an empty `EngineRegistry`, and no
//! production code calls `RegisterEngine` (the PostgreSQL and AWS STS engines
//! exist only behind the `dynamic_secrets` build tag and are never registered,
//! not even in a tagged build). Every invocation that reaches the command body
//! therefore fails with `generate dynamic secret: dynamic secret engine not
//! found`, reported by cobra and again by `ExecuteRoot` (exit 1). This module
//! reproduces exactly that; there is no engine to port.
//!
//! Flag parsing (`--engine`/`--role` are `MarkFlagRequired`, `--ttl` is a
//! `time.Duration`) and the output-format gate run before the body in
//! `cobra_usage`.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

/// `dynamicsecret.ErrEngineNotFound` wrapped by `newDynamicGenerateCmd`.
pub(crate) const ENGINE_NOT_FOUND: &str =
    "generate dynamic secret: dynamic secret engine not found";

pub(crate) fn generate(explicit_vault: Option<&Path>, profile: Option<&str>) -> ExitCode {
    let result = (|| {
        let vault = crate::resolve_vault(explicit_vault, profile)?;
        crate::require_initialized(&vault)?;
        crate::device::unlock_vault(&vault)?;
        Err(ENGINE_NOT_FOUND.to_owned())
    })();
    finish(result)
}

/// The hint `ExecuteRoot` prints after an `ExitLocked` error.
const LOCKED_HINT: &str = "Unlock with 'symvault unlock'. For non-interactive use, set SYMVAULT_PASSPHRASE together with SYMVAULT_ALLOW_ENV_PASSPHRASE=1 (or security.allow_env_passphrase: true in config.yaml) \u{2014} the passphrase variable alone is ignored.";

/// The hint of the `ExitLocked` error `resolveUnlockPassphrase` returns when
/// `SYMVAULT_PASSPHRASE` is set but not allowed.
const ENV_DISABLED_HINT: &str = "Set SYMVAULT_ALLOW_ENV_PASSPHRASE=1 or security.allow_env_passphrase: true in config.yaml to allow SYMVAULT_PASSPHRASE for non-interactive use.";

fn finish(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if crate::is_not_initialized(&error) => {
            crate::write_not_initialized(&error);
            ExitCode::from(3)
        }
        Err(error) => {
            // cobra and `ExecuteRoot` each print the error.
            crate::print_error_like_go(&error);
            let locked_hint = if error.starts_with("vault locked:") {
                Some(
                    if error.contains(
                        "SYMVAULT_PASSPHRASE is set but env passphrase unlock is disabled",
                    ) {
                        ENV_DISABLED_HINT
                    } else {
                        LOCKED_HINT
                    },
                )
            } else if error.starts_with("read passphrase: ") {
                // A failed passphrase read is an `ExitLocked` error too.
                Some(LOCKED_HINT)
            } else {
                None
            };
            match locked_hint {
                Some(hint) => {
                    let _ = writeln!(io::stderr(), "{hint}");
                    ExitCode::from(4)
                }
                None => ExitCode::from(1),
            }
        }
    }
}
