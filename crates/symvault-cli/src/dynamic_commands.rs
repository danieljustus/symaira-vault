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

/// `cli.WithVault` unlocks interactively, so of Go's `ExitLocked` errors only a
/// failed passphrase read can occur here (the `vault locked: ...` variants are
/// non-interactive only).
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
            if error.starts_with("read passphrase: ") {
                let _ = writeln!(io::stderr(), "{LOCKED_HINT}");
                ExitCode::from(4)
            } else {
                ExitCode::from(1)
            }
        }
    }
}
