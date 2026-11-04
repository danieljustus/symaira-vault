# CLI Exit Code Contract

This document is the public contract for the process exit codes emitted by
`symvault`. Script authors depend on these codes to distinguish between
categories of failure, so they are **stable**: new categories are added at
the end of the numeric range and existing values are never repurposed.

## Categories

| Code | Variant                         | Meaning                                                                           |
| ---- | ------------------------- | --------------------------------------------------------------------------------- |
| 0    | `ExitCode::Success`             | Command completed successfully.                                                   |
| 1    | `ExitCode::General`        | General error. Reserved for failures that do not match a more specific category.   |
| 2    | `ExitCode::NotFound`            | The requested entry, field, or resource was not found.                            |
| 3    | `ExitCode::NotInitialized`      | The vault has not been initialized.                                               |
| 4    | `ExitCode::Locked`              | The vault is locked or the passphrase is missing.                                 |
| 5    | `ExitCode::PermissionDenied`    | The agent or user is not permitted to perform the operation.                      |
| 6    | `ExitCode::Config`         | The on-disk configuration is malformed or invalid.                                |
| 7    | `ExitCode::DoctorWarn`          | `symvault doctor` found warnings.                                                 |
| 8    | `ExitCode::DoctorFail`          | `symvault doctor` found failures.                                                 |
| 9    | `ExitCode::InvalidInput`        | User input failed validation (empty argument, malformed value, parse failure).    |
| 10   | `ExitCode::UpdateAvailable`     | A new version is available for download.                                          |

Codes 11+ are reserved for future use. New categories are added at the next
free number and documented here.

## Authoring rules

- The numeric values live in one place: the `ExitCode` enum in
  `crates/symvault-core/src/error.rs`. Command handlers return a `CliError` whose
  `code()` is one of its variants (see `error.rs`); do not
  hard-code the numbers in `crates/symvault-cli`. An error without a category
  maps to `ExitCode::General`, which hides the failure class from scripts, so
  pick the specific variant.
- `crates/symvault-cli/tests/error_taxonomy.rs` replays the frozen Go-recorded
  error taxonomy (message, stream and exit code per failure) against the Rust CLI
  and is the regression gate for the table above.

## Adding a new category

1. Add a new variant at the end of the `ExitCode` enum in
   `crates/symvault-core/src/error.rs` (next free number).
2. Add a row to the table above.
3. Add a test in `crates/symvault-core` covering the numeric mapping.
4. Use the new variant in the CLI paths that should report it and add a CLI test
   for the exit code.
