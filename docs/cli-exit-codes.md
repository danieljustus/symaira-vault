# CLI Exit Code Contract

This document is the public contract for the process exit codes emitted by
`symvault`. Script authors depend on these codes to distinguish between
categories of failure, so they are **stable**: new categories are added at
the end of the numeric range and existing values are never repurposed.

## Categories

| Code | Constant                  | Meaning                                                                           |
| ---- | ------------------------- | --------------------------------------------------------------------------------- |
| 0    | `ExitSuccess`             | Command completed successfully.                                                   |
| 1    | `ExitGeneralError`        | General error. Reserved for failures that do not match a more specific category.   |
| 2    | `ExitNotFound`            | The requested entry, field, or resource was not found.                            |
| 3    | `ExitNotInitialized`      | The vault has not been initialized.                                               |
| 4    | `ExitLocked`              | The vault is locked or the passphrase is missing.                                 |
| 5    | `ExitPermissionDenied`    | The agent or user is not permitted to perform the operation.                      |
| 6    | `ExitConfigError`         | The on-disk configuration is malformed or invalid.                                |
| 7    | `ExitDoctorWarn`          | `symvault doctor` found warnings.                                                 |
| 8    | `ExitDoctorFail`          | `symvault doctor` found failures.                                                 |
| 9    | `ExitInvalidInput`        | User input failed validation (empty argument, malformed value, parse failure).    |
| 10   | `ExitUpdateAvailable`     | A new version is available for download.                                          |

Codes 11+ are reserved for future use. New categories are added at the next
free number and documented here.

## Authoring rules

- Every `RunE` handler **must** return an error built from the constructors
  in `internal/errors` (`errors.NotFound`, `errors.InvalidInput`,
  `errors.Wrap`, ...). Bare `fmt.Errorf` collapses every failure into
  `ExitGeneralError` and is rejected by the `clierror` passlint analyzer.
- The `clierror` analyzer is part of the `make vet` and `make passlint`
  targets and runs in CI on every PR.
- The `Exit*` constants in `internal/errors` are the single source of truth
  for numeric values. Do not hard-code the numbers in `cmd/` packages.

## Adding a new category

1. Add a new constant at the end of the `ExitCode` block in
   `internal/errors/errors.go` (next free number).
2. Add a corresponding typed constructor in the same file (e.g.
   `func MyCategory(...) *CLIError`).
3. Add a row to the table above.
4. Add a test case to `internal/errors/errors_test.go` covering the new
   constructor and its exit-code mapping.
5. Update existing `cmd/` packages that should now use the new category.
