//! Deprecated hidden v4.0 compatibility stubs: `symvault agent setup` and
//! `symvault serve token*`.
//!
//! Go references in the pinned oracle:
//!
//! - `cmd/mcp/agent.go` — `newAgentSetupCmd` (hidden, `ArbitraryArgs`,
//!   `cliout.Warnf` notice + `NewCLIError(ExitNotFound, …)` with the same
//!   message text).
//! - `cmd/mcp/mcp_token.go` — `newMcpTokenCmd` and its three children. The
//!   oracle shares that one constructor between the `mcp` and `serve`
//!   parents (`cmd/mcp/serve.go` calls `AddCommand(newMcpTokenCmd())`), so
//!   every `serve token` path is byte-identical to its `mcp token`
//!   counterpart — re-verified against the built oracle, see
//!   `tests/cli_agent_setup_serve_stubs.rs`.
//!
//! Both parents therefore reuse this crate's single stub printer
//! (`deprecated_stub_message`, which reproduces the four stderr lines and
//! exit status 2 of the pinned oracle) and, for `serve token`, the shared
//! word-to-notice mapping `deprecated_token_message`.
//!
//! # Known differences (deliberate)
//!
//! Only the deprecated `token` children of `serve` are ported. The `serve`
//! parent is declared (hidden, like the oracle) solely so those children are
//! reachable, and it declares `token` as its only subcommand: bare `serve`
//! and `serve install|status|uninstall` belong to the server/service runtime,
//! which this port does not implement (HTTP client, launchd/systemd). In the
//! oracle an uninitialized vault makes bare `serve` print a deprecation
//! warning and fail with `vault not initialized` (exit 3), and an initialized
//! one starts the HTTP/stdio server; here the word forms are rejected with
//! clap's `unrecognized subcommand` (exit 1) and the bare form renders clap's
//! help on stderr (exit 1) — the established shape for required-subcommand
//! parents such as `agent` and `policy`. Declaring the unported children
//! would only make the surface inventory prettier than the runtime is — the
//! same decision already recorded for `update check`/`update apply`.

use std::process::ExitCode;

/// The `agent setup` notice, verbatim from `newAgentSetupCmd` in
/// `cmd/mcp/agent.go`.
const DEPRECATED_AGENT_SETUP: &str =
    "This command is deprecated in v4.0. Use: symvault agent install <name>";

/// `symvault agent setup [name …]` — hidden stub, empty stdout, exit status 2.
///
/// The oracle declares `ArbitraryArgs`, so zero words and any number of
/// extra words reach the handler unchanged; the catch-all argument on
/// `AgentCommand::Setup` reproduces that.
pub(crate) fn agent_setup() -> ExitCode {
    crate::deprecated_stub_message(DEPRECATED_AGENT_SETUP)
}

/// `symvault serve token [words …]` — byte-identical to `symvault mcp token`.
///
/// Cobra has no `Args` restriction on the group or its children, so an
/// unknown first word falls through to the group handler; the shared
/// `deprecated_token_message` mapping reproduces that dispatch for both
/// parents.
pub(crate) fn serve_token(args: &[String]) -> ExitCode {
    crate::deprecated_stub_message(crate::deprecated_token_message(
        args.first().map(String::as_str),
    ))
}
