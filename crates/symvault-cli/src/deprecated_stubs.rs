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
//! Bare serve and its service commands reuse the canonical MCP dispatcher;
//! only the token children retain these v4.0 stub notices.

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
