//! Runtime policy-evaluation context, a field-by-field mirror of Go's
//! `policy.ContextProvider.BuildContext` (`internal/policy/context.go`).
//!
//! Every policy evaluation in this crate must build its [`EvalContext`] here.
//! A hand-built context (`..EvalContext::default()`) leaves `home_dir`,
//! `working_dir`, `env_vars` and `now` empty, so `~/` path patterns,
//! `working_dir`, `env_vars` and `time_of_day` conditions silently stop
//! matching and a deny/prompt/require_biometry rule that Go applies is skipped:
//! Rust would be more permissive than Go.
//!
//! Go sets exactly these fields and nothing else:
//!
//! | field         | Go source                                                        |
//! |---------------|------------------------------------------------------------------|
//! | `agent_id`    | argument                                                         |
//! | `path`        | `ToLogicalPath(path)` (`filepath.ToSlash(filepath.Clean(..))`)   |
//! | `tags`        | argument (both Go call sites pass `nil`)                         |
//! | `action_type` | argument                                                         |
//! | `now`         | `time.Now()` — the **local** wall clock (`Hour()/Minute()/Second()`) |
//! | `working_dir` | `ToLogicalPath(os.Getwd())`, `""` on error                       |
//! | `home_dir`    | `ToLogicalPath(os.UserHomeDir())`, `""` on error (`$HOME` unset/empty) |
//! | `env_vars`    | `GIT_BRANCH` (see below) and `HOME` (raw, unconverted `$HOME`)   |
//!
//! `GIT_BRANCH` is `git -C <logical working dir> rev-parse --abbrev-ref HEAD`
//! run with only Go's `secrets.DefaultWhitelist()` environment; any failure,
//! an empty working dir, or the literal `HEAD` (detached) yields `""`. The key
//! is present even when the value is empty, as in Go.
//!
//! `tool_name` is deliberately **not** set: Go's `BuildContext` never sets
//! `EvalContext.ToolName`, and `matchAllowedTool` returns `true` for an empty
//! name, so an `allowed_tools` policy condition matches every tool in Go
//! (documented in `docs/rust-port/upstream-go-bugs.md`). Setting the name here
//! would make a `deny` rule scoped by `allowed_tools` stop applying to the
//! other tools. The tool name is still used by the separate tool-scope and
//! catalog checks, which are not policy conditions.

use std::collections::BTreeMap;
use std::process::{Command, Stdio};

use symvault_core::policy::{EvalContext, UtcTime};

/// Go's `secrets.DefaultWhitelist()` (`internal/secrets/filter.go`): the only
/// variables the `git` child process sees.
const GIT_ENV_WHITELIST: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "SHELL",
    "TERM",
    "COLORTERM",
    "DISPLAY",
    "XAUTHORITY",
    "GIT_ASKPASS",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_LAUNCHER",
    "GNUPGHOME",
];

/// Raw, unconverted runtime facts that feed [`assemble`]. Splitting them from
/// the assembly keeps the field mapping testable without mutating the process.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeFacts {
    /// `os.Getwd()` result, `""` on error.
    pub working_dir: String,
    /// `os.UserHomeDir()` result, `""` on error.
    pub home_dir: String,
    /// `git rev-parse --abbrev-ref HEAD` result for the *logical* working dir.
    pub git_branch: String,
}

/// Go's `ContextProvider`: gathers runtime context for policy evaluation.
#[derive(Clone, Debug, Default)]
pub struct ContextProvider {
    working_dir: String,
    git_branch: String,
}

impl ContextProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Go `SetWorkingDir` (testing override).
    pub fn set_working_dir(&mut self, dir: &str) {
        self.working_dir = dir.to_owned();
    }

    /// Go `SetGitBranch` (testing override).
    pub fn set_git_branch(&mut self, branch: &str) {
        self.git_branch = branch.to_owned();
    }

    /// Go `BuildContext(agentID, path, actionType, tags)`.
    #[must_use]
    pub fn build_context(
        &self,
        agent_id: &str,
        path: &str,
        action_type: &str,
        tags: &[String],
    ) -> EvalContext {
        let working_dir = if self.working_dir.is_empty() {
            get_working_dir()
        } else {
            self.working_dir.clone()
        };
        let home_dir = get_home_dir();
        let git_branch = if self.git_branch.is_empty() {
            get_git_branch(&to_logical_path(&working_dir))
        } else {
            self.git_branch.clone()
        };
        assemble(
            agent_id,
            path,
            action_type,
            tags,
            &RuntimeFacts {
                working_dir,
                home_dir,
                git_branch,
            },
            local_time_of_day(),
        )
    }
}

/// Builds the context for `agent_id`/`path`/`action_type` exactly as Go's
/// `policy.NewContextProvider().BuildContext(agentID, path, actionType, nil)`
/// does at every production call site.
#[must_use]
pub fn build_context(agent_id: &str, path: &str, action_type: &str) -> EvalContext {
    ContextProvider::new().build_context(agent_id, path, action_type, &[])
}

/// Pure field assembly of Go's `BuildContext`.
#[must_use]
pub fn assemble(
    agent_id: &str,
    path: &str,
    action_type: &str,
    tags: &[String],
    facts: &RuntimeFacts,
    now: UtcTime,
) -> EvalContext {
    let mut env_vars = BTreeMap::new();
    env_vars.insert("GIT_BRANCH".to_owned(), facts.git_branch.clone());
    env_vars.insert("HOME".to_owned(), facts.home_dir.clone());
    EvalContext {
        agent_id: agent_id.to_owned(),
        path: to_logical_path(path),
        tags: tags.to_vec(),
        working_dir: to_logical_path(&facts.working_dir),
        home_dir: to_logical_path(&facts.home_dir),
        env_vars,
        action_type: action_type.to_owned(),
        // Go never sets ToolName; see the module docs.
        tool_name: String::new(),
        now,
        secrets_accessed: 0,
    }
}

/// Go `policy.ToLogicalPath`: `""` stays `""`, anything else is
/// `filepath.ToSlash(filepath.Clean(value))` (so a path that cleans to nothing
/// becomes `"."`).
#[must_use]
pub fn to_logical_path(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let absolute = value.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    match (absolute, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".to_owned(),
        (false, false) => joined,
    }
}

/// Go `os.UserHomeDir` on unix: `$HOME`, an error (`""`) when unset or empty.
fn get_home_dir() -> String {
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => home.to_string_lossy().into_owned(),
        _ => String::new(),
    }
}

/// Go `os.Getwd`: `$PWD` when it is absolute and names the same directory as
/// `.`, otherwise the kernel's cwd; `""` on error.
fn get_working_dir() -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Some(pwd) = std::env::var_os("PWD")
            && pwd.as_encoded_bytes().first() == Some(&b'/')
            && let (Ok(dot), Ok(named)) = (std::fs::metadata("."), std::fs::metadata(&pwd))
            && dot.dev() == named.dev()
            && dot.ino() == named.ino()
        {
            return pwd.to_string_lossy().into_owned();
        }
    }
    std::env::current_dir()
        .map(|dir| dir.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Go `getGitBranch`: runs git in `working_dir` with Go's whitelisted env.
fn get_git_branch(working_dir: &str) -> String {
    if working_dir.is_empty() {
        return String::new();
    }
    let mut command = Command::new("git");
    command
        .args(["-C", working_dir, "rev-parse", "--abbrev-ref", "HEAD"])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    for name in GIT_ENV_WHITELIST.iter().copied() {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let Ok(output) = command.output() else {
        return String::new();
    };
    if !output.status.success() {
        return String::new();
    }
    let branch = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if branch == "HEAD" {
        String::new()
    } else {
        branch
    }
}

/// The **local** wall-clock time of day, matching Go's `time.Now().Hour()` etc.
/// (`TimeRange.Contains` reads the hour/minute/second of `Now` in its own
/// location, which for `time.Now()` is `time.Local`).
fn local_time_of_day() -> UtcTime {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    #[cfg(unix)]
    {
        if let Some(parts) = local_hms_unix(seconds) {
            return parts;
        }
    }
    utc_time_of_day(seconds)
}

fn utc_time_of_day(unix_seconds: u64) -> UtcTime {
    let in_day = unix_seconds % 86_400;
    UtcTime {
        hour: (in_day / 3600) as u8,
        minute: (in_day % 3600 / 60) as u8,
        second: (in_day % 60) as u8,
    }
}

#[cfg(unix)]
fn local_hms_unix(unix_seconds: u64) -> Option<UtcTime> {
    let timestamp = libc::time_t::try_from(unix_seconds).ok()?;
    // SAFETY: `localtime_r` writes only into the zeroed `tm` we own and reads
    // the `time_t` we pass by reference; it keeps no pointer past the call.
    let tm = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&timestamp, &mut tm).is_null() {
            return None;
        }
        tm
    };
    Some(UtcTime {
        hour: u8::try_from(tm.tm_hour).ok()?,
        minute: u8::try_from(tm.tm_min).ok()?,
        // tm_sec may be 60 on a leap second; Go reports 59 there too.
        second: u8::try_from(tm.tm_sec.min(59)).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use symvault_core::policy::{Engine, Policy};

    fn engine(yaml: &str) -> Engine {
        let policy: Policy = serde_yaml_ng::from_str(yaml).expect("policy yaml");
        Engine::new([policy])
    }

    fn facts() -> RuntimeFacts {
        RuntimeFacts {
            working_dir: "/work/repo/./src/".into(),
            home_dir: "/home/dev".into(),
            git_branch: "feature/x".into(),
        }
    }

    fn ctx(path: &str) -> EvalContext {
        assemble(
            "agent",
            path,
            "get",
            &[],
            &facts(),
            UtcTime::from_hms(12, 0, 0).unwrap(),
        )
    }

    #[test]
    fn logical_path_matches_go_clean() {
        for (input, want) in [
            ("", ""),
            (".", "."),
            ("a/..", "."),
            ("/a/../..", "/"),
            ("../a", "../a"),
            ("a//b/./c/", "a/b/c"),
            ("/", "/"),
            ("//x", "/x"),
            ("a/../../b", "../b"),
        ] {
            assert_eq!(to_logical_path(input), want, "input {input:?}");
        }
    }

    #[test]
    fn assemble_sets_every_go_field_and_never_the_tool_name() {
        let got = assemble(
            "agent",
            "ssh//keys/../prod",
            "run",
            &["t".to_owned()],
            &facts(),
            UtcTime::from_hms(1, 2, 3).unwrap(),
        );
        assert_eq!(got.agent_id, "agent");
        assert_eq!(got.path, "ssh/prod");
        assert_eq!(got.tags, ["t"]);
        assert_eq!(got.action_type, "run");
        assert_eq!(got.working_dir, "/work/repo/src");
        assert_eq!(got.home_dir, "/home/dev");
        assert_eq!(got.now, UtcTime::from_hms(1, 2, 3).unwrap());
        assert_eq!(got.env_vars.len(), 2);
        assert_eq!(got.env_vars["GIT_BRANCH"], "feature/x");
        assert_eq!(got.env_vars["HOME"], "/home/dev");
        assert_eq!(got.tool_name, "");
        assert_eq!(got.secrets_accessed, 0);
    }

    #[test]
    fn empty_facts_keep_go_env_keys_with_empty_values() {
        let got = assemble(
            "a",
            "p",
            "get",
            &[],
            &RuntimeFacts::default(),
            UtcTime::default(),
        );
        assert_eq!(got.working_dir, "");
        assert_eq!(got.home_dir, "");
        assert_eq!(got.env_vars["GIT_BRANCH"], "");
        assert_eq!(got.env_vars["HOME"], "");
    }

    #[test]
    fn deny_with_allowed_tools_applies_to_every_tool() {
        // Go: ToolName is empty, so allowed_tools=[X] matches every tool.
        let engine = engine(
            "rules:\n  - name: deny-x\n    action: deny\n    conditions:\n      allowed_tools: [X]\n  - name: allow-all\n    action: allow\n    conditions: {}\n",
        );
        let result = engine.evaluate(ctx("secret"));
        assert!(result.matched);
        assert_eq!(result.rule_name, "deny-x");
        assert_eq!(result.action, symvault_core::policy::Action::Deny);
    }

    #[test]
    fn allow_with_allowed_tools_applies_to_every_tool() {
        let engine = engine(
            "rules:\n  - name: allow-x\n    action: allow\n    conditions:\n      allowed_tools: [X]\n",
        );
        let result = engine.evaluate(ctx("secret"));
        assert!(result.matched);
        assert_eq!(result.action, symvault_core::policy::Action::Allow);
    }

    #[test]
    fn home_relative_deny_pattern_matches() {
        let engine = engine(
            "rules:\n  - name: deny-vault\n    action: deny\n    conditions:\n      path: '~/vault/**'\n  - name: allow-all\n    action: allow\n    conditions: {}\n",
        );
        let hit = engine.evaluate(ctx("/home/dev/vault/prod/key"));
        assert_eq!(hit.rule_name, "deny-vault");
        let miss = engine.evaluate(ctx("/home/dev/other"));
        assert_eq!(miss.rule_name, "allow-all");
    }

    #[test]
    fn working_dir_and_env_conditions_match() {
        let engine = engine(
            "rules:\n  - name: deny-branch\n    action: deny\n    conditions:\n      working_dir: /work/repo/**\n      env_vars:\n        GIT_BRANCH: feature/x\n        HOME: /home/dev\n  - name: allow-all\n    action: allow\n    conditions: {}\n",
        );
        assert_eq!(engine.evaluate(ctx("p")).rule_name, "deny-branch");
        let mut elsewhere = ctx("p");
        elsewhere.working_dir = "/other".into();
        assert_eq!(engine.evaluate(elsewhere).rule_name, "allow-all");
        let mut other_branch = ctx("p");
        other_branch
            .env_vars
            .insert("GIT_BRANCH".into(), "main".into());
        assert_eq!(engine.evaluate(other_branch).rule_name, "allow-all");
    }

    #[test]
    fn runtime_provider_reports_process_facts() {
        let mut provider = ContextProvider::new();
        provider.set_git_branch("pinned");
        let got = provider.build_context("a", "x/../y", "get", &[]);
        assert_eq!(got.path, "y");
        assert_eq!(got.tool_name, "");
        assert_eq!(got.env_vars["GIT_BRANCH"], "pinned");
        let home = std::env::var("HOME").unwrap_or_default();
        assert_eq!(got.env_vars["HOME"], home);
        assert_eq!(got.home_dir, to_logical_path(&home));
        let cwd = std::env::current_dir().unwrap();
        assert!(Path::new(&got.working_dir).is_dir());
        assert_eq!(
            std::fs::canonicalize(&got.working_dir).unwrap(),
            std::fs::canonicalize(cwd).unwrap()
        );
    }

    #[test]
    fn provider_override_working_dir_is_logicalised() {
        let mut provider = ContextProvider::new();
        provider.set_working_dir("/a/b/../c/");
        provider.set_git_branch("b");
        let got = provider.build_context("a", "p", "get", &[]);
        assert_eq!(got.working_dir, "/a/c");
    }

    #[test]
    fn utc_fallback_time_of_day() {
        assert_eq!(
            utc_time_of_day(86_400 + 3_723),
            UtcTime::from_hms(1, 2, 3).unwrap()
        );
    }
}
