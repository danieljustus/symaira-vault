//! `symvault agent skill`, `agent skill export` and `agent skill refresh`.
//!
//! Ported from `cmd/mcp/agent_skill.go` plus `internal/agentskill`
//! (`skill.go`, `install.go`, `manifest.go`); oracle pin `3232e31f`.
//!
//! Measured against the pinned oracle, not assumed:
//!
//! - The frontmatter keys follow the Go struct order and `managed_installed_at`
//!   is **quoted** (`"2026-09-21T16:03:02Z"`), because `yaml.v3` refuses to emit
//!   a plain scalar that would parse back as a timestamp. The description stays
//!   unquoted and is not folded, even though its line exceeds 80 columns.
//! - `refresh` resolves the target through the vault's `config.yaml` with the
//!   built-in agent defaults merged in; when that load fails it reports
//!   `no skill path configured for agent "hermes"` — so a config that is merely
//!   *absent* still resolves, while an unreadable one does not.
//! - `export` prints `Exported skill for <agent> to <path>` on stdout through
//!   `cmd.OutOrStdout()`, so `--quiet` does **not** suppress it.
//! - Errors are printed once by this port; the oracle prints every returned error
//!   twice (`CLI-005`, an inherited, cross-cutting taxonomy gap).
//!
//! Deliberate, documented differences:
//! - Go iterates a map when writing the tar entries, so the entry order is not a
//!   contract; this port writes them sorted by name (deterministic by design).
//! - Go's `compress/gzip` byte stream is not reproducible byte-for-byte; the
//!   export differential compares the **archive contents** (entry names, modes,
//!   payload bytes), never the gzip stream. The `tar` headers are built to match
//!   the oracle's (mode `0o644`, mtime 0, uid/gid 0, empty uname/gname).
//! - The template interpreter is a small subset of Go's `text/template`: it
//!   supports exactly the constructs the six embedded templates use
//!   (`define`, `template`, `{{.Field}}`, `if eq`, `else if`, `if .Field`,
//!   `end`, and the `{{-`/`-}}` trim markers). A template that starts using
//!   `range`, `with`, pipelines or the `now` function must extend it — the
//!   byte-differential in `tests/cli_agent_skill.rs` is what catches that.
//!   ponytail: extend the interpreter when a template needs it, not before.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use flate2::Compression;
use flate2::write::GzEncoder;
use symvault_core::config::Config;

use super::agent_doctor_commands::{SENTINEL, expand_tilde, parse_manifest};
use super::agent_token_commands::display_rfc3339;
use crate::VERSION;

const COMMON_TEMPLATE: &str = include_str!("../assets/agent-skill/common/SKILL.md.tmpl");
const AGENT_TEMPLATES: &[(&str, &str, &str)] = &[
    (
        "hermes",
        include_str!("../assets/agent-skill/hermes/SKILL.md.tmpl"),
        "SKILL.md",
    ),
    (
        "claude-code",
        include_str!("../assets/agent-skill/claude-code/SKILL.md.tmpl"),
        "SKILL.md",
    ),
    (
        "codex",
        include_str!("../assets/agent-skill/codex/AGENTS.md.tmpl"),
        "AGENTS.md",
    ),
    (
        "opencode",
        include_str!("../assets/agent-skill/opencode/SKILL.md.tmpl"),
        "SKILL.md",
    ),
    (
        "openclaw",
        include_str!("../assets/agent-skill/openclaw/SKILL.md.tmpl"),
        "SKILL.md",
    ),
];

/// Go `agentskill.DefaultSkillSchemaVersion`.
const DEFAULT_SKILL_SCHEMA_VERSION: &str = "1";
/// Go `agentskill.backupSuffix`.
const BACKUP_SUFFIX: &str = ".bak";
/// Go's `buildTemplateVars` hardcodes this tier for the skill CLI.
const PROFILE_TIER: &str = "safe";

fn agent_template(agent: &str) -> Option<(&'static str, &'static str)> {
    AGENT_TEMPLATES
        .iter()
        .find(|(name, _, _)| *name == agent)
        .map(|(_, template, out_name)| (*template, *out_name))
}

/// Go `agentskill.PrefixConfig`.
fn prefix_config(agent: &str) -> (&'static str, &'static str) {
    match agent {
        "hermes" => ("mcp_symaira_", "/symaira:"),
        "claude-code" => ("mcp__symaira__", "/mcp__symaira__"),
        _ => ("", ""),
    }
}

// ---------------------------------------------------------------------------
// A small `text/template` subset (see the module note for its exact scope).

#[derive(Debug)]
enum Item {
    Text(String),
    /// An action body with the trim markers already applied to the surrounding
    /// text, so only the directive itself is carried here.
    Action {
        body: String,
    },
}

#[derive(Debug, Clone)]
enum Node {
    Text(String),
    Field(String),
    /// `{{template "name" .}}`
    Call(String),
    /// `{{if …}}…{{else if …}}…{{else}}…{{end}}`
    If(Vec<(Condition, Vec<Node>)>, Option<Vec<Node>>),
}

#[derive(Debug, Clone)]
enum Condition {
    /// `eq .Field "literal"`
    Equals(String, String),
    /// `.Field` treated as a string: empty is false.
    Truthy(String),
}

fn tokenize(source: &str) -> Result<Vec<Item>, String> {
    let mut items = Vec::new();
    let mut rest = source;
    let mut pending_trim_left = false;
    while let Some(start) = rest.find("{{") {
        let (before, action_start) = rest.split_at(start);
        let mut text = before.to_owned();
        if pending_trim_left {
            text = text.trim_start().to_owned();
        }
        let after = &action_start[2..];
        let Some(end) = after.find("}}") else {
            return Err("unterminated action".to_owned());
        };
        let raw = &after[..end];
        let trim_left = raw.starts_with('-');
        let trim_right = raw.trim_end().ends_with('-');
        if trim_left {
            text = text.trim_end().to_owned();
        }
        if !text.is_empty() {
            items.push(Item::Text(text));
        }
        items.push(Item::Action {
            body: raw.trim_matches('-').trim().to_owned(),
        });
        pending_trim_left = trim_right;
        rest = &after[end + 2..];
    }
    let mut tail = rest.to_owned();
    if pending_trim_left {
        tail = tail.trim_start().to_owned();
    }
    if !tail.is_empty() {
        items.push(Item::Text(tail));
    }
    Ok(items)
}

fn parse_nodes(
    items: &[Item],
    cursor: &mut usize,
    blocks: &mut BTreeMap<String, Vec<Node>>,
) -> Result<(Vec<Node>, String), String> {
    let mut nodes = Vec::new();
    while let Some(item) = items.get(*cursor) {
        match item {
            Item::Text(text) => {
                nodes.push(Node::Text(text.clone()));
                *cursor += 1;
            }
            Item::Action { body, .. } => {
                if body == "end" {
                    *cursor += 1;
                    return Ok((nodes, "end".to_owned()));
                }
                if body == "else" || body.starts_with("else if ") {
                    *cursor += 1;
                    return Ok((nodes, body.clone()));
                }
                if let Some(rest) = body.strip_prefix("define ") {
                    let name = parse_string_literal(rest)?;
                    *cursor += 1;
                    let (defined, terminator) = parse_nodes(items, cursor, blocks)?;
                    if terminator != "end" {
                        return Err(format!("define {name} without end"));
                    }
                    blocks.insert(name, defined);
                    continue;
                }
                if let Some(rest) = body.strip_prefix("if ") {
                    *cursor += 1;
                    let mut branches = Vec::new();
                    let mut else_body = None;
                    let condition = parse_condition(rest)?;
                    let (body_nodes, mut terminator) = parse_nodes(items, cursor, blocks)?;
                    branches.push((condition, body_nodes));
                    loop {
                        match terminator.as_str() {
                            "end" => break,
                            "else" => {
                                let (tail_nodes, tail_terminator) =
                                    parse_nodes(items, cursor, blocks)?;
                                else_body = Some(tail_nodes);
                                terminator = tail_terminator;
                            }
                            other if other.starts_with("else if ") => {
                                let condition = parse_condition(&other["else if ".len()..])?;
                                let (branch_nodes, branch_terminator) =
                                    parse_nodes(items, cursor, blocks)?;
                                branches.push((condition, branch_nodes));
                                terminator = branch_terminator;
                            }
                            other => return Err(format!("unexpected {other}")),
                        }
                    }
                    nodes.push(Node::If(branches, else_body));
                    continue;
                }
                if let Some(rest) = body.strip_prefix("template ") {
                    let name = parse_string_literal(rest)?;
                    nodes.push(Node::Call(name));
                    *cursor += 1;
                    continue;
                }
                if let Some(field) = body.strip_prefix('.') {
                    if field.contains(' ') {
                        return Err(format!("unsupported action: {body}"));
                    }
                    nodes.push(Node::Field(field.to_owned()));
                    *cursor += 1;
                    continue;
                }
                return Err(format!("unsupported action: {body}"));
            }
        }
    }
    Ok((nodes, String::new()))
}

fn parse_string_literal(text: &str) -> Result<String, String> {
    let text = text.trim();
    let Some(rest) = text.strip_prefix('"') else {
        return Err(format!("unsupported literal: {text}"));
    };
    match rest.find('"') {
        Some(end) => Ok(rest[..end].to_owned()),
        None => Err(format!("unterminated literal: {text}")),
    }
}

fn parse_condition(text: &str) -> Result<Condition, String> {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix("eq ") {
        let mut parts = rest.trim().splitn(2, ' ');
        let field = parts.next().unwrap_or_default().trim_start_matches('.');
        let value = parts.next().unwrap_or_default();
        return Ok(Condition::Equals(
            field.to_owned(),
            parse_string_literal(value)?,
        ));
    }
    let field = text
        .strip_prefix('.')
        .ok_or_else(|| format!("unsupported condition: {text}"))?;
    if field.contains(' ') {
        return Err(format!("unsupported condition: {text}"));
    }
    Ok(Condition::Truthy(field.to_owned()))
}

/// The variables a skill template may reference.
struct Vars {
    agent_name: String,
    tool_prefix: String,
    slash_prefix: String,
    version: String,
    profile_tier: String,
    vault_path: String,
    installed_at: String,
    skill_schema_version: String,
}

impl Vars {
    fn field(&self, name: &str) -> Result<&str, String> {
        Ok(match name {
            "AgentName" => &self.agent_name,
            "ToolPrefix" => &self.tool_prefix,
            "SlashPrefix" => &self.slash_prefix,
            "SymairaVaultVersion" => &self.version,
            "ProfileTier" => &self.profile_tier,
            "VaultPath" => &self.vault_path,
            "InstalledAt" => &self.installed_at,
            "SkillSchemaVersion" => &self.skill_schema_version,
            // Fails loudly instead of silently rendering nothing when a future
            // template references a variable this port does not know.
            other => return Err(format!("unknown template variable: .{other}")),
        })
    }
}

fn render_nodes(
    nodes: &[Node],
    vars: &Vars,
    blocks: &BTreeMap<String, Vec<Node>>,
) -> Result<String, String> {
    let mut out = String::new();
    for node in nodes {
        match node {
            Node::Text(text) => out.push_str(text),
            Node::Field(name) => out.push_str(vars.field(name)?),
            Node::Call(name) => {
                let body = blocks
                    .get(name)
                    .ok_or_else(|| format!("template not defined: {name}"))?;
                out.push_str(&render_nodes(body, vars, blocks)?);
            }
            Node::If(branches, else_body) => {
                let mut matched = false;
                for (condition, body) in branches {
                    let applies = match condition {
                        Condition::Equals(field, value) => vars.field(field)? == value,
                        Condition::Truthy(field) => !vars.field(field)?.is_empty(),
                    };
                    if applies {
                        out.push_str(&render_nodes(body, vars, blocks)?);
                        matched = true;
                        break;
                    }
                }
                if !matched && let Some(body) = else_body {
                    out.push_str(&render_nodes(body, vars, blocks)?);
                }
            }
        }
    }
    Ok(out)
}

/// Renders the shared template plus the agent template exactly like
/// `agentskill.Render` does before the frontmatter is prepended.
fn render_body(agent: &str, vars: &Vars) -> Result<String, String> {
    let (agent_source, _) =
        agent_template(agent).ok_or_else(|| format!("unknown agent: {agent}"))?;
    let mut blocks = BTreeMap::new();
    let common_items = tokenize(COMMON_TEMPLATE)?;
    let mut cursor = 0;
    parse_nodes(&common_items, &mut cursor, &mut blocks)?;

    let agent_items = tokenize(agent_source)?;
    cursor = 0;
    let (nodes, _) = parse_nodes(&agent_items, &mut cursor, &mut blocks)?;
    render_nodes(&nodes, vars, &blocks)
}

/// Go `agentskill.HashBytes`.
fn hash_bytes(data: &[u8]) -> String {
    format!("sha256:{}", symvault_store::sha256_hex(data))
}

/// `yaml.v3`'s quoting for the two non-constant frontmatter scalars. The
/// timestamp is always quoted; a version that would parse back as a number,
/// boolean or null is quoted too, because `yaml.v3` would otherwise drop its
/// string-ness on a round trip.
fn yaml_scalar(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let numeric = value.parse::<f64>().is_ok() || value.parse::<i64>().is_ok();
    if numeric || matches!(lower.as_str(), "true" | "false" | "null" | "~" | "") {
        format!("\"{value}\"")
    } else {
        value.to_owned()
    }
}

/// Renders the complete skill file including its YAML frontmatter.
fn render(agent: &str, vars: &Vars) -> Result<Vec<u8>, String> {
    let body = render_body(agent, vars)?;
    let manifest = format!(
        "---\nname: {name}\ndescription: {description}\nmanaged_by: {managed_by}\nmanaged_version: {version}\nmanaged_hash: {hash}\nmanaged_installed_at: \"{installed_at}\"\nmanaged_profile_tier: {tier}\n---\n\n",
        name = SENTINEL,
        description = "Use Symaira Vault as the credential manager via native MCP tools and CLI.",
        managed_by = SENTINEL,
        version = yaml_scalar(&vars.version),
        hash = hash_bytes(body.as_bytes()),
        installed_at = vars.installed_at,
        tier = vars.profile_tier,
    );
    // Go normalizes to LF-only for cross-platform consistency.
    let combined = format!("{manifest}{body}").replace("\r\n", "\n");
    Ok(combined.into_bytes())
}

// ---------------------------------------------------------------------------
// The three commands.

fn template_vars(agent: &str, vault: &Path, installed_at: String) -> Vars {
    let (tool_prefix, slash_prefix) = prefix_config(agent);
    Vars {
        agent_name: agent.to_owned(),
        tool_prefix: tool_prefix.to_owned(),
        slash_prefix: slash_prefix.to_owned(),
        version: VERSION.to_owned(),
        profile_tier: PROFILE_TIER.to_owned(),
        vault_path: vault.to_string_lossy().into_owned(),
        installed_at,
        skill_schema_version: DEFAULT_SKILL_SCHEMA_VERSION.to_owned(),
    }
}

/// Go's `time.Now().UTC().Format(time.RFC3339)` for `TemplatesVars.InstalledAt`:
/// seconds precision, no fractional part (unlike the stored timestamps).
fn now_rfc3339() -> String {
    display_rfc3339(&symvault_sync::GoTime::now().to_rfc3339_nano())
}

/// `agent skill export <agent>` with `-o/--output`.
pub(crate) fn export(vault: &Path, agent: &str, output: Option<&str>) -> Result<(), String> {
    let output = match output {
        Some(path) if !path.is_empty() => path.to_owned(),
        _ => format!("symvault-{agent}-skill.tar.gz"),
    };
    let output = clean_path(&output);

    // Go creates the file first and removes it again when the export fails, so an
    // unknown agent leaves no stray archive behind.
    let file =
        std::fs::File::create(&output).map_err(|error| format!("create output file: {error}"))?;
    let vars = template_vars(agent, vault, now_rfc3339());
    let result = render_for_export(agent, &vars).and_then(|files| write_archive(&files, file));
    if let Err(error) = result {
        let _ = std::fs::remove_file(&output);
        return Err(format!("export skill: {error}"));
    }
    // Go prints this through `cmd.OutOrStdout()`, so `--quiet` does not hide it.
    println!("Exported skill for {agent} to {output}");
    Ok(())
}

/// Go `filepath.Clean` for a relative path without symlink resolution.
fn clean_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if let Some(last) = parts.last()
                    && *last != ".."
                {
                    parts.pop();
                    continue;
                }
                if absolute {
                    continue;
                }
                parts.push("..");
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

/// Go `agentskill.renderForExport`: the rendered skill plus the INSTALL.md that
/// travels with it.
fn render_for_export(agent: &str, vars: &Vars) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let (_, out_name) = agent_template(agent).ok_or_else(|| format!("unknown agent: {agent}"))?;
    let mut files = BTreeMap::new();
    files.insert(out_name.to_owned(), render(agent, vars)?);
    let install_md = format!(
        "# {agent} Symaira Vault Skill — Manual Install\n\n\
         This skill was exported by Symaira Vault v{version}.\n\n\
         ## Steps\n\n\
         1. Place {out_name} in your agent's skill directory.\n\
         2. Create a scoped access token:\n   \
         symvault agent token new {agent} --tools list_entries,get_entry --ttl 90d\n\
         3. Restart your agent.\n\n\
         ## Verification\n\n\
         Run the agent's MCP discovery command to verify Symaira Vault tools are available.\n",
        version = vars.version,
    );
    files.insert("INSTALL.md".to_owned(), install_md.into_bytes());
    Ok(files)
}

fn write_archive<W: Write>(files: &BTreeMap<String, Vec<u8>>, sink: W) -> Result<(), String> {
    let mut gz = GzEncoder::new(sink, Compression::default());
    {
        let mut tar = tar::Builder::new(&mut gz);
        // Sorted order is a deliberate difference: Go iterates a map here.
        for (name, data) in files {
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(data.len() as u64);
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header
                .set_path(name)
                .map_err(|error| format!("write tar header for {name}: {error}"))?;
            // `tar` 0.4 does not recompute the checksum for us: without this the
            // archive reads fine through the same crate but has an empty cksum
            // field and is rejected by `tar(1)` and Python's `tarfile`.
            header.set_cksum();
            tar.append(&header, data.as_slice())
                .map_err(|error| format!("write tar entry for {name}: {error}"))?;
        }
        tar.finish().map_err(|error| error.to_string())?;
    }
    gz.finish().map_err(|error| error.to_string())?;
    Ok(())
}

/// Go `corekitfsutil.HasTraversal`: true when any path component is `..`.
/// Semantics taken from corekit's own table test (`foo/../bar` true,
/// `/etc/passwd` false, `""` false).
fn has_traversal(path: &str) -> bool {
    path.split(['/', '\\']).any(|part| part == "..")
}

/// `agent skill refresh <agent>`.
pub(crate) fn refresh(vault: &Path, agent: &str) -> Result<(), String> {
    let target = skill_target(vault, agent);
    if target.is_empty() {
        return Err(format!("no skill path configured for agent {agent:?}"));
    }
    let target = require_tilde_expansion(&target);

    // Go's `expandTilde` keeps the path untouched when `~` cannot be resolved.
    if has_traversal(&target) {
        return Err(format!(
            "refresh skill: target path contains traversal: {target}"
        ));
    }
    let target = clean_path(&target);

    match std::fs::read(&target) {
        Ok(existing) => {
            if !find_sentinel(&existing) {
                return Err(format!(
                    "refresh skill: skill file exists without managed sentinel: {target}"
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "refresh skill: skill not installed: open {target}: no such file or directory"
            ));
        }
        Err(error) => return Err(format!("refresh skill: read existing skill: {error}")),
    }

    install(vault, agent, &target, false).map_err(|error| format!("refresh skill: {error}"))?;
    println!("Refreshed skill for {agent} at {target}");
    Ok(())
}

/// Go `agentskill.Install`.
fn install(vault: &Path, agent: &str, target: &str, force: bool) -> Result<(), String> {
    if has_traversal(target) {
        return Err(format!("target path contains traversal: {target}"));
    }
    let vars = template_vars(agent, vault, now_rfc3339());
    let rendered = render(agent, &vars).map_err(|error| format!("render skill: {error}"))?;
    let target = clean_path(target);

    let existing = match std::fs::read(&target) {
        Ok(existing) => existing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return write_skill(&target, &rendered);
        }
        Err(error) => return Err(format!("read existing skill: {error}")),
    };

    if !find_sentinel(&existing) {
        if !force {
            return Err(format!(
                "skill file exists without managed sentinel: {target}"
            ));
        }
        return write_skill(&target, &rendered);
    }

    let current = body_hash(&existing)?;
    let new = body_hash(&rendered)?;
    if current == new {
        return Ok(());
    }
    backup_file(&target).map_err(|error| format!("backup skill: {error}"))?;
    write_skill(&target, &rendered)
}

fn write_skill(target: &str, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = Path::new(target).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create skill directory: {error}"))?;
    }
    std::fs::write(target, data).map_err(|error| format!("write skill file: {error}"))
}

fn backup_file(target: &str) -> Result<(), std::io::Error> {
    let data = std::fs::read(target)?;
    std::fs::write(format!("{target}{BACKUP_SUFFIX}"), data)
}

/// Go `manifest.FindSentinel`.
fn find_sentinel(data: &[u8]) -> bool {
    parse_manifest(data).is_ok_and(|(manifest, _)| manifest.managed_by == SENTINEL)
}

/// Go `manifest.ExtractBody` + `HashBytes`.
fn body_hash(data: &[u8]) -> Result<String, String> {
    match parse_manifest(data) {
        Ok((_, body)) => Ok(hash_bytes(body)),
        Err(()) => Err("no frontmatter found: missing opening ---".to_owned()),
    }
}

/// Go's `getSkillTargetPath`: the agent's `skillPath` from the vault config,
/// empty when the config cannot be loaded, or when the agent has no entry.
fn skill_target(vault: &Path, agent: &str) -> String {
    let Ok(config) = Config::load(vault.join("config.yaml")) else {
        return String::new();
    };
    config
        .agents
        .get(agent)
        .map(|profile| profile.skill_path.clone())
        .unwrap_or_default()
}

/// Go's `expandTilde` keeps the path untouched when `~` cannot be resolved.
fn require_tilde_expansion(path: &str) -> String {
    expand_tilde(path)
        .map(|expanded| expanded.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars_for(agent: &str) -> Vars {
        let mut vars = template_vars(agent, Path::new("/fixture/vault"), "INSTALLED".to_owned());
        vars.version = "v0.0.0-port".to_owned();
        vars
    }

    /// Rewrites the build-injected, environment-derived and body-derived scalars
    /// of a frozen fixture, so the rest of the bytes can be compared exactly.
    ///
    /// `{{BODY_HASH}}` is filled with the digest of the *fixture's own* body:
    /// that keeps the check meaningful (the renderer's `managed_hash` must cover
    /// exactly these bytes) while allowing the vault path to differ.
    fn fill(fixture: &str, vars: &Vars) -> String {
        // The digest is not known until the body is assembled, so the hash field
        // gets a plain (YAML-valid) placeholder first — `{{…}}` would make the
        // frontmatter unparsable and hide a real mismatch.
        let substituted = fixture
            .replace("{{BODY_HASH}}", "BODY_HASH_PENDING")
            .replace("{{VERSION}}", &vars.version)
            .replace("{{VERSION_RAW}}", &vars.version)
            .replace("{{INSTALLED_AT}}", &vars.installed_at)
            .replace("{{VAULT}}", &vars.vault_path);
        match parse_manifest(substituted.as_bytes()) {
            Ok((_, body)) => substituted.replace("BODY_HASH_PENDING", &hash_bytes(body)),
            // INSTALL.md has no frontmatter and therefore no body hash.
            Err(()) => substituted,
        }
    }

    /// `.gitattributes` pins these files to LF; normalizing again keeps the
    /// comparison honest in checkouts that ignore that setting.
    fn fixture(name: &str) -> String {
        load_fixture(name).replace("\r\n", "\n")
    }

    fn load_fixture(name: &str) -> &'static str {
        match name {
            "hermes.SKILL.md" => include_str!("../tests/fixtures/agent-skill/hermes.SKILL.md"),
            "claude-code.SKILL.md" => {
                include_str!("../tests/fixtures/agent-skill/claude-code.SKILL.md")
            }
            "codex.AGENTS.md" => include_str!("../tests/fixtures/agent-skill/codex.AGENTS.md"),
            "opencode.SKILL.md" => include_str!("../tests/fixtures/agent-skill/opencode.SKILL.md"),
            "openclaw.SKILL.md" => include_str!("../tests/fixtures/agent-skill/openclaw.SKILL.md"),
            "hermes.INSTALL.md" => include_str!("../tests/fixtures/agent-skill/hermes.INSTALL.md"),
            "codex.INSTALL.md" => include_str!("../tests/fixtures/agent-skill/codex.INSTALL.md"),
            other => panic!("unknown fixture {other}"),
        }
    }

    #[test]
    fn every_agent_body_matches_the_frozen_oracle_bytes() {
        for (agent, fixture_name) in [
            ("hermes", "hermes.SKILL.md"),
            ("claude-code", "claude-code.SKILL.md"),
            ("codex", "codex.AGENTS.md"),
            ("opencode", "opencode.SKILL.md"),
            ("openclaw", "openclaw.SKILL.md"),
        ] {
            let vars = vars_for(agent);
            let expected = fill(&fixture(fixture_name), &vars);
            let rendered = String::from_utf8(render(agent, &vars).expect("render")).expect("utf8");
            assert_eq!(rendered, expected, "{agent}");
        }
    }

    #[test]
    fn install_md_matches_the_frozen_oracle_bytes() {
        for (agent, fixture_name) in [
            ("hermes", "hermes.INSTALL.md"),
            ("codex", "codex.INSTALL.md"),
        ] {
            let vars = vars_for(agent);
            let files = render_for_export(agent, &vars).expect("export");
            let install = String::from_utf8(files["INSTALL.md"].clone()).expect("utf8");
            assert_eq!(install, fill(&fixture(fixture_name), &vars), "{agent}");
        }
    }

    #[test]
    fn frontmatter_hash_covers_the_body_and_quoting_matches_yaml_v3() {
        let vars = vars_for("hermes");
        let rendered = String::from_utf8(render("hermes", &vars).expect("render")).expect("utf8");
        let body = parse_manifest(rendered.as_bytes()).expect("manifest").1;
        assert!(
            rendered.contains(&format!("managed_hash: {}", hash_bytes(body))),
            "{rendered}"
        );
        assert!(
            rendered.contains("managed_installed_at: \"INSTALLED\""),
            "the timestamp stays quoted like yaml.v3 emits it"
        );
        assert_eq!(yaml_scalar("v0.0.0-port"), "v0.0.0-port");
        assert_eq!(yaml_scalar("1"), "\"1\"");
        assert_eq!(yaml_scalar("true"), "\"true\"");
    }

    #[test]
    fn unknown_agents_and_unknown_template_variables_fail_loudly() {
        let vars = vars_for("hermes");
        assert_eq!(
            render("nope", &vars).expect_err("unknown agent"),
            "unknown agent: nope"
        );
        assert_eq!(
            vars.field("NotAVariable").expect_err("unknown field"),
            "unknown template variable: .NotAVariable"
        );
    }

    #[test]
    fn the_interpreter_handles_the_constructs_the_templates_use() {
        let vars = vars_for("codex");
        // codex has no slash prefix, so the `{{if .SlashPrefix -}}` block is skipped.
        let body = render_body("codex", &vars).expect("render");
        assert!(!body.contains("Slash Commands"), "{body}");
        let hermes = render_body("hermes", &vars_for("hermes")).expect("render");
        assert!(hermes.contains("## Slash Commands"), "{hermes}");
        assert!(hermes.contains("/symaira:"), "{hermes}");
        // The `if eq .ProfileTier "safe"` branch is the one the CLI always takes.
        assert!(hermes.contains("**Limited access**"), "{hermes}");
    }

    #[test]
    fn traversal_detection_matches_corekit() {
        assert!(has_traversal("foo/../bar"));
        assert!(has_traversal("../foo"));
        assert!(has_traversal("foo/.."));
        assert!(has_traversal("foo/../../etc"));
        assert!(!has_traversal("foo/bar"));
        assert!(!has_traversal("/etc/passwd"));
        assert!(!has_traversal(""));
    }

    #[test]
    fn path_cleaning_matches_filepath_clean() {
        assert_eq!(clean_path("./a/./b"), "a/b");
        assert_eq!(clean_path("a/../b"), "b");
        assert_eq!(clean_path("/a/../b/"), "/b");
        assert_eq!(clean_path(""), ".");
    }

    #[test]
    fn archives_carry_the_oracle_entry_metadata() {
        let vars = vars_for("hermes");
        let files = render_for_export("hermes", &vars).expect("export");
        let mut buffer = Vec::new();
        write_archive(&files, &mut buffer).expect("archive");
        let gz = flate2::read::GzDecoder::new(buffer.as_slice());
        let mut archive = tar::Archive::new(gz);
        let mut seen = Vec::new();
        for entry in archive.entries().expect("entries") {
            let entry = entry.expect("entry");
            let header = entry.header().clone();
            assert_eq!(header.mode().expect("mode"), 0o644);
            assert_eq!(header.mtime().expect("mtime"), 0);
            assert_eq!(header.uid().expect("uid"), 0);
            seen.push(entry.path().expect("path").to_string_lossy().into_owned());
        }
        assert_eq!(seen, vec!["INSTALL.md".to_owned(), "SKILL.md".to_owned()]);
    }

    #[test]
    fn refresh_reports_a_missing_config_before_touching_the_filesystem() {
        let tmp = tempfile::TempDir::new().expect("tmp");
        let error = refresh(tmp.path(), "hermes").expect_err("must fail");
        assert!(error.starts_with("no skill path configured"), "{error}");
    }

    #[test]
    fn install_writes_the_managed_file_and_skips_an_unchanged_refresh() {
        let tmp = tempfile::TempDir::new().expect("tmp");
        let target = tmp.path().join("nested").join("SKILL.md");
        let target = target.to_string_lossy().into_owned();
        install(tmp.path(), "hermes", &target, false).expect("install");
        let written = std::fs::read(&target).expect("read");
        assert!(find_sentinel(&written));

        // Same body hash: no rewrite, and therefore no backup file.
        let before = written.clone();
        install(tmp.path(), "hermes", &target, false).expect("refresh");
        assert_eq!(std::fs::read(&target).expect("read"), before);
        assert!(!Path::new(&format!("{target}{BACKUP_SUFFIX}")).exists());
    }

    #[test]
    fn install_backs_up_a_managed_file_whose_body_changed() {
        let tmp = tempfile::TempDir::new().expect("tmp");
        let target = tmp.path().join("SKILL.md");
        let target = target.to_string_lossy().into_owned();
        install(tmp.path(), "hermes", &target, false).expect("install");
        let tampered = std::fs::read(&target)
            .expect("read")
            .into_iter()
            .chain(b"\n<!-- edited -->\n".iter().copied())
            .collect::<Vec<u8>>();
        std::fs::write(&target, &tampered).expect("write");

        install(tmp.path(), "hermes", &target, false).expect("refresh");
        assert_eq!(
            std::fs::read(format!("{target}{BACKUP_SUFFIX}")).expect("backup"),
            tampered
        );
        assert!(find_sentinel(&std::fs::read(&target).expect("read")));
    }
}
