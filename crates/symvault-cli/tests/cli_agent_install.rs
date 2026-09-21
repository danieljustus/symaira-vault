//! Contract for `symvault agent install`.
//!
//! Everything asserted here was measured against the pinned Go oracle
//! (`target/port/symvault-go`); file bodies come from
//! `tests/fixtures/agent-install/*`, which are the oracle's own output with
//! throwaway roots replaced by placeholders at comparison time.
//!
//! Deliberate, documented differences from the oracle:
//!
//! * `managed_version` in installed skill files is build-injected
//!   (`unreleased` in the oracle build, `SYMVAULT_VERSION` here), so the
//!   fixture comparison pins its shape and anchors it to this binary's
//!   version; the hash is recomputed over the body like `cli_agent_skill`.
//! * Token IDs, secrets, hashes and timestamps are random per run; the tests
//!   assert their shape (and the pinned tool-registry hash), not their value.
//! * Multi-agent `--auto-detect` order is random in the oracle (Go map
//!   iteration); the port walks definition order. Only single-agent
//!   auto-detect runs are byte-compared.
//! * Errors surface twice here, exactly like the oracle (inherited `CLI-005`
//!   behavior: every returned error is printed twofold).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

/// Tool-registry hash the pinned oracle stamps into install tokens
/// (`server.init()` over the compiled MCP tool definitions). Must match
/// `PINNED_TOOL_REGISTRY_HASH` in `agent_install_commands.rs`.
const PINNED_TOOL_REGISTRY_HASH: &str =
    "01c5ea5101379933ab1ffba00f6b11b0f71afed220890cd7cb3460aeedcbb77f";

fn rust_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_symvault"))
}

/// Guard owning a unique temporary directory plus the disposable roots inside
/// it. `tempfile` is used instead of a clock-derived name on purpose: the
/// nanosecond temp names of older tests collide (issue #1085).
struct Roots {
    _guard: TempDir,
    home: PathBuf,
    vault: PathBuf,
}

fn disposable_roots() -> Roots {
    let guard = TempDir::new().expect("temp dir");
    let home = guard.path().join("home");
    let vault = guard.path().join("vault");
    for directory in [&home, &vault] {
        std::fs::create_dir_all(directory).expect("create root");
    }
    // No vault seed: like the oracle captures, every install starts from a
    // missing config.yaml so `Default()` supplies the built-in profiles.
    Roots {
        _guard: guard,
        home,
        vault,
    }
}

fn run(args: &[&str], roots: &Roots) -> Output {
    Command::new(rust_binary())
        .args(args)
        .env("HOME", &roots.home)
        // Windows: Go's `os.UserHomeDir` (mirrored by `expand_tilde`) reads
        // `%USERPROFILE%`, ignoring `HOME` — sandbox it too, or the default
        // `~/.hermes/...` skill path escapes the throwaway home.
        .env("USERPROFILE", &roots.home)
        .env("XDG_CONFIG_HOME", roots.home.join(".config"))
        .env("XDG_DATA_HOME", roots.home.join(".local/share"))
        .env("SYMVAULT_VAULT", &roots.vault)
        // Restricted PATH like the oracle captures: auto-detect must only see
        // seeded config files, never the developer machine's real binaries.
        .env("PATH", "/usr/bin:/bin")
        .env("NO_COLOR", "1")
        .env_remove("SYMVAULT_PASSPHRASE")
        .env_remove("SYMVAULT_MCP_TOKEN")
        .output()
        .expect("spawn")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn root_of(roots: &Roots) -> String {
    roots._guard.path().to_string_lossy().into_owned()
}

/// Normalizes everything that varies run to run: the throwaway root, token
/// IDs, 64-hex secrets, RFC3339 timestamps and digest lines.
fn normalize(text: &str, root: &str) -> String {
    let mut out = text.replace(root, "<ROOT>");
    // Windows prints native `\` separators (fixtures are Unix `/`); no
    // fixture contains a backslash, so a global fold is safe.
    out = out.replace('\\', "/");
    out = regex_replace(&out);
    out
}

fn regex_replace(text: &str) -> String {
    // Minimal regex-free normalizer: 64-hex runs, tok IDs, timestamps, digests.
    // All patterns are ASCII; anything else passes through untouched (slicing
    // the raw bytes would panic on multi-byte output like `✓`).
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if is_hex_run(&chars, index, 64) {
            out.push_str("HEX");
            index += 64;
        } else if starts_with(&chars, index, "tok-") && is_tok_id(&chars, index) {
            out.push_str("tok-ID");
            index += 21;
        } else if starts_with(&chars, index, "sha256:") && is_hex_run(&chars, index + 7, 64) {
            out.push_str("sha256:HEX");
            index += 7 + 64;
        } else if let Some(length) = timestamp_length_chars(&chars, index) {
            out.push_str("TS");
            index += length;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

fn starts_with(chars: &[char], start: usize, prefix: &str) -> bool {
    let prefix: Vec<char> = prefix.chars().collect();
    chars.len() >= start + prefix.len() && chars[start..start + prefix.len()] == prefix[..]
}

fn is_hex_run(chars: &[char], start: usize, length: usize) -> bool {
    chars.len() >= start + length
        && chars[start..start + length]
            .iter()
            .all(|c| c.is_ascii_hexdigit())
}

fn is_tok_id(chars: &[char], start: usize) -> bool {
    // `tok-YYYYMMDD-xxxxxxxx` is always 3 + 1 + 8 + 1 + 8 = 21 chars.
    chars.len() >= start + 21
        && chars[start..start + 21]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == '-')
}

fn timestamp_length_chars(chars: &[char], start: usize) -> Option<usize> {
    // `YYYY-MM-DDTHH:MM:SS[.frac]Z`, second precision or finer.
    if chars.len() < start + 20 {
        return None;
    }
    let digit = |i: usize| chars[start + i].is_ascii_digit();
    if !(digit(0)
        && digit(1)
        && digit(2)
        && digit(3)
        && chars[start + 4] == '-'
        && digit(5)
        && digit(6)
        && chars[start + 7] == '-'
        && digit(8)
        && digit(9)
        && chars[start + 10] == 'T'
        && digit(11)
        && digit(12)
        && chars[start + 13] == ':'
        && digit(14)
        && digit(15)
        && chars[start + 16] == ':'
        && digit(17)
        && digit(18)
        && digit(19))
    {
        return None;
    }
    let mut length = 20;
    if chars.get(start + 20) == Some(&'.') {
        let mut end = start + 21;
        while end < chars.len() && chars[end].is_ascii_digit() {
            end += 1;
        }
        if end == start + 21 {
            return None;
        }
        length = end - start;
    }
    if chars.get(start + length) == Some(&'Z') {
        Some(length + 1)
    } else {
        None
    }
}

fn fixture(name: &str) -> String {
    // `.gitattributes` pins these files to LF; normalizing again keeps the
    // comparison honest in checkouts that ignore that setting.
    let raw = match name {
        "hermes.mcp.yaml" => include_str!("fixtures/agent-install/hermes.mcp.yaml"),
        "hermes.mcp.yaml.backup" => {
            include_str!("fixtures/agent-install/hermes.mcp.yaml.backup")
        }
        "opencode.json" => include_str!("fixtures/agent-install/opencode.json"),
        "codex.empty.toml" => include_str!("fixtures/agent-install/codex.empty.toml"),
        "codex.existing.input.toml" => {
            include_str!("fixtures/agent-install/codex.existing.input.toml")
        }
        "codex.existing.toml" => include_str!("fixtures/agent-install/codex.existing.toml"),
        "codex.existing.toml.backup" => {
            include_str!("fixtures/agent-install/codex.existing.toml.backup")
        }
        "hermes.http.mcp.yaml" => include_str!("fixtures/agent-install/hermes.http.mcp.yaml"),
        "vault.config.yaml" => include_str!("fixtures/agent-install/vault.config.yaml"),
        "hermes.skill.md" => include_str!("fixtures/agent-install/hermes.skill.md"),
        "opencode.skill.md" => include_str!("fixtures/agent-install/opencode.skill.md"),
        "codex.skill.md" => include_str!("fixtures/agent-install/codex.skill.md"),
        other => panic!("unknown fixture {other}"),
    };
    raw.replace("\r\n", "\n")
}

fn read_tree(roots: &Roots, relative: &str) -> Vec<u8> {
    let mut path = PathBuf::from(&roots.home);
    let mut vault_path = roots.vault.clone();
    let _ = &mut vault_path;
    let full = if let Some(rest) = relative.strip_prefix("home/") {
        path.push(rest);
        path
    } else if let Some(rest) = relative.strip_prefix("vault/") {
        let mut full = roots.vault.clone();
        full.push(rest);
        full
    } else {
        path.push(relative);
        path
    };
    std::fs::read(&full).unwrap_or_else(|_| panic!("read {}", full.display()))
}

fn seed_agent_config(roots: &Roots, relative: &str, content: &str) {
    let full = if let Some(rest) = relative.strip_prefix("home/") {
        roots.home.join(rest)
    } else {
        roots.vault.join(relative)
    };
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).expect("seed parent");
    }
    std::fs::write(&full, content).expect("seed agent config");
}

/// Asserts an installed skill file against its oracle fixture: frontmatter
/// shape plus a byte-exact body (the hash is recomputed over the body, the
/// version is anchored to this binary, the timestamp is shape-checked).
fn assert_skill_file(path: &Path, fixture_name: &str, roots: &Roots) {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("read {}", path.display()))
        .replace("\r\n", "\n");
    let expected = with_live_root(fixture_name, "<ROOT>").replace(
        "managed_version: unreleased",
        "managed_version: {{VERSION}}",
    );
    let expected = expected.replace(
        "{{VERSION}}",
        option_env!("SYMVAULT_VERSION").unwrap_or("dev"),
    );
    let expected = normalize(&expected, "<ROOT>");
    // The digest covers the raw body bytes, so keep an un-normalized copy for
    // the hash check and only normalize for the line comparison.
    let raw_actual = text.replace(&root_of(roots), "<ROOT>");
    let actual = normalize(&raw_actual, "<ROOT>");
    let actual_lines: Vec<&str> = actual.lines().collect();
    let expected_lines: Vec<&str> = expected.lines().collect();
    assert!(
        actual_lines.len() == expected_lines.len(),
        "{fixture_name}: line count {} != {}",
        actual_lines.len(),
        expected_lines.len()
    );
    for (index, (actual_line, expected_line)) in
        actual_lines.iter().zip(expected_lines.iter()).enumerate()
    {
        if expected_line.starts_with("managed_version: ") {
            assert!(
                actual_line.starts_with("managed_version: ") && actual_line.len() > 18,
                "{fixture_name} line {index}: version shape {actual_line:?}"
            );
        } else if expected_line.starts_with("managed_hash: sha256:") {
            // The digest covers the body bytes with the real root path, so
            // split the untouched text at the frontmatter boundary (the
            // description may wrap, so no fixed line number).
            let untouched: Vec<&str> = text.lines().collect();
            let (_, body) = text.split_once("---\n\n").expect("frontmatter boundary");
            assert_eq!(
                untouched[index],
                format!(
                    "managed_hash: sha256:{}",
                    symvault_store::sha256_hex(body.as_bytes())
                ),
                "{fixture_name}: digest must cover exactly the body"
            );
        } else if expected_line.starts_with("managed_installed_at: ") {
            let prefix = "managed_installed_at: \"";
            assert!(
                actual_line.starts_with(prefix)
                    && actual_line.ends_with("Z\"")
                    && actual_line.len() == prefix.len() + 20 + 1,
                "{fixture_name} line {index}: timestamp shape {actual_line:?}"
            );
        } else {
            assert_eq!(actual_line, expected_line, "{fixture_name} line {index}");
        }
    }
}

fn root_in(content: &str) -> Option<String> {
    // Frozen fixtures usually embed exactly one throwaway root before `/vault`
    // (followed by a path boundary: newline, quote, comma, bracket, ...).
    // Files without any vault path (the HTTP agent YAML) yield `None`.
    let bytes = content.as_bytes();
    let mut search_from = 0;
    let marker = loop {
        let relative = content[search_from..].find("/vault")?;
        let absolute = search_from + relative;
        let after = absolute + "/vault".len();
        let boundary = bytes
            .get(after)
            .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_');
        if boundary {
            break absolute;
        }
        search_from = absolute + 1;
    };
    let start = content[..marker]
        .rfind([' ', '"', '\n', '\'', '`'])
        .map_or(0, |i| i + 1);
    Some(content[start..marker].to_owned())
}

/// Replaces the throwaway root a fixture embeds with the live one; fixtures
/// without any vault path pass through unchanged.
fn with_live_root(fixture_name: &str, live_root: &str) -> String {
    let content = fixture(fixture_name);
    match root_in(&content) {
        Some(frozen) => content.replace(&frozen, live_root),
        None => content,
    }
}

fn registry_tokens(roots: &Roots) -> serde_json::Value {
    let raw = read_tree(roots, "vault/mcp-tokens.json");
    serde_json::from_slice(&raw).expect("registry json")
}

#[test]
fn install_hermes_stdio_matches_oracle() {
    let roots = disposable_roots();
    seed_agent_config(&roots, "home/.config/hermes/mcp.yaml", "{}\n");
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "hermes",
            "--force",
        ],
        &roots,
    );
    let root = root_of(&roots);
    assert_eq!(output.status.code(), Some(0));
    let expected_stdout = format!(
        "✓ Agent \"hermes\" configured\n  Tier:         safe\n  Transport:    stdio\n  Profile:      {root}/vault/config.yaml\n  Token ID:     tok-ID\n  MCP config:   {root}/home/.config/hermes/mcp.yaml\n  Backup:       {root}/home/.config/hermes/mcp.yaml.backup\n  Skill:        {root}/home/.hermes/skills/symvault/SKILL.md\n  Smoke test:   skipped\n"
    );
    assert_eq!(
        normalize(&stdout_of(&output), &root),
        normalize(&expected_stdout, &root)
    );
    assert_eq!(stderr_of(&output), "");

    let mcp_yaml = String::from_utf8(read_tree(&roots, "home/.config/hermes/mcp.yaml"))
        .expect("utf8")
        .replace("\r\n", "\n");
    assert_eq!(
        normalize(&mcp_yaml, &root),
        normalize(&with_live_root("hermes.mcp.yaml", &root), &root)
    );
    let backup =
        String::from_utf8(read_tree(&roots, "home/.config/hermes/mcp.yaml.backup")).expect("utf8");
    assert_eq!(backup, "{}\n");

    let config_yaml = String::from_utf8(read_tree(&roots, "vault/config.yaml")).expect("utf8");
    assert_eq!(
        normalize(&config_yaml, &root),
        normalize(&with_live_root("vault.config.yaml", &root), &root)
    );

    let registry = registry_tokens(&roots);
    let tokens = registry["tokens"].as_object().expect("tokens map");
    assert_eq!(tokens.len(), 1, "one display token, got {tokens:?}");
    let token = tokens.values().next().expect("token");
    assert_eq!(token["label"], "agent-install-hermes");
    assert_eq!(token["agent_name"], "hermes");
    assert_eq!(token["tool_registry_hash"], PINNED_TOOL_REGISTRY_HASH);
    assert_eq!(token["allowed_tools"], serde_json::json!(["*"]));
    assert_eq!(token["revoked"], false);
    assert!(token["expires_at"].is_null(), "display token never expires");

    let token_id = token["id"].as_str().expect("id");
    let raw_file = read_tree(&roots, "vault/mcp-tokens/hermes.token");
    assert_eq!(raw_file.len(), 65, "64 hex + newline");
    assert!(raw_file.ends_with(b"\n"));
    assert!(raw_file[..64].iter().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(
        &token["prefix"],
        &serde_json::json!(String::from_utf8_lossy(&raw_file[..4]).into_owned())
    );

    assert_skill_file(
        &roots.home.join(".hermes/skills/symvault/SKILL.md"),
        "hermes.skill.md",
        &roots,
    );
    let _ = token_id;
}

#[test]
fn install_opencode_json_matches_oracle() {
    let roots = disposable_roots();
    seed_agent_config(&roots, "home/.config/opencode/opencode.json", "{}\n");
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "opencode",
            "--force",
        ],
        &roots,
    );
    let root = root_of(&roots);
    assert_eq!(output.status.code(), Some(0));
    let rendered = String::from_utf8(read_tree(&roots, "home/.config/opencode/opencode.json"))
        .expect("utf8")
        .replace("\r\n", "\n");
    assert_eq!(
        normalize(&rendered, &root),
        normalize(&with_live_root("opencode.json", &root), &root)
    );
    assert_skill_file(
        &roots.home.join(".opencode/skills/symvault/SKILL.md"),
        "opencode.skill.md",
        &roots,
    );
}

#[test]
fn install_codex_empty_toml_matches_oracle() {
    let roots = disposable_roots();
    // An empty (zero-byte) file detects codex and parses as an empty document.
    seed_agent_config(&roots, "home/.codex/config.toml", "");
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "codex",
            "--force",
        ],
        &roots,
    );
    let root = root_of(&roots);
    assert_eq!(output.status.code(), Some(0));
    let rendered = String::from_utf8(read_tree(&roots, "home/.codex/config.toml"))
        .expect("utf8")
        .replace("\r\n", "\n");
    assert_eq!(
        normalize(&rendered, &root),
        normalize(&with_live_root("codex.empty.toml", &root), &root)
    );
    // An empty seed detects codex, and the oracle still backs the (empty)
    // file up before replacing it.
    let backup = roots.home.join(".codex/config.toml.backup");
    assert!(backup.exists(), "empty seed is backed up");
    assert_eq!(std::fs::read(&backup).expect("read backup").len(), 0);
    assert_skill_file(
        &roots.home.join(".codex/skills/symvault/AGENTS.md"),
        "codex.skill.md",
        &roots,
    );
}

#[test]
fn install_codex_existing_toml_matches_oracle() {
    let roots = disposable_roots();
    seed_agent_config(
        &roots,
        "home/.codex/config.toml",
        &fixture("codex.existing.input.toml"),
    );
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "codex",
            "--force",
        ],
        &roots,
    );
    let root = root_of(&roots);
    assert_eq!(output.status.code(), Some(0));
    let rendered = String::from_utf8(read_tree(&roots, "home/.codex/config.toml"))
        .expect("utf8")
        .replace("\r\n", "\n");
    assert_eq!(
        normalize(&rendered, &root),
        normalize(&with_live_root("codex.existing.toml", &root), &root)
    );
    let backup =
        String::from_utf8(read_tree(&roots, "home/.codex/config.toml.backup")).expect("utf8");
    assert_eq!(
        backup.replace("\r\n", "\n"),
        fixture("codex.existing.input.toml")
    );
}

#[test]
fn install_hermes_http_matches_oracle() {
    let roots = disposable_roots();
    seed_agent_config(&roots, "home/.config/hermes/mcp.yaml", "{}\n");
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "hermes",
            "--force",
            "--http",
        ],
        &roots,
    );
    let root = root_of(&roots);
    assert_eq!(output.status.code(), Some(0));
    let expected_stdout = format!(
        "✓ Agent \"hermes\" configured\n  Tier:         safe\n  Transport:    http\n  Profile:      {root}/vault/config.yaml\n  Token ID:     tok-ID\n  MCP config:   {root}/home/.config/hermes/mcp.yaml\n  Backup:       {root}/home/.config/hermes/mcp.yaml.backup\n  Skill:        {root}/home/.hermes/skills/symvault/SKILL.md\n  Smoke test:   skipped\n"
    );
    assert_eq!(
        normalize(&stdout_of(&output), &root),
        normalize(&expected_stdout, &root)
    );

    let mcp_yaml = String::from_utf8(read_tree(&roots, "home/.config/hermes/mcp.yaml"))
        .expect("utf8")
        .replace("\r\n", "\n");
    assert_eq!(
        normalize(&mcp_yaml, &root),
        normalize(&with_live_root("hermes.http.mcp.yaml", &root), &root)
    );
    // The full 64-hex Bearer survives normalization as `HEX`, which proves the
    // oracle writes the whole scoped secret (not a redaction) into the file.
    let bearer_line = mcp_yaml
        .lines()
        .find(|line| line.contains("Authorization:"))
        .expect("bearer line");
    let bearer = bearer_line.rsplit(' ').next().expect("bearer value");
    assert_eq!(bearer.len(), 64, "full scoped secret in agent YAML");
    assert!(bearer.bytes().all(|b| b.is_ascii_hexdigit()));

    // The HTTP token file holds a full secret too.
    let http_token = read_tree(&roots, "vault/mcp-token");
    assert_eq!(http_token.len(), 65);
    assert!(http_token[..64].iter().all(|b| b.is_ascii_hexdigit()));

    // HTTP installs mint TWO registry tokens: the display token plus the
    // scoped `mcp-install-*` token whose raw value becomes the Bearer entry.
    let registry = registry_tokens(&roots);
    let tokens = registry["tokens"].as_object().expect("tokens map");
    assert_eq!(tokens.len(), 2, "display + scoped, got {tokens:?}");
    let mut labels: Vec<&str> = tokens
        .values()
        .map(|t| t["label"].as_str().expect("label"))
        .collect();
    labels.sort_unstable();
    assert_eq!(labels, ["agent-install-hermes", "mcp-install-hermes"]);
    for token in tokens.values() {
        assert_eq!(token["tool_registry_hash"], PINNED_TOOL_REGISTRY_HASH);
    }
    let scoped = tokens
        .values()
        .find(|t| t["label"] == "mcp-install-hermes")
        .expect("scoped token");
    assert!(
        scoped["expires_at"].is_string(),
        "scoped token carries a 30-day TTL"
    );
}

#[test]
fn install_yaml_and_json_output_match_oracle() {
    for format in ["yaml", "json"] {
        let roots = disposable_roots();
        seed_agent_config(&roots, "home/.config/hermes/mcp.yaml", "{}\n");
        let output = run(
            &[
                "--vault",
                &roots.vault.to_string_lossy(),
                "agent",
                "install",
                "hermes",
                "--force",
                "--output",
                format,
            ],
            &roots,
        );
        let root = root_of(&roots);
        assert_eq!(output.status.code(), Some(0), "{format}");
        let expected = if format == "yaml" {
            format!(
                "agent_name: hermes\ntier: safe\nmethod: stdio\nprofile_path: {root}/vault/config.yaml\ntoken_id: tok-ID\nmcp_config_path: {root}/home/.config/hermes/mcp.yaml\nskill_path: {root}/home/.hermes/skills/symvault/SKILL.md\nsmoke_test: skipped\nbackup_path: {root}/home/.config/hermes/mcp.yaml.backup\n"
            )
        } else {
            format!(
                "{{\n  \"agent_name\": \"hermes\",\n  \"tier\": \"safe\",\n  \"method\": \"stdio\",\n  \"profile_path\": \"{root}/vault/config.yaml\",\n  \"token_id\": \"tok-ID\",\n  \"mcp_config_path\": \"{root}/home/.config/hermes/mcp.yaml\",\n  \"skill_path\": \"{root}/home/.hermes/skills/symvault/SKILL.md\",\n  \"smoke_test\": \"skipped\",\n  \"backup_path\": \"{root}/home/.config/hermes/mcp.yaml.backup\"\n}}\n"
            )
        };
        assert_eq!(
            normalize(&stdout_of(&output), &root),
            normalize(&expected, &root),
            "{format}"
        );
    }
}

#[test]
fn install_dry_run_writes_nothing() {
    let roots = disposable_roots();
    seed_agent_config(&roots, "home/.config/hermes/mcp.yaml", "{}\n");
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "hermes",
            "--dry-run",
        ],
        &roots,
    );
    let root = root_of(&roots);
    assert_eq!(output.status.code(), Some(0));
    let expected_stdout = format!(
        "✓ Agent \"hermes\" configured\n  Tier:         safe\n  Transport:    stdio\n  Profile:      {root}/vault/config.yaml\n  Token ID:     <not generated (dry-run)>\n  MCP config:   {root}/home/.config/hermes/mcp.yaml\n  Skill:        {root}/home/.hermes/skills/symvault/SKILL.md\n  Smoke test:   skipped\n"
    );
    assert_eq!(
        normalize(&stdout_of(&output), &root),
        normalize(&expected_stdout, &root)
    );
    assert_eq!(
        std::fs::read_to_string(roots.home.join(".config/hermes/mcp.yaml")).expect("seed intact"),
        "{}\n"
    );
    assert!(!roots.home.join(".config/hermes/mcp.yaml.backup").exists());
    assert!(!roots.vault.join("mcp-tokens.json").exists());
    assert!(!roots.home.join(".hermes/skills/symvault/SKILL.md").exists());
    // Dry-run changes nothing: the vault config is never even created.
    assert!(!roots.vault.join("config.yaml").exists());
}

#[test]
fn install_quiet_prints_nothing() {
    let roots = disposable_roots();
    seed_agent_config(&roots, "home/.config/hermes/mcp.yaml", "{}\n");
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "hermes",
            "--force",
            "--quiet",
        ],
        &roots,
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        stderr_of(&output)
    );
    assert_eq!(stdout_of(&output), "", "stdout");
    assert_eq!(stderr_of(&output), "", "stderr");
    assert!(roots.home.join(".config/hermes/mcp.yaml").exists());
}

#[test]
fn install_skill_only_skips_profile_and_token() {
    let roots = disposable_roots();
    seed_agent_config(&roots, "home/.config/hermes/mcp.yaml", "{}\n");
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "hermes",
            "--force",
            "--skill-only",
        ],
        &roots,
    );
    let root = root_of(&roots);
    assert_eq!(output.status.code(), Some(0));
    let expected_stdout = format!(
        "✓ Agent \"hermes\" configured\n  Tier:         safe\n  Transport:    stdio\n  Profile:      {root}/vault/config.yaml\n  Skill:        {root}/home/.hermes/skills/symvault/SKILL.md\n  Smoke test:   skipped\n"
    );
    assert_eq!(
        normalize(&stdout_of(&output), &root),
        normalize(&expected_stdout, &root)
    );
    assert!(!roots.vault.join("mcp-tokens.json").exists());
    // Skill-only still writes the vault profile, just no token.
    let written =
        std::fs::read_to_string(roots.vault.join("config.yaml")).expect("profile written");
    assert!(
        written.contains("hermes:\n        tier: safe\n"),
        "hermes profile persisted"
    );
    assert!(roots.home.join(".hermes/skills/symvault/SKILL.md").exists());
}

#[test]
fn install_config_only_skips_skill() {
    let roots = disposable_roots();
    seed_agent_config(&roots, "home/.config/hermes/mcp.yaml", "{}\n");
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "hermes",
            "--force",
            "--config-only",
        ],
        &roots,
    );
    let root = root_of(&roots);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout_of(&output).contains("MCP config:"));
    assert!(!stdout_of(&output).contains("Skill:"));
    assert!(!roots.home.join(".hermes/skills/symvault/SKILL.md").exists());
    assert!(roots.vault.join("mcp-tokens.json").exists());
    let _ = root;
}

#[test]
fn install_rejects_bad_input_like_oracle() {
    // Unknown tier.
    let roots = disposable_roots();
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "hermes",
            "--tier",
            "admin2",
        ],
        &roots,
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout_of(&output), "");
    let doubled = "Error: invalid tier \"admin2\": must be one of: safe, standard, admin\nError: invalid tier \"admin2\": must be one of: safe, standard, admin\n";
    assert_eq!(stderr_of(&output), doubled);

    // Unknown agent.
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "watson",
        ],
        &roots,
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr_of(&output),
        "Error: unsupported agent \"watson\"\nError: unsupported agent \"watson\"\n"
    );

    // Mutually exclusive modes.
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "hermes",
            "--skill-only",
            "--config-only",
        ],
        &roots,
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr_of(&output),
        "Error: --skill-only and --config-only cannot be used together\nError: --skill-only and --config-only cannot be used together\n"
    );

    // Arity: zero and two names.
    let vault_arg = roots.vault.to_string_lossy().into_owned();
    for args in [
        vec!["agent", "install"],
        vec!["agent", "install", "hermes", "codex"],
    ] {
        let mut full = vec!["--vault", vault_arg.as_str()];
        full.extend(args);
        let output = run(&full, &roots);
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(stdout_of(&output), "");
        assert!(stderr_of(&output).contains("requires exactly 1 argument"));
    }

    // Non-safe tiers need a TTY; the test harness has none.
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "hermes",
            "--tier",
            "standard",
        ],
        &roots,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr_of(&output).contains("--tier \"standard\" requires an interactive terminal"));

    // Undetected agent without --auto-detect.
    let bare = disposable_roots();
    let output = run(
        &[
            "--vault",
            &bare.vault.to_string_lossy(),
            "agent",
            "install",
            "hermes",
        ],
        &bare,
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr_of(&output),
        "Error: agent \"Hermes\" not detected (checked binary in PATH and config files)\nError: agent \"Hermes\" not detected (checked binary in PATH and config files)\n"
    );
}

#[test]
fn install_existing_profile_needs_force() {
    let roots = disposable_roots();
    seed_agent_config(&roots, "home/.config/hermes/mcp.yaml", "{}\n");
    let vault = roots.vault.to_string_lossy().into_owned();
    let first = run(
        &["--vault", &vault, "agent", "install", "hermes", "--force"],
        &roots,
    );
    assert_eq!(first.status.code(), Some(0));
    // A second install without --force fails with the doubled oracle error.
    let second = run(&["--vault", &vault, "agent", "install", "hermes"], &roots);
    assert_eq!(second.status.code(), Some(1));
    assert_eq!(stdout_of(&second), "");
    assert_eq!(
        stderr_of(&second),
        "Error: create agent profile: agent \"hermes\" already exists in config (use --force to overwrite)\nError: create agent profile: agent \"hermes\" already exists in config (use --force to overwrite)\n"
    );
    // --force again succeeds and leaves a backup of the previous agent file.
    let third = run(
        &["--vault", &vault, "agent", "install", "hermes", "--force"],
        &roots,
    );
    assert_eq!(third.status.code(), Some(0));
    assert!(roots.home.join(".config/hermes/mcp.yaml.backup").exists());
}

#[test]
fn install_auto_detect_single_agent_matches_oracle() {
    // Only codex leaves a trace, so exactly one agent is detected and the run
    // is byte-deterministic on both sides (multi-agent order is random in Go).
    let roots = disposable_roots();
    seed_agent_config(&roots, "home/.codex/config.toml", "");
    let output = run(
        &[
            "--vault",
            &roots.vault.to_string_lossy(),
            "agent",
            "install",
            "--auto-detect",
            "--force",
        ],
        &roots,
    );
    let root = root_of(&roots);
    assert_eq!(output.status.code(), Some(0));
    let expected_stdout = format!(
        "Detected Codex\n✓ Agent \"codex\" configured\n  Tier:         safe\n  Transport:    stdio\n  Profile:      {root}/vault/config.yaml\n  Token ID:     tok-ID\n  MCP config:   {root}/home/.codex/config.toml\n  Backup:       {root}/home/.codex/config.toml.backup\n  Skill:        {root}/home/.codex/skills/symvault/AGENTS.md\n  Smoke test:   skipped\n"
    );
    assert_eq!(
        normalize(&stdout_of(&output), &root),
        normalize(&expected_stdout, &root)
    );
}
