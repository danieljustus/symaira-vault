//! Contract tests for `agent upgrade` (Go `cmd/mcp/agent_upgrade.go`).
//!
//! Every expectation is pinned against the frozen oracle capture
//! (`agent-upgrade-oracle/*.json`, see the differential script
//! `diff-upgrade.py`): same exit codes, byte-identical stderr after
//! normalizing throwaway roots, token IDs, hex secrets and timestamps.
//!
//! Conventions (issue #1085): `tempfile::TempDir` owns every root — never
//! clock-derived names. The oracle is never run against the real HOME: each
//! case gets a throwaway `HOME`/`USERPROFILE` plus a restricted `PATH`, so
//! agent auto-detect only sees seeded files.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

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
    work: PathBuf,
}

fn disposable_roots() -> Roots {
    let guard = TempDir::new().expect("temp dir");
    let home = guard.path().join("home");
    let vault = guard.path().join("vault");
    let work = guard.path().join("work");
    for directory in [&home, &vault, &work] {
        std::fs::create_dir_all(directory).expect("create root");
    }
    Roots {
        _guard: guard,
        home,
        vault,
        work,
    }
}

/// Seed a hand-written `tier: safe` profile. The Go loader records the tier
/// but `TierPresets` has no `"safe"` key, so the preset application misses
/// and the capabilities stay at the built-in defaults (`canWrite: true`).
/// `get_preset("safe")` replicates the miss (`None`), which the dry-run
/// table below pins.
fn seed_safe(roots: &Roots) {
    std::fs::write(
        roots.vault.join("config.yaml"),
        "defaultAgent: hermes\nagents:\n  hermes:\n    tier: safe\n",
    )
    .expect("seed config");
}

fn seed_standard(roots: &Roots) {
    std::fs::write(
        roots.vault.join("config.yaml"),
        "defaultAgent: hermes\nagents:\n  hermes:\n    tier: standard\n",
    )
    .expect("seed config");
}

fn run(args: &[&str], roots: &Roots, stdin: Option<&[u8]>) -> Output {
    let mut child = Command::new(rust_binary())
        .args(args)
        .current_dir(&roots.work)
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
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(input)
            .expect("write stdin");
    }
    // Dropping the pipe without writing (stdin=None) reports EOF, which is
    // how the oracle capture drives the non-TTY cancel path.
    drop(child.stdin.take());
    child.wait_with_output().expect("wait")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn root_of(roots: &Roots) -> String {
    roots._guard.path().to_string_lossy().into_owned()
}

/// Normalizes everything that varies run to run: the throwaway root, token
/// IDs (label-anchored — registry keys are random suffixes whose sort order
/// varies per run, so a flat placeholder would compare the wrong entries),
/// 64-hex secrets, RFC3339 timestamps and digest lines.
fn normalize(text: &str, root: &str) -> String {
    // JSON files escape `\` as `\\`: replace that form first, then the
    // native form (identical on Unix), then fold stray separators.
    let mut out = text.replace(&root.replace('\\', "\\\\"), "<ROOT>");
    out = out.replace(root, "<ROOT>");
    // Windows prints native `\` separators; no expectation contains a
    // backslash, so a global fold is safe.
    out = out.replace('\\', "/");
    // An escaped root leaves `<ROOT>\\…`, which folds to double slashes —
    // collapse every `//` run except URL schemes (`http://`).
    let mut collapsed = String::with_capacity(out.len());
    let mut prev = '\0';
    let mut prev_prev = '\0';
    for ch in out.chars() {
        if ch == '/' && prev == '/' && prev_prev != ':' {
            continue;
        }
        collapsed.push(ch);
        prev_prev = prev;
        prev = ch;
    }
    out = collapsed;
    out = anchor_token_ids(&out);
    out = regex_replace(&out);
    out
}

/// Map each `tok-…` ID (and its registry hash) to the entry's stable label:
/// `"tok-AAA": { "id": "tok-AAA", "label": "LBL", "hash": "HHH", … }`.
/// Registry keys are random suffixes whose sort order varies per run, so a
/// flat placeholder would compare the wrong entries. Anything left over (a
/// stdio-only ID with no registry context) falls through to `regex_replace`.
fn anchor_token_ids(text: &str) -> String {
    let mut out = text.to_owned();
    let mut search_from = 0;
    while let Some(key_start) = out[search_from..].find("\"tok-") {
        let key_start = search_from + key_start + 1;
        if out.len() < key_start + 21 {
            break;
        }
        let id: String = out[key_start..key_start + 21].chars().collect();
        if !is_tok_id(&id) {
            search_from = key_start + 1;
            continue;
        }
        let window_end = (key_start + 400).min(out.len());
        let window = &out[key_start..window_end];
        let label = window
            .find("\"label\": \"")
            .and_then(|at| {
                let rest = &window[at + 10..];
                rest.find('"').map(|end| rest[..end].to_owned())
            })
            .unwrap_or_default();
        if label.is_empty() {
            search_from = key_start + 1;
            continue;
        }
        let tag: String = label
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        let tag = tag.trim_matches('-').to_owned();
        // The entry hash sits right after the label; anchor it too.
        if let Some(hash_at) = window.find("\"hash\": \"") {
            let hash_start = key_start + hash_at + 9;
            if out.len() >= hash_start + 64 {
                let hash: String = out[hash_start..hash_start + 64].chars().collect();
                if hash.chars().all(|c| c.is_ascii_hexdigit()) {
                    out = out.replace(&hash, &format!("HEX-{tag}"));
                }
            }
        }
        out = out.replace(&id, &format!("tok-{tag}"));
        search_from = key_start + 1;
    }
    out
}

fn is_tok_id(id: &str) -> bool {
    // `tok-YYYYMMDD-xxxxxxxx` is always 3 + 1 + 8 + 1 + 8 = 21 chars.
    id.len() == 21
        && id.starts_with("tok-")
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn regex_replace(text: &str) -> String {
    // Minimal regex-free normalizer: 64-hex runs, tok IDs, timestamps,
    // digests. All patterns are ASCII; anything else passes through
    // untouched (slicing the raw bytes would panic on `✓`/`⚠`).
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if is_hex_run(&chars, index, 64) {
            out.push_str("HEX");
            index += 64;
        } else if starts_with(&chars, index, "tok-") && is_tok_id_chars(&chars, index) {
            out.push_str("tok-ID");
            index += 21;
        } else if starts_with(&chars, index, "\"prefix\": \"")
            && is_hex_run(&chars, index + 11, 4)
            && chars.get(index + 15) == Some(&'"')
        {
            out.push_str("\"prefix\": \"PREFIX\"");
            index += 16;
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

fn is_tok_id_chars(chars: &[char], start: usize) -> bool {
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
    let head: String = chars[start..start + 19].iter().collect();
    if head.len() != 19
        || !head[0..4].chars().all(|c| c.is_ascii_digit())
        || &head[4..5] != "-"
        || &head[10..11] != "T"
    {
        return None;
    }
    let mut end = start + 19;
    if chars.get(end) == Some(&'.') {
        end += 1;
        while chars.get(end).is_some_and(|c| c.is_ascii_digit()) {
            end += 1;
        }
    }
    if chars.get(end) == Some(&'Z') {
        end += 1;
    }
    Some(end - start)
}

const DRY_RUN_TABLE: &str = concat!(
    "Agent:   hermes\n",
    "Current: safe\n",
    "Target:  standard\n",
    "\n",
    "Tier changes:\n",
    "  FIELD                    CURRENT                  NEW\n",
    "  ------------------------------------------------------------------------\n",
    "  ✓ canWrite               true                     false\n",
    "  ✓ canRunCommands         true                     false\n",
    "  canManageConfig         false                    false (unchanged)\n",
    "  ✓ canUseClipboard        false                    true\n",
    "  ✓ canUseAutotype         false                    true\n",
    "  ✓ canReadValues          false                    true\n",
    "  ✓ exposeValueTools       true                     false\n",
    "  autoUnseal              false                    false (unchanged)\n",
    "  ✓ requireApproval        false                    true\n",
    "  ✓ approvalMode           deny                     prompt\n",
    "  ✓ allowedExecutables     (none)                   curl, git, terraform, npm, node, python, python3, docker, kubectl\n",
    "  allowedTools            (all)                    (all) (unchanged)\n",
);

const INSTALL_TABLE: &str = concat!(
    "Agent:   hermes\n",
    "Current: safe\n",
    "Target:  standard\n",
    "Reason:  capture\n",
    "\n",
    "Tier changes:\n",
    "  FIELD                    CURRENT                  NEW\n",
    "  ------------------------------------------------------------------------\n",
    "  canWrite                false                    false (unchanged)\n",
    "  canRunCommands          false                    false (unchanged)\n",
    "  canManageConfig         false                    false (unchanged)\n",
    "  ✓ canUseClipboard        false                    true\n",
    "  ✓ canUseAutotype         false                    true\n",
    "  ✓ canReadValues          false                    true\n",
    "  exposeValueTools        false                    false (unchanged)\n",
    "  autoUnseal              false                    false (unchanged)\n",
    "  ✓ requireApproval        false                    true\n",
    "  ✓ approvalMode           deny                     prompt\n",
    "  ✓ allowedExecutables     (none)                   curl, git, terraform, npm, node, python, python3, docker, kubectl\n",
    "  allowedTools            (all)                    (all) (unchanged)\n",
);

fn upgrade_args(extra: &[&str]) -> Vec<String> {
    let mut args = vec![
        "agent".to_owned(),
        "upgrade".to_owned(),
        "hermes".to_owned(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    args.push("--no-biometric".to_owned());
    args
}

/// Install hermes first so upgrade runs on an install-written config (old
/// capabilities `false`, managed skill file present). Detection needs a
/// seeded agent config file, like the oracle captures.
fn setup_install(roots: &Roots) {
    let seed = roots.home.join(".config/hermes/mcp.yaml");
    std::fs::create_dir_all(seed.parent().expect("parent")).expect("seed dir");
    std::fs::write(&seed, "{}\n").expect("seed agent config");
    let output = run(&["agent", "install", "hermes", "--force"], roots, None);
    assert_eq!(
        output.status.code(),
        Some(0),
        "setup install failed: {}",
        stderr_of(&output)
    );
}

#[test]
fn dry_run_safe_to_standard_matches_oracle() {
    let roots = disposable_roots();
    seed_safe(&roots);
    let args = upgrade_args(&["--tier", "standard", "--dry-run"]);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&arg_refs, &roots, None);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    let expected = format!("{DRY_RUN_TABLE}\n[DRY-RUN] No changes written.\n");
    assert_eq!(normalize(&stderr_of(&output), &root_of(&roots)), expected);
    // Dry-run writes nothing: the seed config is untouched.
    let config = std::fs::read_to_string(roots.vault.join("config.yaml")).expect("config");
    assert!(config.contains("tier: safe"), "{config}");
}

#[test]
fn missing_tier_is_doubled_error() {
    let roots = disposable_roots();
    seed_safe(&roots);
    let args = upgrade_args(&["--dry-run"]);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&arg_refs, &roots, None);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        normalize(&stderr_of(&output), &root_of(&roots)),
        "Error: --tier is required (valid: safe, standard, admin)\n\
         Error: --tier is required (valid: safe, standard, admin)\n"
    );
}

#[test]
fn invalid_tier_is_doubled_error() {
    let roots = disposable_roots();
    seed_safe(&roots);
    let args = upgrade_args(&["--tier", "bogus", "--dry-run"]);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&arg_refs, &roots, None);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        normalize(&stderr_of(&output), &root_of(&roots)),
        "Error: invalid tier \"bogus\": valid values are safe, standard, admin\n\
         Error: invalid tier \"bogus\": valid values are safe, standard, admin\n"
    );
}

#[test]
fn yes_without_reason_fails() {
    let roots = disposable_roots();
    seed_safe(&roots);
    let args = upgrade_args(&["--tier", "standard", "--yes"]);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&arg_refs, &roots, None);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        normalize(&stderr_of(&output), &root_of(&roots)),
        "Error: --reason is required when using --yes\n\
         Error: --reason is required when using --yes\n"
    );
}

#[test]
fn unknown_agent_is_doubled_error() {
    let roots = disposable_roots();
    seed_safe(&roots);
    let output = run(
        &[
            "agent",
            "upgrade",
            "nope",
            "--tier",
            "standard",
            "--dry-run",
            "--no-biometric",
        ],
        &roots,
        None,
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        normalize(&stderr_of(&output), &root_of(&roots)),
        "Error: agent \"nope\" not found in config\n\
         Error: agent \"nope\" not found in config\n"
    );
}

#[test]
fn already_at_tier_is_doubled_error() {
    let roots = disposable_roots();
    seed_standard(&roots);
    let args = upgrade_args(&["--tier", "standard", "--dry-run"]);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&arg_refs, &roots, None);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        normalize(&stderr_of(&output), &root_of(&roots)),
        "Error: agent \"hermes\" is already at tier \"standard\"\n\
         Error: agent \"hermes\" is already at tier \"standard\"\n"
    );
}

#[test]
fn arity_violations_are_doubled_errors() {
    let roots = disposable_roots();
    seed_safe(&roots);
    for (argv, received) in [
        (
            vec!["agent", "upgrade", "--tier", "standard", "--no-biometric"],
            0,
        ),
        (
            vec![
                "agent",
                "upgrade",
                "hermes",
                "extra",
                "--tier",
                "standard",
                "--no-biometric",
            ],
            2,
        ),
    ] {
        let output = run(&argv, &roots, None);
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(
            normalize(&stderr_of(&output), &root_of(&roots)),
            format!(
                "Error: accepts 1 arg(s), received {received}\n\
                 Error: accepts 1 arg(s), received {received}\n"
            )
        );
    }
}

#[test]
fn piped_stdin_cancels_without_writing() {
    let roots = disposable_roots();
    seed_safe(&roots);
    let args = upgrade_args(&["--tier", "standard"]);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    // EOF on stdin (no TTY): the confirm prompt cancels like the oracle.
    let output = run(&arg_refs, &roots, None);
    assert_eq!(output.status.code(), Some(0));
    let table = DRY_RUN_TABLE;
    assert_eq!(
        normalize(&stderr_of(&output), &root_of(&roots)),
        format!("{table}\nUpgrade canceled.\n")
    );
    let config = std::fs::read_to_string(roots.vault.join("config.yaml")).expect("config");
    assert!(config.contains("tier: safe"), "{config}");
}

#[test]
fn write_standard_upgrades_profile_and_warns_on_missing_skill() {
    let roots = disposable_roots();
    seed_safe(&roots);
    let args = upgrade_args(&["--tier", "standard", "--yes", "--reason", "capture"]);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&arg_refs, &roots, None);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    let table = DRY_RUN_TABLE.replace(
        "Target:  standard\n",
        "Target:  standard\nReason:  capture\n",
    );
    let expected = format!(
        "{table}\n✓ Profile for \"hermes\" upgraded to \"standard\"\n\
         ⚠ Skill refresh: skill not installed: open <ROOT>/home/.hermes/skills/symvault/SKILL.md: no such file or directory\n"
    );
    assert_eq!(normalize(&stderr_of(&output), &root_of(&roots)), expected);
    let config = std::fs::read_to_string(roots.vault.join("config.yaml")).expect("config");
    let config = normalize(&config, &root_of(&roots));
    assert!(config.contains("tier: standard"), "{config}");
    assert!(config.contains("canWrite: false"), "{config}");
    assert!(config.contains("requireApproval: true"), "{config}");
    // No rotation requested: no token registry appears.
    assert!(!roots.vault.join("mcp-tokens.json").exists());
}

#[test]
fn write_rotate_revokes_install_token_and_writes_new_one() {
    let roots = disposable_roots();
    seed_safe(&roots);
    setup_install(&roots);
    let args = upgrade_args(&[
        "--tier",
        "standard",
        "--yes",
        "--reason",
        "capture",
        "--rotate-token",
    ]);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&arg_refs, &roots, None);
    assert_eq!(output.status.code(), Some(0));
    let expected = format!(
        "{INSTALL_TABLE}\n✓ Profile for \"hermes\" upgraded to \"standard\"\n\
         ✓ Token rotated: <ROOT>/vault/mcp-tokens/hermes.token (id=tok-ID)\n\
         ✓ Skill refreshed at <ROOT>/home/.hermes/skills/symvault/SKILL.md\n"
    );
    assert_eq!(normalize(&stderr_of(&output), &root_of(&roots)), expected);
    let registry = std::fs::read_to_string(roots.vault.join("mcp-tokens.json")).expect("registry");
    let registry: serde_json::Value = serde_json::from_str(&registry).expect("registry json");
    let tokens = registry["tokens"].as_object().expect("tokens map");
    assert_eq!(tokens.len(), 2, "{tokens:?}");
    let by_label = |label: &str| {
        tokens
            .values()
            .find(|token| token["label"] == label)
            .unwrap_or_else(|| panic!("missing token {label}: {tokens:?}"))
            .clone()
    };
    let install_token = by_label("agent-install-hermes");
    assert_eq!(install_token["revoked"], true);
    assert!(install_token["revoked_at"].is_string());
    let upgrade_token = by_label("upgrade-hermes-standard");
    assert_eq!(upgrade_token["revoked"], false);
    assert_eq!(upgrade_token["agent_name"], "hermes");
    let token_file =
        std::fs::read_to_string(roots.vault.join("mcp-tokens/hermes.token")).expect("token");
    assert_eq!(normalize(&token_file, &root_of(&roots)), "HEX\n");
}

#[test]
fn refresh_after_install_rewrites_skill_with_new_tier() {
    let roots = disposable_roots();
    seed_safe(&roots);
    setup_install(&roots);
    let args = upgrade_args(&["--tier", "standard", "--yes", "--reason", "capture"]);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&arg_refs, &roots, None);
    assert_eq!(output.status.code(), Some(0));
    let expected = format!(
        "{INSTALL_TABLE}\n✓ Profile for \"hermes\" upgraded to \"standard\"\n\
         ✓ Skill refreshed at <ROOT>/home/.hermes/skills/symvault/SKILL.md\n"
    );
    assert_eq!(normalize(&stderr_of(&output), &root_of(&roots)), expected);
    // The refreshed skill renders the new tier (template `profile_tier` var).
    let skill = std::fs::read_to_string(roots.home.join(".hermes/skills/symvault/SKILL.md"))
        .expect("skill");
    assert!(skill.contains("(tier: standard)"), "tier not rendered");
    assert!(
        roots
            .home
            .join(".hermes/skills/symvault/SKILL.md.bak")
            .exists(),
        "refresh must back up the install-written skill"
    );
}
