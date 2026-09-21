//! Contract for `symvault agent skill`, `agent skill export` and
//! `agent skill refresh`.
//!
//! Everything asserted here was measured against the pinned Go oracle
//! (`target/port/symvault-go`, revision `3232e31f`); the bodies come from
//! `tests/fixtures/agent-skill/*`, which are the oracle's own output with its
//! build-injected scalars replaced by placeholders.
//!
//! Deliberate, documented differences from the oracle:
//!
//! * `managed_version` and `managed_installed_at` are build-injected/time-based,
//!   so the fixture comparison pins their *shape* (quoted, second precision) and
//!   anchors `managed_version` to the version the same binary reports. The body
//!   below the frontmatter is compared byte for byte.
//! * `managed_hash` is a digest over a body that contains the vault path, so it
//!   is recomputed and checked against the body in the same run.
//! * The tar entry order is sorted here while the oracle iterates a map; the
//!   entry set, modes and payloads are compared instead.
//! * `agent skill` without a subcommand: the oracle prints Cobra's help and exits
//!   0. Cobra's help rendering is a documented non-goal of this port (same class
//!   as `symvault help`), so only the exit status is matched.
//! * Errors are printed once; the oracle prints every returned error twice
//!   (`CLI-005`, an inherited taxonomy gap).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use flate2::read::GzDecoder;
use tar::Archive;
use tempfile::TempDir;

const AGENTS: &[(&str, &str, &str)] = &[
    ("hermes", "SKILL.md", "hermes.SKILL.md"),
    ("claude-code", "SKILL.md", "claude-code.SKILL.md"),
    ("codex", "AGENTS.md", "codex.AGENTS.md"),
    ("opencode", "SKILL.md", "opencode.SKILL.md"),
    ("openclaw", "SKILL.md", "openclaw.SKILL.md"),
];

fn rust_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_symvault"))
}

/// A guard owning a unique temporary directory plus the disposable roots inside
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

fn run(args: &[&str], roots: &Roots, stdin_text: Option<&str>) -> Output {
    let mut command = Command::new(rust_binary());
    command
        .args(args)
        .current_dir(&roots.work)
        .env("HOME", &roots.home)
        .env("SYMVAULT_VAULT", &roots.vault)
        .env_remove("SYMVAULT_PASSPHRASE");
    match stdin_text {
        Some(text) => {
            command.stdin(Stdio::piped());
            let mut child = command.spawn().expect("spawn");
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(text.as_bytes())
                .expect("write stdin");
            child.wait_with_output().expect("output")
        }
        None => command.output().expect("output"),
    }
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn fixture(name: &str) -> String {
    match name {
        "hermes.SKILL.md" => include_str!("fixtures/agent-skill/hermes.SKILL.md").to_owned(),
        "claude-code.SKILL.md" => {
            include_str!("fixtures/agent-skill/claude-code.SKILL.md").to_owned()
        }
        "codex.AGENTS.md" => include_str!("fixtures/agent-skill/codex.AGENTS.md").to_owned(),
        "opencode.SKILL.md" => include_str!("fixtures/agent-skill/opencode.SKILL.md").to_owned(),
        "openclaw.SKILL.md" => include_str!("fixtures/agent-skill/openclaw.SKILL.md").to_owned(),
        "hermes.INSTALL.md" => include_str!("fixtures/agent-skill/hermes.INSTALL.md").to_owned(),
        "codex.INSTALL.md" => include_str!("fixtures/agent-skill/codex.INSTALL.md").to_owned(),
        "claude-code.INSTALL.md" => {
            include_str!("fixtures/agent-skill/claude-code.INSTALL.md").to_owned()
        }
        "opencode.INSTALL.md" => {
            include_str!("fixtures/agent-skill/opencode.INSTALL.md").to_owned()
        }
        "openclaw.INSTALL.md" => {
            include_str!("fixtures/agent-skill/openclaw.INSTALL.md").to_owned()
        }
        other => panic!("unknown fixture {other}"),
    }
}

/// Splits a rendered skill into its frontmatter lines and body. The body starts
/// after the blank line that follows the closing marker (the rule
/// `parse_manifest` uses), so the digest can be recomputed from it.
fn split_skill(data: &str) -> (Vec<&str>, &str) {
    let rest = data.strip_prefix("---\n").expect("opening ---");
    let close = rest.find("\n---\n").expect("closing ---");
    let frontmatter = rest[..close].lines().collect();
    let body = rest[close + "\n---\n".len()..].trim_start_matches(['\r', '\n']);
    (frontmatter, body)
}

/// Splits a frozen fixture the same way, with the anchors already substituted.
fn fixture_body(name: &str, vault: &Path) -> String {
    let data = fixture(name).replace("{{VAULT}}", &vault.to_string_lossy());
    split_skill(&data).1.to_owned()
}

fn members_of(archive_path: &Path) -> Vec<(String, u32, u64, u64, u64, Vec<u8>)> {
    let file = std::fs::File::open(archive_path).expect("open archive");
    let mut archive = Archive::new(GzDecoder::new(file));
    archive
        .entries()
        .expect("entries")
        .map(|entry| {
            let mut entry = entry.expect("entry");
            let header = entry.header().clone();
            let name = entry.path().expect("path").to_string_lossy().into_owned();
            let mut payload = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut payload).expect("payload");
            (
                name,
                header.mode().expect("mode"),
                header.size().expect("size"),
                header.mtime().expect("mtime"),
                header.uid().expect("uid"),
                payload,
            )
        })
        .collect()
}

/// Runs `agent skill export` inside the caller's roots, so the rendered skill
/// carries the vault path that the refreshed file will be compared against.
fn export_in(roots: &Roots, agent: &str, output: Option<&str>) -> (Output, PathBuf) {
    let name = output.unwrap_or("");
    let mut args = vec!["agent", "skill", "export", agent];
    if !name.is_empty() {
        args.push("--output");
        args.push(name);
    }
    let result = run(&args, roots, None);
    let archive = roots.work.join(if name.is_empty() {
        format!("symvault-{agent}-skill.tar.gz")
    } else {
        name.to_owned()
    });
    (result, archive)
}

fn export(agent: &str, output: Option<&str>) -> (Roots, Output, PathBuf) {
    let roots = disposable_roots();
    let (result, archive) = export_in(&roots, agent, output);
    (roots, result, archive)
}

#[test]
fn export_reproduces_the_frozen_oracle_skill_and_its_archive_metadata() {
    for (agent, out_name, fixture_name) in AGENTS {
        let (roots, output, archive) = export(agent, None);
        assert_eq!(output.status.code(), Some(0), "{agent}");
        assert_eq!(
            stdout_of(&output),
            format!("Exported skill for {agent} to symvault-{agent}-skill.tar.gz\n"),
            "{agent}"
        );
        assert_eq!(stderr_of(&output), "", "{agent}");

        let members = members_of(&archive);
        let mut names: Vec<&str> = members.iter().map(|member| member.0.as_str()).collect();
        names.sort_unstable();
        let mut expected = vec!["INSTALL.md", out_name];
        expected.sort_unstable();
        assert_eq!(names, expected, "{agent}");
        for (name, mode, size, mtime, uid, payload) in &members {
            assert_eq!(*mode, 0o644, "{agent}/{name}");
            assert_eq!(*mtime, 0, "{agent}/{name}");
            assert_eq!(*uid, 0, "{agent}/{name}");
            assert_eq!(*size as usize, payload.len(), "{agent}/{name}");
        }

        let skill = members
            .iter()
            .find(|member| member.0 == *out_name)
            .expect("skill member");
        let skill_text = String::from_utf8(skill.5.clone()).expect("utf8");
        let (frontmatter, body) = split_skill(&skill_text);

        // Frontmatter key order and quoting, as the oracle emits it.
        assert_eq!(frontmatter[0], "name: symaira", "{agent}");
        assert!(
            frontmatter[1].starts_with("description: Use Symaira Vault as "),
            "{agent}: {}",
            frontmatter[1]
        );
        assert_eq!(frontmatter[2], "managed_by: symaira", "{agent}");
        assert_eq!(frontmatter[6], "managed_profile_tier: safe", "{agent}");
        let version = frontmatter[3]
            .strip_prefix("managed_version: ")
            .expect("version line");
        assert_eq!(
            frontmatter[4],
            format!(
                "managed_hash: sha256:{}",
                symvault_store::sha256_hex(body.as_bytes())
            ),
            "{agent}: the digest must cover exactly the body"
        );
        let installed_at = frontmatter[5]
            .strip_prefix("managed_installed_at: \"")
            .and_then(|rest| rest.strip_suffix('"'))
            .expect("quoted timestamp");
        assert!(
            installed_at.len() == 20 && installed_at.ends_with('Z'),
            "{agent}: second precision RFC3339, got {installed_at}"
        );

        // Body: byte-exact against the oracle fixture, vault path included.
        assert_eq!(
            body,
            fixture_body(fixture_name, &roots.vault),
            "{agent}: rendered body"
        );

        // INSTALL.md travels with the skill and carries the same version string.
        let install = members
            .iter()
            .find(|member| member.0 == "INSTALL.md")
            .expect("install member");
        let install_text = String::from_utf8(install.5.clone()).expect("utf8");
        let expected_install = fixture(&format!("{agent}.INSTALL.md"))
            .replace("{{VERSION_RAW}}", version)
            .replace("{{BODY_HASH}}", "")
            .replace("{{VAULT}}", "");
        assert_eq!(install_text, expected_install, "{agent}: INSTALL.md");
    }
}

#[test]
fn export_honours_the_output_flag_and_reports_the_cleaned_path() {
    let (roots, output, archive) = export("hermes", Some("./nested.tar.gz"));
    assert_eq!(output.status.code(), Some(0));
    // The oracle prints the *cleaned* path it was given, not an absolute one.
    assert_eq!(
        stdout_of(&output),
        "Exported skill for hermes to nested.tar.gz\n"
    );
    assert!(roots.work.join("nested.tar.gz").exists());
    assert_eq!(archive, roots.work.join("nested.tar.gz"));
}

#[test]
fn export_fails_for_an_unknown_agent_without_leaving_an_archive() {
    let (roots, output, archive) = export("nope", None);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout_of(&output), "");
    assert_eq!(
        stderr_of(&output),
        "Error: export skill: unknown agent: nope\nError: export skill: unknown agent: nope\n"
    );
    assert!(!archive.exists(), "the created file must be removed again");
    assert_eq!(std::fs::read_dir(&roots.work).expect("work").count(), 0);
}

#[test]
fn export_argument_count_matches_cobra() {
    let roots = disposable_roots();
    let none = run(&["agent", "skill", "export"], &roots, None);
    assert_eq!(none.status.code(), Some(1));
    assert_eq!(
        stderr_of(&none),
        "Error: accepts 1 arg(s), received 0\nError: accepts 1 arg(s), received 0\n"
    );

    let two = run(
        &["agent", "skill", "export", "hermes", "codex"],
        &roots,
        None,
    );
    assert_eq!(two.status.code(), Some(1));
    assert_eq!(
        stderr_of(&two),
        "Error: accepts 1 arg(s), received 2\nError: accepts 1 arg(s), received 2\n"
    );
}

#[test]
fn export_prints_even_under_quiet_like_the_oracle() {
    let roots = disposable_roots();
    let output = run(
        &["--quiet", "agent", "skill", "export", "hermes"],
        &roots,
        None,
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout_of(&output).starts_with("Exported skill for hermes to "));
}

#[test]
fn parent_command_exits_zero() {
    let roots = disposable_roots();
    let output = run(&["agent", "skill"], &roots, None);
    assert_eq!(output.status.code(), Some(0));
    // The oracle prints Cobra's help here; the port documents that help surface
    // as a non-goal, so the status is matched and stdout stays empty.
    assert_eq!(stdout_of(&output), "");
}

fn configure_skill_path(roots: &Roots, target: &Path) {
    std::fs::write(
        roots.vault.join("config.yaml"),
        format!(
            "agents:\n  hermes:\n    skillPath: {}\n",
            target.to_string_lossy()
        ),
    )
    .expect("config");
}

/// Places a managed skill file the way an operator would: export, extract.
fn install_managed_skill(roots: &Roots, target: &Path) {
    let (output, archive) = export_in(roots, "hermes", None);
    assert_eq!(output.status.code(), Some(0));
    let members = members_of(&archive);
    let skill = members
        .iter()
        .find(|member| member.0 == "SKILL.md")
        .expect("skill member");
    std::fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
    std::fs::write(target, &skill.5).expect("write target");
}

#[test]
fn refresh_reports_a_missing_skill_path_like_the_oracle() {
    let roots = disposable_roots();
    let output = run(&["agent", "skill", "refresh", "hermes"], &roots, None);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout_of(&output), "");
    assert_eq!(
        stderr_of(&output),
        concat!(
            "Error: no skill path configured for agent \"hermes\"\n",
            "Error: no skill path configured for agent \"hermes\"\n"
        )
    );
}

#[test]
fn refresh_reports_an_absent_target_like_the_oracle() {
    let roots = disposable_roots();
    let target = roots.work.join("missing").join("SKILL.md");
    configure_skill_path(&roots, &target);
    let output = run(&["agent", "skill", "refresh", "hermes"], &roots, None);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr_of(&output),
        format!(
            "Error: refresh skill: skill not installed: open {}: no such file or directory\n\
             Error: refresh skill: skill not installed: open {}: no such file or directory\n",
            target.to_string_lossy(),
            target.to_string_lossy()
        )
    );
}

#[test]
fn refresh_rejects_a_traversal_target_like_the_oracle() {
    let roots = disposable_roots();
    configure_skill_path(&roots, Path::new("../../etc/symvault-skill.md"));
    let output = run(&["agent", "skill", "refresh", "hermes"], &roots, None);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr_of(&output),
        "Error: refresh skill: target path contains traversal: ../../etc/symvault-skill.md\n\
         Error: refresh skill: target path contains traversal: ../../etc/symvault-skill.md\n"
    );
}

#[test]
fn refresh_rejects_an_unmanaged_file_like_the_oracle() {
    let roots = disposable_roots();
    let target = roots.work.join("unmanaged.md");
    std::fs::write(&target, "not managed\n").expect("write");
    configure_skill_path(&roots, &target);
    let output = run(&["agent", "skill", "refresh", "hermes"], &roots, None);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr_of(&output),
        format!(
            "Error: refresh skill: skill file exists without managed sentinel: {}\n\
             Error: refresh skill: skill file exists without managed sentinel: {}\n",
            target.to_string_lossy(),
            target.to_string_lossy()
        )
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("read"),
        "not managed\n",
        "an unmanaged file must stay untouched"
    );
}

#[test]
fn refresh_skips_an_unchanged_file_and_backs_up_a_changed_one() {
    let roots = disposable_roots();
    let target = roots.work.join("target").join("SKILL.md");
    configure_skill_path(&roots, &target);
    install_managed_skill(&roots, &target);
    let installed = std::fs::read(&target).expect("read");

    let unchanged = run(&["agent", "skill", "refresh", "hermes"], &roots, None);
    assert_eq!(unchanged.status.code(), Some(0));
    assert_eq!(
        stdout_of(&unchanged),
        format!(
            "Refreshed skill for hermes at {}\n",
            target.to_string_lossy()
        )
    );
    assert_eq!(std::fs::read(&target).expect("read"), installed);
    assert!(
        !target.with_extension("md.bak").exists(),
        "an unchanged refresh writes no backup"
    );

    let tampered = {
        let mut bytes = installed.clone();
        bytes.extend_from_slice(b"\n<!-- edited -->\n");
        bytes
    };
    std::fs::write(&target, &tampered).expect("write");
    let changed = run(&["agent", "skill", "refresh", "hermes"], &roots, None);
    assert_eq!(changed.status.code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(format!("{}.bak", target.to_string_lossy())).expect("backup"),
        String::from_utf8(tampered).expect("utf8")
    );
    assert_eq!(std::fs::read(&target).expect("read"), installed);
}

#[test]
fn refresh_argument_count_matches_cobra() {
    let roots = disposable_roots();
    let output = run(&["agent", "skill", "refresh"], &roots, None);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr_of(&output),
        "Error: accepts 1 arg(s), received 0\nError: accepts 1 arg(s), received 0\n"
    );
}
