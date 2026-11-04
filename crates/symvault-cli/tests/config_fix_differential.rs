//! Go-vs-Rust differential for `symvault config validate --fix`.
//!
//! `--fix` only repairs when stdin is a terminal, so every scenario runs the
//! binary under a pseudo-terminal driven by a small Python helper (the test
//! crate forbids `unsafe`, so no `openpty` here). The helper answers each
//! `(y/N): ` prompt in order. Scenarios use a deterministic `$EDITOR` script
//! that copies a fixed payload over the config (or fails in a chosen way).
//!
//! Compared per scenario: exit status, stdout, stderr (or the merged terminal
//! stream), the resulting `config.yaml` bytes and the directory listing, i.e.
//! any backup or temporary file. Go keeps no backup; the listing proves it.
//!
//! The Go side of every scenario was recorded once from the pinned oracle
//! (`testdata/port/cli-observations/config_fix_differential.json`) and is
//! replayed; `rust_flow_matches_recorded_go_output` additionally pins the same
//! flows against bytes written out below.
#![cfg(unix)]
#![deny(unsafe_code)]

#[path = "common/go_oracle_ext.rs"]
mod go_oracle_ext;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use go_oracle_ext::Observations;
use serde::{Deserialize, Serialize};
use symvault_core::config::Config;

/// Pinned Go oracle.
const ORACLE_COMMIT: &str = "fca3f89401833b5e14ec4ec74ef736b0f63bca74";

const PROMPT: &str = "(y/N): ";
const OK_CFG: &str = "vaultDir: /tmp/x\n";
const CLIP_BAD: &str = "clipboard:\n  auto_clear_duration: -5\nvaultDir: /tmp/x\n";
const YAML_BAD: &str = "agents: [\n";
const EOF: &str = "\u{4}";

/// stdin on a pty; stdout/stderr on pipes ("split") or all three on one pty
/// ("merged"). Prints one JSON object. Python is run with `-I`.
const PTY_DRIVER: &str = r#"
import json, os, pty, select, subprocess, sys, time, signal

spec = json.load(sys.stdin)
binp, args, env, cwd = spec["bin"], spec["args"], spec["env"], spec["cwd"]
steps, merged = spec["steps"], spec["merged"]
deadline = time.time() + spec.get("timeout", 25)
out = {"merged": b"", "stdout": b"", "stderr": b"", "echo": b""}
if merged:
    pid, master = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execve(binp, [binp] + args, env)
    fds = {master: "merged"}
    proc = None
    watch = "merged"
else:
    master, slave = pty.openpty()
    proc = subprocess.Popen([binp] + args, env=env, cwd=cwd, stdin=slave, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)
    os.close(slave)
    fds = {proc.stdout.fileno(): "stdout", proc.stderr.fileno(): "stderr", master: "echo"}
    watch = "stderr"
    pid = proc.pid
pos = si = 0
while fds and time.time() < deadline:
    ready, _, _ = select.select(list(fds), [], [], 0.05)
    for f in ready:
        try:
            data = os.read(f, 65536)
        except OSError:
            data = b""
        if not data:
            del fds[f]
            continue
        out[fds[f]] += data
    if si < len(steps):
        expect, send = steps[si]
        idx = out[watch].find(expect.encode(), pos)
        if idx >= 0:
            pos = idx + len(expect)
            time.sleep(0.05)
            os.write(master, send.encode())
            si += 1
code = None
end = time.time() + 3
while time.time() < end:
    if proc is not None:
        if proc.poll() is not None:
            code = proc.returncode
            break
    else:
        p, st = os.waitpid(pid, os.WNOHANG)
        if p:
            code = os.waitstatus_to_exitcode(st)
            break
    time.sleep(0.02)
if code is None:
    code = "timeout"
    try:
        os.kill(pid, signal.SIGKILL)
        if proc is not None:
            proc.wait()
        else:
            os.waitpid(pid, 0)
    except Exception:
        pass
print(json.dumps({"exit": str(code), "stdout": out["stdout"].decode("utf-8", "replace"),
                  "stderr": out["stderr"].decode("utf-8", "replace"),
                  "merged": out["merged"].decode("utf-8", "replace"),
                  "steps_done": si}))
"#;

/// Editor scripts: `(body, payload copied over the config)`.
const EDITOR_FIX: (&str, &str) = ("cp \"$ED_PAYLOAD\" \"$1\"\n", OK_CFG);
const EDITOR_FIX_CLIP: (&str, &str) = ("cp \"$ED_PAYLOAD\" \"$1\"\n", CLIP_BAD);
const EDITOR_NOOP: (&str, &str) = ("exit 0\n", "");
const EDITOR_FAIL: (&str, &str) = ("exit 3\n", "");
const EDITOR_FAIL_MODIFY: (&str, &str) = ("cp \"$ED_PAYLOAD\" \"$1\"\nexit 1\n", OK_CFG);
const EDITOR_KILLED: (&str, &str) = ("kill -9 $$\n", "");
const EDITOR_GARBLE: (&str, &str) = ("cp \"$ED_PAYLOAD\" \"$1\"\n", YAML_BAD);
const EDITOR_ECHO: (&str, &str) = (
    "echo \"EDITOR-ARGS: $# $1\" >&2\necho \"EDITOR-OUT\"\ncp \"$ED_PAYLOAD\" \"$1\"\n",
    OK_CFG,
);

#[derive(Clone, Copy)]
enum Editor {
    /// `EDITOR` unset and no `vi` on `PATH` (never reached).
    None,
    Script((&'static str, &'static str)),
    /// `EDITOR` names a file that does not exist.
    Missing,
    /// `EDITOR` unset; a fake `vi` on `PATH` applies [`EDITOR_FIX`].
    DefaultVi,
}

#[derive(Clone, Copy, PartialEq)]
enum Pre {
    None,
    ReadOnlyDir,
    Traversal,
    DirAsConfig,
}

struct Scenario {
    name: &'static str,
    cfg: Option<&'static str>,
    answers: &'static [&'static str],
    editor: Editor,
    args: &'static [&'static str],
    merged: bool,
    pre: Pre,
    home_empty: bool,
}

const fn sc(
    name: &'static str,
    cfg: &'static str,
    answers: &'static [&'static str],
    editor: Editor,
) -> Scenario {
    Scenario {
        name,
        cfg: Some(cfg),
        answers,
        editor,
        args: &[],
        merged: false,
        pre: Pre::None,
        home_empty: false,
    }
}

fn scenarios() -> Vec<Scenario> {
    use Editor::{DefaultVi, Missing, None as NoEditor, Script};
    let mut list = vec![
        // --- load errors (no config yet): straight to the editor offer
        sc("yaml_decline", YAML_BAD, &["n"], NoEditor),
        sc("yaml_accept_fix", YAML_BAD, &["y"], Script(EDITOR_FIX)),
        sc("yaml_accept_noop", YAML_BAD, &["y"], Script(EDITOR_NOOP)),
        sc("yaml_accept_fail", YAML_BAD, &["y"], Script(EDITOR_FAIL)),
        sc(
            "yaml_accept_fail_after_modify",
            YAML_BAD,
            &["y"],
            Script(EDITOR_FAIL_MODIFY),
        ),
        sc(
            "yaml_accept_killed",
            YAML_BAD,
            &["y"],
            Script(EDITOR_KILLED),
        ),
        sc(
            "yaml_accept_garble",
            YAML_BAD,
            &["y"],
            Script(EDITOR_GARBLE),
        ),
        sc("yaml_accept_missing_editor", YAML_BAD, &["y"], Missing),
        sc("yaml_accept_default_vi", YAML_BAD, &["y"], DefaultVi),
        sc(
            "yaml_accept_editor_io",
            YAML_BAD,
            &["y"],
            Script(EDITOR_ECHO),
        ),
        sc("yaml_answer_upper_y", YAML_BAD, &["Y"], Script(EDITOR_FIX)),
        sc(
            "yaml_answer_yes_declines",
            YAML_BAD,
            &["yes"],
            Script(EDITOR_FIX),
        ),
        sc(
            "yaml_answer_padded",
            YAML_BAD,
            &["  y  "],
            Script(EDITOR_FIX),
        ),
        sc("yaml_answer_empty", YAML_BAD, &[""], Script(EDITOR_FIX)),
        sc("yaml_answer_eof", YAML_BAD, &[EOF], Script(EDITOR_FIX)),
        sc(
            "approval_load_error",
            "agents:\n  a:\n    approvalMode: weird\nvaultDir: /tmp/x\n",
            &["y"],
            Script(EDITOR_FIX),
        ),
        // --- load error -> edit -> validation error: second round
        sc(
            "chain_autofix",
            YAML_BAD,
            &["y", "y"],
            Script(EDITOR_FIX_CLIP),
        ),
        sc(
            "chain_decline_all",
            YAML_BAD,
            &["y", "n", "n"],
            Script(EDITOR_FIX_CLIP),
        ),
        sc(
            "chain_decline_then_edit_still_invalid",
            YAML_BAD,
            &["y", "n", "y"],
            Script(EDITOR_FIX_CLIP),
        ),
        // --- validation errors: deterministic repairs
        sc("clipboard_fix", CLIP_BAD, &["y"], NoEditor),
        sc(
            "clipboard_decline_decline",
            CLIP_BAD,
            &["n", "n"],
            Script(EDITOR_FIX),
        ),
        sc(
            "clipboard_decline_edit_fix",
            CLIP_BAD,
            &["n", "y"],
            Script(EDITOR_FIX),
        ),
        sc(
            "clipboard_decline_edit_noop",
            CLIP_BAD,
            &["n", "y"],
            Script(EDITOR_NOOP),
        ),
        sc(
            "clipboard_decline_edit_still_bad",
            CLIP_BAD,
            &["n", "y"],
            Script(EDITOR_FIX_CLIP),
        ),
        sc(
            "clipboard_decline_edit_fail",
            CLIP_BAD,
            &["n", "y"],
            Script(EDITOR_FAIL),
        ),
        sc(
            "clipboard_decline_edit_garble",
            CLIP_BAD,
            &["n", "y"],
            Script(EDITOR_GARBLE),
        ),
        sc(
            "clipboard_eof_twice",
            CLIP_BAD,
            &[EOF, EOF],
            Script(EDITOR_FIX),
        ),
        sc(
            "audit_zero",
            "audit:\n  maxSizeMb: 0\nvaultDir: /tmp/x\n",
            &["y"],
            NoEditor,
        ),
        sc(
            "audit_negative_keeps_other_fields",
            "audit:\n  maxSizeMb: -3\n  maxBackups: 7\nvaultDir: /tmp/x\n",
            &["y"],
            NoEditor,
        ),
        sc(
            "audit_decline_edit",
            "audit:\n  maxSizeMb: 0\nvaultDir: /tmp/x\n",
            &["n", "y"],
            Script(EDITOR_FIX),
        ),
        sc(
            "audit_logging_scan_patterns_survive_save",
            "audit:\n  maxSizeMb: 0\n  maxAgeDays: 9\nlogging:\n  level: debug\nscan_patterns:\n  - name: foo\n    pattern: 'a.*b'\n    description: d\n    severity: high\nvaultDir: /tmp/x\n",
            &["y"],
            NoEditor,
        ),
        sc(
            "clipboard_logging_survives_save",
            "logging:\n  format: json\nclipboard:\n  auto_clear_duration: -1\n  copyByDefault: true\nvaultDir: /tmp/x\n",
            &["y"],
            NoEditor,
        ),
        sc("vaultdir_blank_fix", "vaultDir: '   '\n", &["y"], NoEditor),
        sc(
            "vaultdir_blank_decline",
            "vaultDir: '   '\n",
            &["n", "n"],
            Script(EDITOR_FIX),
        ),
        sc(
            "multi_all_accepted",
            "vaultDir: '  '\naudit:\n  maxSizeMb: 0\nclipboard:\n  auto_clear_duration: -2\n",
            &["y", "y", "y"],
            NoEditor,
        ),
        sc(
            "multi_partial_keeps_blank_vault_dir",
            "vaultDir: '  '\naudit:\n  maxSizeMb: 0\nclipboard:\n  auto_clear_duration: -2\n",
            &["n", "y", "n", "n"],
            Script(EDITOR_FIX),
        ),
        sc(
            "argon_remains_after_autofix_decline",
            "vault:\n  argon2id_time: 1\nclipboard:\n  auto_clear_duration: -2\nvaultDir: /tmp/x\n",
            &["y", "n"],
            Script(EDITOR_FIX),
        ),
        sc(
            "argon_remains_after_autofix_edit",
            "vault:\n  argon2id_time: 1\nclipboard:\n  auto_clear_duration: -2\nvaultDir: /tmp/x\n",
            &["y", "y"],
            Script(EDITOR_FIX),
        ),
        sc(
            "argon_only_edit",
            "vault:\n  argon2id_time: 1\nvaultDir: /tmp/x\n",
            &["y"],
            Script(EDITOR_FIX),
        ),
        sc(
            "argon_only_decline",
            "vault:\n  argon2id_time: 1\nvaultDir: /tmp/x\n",
            &["n"],
            NoEditor,
        ),
        sc(
            "allowed_paths_glob_edit",
            "agents:\n  a:\n    allowedPaths: ['[a']\nvaultDir: /tmp/x\n",
            &["y"],
            Script(EDITOR_FIX),
        ),
        // --- already valid / output modes
        sc("valid_config_needs_no_prompt", OK_CFG, &[], NoEditor),
        sc(
            "vaultdir_blank_empty_home",
            "vaultDir: '   '\n",
            &["y"],
            NoEditor,
        ),
        // --- file level
        Scenario {
            cfg: None,
            ..sc("missing_file_decline", "", &["n"], NoEditor)
        },
        Scenario {
            cfg: None,
            ..sc(
                "missing_file_editor_creates",
                "",
                &["y"],
                Script(EDITOR_FIX),
            )
        },
        Scenario {
            pre: Pre::Traversal,
            ..sc(
                "traversal_path_is_load_error",
                OK_CFG,
                &["y"],
                Script(EDITOR_FIX),
            )
        },
        Scenario {
            cfg: None,
            pre: Pre::DirAsConfig,
            ..sc("directory_as_config", "", &["n"], NoEditor)
        },
        sc("empty_file_is_valid", "", &[], NoEditor),
        sc("two_documents", "a: 1\n---\nb: 2\n", &["n"], NoEditor),
        Scenario {
            pre: Pre::ReadOnlyDir,
            ..sc(
                "save_failure_falls_back_to_editor",
                CLIP_BAD,
                &["y", "n"],
                Script(EDITOR_FIX),
            )
        },
        // --- output flags
        Scenario {
            args: &["--json"],
            ..sc("json_valid", OK_CFG, &[], NoEditor)
        },
        Scenario {
            args: &["--json"],
            ..sc("json_clipboard_fix", CLIP_BAD, &["y"], NoEditor)
        },
        Scenario {
            args: &["--json"],
            ..sc("json_edit_fix", CLIP_BAD, &["n", "y"], Script(EDITOR_FIX))
        },
        Scenario {
            args: &["--json"],
            ..sc(
                "json_still_invalid",
                CLIP_BAD,
                &["n", "y"],
                Script(EDITOR_FIX_CLIP),
            )
        },
        Scenario {
            args: &["--json"],
            ..sc("json_decline", YAML_BAD, &["n"], NoEditor)
        },
        Scenario {
            args: &["--quiet"],
            ..sc("quiet_clipboard_fix", CLIP_BAD, &["y"], NoEditor)
        },
        Scenario {
            args: &["--quiet"],
            ..sc("quiet_yaml_edit", YAML_BAD, &["y"], Script(EDITOR_FIX))
        },
        // --- one terminal for everything
        Scenario {
            merged: true,
            ..sc("terminal_clipboard_fix", CLIP_BAD, &["y"], NoEditor)
        },
        Scenario {
            merged: true,
            ..sc("terminal_yaml_edit", YAML_BAD, &["y"], Script(EDITOR_ECHO))
        },
        Scenario {
            merged: true,
            ..sc("terminal_yaml_decline", YAML_BAD, &["n"], NoEditor)
        },
        Scenario {
            merged: true,
            ..sc(
                "terminal_audit_logging",
                "audit:\n  maxSizeMb: 0\nlogging:\n  level: debug\nvaultDir: /tmp/x\n",
                &["y"],
                NoEditor,
            )
        },
    ];
    for scenario in &mut list {
        scenario.home_empty = scenario.name == "vaultdir_blank_empty_home";
    }
    list
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
struct Outcome {
    exit: String,
    stdout: String,
    stderr: String,
    merged: String,
    cfg: Option<String>,
    listing: Vec<String>,
    steps_done: u64,
}

fn run_pty(binary: &Path, scenario: &Scenario) -> Option<Outcome> {
    let root = tempfile::Builder::new()
        .prefix("symvault-config-fix-")
        .tempdir()
        .expect("scenario root");
    let root_path = fs::canonicalize(root.path()).expect("canonical root");
    let cfg_dir = root_path.join("cfg");
    let home = root_path.join("home");
    let bin_dir = root_path.join("bin");
    for dir in [&cfg_dir, &home, &bin_dir] {
        fs::create_dir_all(dir).expect("scenario dir");
    }
    let cfg = cfg_dir.join("config.yaml");
    if let Some(text) = scenario.cfg {
        fs::write(&cfg, text).expect("seed config");
    }
    if scenario.pre == Pre::DirAsConfig {
        fs::create_dir_all(&cfg).expect("config as directory");
    }
    let payload = root_path.join("payload.yaml");
    let mut env: Vec<(String, String)> = vec![
        (
            "HOME".into(),
            if scenario.home_empty {
                String::new()
            } else {
                home.to_string_lossy().into_owned()
            },
        ),
        (
            "PATH".into(),
            format!("{}:/usr/bin:/bin", bin_dir.to_string_lossy()),
        ),
        ("TERM".into(), "dumb".into()),
        ("NO_COLOR".into(), "1".into()),
        ("LANG".into(), "C".into()),
        ("TMPDIR".into(), root_path.to_string_lossy().into_owned()),
    ];
    let install = |name: &str, body: &str| {
        let path = bin_dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}")).expect("write editor");
        set_mode(&path, 0o755);
        path
    };
    match scenario.editor {
        Editor::None => {}
        Editor::Script((body, content)) => {
            let script = install("myeditor", body);
            fs::write(&payload, content).expect("payload");
            env.push(("EDITOR".into(), script.to_string_lossy().into_owned()));
            env.push(("ED_PAYLOAD".into(), payload.to_string_lossy().into_owned()));
        }
        Editor::Missing => env.push((
            "EDITOR".into(),
            root_path
                .join("nonexistent-editor")
                .to_string_lossy()
                .into_owned(),
        )),
        Editor::DefaultVi => {
            install("vi", EDITOR_FIX.0);
            fs::write(&payload, EDITOR_FIX.1).expect("payload");
            env.push(("ED_PAYLOAD".into(), payload.to_string_lossy().into_owned()));
        }
    }
    let target = if scenario.pre == Pre::Traversal {
        cfg_dir.join("..").join("cfg").join("config.yaml")
    } else {
        cfg.clone()
    };
    if scenario.pre == Pre::ReadOnlyDir {
        set_mode(&cfg_dir, 0o555);
        // Running as root (or on a filesystem that ignores modes) cannot
        // provoke the failure this scenario is about.
        if fs::File::create(cfg_dir.join(".probe")).is_ok() {
            let _ = fs::remove_file(cfg_dir.join(".probe"));
            set_mode(&cfg_dir, 0o755);
            return None;
        }
    }

    let mut args: Vec<String> = vec![
        "config".into(),
        "validate".into(),
        target.to_string_lossy().into_owned(),
        "--fix".into(),
    ];
    args.extend(scenario.args.iter().map(|arg| (*arg).to_owned()));
    let steps: Vec<(String, String)> = scenario
        .answers
        .iter()
        .map(|answer| {
            (
                PROMPT.to_owned(),
                if *answer == EOF {
                    EOF.to_owned()
                } else {
                    format!("{answer}\n")
                },
            )
        })
        .collect();
    let spec = serde_json::json!({
        "bin": binary,
        "args": args,
        "env": env.iter().cloned().collect::<std::collections::BTreeMap<_, _>>(),
        "cwd": root_path,
        "steps": steps,
        "merged": scenario.merged,
    });
    let mut child = Command::new("python3")
        .args(["-I", "-c", PTY_DRIVER])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3 is required for the PTY differential");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("driver stdin")
            .write_all(spec.to_string().as_bytes())
            .expect("send spec");
    }
    let output = child.wait_with_output().expect("driver output");
    assert!(
        output.status.success(),
        "{}: PTY driver failed: {}",
        scenario.name,
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("driver JSON");
    if scenario.pre == Pre::ReadOnlyDir {
        set_mode(&cfg_dir, 0o755);
    }

    let root_text = root_path.to_string_lossy().into_owned();
    let normalise = |value: &serde_json::Value| -> String {
        let text = value
            .as_str()
            .unwrap_or_default()
            .replace(&root_text, "<ROOT>");
        // Go's temporary name carries a random decimal suffix.
        let mut out = String::new();
        let mut rest = text.as_str();
        while let Some(at) = rest.find(".tmp-") {
            out.push_str(&rest[..at + 5]);
            rest = &rest[at + 5..];
            let digits = rest.chars().take_while(char::is_ascii_digit).count();
            if digits > 0 {
                out.push_str("<RAND>");
            }
            rest = &rest[digits..];
        }
        out.push_str(rest);
        out
    };
    let mut listing: Vec<String> = fs::read_dir(&cfg_dir)
        .expect("list config dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    listing.sort();
    Some(Outcome {
        exit: result["exit"].as_str().unwrap_or_default().to_owned(),
        stdout: normalise(&result["stdout"]),
        stderr: normalise(&result["stderr"]),
        merged: normalise(&result["merged"]),
        cfg: fs::read(&cfg)
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).replace(&root_text, "<ROOT>")),
        listing,
        steps_done: result["steps_done"].as_u64().unwrap_or(u64::MAX),
    })
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
}

fn rust_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_symvault"))
}

fn python_available() -> bool {
    Command::new("python3")
        .args(["-I", "-c", "import pty"])
        .output()
        .is_ok_and(|output| output.status.success())
}

#[test]
fn pty_flow_matches_go_contract() {
    let observations =
        Observations::begin("config_fix_differential", "pty_flow_matches_go_contract", Some(ORACLE_COMMIT));
    assert!(
        python_available(),
        "python3 with the pty module is required"
    );
    let rust = rust_binary();
    let mut compared = 0;
    for scenario in scenarios() {
        let recorded = observations.observe(scenario.name, |go| {
            serde_json::to_value(run_pty(go, &scenario)).expect("Go outcome json")
        });
        let go_out: Option<Outcome> = serde_json::from_value(recorded).expect("recorded outcome");
        let (Some(go_out), Some(rust_out)) = (go_out, run_pty(&rust, &scenario)) else {
            panic!("{}: the scenario needs an unprivileged user", scenario.name);
        };
        // Both must have consumed every scripted answer, or the comparison
        // proves nothing about the prompts that were never reached.
        assert_eq!(
            go_out.steps_done as usize,
            scenario.answers.len(),
            "{}: Go did not reach every prompt: {go_out:#?}",
            scenario.name
        );
        assert_eq!(rust_out, go_out, "{}: Go vs Rust", scenario.name);
        compared += 1;
    }
    assert!(compared >= 55, "only {compared} scenarios ran");
    assert_eq!(observations.count(), compared);
}

/// Non-terminal `--fix` is plain validation, byte for byte.
#[test]
fn non_tty_fix_matches_go_contract() {
    let observations = Observations::begin(
        "config_fix_differential",
        "non_tty_fix_matches_go_contract",
        Some(ORACLE_COMMIT),
    );
    let rust = rust_binary();
    let cases: &[(&str, &[&str])] = &[
        ("valid", &[OK_CFG]),
        ("yaml", &[YAML_BAD]),
        ("clipboard", &[CLIP_BAD]),
        ("audit", &["audit:\n  maxSizeMb: 0\nvaultDir: /tmp/x\n"]),
        (
            "audit_and_clipboard",
            &["audit:\n  maxSizeMb: -1\nclipboard:\n  auto_clear_duration: -1\nvaultDir: /tmp/x\n"],
        ),
        ("blank_vault_dir", &["vaultDir: ' '\n"]),
        ("argon", &["vault:\n  argon2id_time: 1\nvaultDir: /tmp/x\n"]),
        ("empty", &[""]),
    ];
    for (name, config) in cases {
        for extra in [&[][..], &["--json"][..], &["--quiet"][..]] {
            let run_one = |binary: &Path| -> (Option<i32>, String, String, String) {
                let root = tempfile::Builder::new()
                    .prefix("symvault-config-fix-nontty-")
                    .tempdir()
                    .expect("root");
                let root_path = fs::canonicalize(root.path()).expect("canonical");
                let path = root_path.join("config.yaml");
                fs::write(&path, config[0]).expect("seed");
                let output = Command::new(binary)
                    .args(["config", "validate"])
                    .arg(&path)
                    .arg("--fix")
                    .args(extra)
                    .env("HOME", &root_path)
                    .env("NO_COLOR", "1")
                    .env("EDITOR", "/nonexistent/should-never-run")
                    .stdin(Stdio::null())
                    .output()
                    .expect("run");
                let root_text = root_path.to_string_lossy().into_owned();
                (
                    output.status.code(),
                    String::from_utf8_lossy(&output.stdout).replace(&root_text, "<ROOT>"),
                    String::from_utf8_lossy(&output.stderr).replace(&root_text, "<ROOT>"),
                    fs::read_to_string(&path).expect("config"),
                )
            };
            let recorded = observations.observe(&format!("{name} {extra:?}"), |go| {
                serde_json::to_value(run_one(go)).expect("Go result json")
            });
            let results = [
                serde_json::from_value(recorded).expect("recorded Go result"),
                run_one(&rust),
            ];
            assert_eq!(results[0], results[1], "non-tty {name} {extra:?}");
            assert_eq!(
                results[1].3, config[0],
                "non-tty --fix must never rewrite the file"
            );
        }
    }
    assert_eq!(observations.count(), cases.len() * 3);
}

/// Bytes recorded from the Go oracle (`symvault-go config validate --fix` on a
/// pty) for the default-agent block `SaveTo` rewrites.
const GO_SAVED_AGENTS: &str = "agents:\n    claude-code:\n        approvalMode: deny\n        canWrite: true\n        canRunCommands: true\n        exposeValueTools: true\n        autoUnseal: false\n        skillPath: ~/.claude/skills/symvault/SKILL.md\n    codex:\n        approvalMode: deny\n        canWrite: false\n        canRunCommands: true\n        exposeValueTools: true\n        autoUnseal: false\n        skillPath: ~/.codex/skills/symvault/AGENTS.md\n    default:\n        approvalMode: deny\n        canWrite: false\n        canRunCommands: false\n        exposeValueTools: true\n        autoUnseal: false\n    hermes:\n        approvalMode: deny\n        canWrite: true\n        canRunCommands: true\n        exposeValueTools: true\n        autoUnseal: false\n        skillPath: ~/.hermes/skills/symvault/SKILL.md\n    openclaw:\n        approvalMode: deny\n        canWrite: true\n        canRunCommands: true\n        exposeValueTools: true\n        autoUnseal: false\n        skillPath: ~/.openclaw/skills/symvault/SKILL.md\n    opencode:\n        approvalMode: deny\n        canWrite: false\n        canRunCommands: true\n        exposeValueTools: true\n        autoUnseal: false\n        skillPath: ~/.opencode/skills/symvault/SKILL.md\n";
const GO_SAVED_TAIL: &str = "vaultDir: /tmp/x\ndefaultAgent: default\nsessionTimeout: 15m0s\nsessionMaxLifetime: 8h0m0s\nauthMethod: passphrase\nuseTouchID: false\n";
const BANNER: &str = "Configuration error detected in <ROOT>/cfg/config.yaml\n";
const CLIP_LINE: &str = "  ✗ Validation error: clipboard.autoClearDuration: must be non-negative (configure clipboard.autoClearDuration in config.yaml)\n";
const CLIP_PROMPT: &str = "Field 'clipboard.autoClearDuration' must be non-negative. Suggestion: 30s. Apply this fix? (y/N): ";
const EDITOR_PROMPT: &str = "Open config.yaml in $EDITOR to fix manually? (y/N): ";
const DOCTOR: &str = "Run 'symvault doctor' to diagnose and fix configuration issues.\n";

fn error_twice(message: &str) -> String {
    format!("Error: {message}\nError: {message}\n{DOCTOR}")
}

fn pinned(name: &str) -> Outcome {
    let scenario = scenarios()
        .into_iter()
        .find(|scenario| scenario.name == name)
        .unwrap_or_else(|| panic!("unknown scenario {name}"));
    run_pty(&rust_binary(), &scenario).expect("scenario runs")
}

/// The Rust flow against bytes recorded from the Go oracle, without needing it.
#[test]
fn rust_flow_matches_recorded_go_output() {
    assert!(
        python_available(),
        "python3 with the pty module is required"
    );
    let load_error = "  ✗ Load error: yaml: line 1: did not find expected node content\n";

    let declined = pinned("yaml_decline");
    assert_eq!(declined.exit, "6");
    assert_eq!(declined.stdout, "");
    assert_eq!(
        declined.stderr,
        format!(
            "{BANNER}{load_error}{EDITOR_PROMPT}{}",
            error_twice("config fix failed: configuration fix aborted by user")
        )
    );
    assert_eq!(declined.cfg.as_deref(), Some(YAML_BAD));
    assert_eq!(declined.listing, ["config.yaml"], "Go keeps no backup");

    let edited = pinned("yaml_accept_fix");
    assert_eq!(edited.exit, "0");
    assert_eq!(
        edited.stdout,
        "Configuration is valid (<ROOT>/cfg/config.yaml)\n"
    );
    assert_eq!(
        edited.stderr,
        format!("{BANNER}{load_error}{EDITOR_PROMPT}")
    );
    assert_eq!(edited.cfg.as_deref(), Some(OK_CFG));

    let still_bad = pinned("yaml_accept_noop");
    assert_eq!(still_bad.exit, "6");
    assert_eq!(
        still_bad.stderr,
        format!(
            "{BANNER}{load_error}{EDITOR_PROMPT}{}",
            error_twice(
                "config still invalid after manual edit: yaml: line 1: did not find expected node content"
            )
        )
    );

    let failed = pinned("yaml_accept_fail");
    assert_eq!(failed.exit, "6");
    assert!(
        failed
            .stderr
            .contains("Error: config fix failed: editor failed: exit status 3\n"),
        "{}",
        failed.stderr
    );
    let killed = pinned("yaml_accept_killed");
    assert!(
        killed
            .stderr
            .contains("config fix failed: editor failed: signal: killed\n"),
        "{}",
        killed.stderr
    );
    let missing = pinned("yaml_accept_missing_editor");
    assert!(
        missing.stderr.contains(
            "config fix failed: editor \"<ROOT>/nonexistent-editor\" not found in PATH\n"
        ),
        "{}",
        missing.stderr
    );

    let fixed = pinned("clipboard_fix");
    assert_eq!(fixed.exit, "0");
    assert_eq!(
        fixed.stdout,
        "Configuration repaired successfully.\nConfiguration is valid (<ROOT>/cfg/config.yaml)\n"
    );
    assert_eq!(
        fixed.stderr,
        format!("{BANNER}{CLIP_LINE}{CLIP_PROMPT}Auto-fixes applied successfully.\n")
    );
    assert_eq!(
        fixed.cfg.as_deref(),
        Some(
            format!(
                "{GO_SAVED_AGENTS}clipboard:\n    auto_clear_duration: 30\n    copyByDefault: true\n{GO_SAVED_TAIL}"
            )
            .as_str()
        )
    );
    assert_eq!(
        fixed.listing,
        ["config.yaml"],
        "no temp or backup file may remain"
    );

    let audit = pinned("audit_zero");
    assert_eq!(
        audit.cfg.as_deref(),
        Some(
            format!(
                "{GO_SAVED_AGENTS}audit:\n    maxSizeMb: 100\n    maxBackups: 5\n    maxAgeDays: 30\n{GO_SAVED_TAIL}"
            )
            .as_str()
        )
    );

    let declined_twice = pinned("clipboard_decline_decline");
    assert_eq!(declined_twice.exit, "6");
    assert_eq!(
        declined_twice.stderr,
        format!(
            "{BANNER}{CLIP_LINE}{CLIP_PROMPT}{EDITOR_PROMPT}{}",
            error_twice("config fix failed: configuration fix aborted by user")
        )
    );
    assert_eq!(declined_twice.cfg.as_deref(), Some(CLIP_BAD));

    let invalid_after_edit = pinned("clipboard_decline_edit_noop");
    assert_eq!(
        invalid_after_edit.stderr,
        format!(
            "{BANNER}{CLIP_LINE}{CLIP_PROMPT}{EDITOR_PROMPT}{}",
            error_twice(
                "config still invalid after manual edit: clipboard.autoClearDuration: must be non-negative (configure clipboard.autoClearDuration in config.yaml)"
            )
        )
    );

    let json = pinned("json_clipboard_fix");
    assert_eq!(
        json.stdout,
        "Configuration repaired successfully.\n{\"path\":\"<ROOT>/cfg/config.yaml\",\"valid\":true}\n"
    );
    let quiet = pinned("quiet_clipboard_fix");
    assert_eq!(quiet.stdout, "");
    assert!(
        quiet.stderr.ends_with("Auto-fixes applied successfully.\n"),
        "hints are not quiet-gated in Go: {}",
        quiet.stderr
    );

    let terminal = pinned("terminal_clipboard_fix");
    assert_eq!(
        terminal.merged,
        format!(
            "{}{}{}y\r\nAuto-fixes applied successfully.\r\nConfiguration repaired successfully.\r\nConfiguration is valid (<ROOT>/cfg/config.yaml)\r\n",
            BANNER.replace('\n', "\r\n"),
            CLIP_LINE.replace('\n', "\r\n"),
            CLIP_PROMPT
        )
    );
}

/// The clipboard section Go prints for `copyByDefault: false` after the
/// clipboard auto-fix, and the line the native writer adds to it.
const COPY_OFF_BAD: &str =
    "clipboard:\n  auto_clear_duration: -5\n  copyByDefault: false\nvaultDir: /tmp/x\n";
const GO_COPY_OFF_CLIPBOARD: &str = "clipboard:\n    auto_clear_duration: 30\n";
const RUST_COPY_OFF_LINE: &str = "    copyByDefault: false\n";

fn copy_off_scenario() -> Scenario {
    sc(
        "intentional_deviation_copy_by_default_false",
        COPY_OFF_BAD,
        &["y"],
        Editor::None,
    )
}

/// INTENTIONAL DEVIATION (not a gap): `config validate --fix` keeps an
/// explicit `clipboard.copyByDefault: false`.
///
/// Go's `ClipboardConfig.CopyByDefault` is a plain `bool` tagged `omitempty`,
/// so `SaveTo` leaves the key out when it is false, and the next load reads the
/// absent key as the default `true`: an operator who opted out of copying
/// secrets to the clipboard is silently opted back in by an unrelated repair.
/// The native writer prints `copyByDefault: false`, so the opt-out survives.
/// Everything else the repair writes is byte-identical to Go; the scenario is
/// deliberately not part of `scenarios()`, which asserts equality. The deviation
/// is recorded in `docs/rust-port/cli-gap-inventory.md`.
#[test]
fn intentional_deviation_copy_by_default_false_survives_fix() {
    assert!(
        python_available(),
        "python3 with the pty module is required"
    );
    let observations = Observations::begin(
        "config_fix_differential",
        "intentional_deviation_copy_by_default_false_survives_fix",
        Some(ORACLE_COMMIT),
    );
    let scenario = copy_off_scenario();
    let native = run_pty(&rust_binary(), &scenario).expect("scenario runs");
    assert_eq!(native.exit, "0", "{native:#?}");
    assert_eq!(native.steps_done, 1, "the clipboard prompt was answered");

    // Bytes recorded from the Go oracle for the same scenario: the opt-out is
    // dropped.
    let go_saved = format!("{GO_SAVED_AGENTS}{GO_COPY_OFF_CLIPBOARD}{GO_SAVED_TAIL}");
    let native_saved = native.cfg.clone().expect("repaired config");
    let kept =
        format!("{GO_SAVED_AGENTS}{GO_COPY_OFF_CLIPBOARD}{RUST_COPY_OFF_LINE}{GO_SAVED_TAIL}");
    assert_eq!(native_saved, kept, "the opt-out must be written back");
    assert_eq!(
        native_saved.replace(RUST_COPY_OFF_LINE, ""),
        go_saved,
        "apart from that one line the repair is byte-identical to Go"
    );
    assert_eq!(
        Config::load_from_bytes(native_saved.as_bytes())
            .expect("repaired config loads")
            .clipboard
            .map(|clipboard| clipboard.copy_by_default),
        Some(false),
        "reloading the native file keeps the opt-out"
    );
    assert_eq!(
        Config::load_from_bytes(go_saved.as_bytes())
            .expect("Go's repaired config loads")
            .clipboard
            .map(|clipboard| clipboard.copy_by_default),
        Some(true),
        "reloading Go's file flips the opt-out to opt-in"
    );

    let recorded = observations.observe("copy-off scenario", |go| {
        serde_json::to_value(run_pty(go, &scenario)).expect("Go outcome json")
    });
    let oracle: Outcome = serde_json::from_value::<Option<Outcome>>(recorded)
        .expect("recorded outcome")
        .expect("the recorded Go scenario ran");
    assert_eq!(
        oracle.cfg.as_deref(),
        Some(go_saved.as_str()),
        "{oracle:#?}"
    );
    let mut expected = native;
    expected.cfg = expected.cfg.map(|cfg| cfg.replace(RUST_COPY_OFF_LINE, ""));
    assert_eq!(expected, oracle, "everything but the one line matches Go");
}

/// Negative control: a native repair that dropped the opt-out like Go does, or
/// that changed anything else, must not satisfy the deviation test above.
#[test]
fn copy_by_default_deviation_is_exactly_one_line() {
    let go_saved = format!("{GO_SAVED_AGENTS}{GO_COPY_OFF_CLIPBOARD}{GO_SAVED_TAIL}");
    let kept =
        format!("{GO_SAVED_AGENTS}{GO_COPY_OFF_CLIPBOARD}{RUST_COPY_OFF_LINE}{GO_SAVED_TAIL}");
    assert_ne!(kept, go_saved);
    assert_eq!(kept.replace(RUST_COPY_OFF_LINE, ""), go_saved);
    let changed = kept.replace("auto_clear_duration: 30", "auto_clear_duration: 31");
    assert_ne!(changed.replace(RUST_COPY_OFF_LINE, ""), go_saved);
}
