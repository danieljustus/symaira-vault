#![cfg(target_os = "linux")]

//! PLATFORM-WIRE-001: the real `symvault` binary on Linux, clipboard through
//! fake POSIX-shell tools on a disposable PATH, compared with the Go-recorded
//! fixtures:
//!
//! * `symvault mcp --stdio` `copy_to_clipboard` and `generate_totp` (clipboard
//!   destination) against `testdata/port/mcp/copy-clipboard-linux.json`
//!   (tools/call responses, tool argv and stdin bytes, timer-driven clear;
//!   Go's TOTP code is a placeholder that must equal a code of the call's time
//!   window);
//! * `symvault get <path.field>` on a pseudo-terminal against
//!   `testdata/port/platform/get_clipboard_linux.json` (stderr, exit code, tool
//!   argv and stdin bytes).
//!
//! Both fixtures come from the real Go commands on GOOS=linux with the
//! production `clipboard.DefaultClipboard()`. Nothing touches a real clipboard,
//! display, or `~/.symvault`: every process gets a disposable HOME and a PATH
//! that holds only the fake tools.
//!
//! One documented difference is normalized: Go's stubbed timer fires between
//! two ticks while the real Rust clock reaches the deadline, so Rust prints one
//! extra `\r[clearing clipboard in 0s] ` (PLATFORM-001 slice 2 residual 2).

#[path = "support/temp_root.rs"]
mod test_temp_root;

use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

const PASSPHRASE: &str = "correct horse battery staple";
const MCP_PASSWORD: &str = "StrongP@ssw0rd123";
/// The real binary refuses TOTP secrets under 26 base32 characters (the
/// fixture's 16-character secret is written to Go's store directly), so the
/// entry gets a longer one; the fixture only records the code as a placeholder
/// that must match a code of the run's time window for the secret in use.
const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
/// Tool invocations the Go-recorded MCP cases hold (clears included).
const CALLS_TOTAL: usize = 31;
/// Tool invocations the Go-recorded `get` scenarios hold.
const GET_CALLS_TOTAL: usize = 41;

#[derive(Debug, Deserialize)]
struct Call {
    tool: String,
    mode: String,
    argv: Vec<String>,
    stdin: String,
}

impl PartialEq for Call {
    fn eq(&self, other: &Self) -> bool {
        (&self.tool, &self.mode, &self.argv, &self.stdin)
            == (&other.tool, &other.mode, &other.argv, &other.stdin)
    }
}

#[derive(Debug, Deserialize)]
struct McpFixture {
    fake_tools: BTreeMap<String, String>,
    totp: Totp,
    cases: Vec<McpCase>,
}

#[derive(Debug, Deserialize)]
struct Totp {
    code_placeholder: String,
}

#[derive(Debug, Deserialize)]
struct McpCase {
    name: String,
    tool: String,
    approval_mode: String,
    #[serde(default)]
    password_repeat: usize,
    #[serde(default)]
    tool_overrides: BTreeMap<String, String>,
    path_tools: Option<Vec<String>>,
    wayland_display: String,
    tool_exit: i32,
    auto_clear_duration: u64,
    want_calls: usize,
    input: Vec<String>,
    output: Vec<Value>,
    tool_calls: Vec<Call>,
}

#[derive(Debug, Deserialize)]
struct GetFixture {
    fake_tools: BTreeMap<String, String>,
    scenarios: Vec<GetScenario>,
}

#[derive(Debug, Deserialize)]
struct GetScenario {
    name: String,
    path_tools: Option<Vec<String>>,
    wayland_display: String,
    tool_exit: i32,
    secret: String,
    #[serde(default)]
    secret_repeat: usize,
    #[serde(default)]
    tool_overrides: BTreeMap<String, String>,
    auto_clear_seconds: u64,
    paste_output: String,
    stdout: String,
    stderr: String,
    exit_code: i32,
    tool_calls: Vec<Call>,
}

struct Sandbox {
    _root: test_temp_root::TempRoot,
    vault: PathBuf,
    home: PathBuf,
    work: PathBuf,
}

/// Fake-tool directory, record directory and environment for one run.
struct Tools {
    bin: PathBuf,
    rec: PathBuf,
    env: Vec<(String, String)>,
}

fn setup_env(command: &mut Command, sandbox: &Sandbox) {
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &sandbox.home)
        .env("USERPROFILE", &sandbox.home)
        .env("XDG_CONFIG_HOME", sandbox.home.join("config"))
        .env("XDG_DATA_HOME", sandbox.home.join("data"))
        .env("XDG_CACHE_HOME", sandbox.home.join("cache"))
        .env("SYMVAULT_VAULT", &sandbox.vault)
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("SYMVAULT_SECUREUI", "none")
        .env("CI", "1")
        .env("NO_COLOR", "1");
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_symvault")
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed: {:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A vault with the synthetic `entry_path` (when given) and, for the MCP run,
/// an agent profile that may use the clipboard.
fn sandbox(label: &str, entry_path: Option<(&str, &str)>, agent: bool) -> Sandbox {
    let root = test_temp_root::TempRoot::missing(&format!("symvault-clip-linux-{label}-"));
    let base: PathBuf = AsRef::<Path>::as_ref(&root).to_path_buf();
    let sandbox = Sandbox {
        vault: base.join("vault"),
        home: base.join("home"),
        work: base.join("work"),
        _root: root,
    };
    for dir in [
        sandbox.home.join("config"),
        sandbox.home.join("data"),
        sandbox.home.join("cache"),
        sandbox.work.clone(),
    ] {
        fs::create_dir_all(dir).unwrap();
    }
    let vault = sandbox.vault.to_str().unwrap();
    let run = |args: &[&str]| {
        let mut command = Command::new(binary());
        setup_env(&mut command, &sandbox);
        command
            .current_dir(&sandbox.work)
            .args(args)
            .output()
            .unwrap()
    };
    assert_success(
        &run(&["--vault", vault, "init", "--auth", "passphrase"]),
        "init",
    );
    if let Some((entry_path, password)) = entry_path {
        assert_success(
            &run(&["--vault", vault, "set", entry_path, "--value", password]),
            "set",
        );
    }
    if agent {
        let config_path = sandbox.vault.join("config.yaml");
        let mut config: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        let replacement: serde_yaml_ng::Value = serde_yaml_ng::from_str(
            "agents:\n  clip:\n    tier: admin\n    allowedPaths: ['*']\n    canWrite: false\n    canRunCommands: false\n    canUseAutotype: false\n    canUseClipboard: true\n    exposeValueTools: false\n    approvalMode: none\ndefaultAgent: clip\n",
        )
        .unwrap();
        let target = config.as_mapping_mut().unwrap();
        for (key, value) in replacement.as_mapping().unwrap() {
            target.insert(key.clone(), value.clone());
        }
        fs::write(&config_path, serde_yaml_ng::to_string(&config).unwrap()).unwrap();
    }
    sandbox
}

/// The fixture's fake tools with a scenario's per-scenario script replacements.
fn with_overrides(
    tools: &BTreeMap<String, String>,
    overrides: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged = tools.clone();
    merged.extend(overrides.iter().map(|(k, v)| (k.clone(), v.clone())));
    merged
}

/// Runs the real binary against the sandbox vault, optionally feeding stdin.
fn run_cli(sandbox: &Sandbox, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut command = Command::new(binary());
    setup_env(&mut command, sandbox);
    let mut child = command
        .current_dir(&sandbox.work)
        .arg("--vault")
        .arg(&sandbox.vault)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn symvault");
    if let Some(bytes) = stdin {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    }
    child.wait_with_output().expect("symvault output")
}

/// The Go fixture's large payload: `"0123456789abcdef"` repeated.
fn large_password(repeat: usize) -> String {
    "0123456789abcdef".repeat(repeat)
}

fn add_large_entry(sandbox: &Sandbox, path: &str, password: &str) {
    let mut line = password.to_owned();
    line.push('\n');
    assert_success(
        &run_cli(
            sandbox,
            &[
                "add",
                path,
                "--stdin-value",
                "--type",
                "password",
                "--force",
            ],
            Some(line.as_bytes()),
        ),
        "add large entry",
    );
}

fn set_approval_mode(sandbox: &Sandbox, mode: &str) {
    let config_path = sandbox.vault.join("config.yaml");
    let mut config: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    config["agents"]["clip"]["approvalMode"] = mode.into();
    fs::write(&config_path, serde_yaml_ng::to_string(&config).unwrap()).unwrap();
}

fn set_auto_clear(sandbox: &Sandbox, seconds: u64) {
    let config_path = sandbox.vault.join("config.yaml");
    let mut config: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    let clipboard: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&format!("auto_clear_duration: {seconds}\n")).unwrap();
    config
        .as_mapping_mut()
        .unwrap()
        .insert("clipboard".into(), clipboard);
    fs::write(&config_path, serde_yaml_ng::to_string(&config).unwrap()).unwrap();
}

fn install_tools(
    sandbox: &Sandbox,
    label: &str,
    templates: &BTreeMap<String, String>,
    names: &[String],
    exit: i32,
    wayland: &str,
    paste: &str,
) -> Tools {
    let bin = sandbox.work.join(format!("{label}-bin"));
    let rec = sandbox.work.join(format!("{label}-rec"));
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&rec).unwrap();
    fs::write(rec.join("paste"), paste).unwrap();
    for name in names {
        let path = bin.join(name);
        let body = templates[name]
            .replace("@REC@", rec.to_str().unwrap())
            .replace("@EXIT@", &exit.to_string())
            .replace("@FOCUS1@", "")
            .replace("@FOCUS2@", "")
            .replace("@FOCUSEXIT@", "0");
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut env = vec![
        ("PATH".to_owned(), bin.to_str().unwrap().to_owned()),
        ("HOME".to_owned(), sandbox.home.to_str().unwrap().to_owned()),
        (
            "USERPROFILE".to_owned(),
            sandbox.home.to_str().unwrap().to_owned(),
        ),
        (
            "XDG_CONFIG_HOME".to_owned(),
            sandbox.home.join("config").to_str().unwrap().to_owned(),
        ),
        (
            "XDG_DATA_HOME".to_owned(),
            sandbox.home.join("data").to_str().unwrap().to_owned(),
        ),
        (
            "XDG_CACHE_HOME".to_owned(),
            sandbox.home.join("cache").to_str().unwrap().to_owned(),
        ),
        (
            "SYMVAULT_VAULT".to_owned(),
            sandbox.vault.to_str().unwrap().to_owned(),
        ),
        ("SYMVAULT_PASSPHRASE".to_owned(), PASSPHRASE.to_owned()),
        ("SYMVAULT_ALLOW_ENV_PASSPHRASE".to_owned(), "1".to_owned()),
        ("SYMVAULT_TEST_KEYRING".to_owned(), "memory".to_owned()),
        ("SYMVAULT_SECUREUI".to_owned(), "none".to_owned()),
        ("CI".to_owned(), "1".to_owned()),
        ("NO_COLOR".to_owned(), "1".to_owned()),
    ];
    if !wayland.is_empty() {
        env.push(("WAYLAND_DISPLAY".to_owned(), wayland.to_owned()));
    }
    Tools { bin, rec, env }
}

fn call_count(rec: &Path) -> usize {
    fs::read_to_string(rec.join("seq"))
        .ok()
        .and_then(|raw| raw.trim().parse().ok())
        .unwrap_or(0)
}

fn read_calls(rec: &Path) -> Vec<Call> {
    (1..=call_count(rec))
        .map(|n| {
            let raw = fs::read_to_string(rec.join(format!("call.{n}"))).unwrap();
            let lines: Vec<&str> = raw.lines().collect();
            let argc: usize = lines[2].parse().unwrap();
            assert_eq!(lines.len(), 3 + argc);
            Call {
                tool: lines[0].to_owned(),
                mode: lines[1].to_owned(),
                argv: lines[3..].iter().map(|s| (*s).to_owned()).collect(),
                stdin: fs::read(rec.join(format!("call.{n}.stdin")))
                    .map(|bytes| String::from_utf8(bytes).unwrap())
                    .unwrap_or_default(),
            }
        })
        .collect()
}

#[test]
fn mcp_copy_to_clipboard_matches_go_on_linux_through_the_real_binary() {
    let fixture: McpFixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/copy-clipboard-linux.json"
    ))
    .expect("decode the Go copy_to_clipboard Linux fixture");
    assert_eq!(fixture.cases.len(), 25);
    let sandbox = sandbox("mcp", None, true);
    assert_success(
        &run_cli(
            &sandbox,
            &[
                "add",
                "github",
                "--value",
                MCP_PASSWORD,
                "--type",
                "password",
                "--totp-secret",
                TOTP_SECRET,
                "--force",
            ],
            None,
        ),
        "add github",
    );
    let big_repeat = fixture
        .cases
        .iter()
        .map(|case| case.password_repeat)
        .max()
        .unwrap();
    assert!(big_repeat > 0);
    add_large_entry(&sandbox, "big", &large_password(big_repeat));
    let mut calls_total = 0;
    for case in &fixture.cases {
        assert_eq!(case.password_repeat == 0, !case.name.starts_with("large_"));
        assert!(case.password_repeat == 0 || case.password_repeat == big_repeat);
        set_auto_clear(&sandbox, case.auto_clear_duration);
        set_approval_mode(&sandbox, &case.approval_mode);
        let label = case.name.replace('_', "");
        let tools = install_tools(
            &sandbox,
            &label,
            &with_overrides(&fixture.fake_tools, &case.tool_overrides),
            case.path_tools.as_deref().unwrap_or_default(),
            case.tool_exit,
            &case.wayland_display,
            "",
        );
        let window_start = unix_now();
        let mut child = Command::new(binary())
            .current_dir(&sandbox.work)
            .env_clear()
            .envs(tools.env.iter().map(|(k, v)| (k, v)))
            .args([
                "--vault",
                sandbox.vault.to_str().unwrap(),
                "mcp",
                "--stdio",
                "--agent",
                "clip",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mcp");
        let mut stdin = child.stdin.take().unwrap();
        for line in &case.input {
            writeln!(stdin, "{line}").unwrap();
        }
        stdin.flush().unwrap();
        // The auto-clear runs on a timer inside the live server; keep stdin
        // open until the fake tools logged everything Go's did.
        let deadline = Instant::now() + Duration::from_secs(30);
        while call_count(&tools.rec) < case.want_calls && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        // An unexpected extra call (a clear after a failed copy, a second
        // clear for a refreshed timer) would show up shortly after.
        std::thread::sleep(Duration::from_millis(400));
        drop(stdin);
        let output = child.wait_with_output().expect("mcp output");
        let window_end = unix_now();
        assert_success(&output, &case.name);
        let responses: Vec<Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON-RPC line"))
            .collect();
        // output[0] answers `initialize` (server identity differs by build).
        assert_eq!(
            responses.iter().skip(1).collect::<Vec<_>>(),
            case.output.iter().skip(1).collect::<Vec<_>>(),
            "tools/call responses of {}",
            case.name
        );
        assert!(
            !serde_json::to_string(&responses)
                .unwrap()
                .contains(MCP_PASSWORD),
            "{} returned its synthetic password",
            case.name
        );
        // Go reads the system clock for TOTP and records a placeholder; the
        // real binary does too, so the copied code must be a code of the
        // window the run happened in (exactly what Go's generator proved).
        let valid_codes = totp_codes(TOTP_SECRET, window_start, window_end);
        let expected: Vec<Call> = case
            .tool_calls
            .iter()
            .map(|call| Call {
                tool: call.tool.clone(),
                mode: call.mode.clone(),
                argv: call.argv.clone(),
                stdin: call.stdin.clone(),
            })
            .collect();
        let actual = read_calls(&tools.rec);
        assert_eq!(actual.len(), expected.len(), "{} tool calls", case.name);
        for (index, (got, want)) in actual.iter().zip(&expected).enumerate() {
            if want.stdin == fixture.totp.code_placeholder {
                assert_eq!(case.tool, "generate_totp", "{}", case.name);
                assert!(
                    valid_codes.contains(&got.stdin),
                    "{} call {index}: {:?} is no TOTP code of the window",
                    case.name,
                    got.stdin
                );
                assert_eq!(
                    (&got.tool, &got.mode, &got.argv),
                    (&want.tool, &want.mode, &want.argv),
                    "{} call {index}",
                    case.name
                );
                assert!(
                    !serde_json::to_string(&responses)
                        .unwrap()
                        .contains(&got.stdin),
                    "{} returned the TOTP code",
                    case.name
                );
            } else {
                assert_eq!(got, want, "{} call {index}", case.name);
            }
        }
        calls_total += case.tool_calls.len();
        drop(tools.bin);
    }
    assert_eq!(
        calls_total, CALLS_TOTAL,
        "recorded tool invocations replayed"
    );
}

fn unix_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// Every code the clock can have produced between `start` and `end`.
fn totp_codes(secret: &str, start: i64, end: i64) -> Vec<String> {
    (start.div_euclid(30)..=end.div_euclid(30))
        .map(|counter| {
            symvault_core::totp::generate_totp_at(secret, "SHA1", 6, 30, counter * 30)
                .expect("TOTP code")
                .code
        })
        .collect()
}

/// Runs `symvault get` with stdout on a pseudo-terminal and stderr on a pipe,
/// so Go's and Rust's "is stdout a terminal" decision is true. The crate forbids
/// `unsafe`, hence the Python `pty` module.
const PTY_HELPER: &str = r#"
import json, os, pty, subprocess, sys
cfg = json.loads(sys.argv[1])
master, slave = pty.openpty()
proc = subprocess.Popen(cfg["argv"], env=cfg["env"], cwd=cfg["cwd"], stdin=subprocess.DEVNULL, stdout=slave, stderr=subprocess.PIPE)
os.close(slave)
err = proc.stderr.read()
code = proc.wait()
out = b""
try:
    os.set_blocking(master, False)
    out = os.read(master, 65536)
except OSError:
    pass
print(json.dumps({"code": code, "stderr": err.decode(), "stdout": out.decode()}))
"#;

fn python_available() -> bool {
    Command::new("python3")
        .args(["-I", "-c", "import pty"])
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Whether the terminal run may proceed. Without python3/pty the run cannot
/// happen: locally that is a visible skip, but in CI and in the local gate
/// (`CI` or `SYMVAULT_GATE` set, the latter by `make
/// clipboard-linux-differential`) a skipped run would be a green gate that
/// verified nothing, so it fails instead.
fn pty_run_possible(python_available: bool, ci: bool, gate: bool) -> bool {
    if python_available {
        return true;
    }
    assert!(
        !(ci || gate),
        "python3 with the pty module is required for the terminal run in CI and the local gate \
         (CI={ci}, SYMVAULT_GATE={gate}); install python3 instead of skipping it"
    );
    false
}

fn env_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

#[test]
fn missing_python_fails_in_ci_and_the_gate_but_skips_locally() {
    assert!(pty_run_possible(true, true, true));
    assert!(pty_run_possible(true, false, false));
    assert!(!pty_run_possible(false, false, false));
    for (ci, gate) in [(true, false), (false, true), (true, true)] {
        let panic = std::panic::catch_unwind(|| pty_run_possible(false, ci, gate))
            .expect_err("a missing python3 must fail, not skip");
        let text = panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
            .unwrap_or_default();
        assert!(
            text.contains("python3 with the pty module is required"),
            "{text}"
        );
    }
}

#[test]
fn get_matches_go_on_linux_through_the_real_binary_on_a_pty() {
    if !pty_run_possible(python_available(), env_set("CI"), env_set("SYMVAULT_GATE")) {
        eprintln!("SKIP: python3 with the pty module is required for the terminal run");
        return;
    }
    let fixture: GetFixture = serde_json::from_str(include_str!(
        "../../../testdata/port/platform/get_clipboard_linux.json"
    ))
    .expect("decode the Go get Linux fixture");
    assert_eq!(fixture.scenarios.len(), 18);
    let secret = fixture.scenarios[0].secret.clone();
    let sandbox = sandbox("get", Some(("fixture-entry.password", &secret)), false);
    let big_repeat = fixture
        .scenarios
        .iter()
        .map(|s| s.secret_repeat)
        .max()
        .unwrap();
    assert!(big_repeat > 0);
    add_large_entry(&sandbox, "big", &secret.repeat(big_repeat));
    let mut calls_total = 0;
    for s in &fixture.scenarios {
        assert_eq!(s.secret, secret);
        assert!(s.secret_repeat == 0 || s.secret_repeat == big_repeat);
        let entry = if s.secret_repeat > 0 {
            "big.password"
        } else {
            "fixture-entry.password"
        };
        set_auto_clear(&sandbox, s.auto_clear_seconds);
        let tools = install_tools(
            &sandbox,
            &s.name.replace('_', ""),
            &with_overrides(&fixture.fake_tools, &s.tool_overrides),
            s.path_tools.as_deref().unwrap_or_default(),
            s.tool_exit,
            &s.wayland_display,
            &s.paste_output.replace("@SECRET@", &s.secret),
        );
        let env: BTreeMap<&str, &str> = tools
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let config = serde_json::json!({
            "argv": [binary(), "--vault", sandbox.vault.to_str().unwrap(), "get", entry],
            "env": env,
            "cwd": sandbox.work.to_str().unwrap(),
        });
        let output = Command::new("python3")
            .args(["-I", "-c", PTY_HELPER, &config.to_string()])
            .output()
            .expect("run the pty helper");
        assert_success(&output, &s.name);
        let result: Value = serde_json::from_slice(&output.stdout).expect("helper JSON");
        let stderr = result["stderr"]
            .as_str()
            .unwrap()
            .replace(
                "SYMVAULT_PASSPHRASE is active — environment passphrases are visible in process listings and crash dumps.\n",
                "",
            )
            .replace("\r[clearing clipboard in 0s] ", "");
        assert_eq!(stderr, s.stderr, "{} stderr", s.name);
        assert_eq!(
            result["code"].as_i64().unwrap(),
            i64::from(s.exit_code),
            "{} exit",
            s.name
        );
        assert_eq!(
            result["stdout"].as_str().unwrap(),
            s.stdout,
            "{} stdout",
            s.name
        );
        assert_eq!(
            read_calls(&tools.rec),
            s.tool_calls,
            "{} tool calls",
            s.name
        );
        assert!(!stderr.contains(&secret), "{} leaked the secret", s.name);
        calls_total += s.tool_calls.len();
        drop(tools.bin);
    }
    assert_eq!(
        calls_total, GET_CALLS_TOTAL,
        "recorded tool invocations replayed"
    );
}
