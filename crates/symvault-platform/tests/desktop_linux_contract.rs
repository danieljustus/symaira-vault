//! Replays the Go-generated PLATFORM-001 Linux desktop fixture
//! (`testdata/port/platform/desktop_linux.json`, from
//! `scripts/rust-port/cmd/desktopgen`) and the shared escaping fixture
//! (`autotype_escape.json`) against the Rust command adapters.
//!
//! Two independent replays run for the tool-routing corpus:
//!
//! * an injected [`DesktopHost`] that models the fake tools, so every case runs
//!   on every OS the workspace builds on; and
//! * on Unix, the *same POSIX-shell fake tools* the Go generator used (their
//!   text comes from the fixture) executed by the real [`SystemHost`] against a
//!   disposable PATH. That compares what Rust actually spawned with what Go
//!   actually spawned, byte for byte, including stdin.
//!
//! No real clipboard, display or credential is touched.
#![deny(unsafe_code)]

use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use symvault_platform::desktop_commands::{
    CommandClipboard, DesktopHost, EnvPolicy, FOREGROUND_PROBE, LinuxAutotype,
    MISSING_CLIPBOARD_COMMANDS, SEND_KEYS_WRAPPER, SystemHost, ToolOutput, WindowsAutotype,
    escape_apple_script_string, escape_send_keys_string,
};
use symvault_platform::{Autotype, Clipboard};

const DESKTOP: &str = include_str!("../../../testdata/port/platform/desktop_linux.json");
const ESCAPE: &str = include_str!("../../../testdata/port/platform/autotype_escape.json");

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
    dependency: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Call {
    tool: String,
    mode: String,
    argv: Vec<String>,
    stdin: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ClipboardCase {
    name: String,
    wayland_display: String,
    #[serde(default)]
    wayland_display_set_to_empty: bool,
    path_tools: Vec<String>,
    payload: String,
    paste_output: String,
    tool_exit: i32,
    calls: Vec<Call>,
    copy_error: String,
    paste_error: String,
    paste_result: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AutotypeCase {
    name: String,
    wayland_display: String,
    #[serde(default)]
    wayland_display_set_to_empty: bool,
    path_tools: Vec<String>,
    strict_focus_env: String,
    focus_class_outputs: [String; 2],
    focus_probe_exit: i32,
    type_exit: i32,
    text: String,
    error: String,
    calls: Vec<Call>,
}

#[derive(Debug, Deserialize)]
struct WindowsExtract {
    file: String,
    kind: String,
    name: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    argv: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    oracle: Oracle,
    script_placeholders: Vec<String>,
    fake_tools: BTreeMap<String, String>,
    clipboard_cases: Vec<ClipboardCase>,
    autotype_cases: Vec<AutotypeCase>,
    windows_extracted_not_executed: Vec<WindowsExtract>,
}

fn fixture() -> Fixture {
    serde_json::from_str(DESKTOP).expect("decode Go-generated desktop fixture")
}

#[test]
fn fixture_has_provenance_and_executed_the_intended_corpus() {
    let f = fixture();
    assert_eq!(f.schema_version, 1);
    assert_eq!(f.oracle.commit, f.oracle.commit_sha);
    assert_eq!(f.oracle.commit_sha.len(), 40);
    assert_eq!(f.oracle.source_digest.len(), 64);
    assert_eq!(f.oracle.generator_digest.len(), 64);
    assert!(
        f.oracle
            .dependency
            .contains("github.com/atotto/clipboard v0.1.4 h1:")
    );
    assert!(
        f.oracle
            .source_files
            .iter()
            .any(|name| name == "internal/autotype/autotype_linux.go")
    );
    assert_eq!(f.script_placeholders.len(), 5);
    assert_eq!(f.fake_tools.len(), 11);
    // A zero-case or all-skipped corpus is not evidence.
    assert_eq!(f.clipboard_cases.len(), 31);
    assert_eq!(f.autotype_cases.len(), 28);
    let executed: usize = f
        .clipboard_cases
        .iter()
        .map(|c| c.calls.len())
        .chain(f.autotype_cases.iter().map(|c| c.calls.len()))
        .sum();
    assert_eq!(executed, 92, "recorded Go tool calls");
    // Every fake tool really ran in the Go oracle.
    for tool in f.fake_tools.keys() {
        let seen = f
            .clipboard_cases
            .iter()
            .flat_map(|c| &c.calls)
            .chain(f.autotype_cases.iter().flat_map(|c| &c.calls))
            .any(|call| &call.tool == tool);
        assert!(seen, "{tool} never executed in the Go oracle");
    }
}

// ----------------------------------------------------------- injected host

/// Models the fixture's fake tools. Mode classification restates the shell
/// templates' rules; the Unix process replay below uses the real templates.
struct ModelHost {
    tools: Vec<String>,
    env: HashMap<String, String>,
    paste_output: Vec<u8>,
    exit: i32,
    focus: [String; 2],
    focus_exit: i32,
    calls: Mutex<Vec<Call>>,
    focus_calls: Mutex<u32>,
}

impl ModelHost {
    fn classify(program: &str, args: &[&str]) -> &'static str {
        match program {
            "wl-copy" | "termux-clipboard-set" | "clip.exe" => "copy",
            "wl-paste" | "termux-clipboard-get" | "powershell.exe" => "paste",
            "xclip" => {
                if args.contains(&"-in") {
                    "copy"
                } else {
                    "paste"
                }
            }
            "xsel" => {
                if args.contains(&"--input") {
                    "copy"
                } else {
                    "paste"
                }
            }
            "xdotool" if args.first() == Some(&"getactivewindow") => "focus",
            _ => "type",
        }
    }
}

impl DesktopHost for ModelHost {
    fn env_var(&self, name: &str) -> Option<String> {
        self.env.get(name).cloned()
    }
    fn tool_exists(&self, name: &str) -> bool {
        self.tools.iter().any(|t| t == name)
    }
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
        _capture: bool,
        _env: EnvPolicy,
    ) -> Result<ToolOutput, String> {
        assert!(
            self.tool_exists(program),
            "{program} is not on the model PATH"
        );
        let mode = Self::classify(program, args);
        let mut calls = self.calls.lock().unwrap();
        let stdin_text = if matches!(mode, "copy" | "type") {
            String::from_utf8(stdin.to_vec()).expect("fixture payloads are UTF-8")
        } else {
            assert!(stdin.is_empty(), "{program} {mode} must get no stdin");
            String::new()
        };
        calls.push(Call {
            tool: program.to_owned(),
            mode: mode.to_owned(),
            argv: args.iter().map(|a| (*a).to_owned()).collect(),
            stdin: stdin_text,
        });
        match mode {
            "paste" => Ok(ToolOutput {
                code: Some(self.exit),
                stdout: self.paste_output.clone(),
            }),
            "focus" => {
                let mut n = self.focus_calls.lock().unwrap();
                *n += 1;
                let class = &self.focus[usize::from(*n > 1)];
                Ok(ToolOutput {
                    code: Some(self.focus_exit),
                    stdout: format!("{class}\n").into_bytes(),
                })
            }
            _ => Ok(ToolOutput {
                code: Some(self.exit),
                stdout: Vec::new(),
            }),
        }
    }
}

fn env_for(display: &str, empty_set: bool, strict: &str) -> HashMap<String, String> {
    let mut env = HashMap::new();
    if !display.is_empty() || empty_set {
        env.insert("WAYLAND_DISPLAY".to_owned(), display.to_owned());
    }
    if !strict.is_empty() {
        env.insert(
            "SYMVAULT_AUTOTYPE_STRICT_FOCUS".to_owned(),
            strict.to_owned(),
        );
    }
    env
}

fn normalize(error: &str) -> String {
    error.to_owned()
}

fn replay_clipboard(
    case: &ClipboardCase,
    clipboard: &CommandClipboard,
) -> (String, String, String) {
    let copy_error = clipboard
        .set(case.payload.as_bytes())
        .err()
        .map(|e| e.message)
        .unwrap_or_default();
    let (paste_error, paste_result) = match clipboard.read() {
        Ok(bytes) => (String::new(), String::from_utf8(bytes).unwrap()),
        Err(error) => (error.message, String::new()),
    };
    (copy_error, paste_error, paste_result)
}

#[test]
fn clipboard_selection_and_io_match_go_via_injected_host() {
    for case in fixture().clipboard_cases {
        let host = Arc::new(ModelHost {
            tools: case.path_tools.clone(),
            env: env_for(&case.wayland_display, case.wayland_display_set_to_empty, ""),
            paste_output: case.paste_output.clone().into_bytes(),
            exit: case.tool_exit,
            focus: [String::new(), String::new()],
            focus_exit: 0,
            calls: Mutex::new(Vec::new()),
            focus_calls: Mutex::new(0),
        });
        let clipboard = CommandClipboard::new(host.clone());
        let (copy_error, paste_error, paste_result) = replay_clipboard(&case, &clipboard);
        assert_eq!(
            *host.calls.lock().unwrap(),
            case.calls,
            "{}: calls",
            case.name
        );
        assert_eq!(
            copy_error,
            normalize(&case.copy_error),
            "{}: copy",
            case.name
        );
        assert_eq!(
            paste_error,
            normalize(&case.paste_error),
            "{}: paste",
            case.name
        );
        assert_eq!(paste_result, case.paste_result, "{}: result", case.name);
        if case.calls.is_empty() {
            assert_eq!(case.copy_error, MISSING_CLIPBOARD_COMMANDS, "{}", case.name);
            assert!(clipboard.backend().is_none());
        }
    }
}

fn run_autotype(case: &AutotypeCase, host: Arc<dyn DesktopHost>) -> String {
    LinuxAutotype::new(host)
        .type_text(&case.text)
        .err()
        .map(|e| e.message)
        .unwrap_or_default()
}

#[test]
fn linux_autotype_routing_matches_go_via_injected_host() {
    for case in fixture().autotype_cases {
        let host = Arc::new(ModelHost {
            tools: case.path_tools.clone(),
            env: env_for(
                &case.wayland_display,
                case.wayland_display_set_to_empty,
                &case.strict_focus_env,
            ),
            paste_output: Vec::new(),
            exit: case.type_exit,
            focus: case.focus_class_outputs.clone(),
            focus_exit: case.focus_probe_exit,
            calls: Mutex::new(Vec::new()),
            focus_calls: Mutex::new(0),
        });
        let error = run_autotype(&case, host.clone());
        assert_eq!(
            *host.calls.lock().unwrap(),
            case.calls,
            "{}: calls",
            case.name
        );
        assert_eq!(error, case.error, "{}: error", case.name);
        // The secret never travels in argv, in any recorded call.
        if case.text.len() > 3 {
            for call in &case.calls {
                assert!(
                    call.argv.iter().all(|a| !a.contains(&case.text)),
                    "{}",
                    case.name
                );
            }
        }
    }
}

// ------------------------------------------------------- real process replay

#[cfg(unix)]
mod process {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    struct Sandbox {
        root: PathBuf,
        bin: PathBuf,
        rec: PathBuf,
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn sandbox(
        label: &str,
        f: &Fixture,
        tools: &[String],
        paste: &str,
        exit: i32,
        focus: &[String; 2],
        focus_exit: i32,
    ) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "symvault-desktop-{}-{}-{}",
            std::process::id(),
            label,
            tools.join("_").replace(['.', '-'], "")
        ));
        let _ = fs::remove_dir_all(&root);
        let bin = root.join("bin");
        let rec = root.join("rec");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&rec).unwrap();
        fs::write(rec.join("paste"), paste).unwrap();
        for tool in tools {
            let template = &f.fake_tools[tool];
            let body = template
                .replace("@REC@", rec.to_str().unwrap())
                .replace("@EXIT@", &exit.to_string())
                .replace("@FOCUS1@", &focus[0])
                .replace("@FOCUS2@", &focus[1])
                .replace("@FOCUSEXIT@", &focus_exit.to_string());
            let path = bin.join(tool);
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Sandbox { root, bin, rec }
    }

    fn read_calls(rec: &Path) -> Vec<Call> {
        let total: usize = match fs::read_to_string(rec.join("seq")) {
            Ok(raw) => raw.trim().parse().unwrap(),
            Err(_) => return Vec::new(),
        };
        (1..=total)
            .map(|n| {
                let raw = fs::read_to_string(rec.join(format!("call.{n}"))).unwrap();
                let lines: Vec<&str> = raw.lines().collect();
                let argc: usize = lines[2].parse().unwrap();
                assert_eq!(lines.len(), 3 + argc);
                let stdin = fs::read(rec.join(format!("call.{n}.stdin")))
                    .map(|b| String::from_utf8(b).unwrap())
                    .unwrap_or_default();
                Call {
                    tool: lines[0].to_owned(),
                    mode: lines[1].to_owned(),
                    argv: lines[3..].iter().map(|s| (*s).to_owned()).collect(),
                    stdin,
                }
            })
            .collect()
    }

    fn host_for(sb: &Sandbox, env: HashMap<String, String>) -> Arc<SystemHost> {
        let mut env = env;
        env.insert("PATH".to_owned(), sb.bin.to_str().unwrap().to_owned());
        env.insert("HOME".to_owned(), sb.root.to_str().unwrap().to_owned());
        Arc::new(SystemHost::isolated(vec![sb.bin.clone()], env))
    }

    #[test]
    fn clipboard_matches_go_with_real_processes_and_the_go_fake_tools() {
        let f = fixture();
        for case in f.clipboard_cases.clone() {
            let sb = sandbox(
                "cb",
                &f,
                &case.path_tools,
                &case.paste_output,
                case.tool_exit,
                &[String::new(), String::new()],
                0,
            );
            let host = host_for(
                &sb,
                env_for(&case.wayland_display, case.wayland_display_set_to_empty, ""),
            );
            let clipboard = CommandClipboard::new(host);
            let (copy_error, paste_error, paste_result) = replay_clipboard(&case, &clipboard);
            assert_eq!(read_calls(&sb.rec), case.calls, "{}: calls", case.name);
            assert_eq!(copy_error, case.copy_error, "{}: copy", case.name);
            assert_eq!(paste_error, case.paste_error, "{}: paste", case.name);
            assert_eq!(paste_result, case.paste_result, "{}: result", case.name);
        }
    }

    #[test]
    fn linux_autotype_matches_go_with_real_processes_and_the_go_fake_tools() {
        let f = fixture();
        for case in f.autotype_cases.clone() {
            let sb = sandbox(
                "at",
                &f,
                &case.path_tools,
                "",
                case.type_exit,
                &case.focus_class_outputs,
                case.focus_probe_exit,
            );
            let host = host_for(
                &sb,
                env_for(
                    &case.wayland_display,
                    case.wayland_display_set_to_empty,
                    &case.strict_focus_env,
                ),
            );
            let error = run_autotype(&case, host);
            assert_eq!(read_calls(&sb.rec), case.calls, "{}: calls", case.name);
            assert_eq!(error, case.error, "{}: error", case.name);
        }
    }
}

// --------------------------------------------------------- Windows + escapes

#[test]
fn windows_constants_equal_the_literals_extracted_from_go() {
    let f = fixture();
    let find = |file: &str, kind: &str, name: &str| {
        f.windows_extracted_not_executed
            .iter()
            .find(|e| e.file == file && e.kind == kind && e.name == name)
            .unwrap_or_else(|| panic!("{file} {kind} {name} not extracted"))
    };
    let wrapper = find(
        "internal/autotype/autotype_windows.go",
        "const",
        "readSendKeysWrapper",
    );
    assert_eq!(wrapper.value, SEND_KEYS_WRAPPER);
    let probe = find(
        "internal/autotype/focus_windows.go",
        "const",
        "foregroundProbe",
    );
    assert_eq!(probe.value, FOREGROUND_PROBE);
    let type_argv = find(
        "internal/autotype/autotype_windows.go",
        "exec_command",
        "exec.Command",
    );
    assert_eq!(
        type_argv.argv,
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SEND_KEYS_WRAPPER
        ]
    );
    let probe_argv = find(
        "internal/autotype/focus_windows.go",
        "exec_command",
        "exec.Command",
    );
    assert_eq!(
        probe_argv.argv,
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            FOREGROUND_PROBE
        ]
    );
}

#[derive(Debug, Deserialize)]
struct EscapeCase {
    name: String,
    input: String,
    output: String,
}

#[derive(Debug, Deserialize)]
struct EscapeFixture {
    commit: String,
    source_files: Vec<String>,
    source_hash: String,
    generator_hash: String,
    apple_script: Vec<EscapeCase>,
    send_keys: Vec<EscapeCase>,
}

#[test]
fn escaping_matches_go_oracle() {
    let f: EscapeFixture = serde_json::from_str(ESCAPE).unwrap();
    assert_eq!(f.commit.len(), 40);
    assert_eq!(f.source_files, ["internal/autotype/autotype_common.go"]);
    assert_eq!(f.source_hash.len(), 64);
    assert_eq!(f.generator_hash.len(), 64);
    assert_eq!(f.apple_script.len(), 22);
    assert_eq!(f.send_keys.len(), 22);
    for case in &f.apple_script {
        assert_eq!(
            escape_apple_script_string(&case.input),
            case.output,
            "apple {}",
            case.name
        );
    }
    for case in &f.send_keys {
        assert_eq!(
            escape_send_keys_string(&case.input),
            case.output,
            "sendkeys {}",
            case.name
        );
    }
}

#[test]
fn windows_autotype_composes_escape_and_wrapper_over_stdin() {
    // The Windows adapter cannot run its real tool here; this pins the
    // composition (escape -> wrapper stdin, text never in argv) on an injected
    // host so a regression in either piece fails.
    struct Rec(Mutex<Vec<(Vec<String>, Vec<u8>)>>);
    impl DesktopHost for Rec {
        fn env_var(&self, _: &str) -> Option<String> {
            None
        }
        fn tool_exists(&self, _: &str) -> bool {
            true
        }
        fn run(
            &self,
            _: &str,
            args: &[&str],
            stdin: &[u8],
            _: bool,
            _: EnvPolicy,
        ) -> Result<ToolOutput, String> {
            self.0.lock().unwrap().push((
                args.iter().map(|a| (*a).to_owned()).collect(),
                stdin.to_vec(),
            ));
            Ok(ToolOutput {
                code: Some(0),
                stdout: b"notepad\n".to_vec(),
            })
        }
    }
    let f: EscapeFixture = serde_json::from_str(ESCAPE).unwrap();
    for case in &f.send_keys {
        let host = Arc::new(Rec(Mutex::new(Vec::new())));
        WindowsAutotype::new(host.clone())
            .type_text(&case.input)
            .unwrap();
        let calls = host.0.lock().unwrap();
        let (args, stdin) = calls.last().unwrap();
        assert_eq!(args[3], SEND_KEYS_WRAPPER, "{}", case.name);
        assert_eq!(
            String::from_utf8(stdin.clone()).unwrap(),
            case.output,
            "{}",
            case.name
        );
    }
}
