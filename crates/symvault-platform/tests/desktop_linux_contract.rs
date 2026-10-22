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
//! The corpus includes relative and empty `PATH` shapes (Go `exec.ErrDot`): a
//! tool reached through them is "not installed" and never receives the secret.
//! Those cases need real path resolution, so only the process replay runs
//! them; the injected host skips them by design.
//!
//! No real clipboard, display or credential is touched.
#![deny(unsafe_code)]

use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use symvault_platform::desktop_commands::{
    AUTOTYPE_ENV_WHITELIST, CommandClipboard, DesktopHost, EnvPolicy, FOREGROUND_PROBE,
    LinuxAutotype, MISSING_CLIPBOARD_COMMANDS, SEND_KEYS_WRAPPER, ToolOutput, WindowsAutotype,
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
    #[serde(default)]
    path_spec: Option<String>,
    #[serde(default)]
    rel_tools: Vec<String>,
    #[serde(default)]
    cwd_tools: Vec<String>,
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
    #[serde(default)]
    path_spec: Option<String>,
    #[serde(default)]
    rel_tools: Vec<String>,
    #[serde(default)]
    cwd_tools: Vec<String>,
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
    autotype_env_whitelist: Vec<String>,
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
    assert_eq!(f.clipboard_cases.len(), 39);
    assert_eq!(f.autotype_cases.len(), 37);
    let executed: usize = f
        .clipboard_cases
        .iter()
        .map(|c| c.calls.len())
        .chain(f.autotype_cases.iter().map(|c| c.calls.len()))
        .sum();
    assert_eq!(executed, 102, "recorded Go tool calls");
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

#[test]
fn autotype_env_whitelist_equals_go_default_whitelist() {
    // The Go list comes from `secrets.DefaultWhitelist()` in the generated
    // fixture, so drift on either side fails here (order included).
    assert_eq!(
        AUTOTYPE_ENV_WHITELIST,
        fixture()
            .autotype_env_whitelist
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
}

/// Cases about relative/empty `PATH` entries need real path resolution.
fn needs_real_path(path_spec: &Option<String>, rel: &[String], cwd: &[String]) -> bool {
    path_spec.is_some() || !rel.is_empty() || !cwd.is_empty()
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
        if needs_real_path(&case.path_spec, &case.rel_tools, &case.cwd_tools) {
            continue;
        }
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
        if needs_real_path(&case.path_spec, &case.rel_tools, &case.cwd_tools) {
            continue;
        }
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
    use std::process::Command;
    use symvault_platform::desktop_commands::{SystemHost, go_split_list};

    struct Sandbox {
        root: PathBuf,
        bin: PathBuf,
        rec: PathBuf,
        cwd: PathBuf,
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// Where each fake tool is installed: the absolute `bin`, `<cwd>/rel`, or
    /// `<cwd>` itself.
    #[derive(Default)]
    struct Placement<'a> {
        bin: &'a [String],
        rel: &'a [String],
        cwd: &'a [String],
    }

    #[allow(clippy::too_many_arguments)]
    fn sandbox(
        label: &str,
        f: &Fixture,
        place: &Placement<'_>,
        paste: &str,
        exit: i32,
        focus: &[String; 2],
        focus_exit: i32,
    ) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "symvault-desktop-{}-{}-{}",
            std::process::id(),
            label,
            place.bin.join("_").replace(['.', '-'], "")
        ));
        let _ = fs::remove_dir_all(&root);
        let bin = root.join("bin");
        let rec = root.join("rec");
        let cwd = root.join("cwd");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&rec).unwrap();
        fs::create_dir_all(cwd.join("rel")).unwrap();
        fs::write(rec.join("paste"), paste).unwrap();
        for (dir, tools) in [
            (&bin, place.bin),
            (&cwd.join("rel"), place.rel),
            (&cwd, place.cwd),
        ] {
            for tool in tools {
                let template = &f.fake_tools[tool];
                let body = template
                    .replace("@REC@", rec.to_str().unwrap())
                    .replace("@EXIT@", &exit.to_string())
                    .replace("@FOCUS1@", &focus[0])
                    .replace("@FOCUS2@", &focus[1])
                    .replace("@FOCUSEXIT@", &focus_exit.to_string());
                write_executable(&dir.join(tool), &body);
            }
        }
        Sandbox {
            root,
            bin,
            rec,
            cwd,
        }
    }

    fn write_executable(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
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

    /// `path_spec` renders PATH (`{bin}` is the absolute tool directory);
    /// relative entries resolve against the sandbox cwd, which is also the
    /// spawn directory.
    fn host_for(
        sb: &Sandbox,
        env: HashMap<String, String>,
        path_spec: Option<&str>,
    ) -> Arc<SystemHost> {
        let path = match path_spec {
            Some(spec) => spec.replace("{bin}", sb.bin.to_str().unwrap()),
            None => sb.bin.to_str().unwrap().to_owned(),
        };
        let mut env = env;
        env.insert("PATH".to_owned(), path.clone());
        env.insert("HOME".to_owned(), sb.root.to_str().unwrap().to_owned());
        Arc::new(
            SystemHost::isolated(go_split_list(std::ffi::OsStr::new(&path)), env)
                .with_cwd(sb.cwd.clone()),
        )
    }

    fn placement<'a>(bin: &'a [String], rel: &'a [String], cwd: &'a [String]) -> Placement<'a> {
        Placement { bin, rel, cwd }
    }

    #[test]
    fn clipboard_matches_go_with_real_processes_and_the_go_fake_tools() {
        let f = fixture();
        let mut with_path_shape = 0;
        for case in f.clipboard_cases.clone() {
            with_path_shape += usize::from(needs_real_path(
                &case.path_spec,
                &case.rel_tools,
                &case.cwd_tools,
            ));
            let sb = sandbox(
                "cb",
                &f,
                &placement(&case.path_tools, &case.rel_tools, &case.cwd_tools),
                &case.paste_output,
                case.tool_exit,
                &[String::new(), String::new()],
                0,
            );
            let host = host_for(
                &sb,
                env_for(&case.wayland_display, case.wayland_display_set_to_empty, ""),
                case.path_spec.as_deref(),
            );
            let clipboard = CommandClipboard::new(host);
            let (copy_error, paste_error, paste_result) = replay_clipboard(&case, &clipboard);
            assert_eq!(read_calls(&sb.rec), case.calls, "{}: calls", case.name);
            assert_eq!(copy_error, case.copy_error, "{}: copy", case.name);
            assert_eq!(paste_error, case.paste_error, "{}: paste", case.name);
            assert_eq!(paste_result, case.paste_result, "{}: result", case.name);
        }
        assert_eq!(with_path_shape, 8, "relative/empty PATH clipboard cases");
    }

    #[test]
    fn linux_autotype_matches_go_with_real_processes_and_the_go_fake_tools() {
        let f = fixture();
        let mut with_path_shape = 0;
        for case in f.autotype_cases.clone() {
            with_path_shape += usize::from(needs_real_path(
                &case.path_spec,
                &case.rel_tools,
                &case.cwd_tools,
            ));
            let sb = sandbox(
                "at",
                &f,
                &placement(&case.path_tools, &case.rel_tools, &case.cwd_tools),
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
                case.path_spec.as_deref(),
            );
            let error = run_autotype(&case, host);
            assert_eq!(read_calls(&sb.rec), case.calls, "{}: calls", case.name);
            assert_eq!(error, case.error, "{}: error", case.name);
        }
        assert_eq!(with_path_shape, 9, "relative/empty PATH autotype cases");
    }

    // ----------------------------------------------------- environment policy

    const DECOYS: [(&str, &str); 7] = [
        ("AWS_SECRET_ACCESS_KEY", "decoy-aws"),
        ("SYMVAULT_PASSPHRASE", "decoy-passphrase"),
        ("SYMVAULT_VAULT", "decoy-vault"),
        ("API_TOKEN", "decoy-token"),
        ("LD_PRELOAD", "decoy-preload"),
        ("XDG_RUNTIME_DIR", "decoy-xdg"),
        ("SSH_PRIVATE_KEY", "decoy-key"),
    ];

    /// A fake tool that dumps its whole environment, one file per process, and
    /// otherwise behaves like a successful xdotool/wtype/xclip.
    fn env_dump_script(rec: &Path) -> String {
        format!(
            "#!/bin/sh\n/usr/bin/env > '{}/env.'$$\ncase \"$1\" in getactivewindow) echo firefox;; *) /bin/cat > /dev/null;; esac\n",
            rec.display()
        )
    }

    /// Names present in every environment dump, minus the variables a
    /// POSIX shell invents on its own.
    fn dumped_names(rec: &Path) -> Vec<std::collections::BTreeSet<String>> {
        let mut dumps = Vec::new();
        for entry in fs::read_dir(rec).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            if !name.starts_with("env.") {
                continue;
            }
            let names = fs::read_to_string(&path)
                .unwrap()
                .lines()
                .filter_map(|line| line.split_once('=').map(|(k, _)| k.to_owned()))
                .filter(|k| !matches!(k.as_str(), "PWD" | "OLDPWD" | "SHLVL" | "_"))
                .collect();
            dumps.push(names);
        }
        dumps
    }

    fn full_env(wayland: bool) -> HashMap<String, String> {
        let mut env: HashMap<String, String> = AUTOTYPE_ENV_WHITELIST
            .iter()
            .map(|name| ((*name).to_owned(), format!("value-of-{name}")))
            .collect();
        for (name, value) in DECOYS {
            env.insert(name.to_owned(), value.to_owned());
        }
        if wayland {
            env.insert("WAYLAND_DISPLAY".to_owned(), "wayland-0".to_owned());
        }
        env
    }

    fn assert_exactly_whitelisted(label: &str, dumps: &[std::collections::BTreeSet<String>]) {
        assert!(!dumps.is_empty(), "{label}: the tool never ran");
        let expected: std::collections::BTreeSet<String> = AUTOTYPE_ENV_WHITELIST
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        for names in dumps {
            assert_eq!(
                names, &expected,
                "{label}: tool environment must equal the whitelist"
            );
            for (decoy, _) in DECOYS {
                assert!(!names.contains(decoy), "{label}: {decoy} leaked");
            }
            assert!(
                !names.contains("WAYLAND_DISPLAY"),
                "{label}: not whitelisted"
            );
        }
    }

    #[test]
    fn autotype_tools_receive_exactly_the_whitelisted_environment() {
        let f = fixture();
        // X11: the focus probes and the typing call all run xdotool.
        let sb = sandbox(
            "envx11",
            &f,
            &Placement::default(),
            "",
            0,
            &[String::new(), String::new()],
            0,
        );
        write_executable(&sb.bin.join("xdotool"), &env_dump_script(&sb.rec));
        let host = host_for(&sb, full_env(false), None);
        LinuxAutotype::new(host)
            .type_text("hunter2-supersecret")
            .unwrap();
        let dumps = dumped_names(&sb.rec);
        assert_eq!(dumps.len(), 3, "two focus probes and one typing call");
        assert_exactly_whitelisted("x11 xdotool", &dumps);

        // Wayland: WAYLAND_DISPLAY routes to wtype but is itself not passed on.
        let sb = sandbox(
            "envwl",
            &f,
            &Placement::default(),
            "",
            0,
            &[String::new(), String::new()],
            0,
        );
        write_executable(&sb.bin.join("wtype"), &env_dump_script(&sb.rec));
        let host = host_for(&sb, full_env(true), None);
        LinuxAutotype::new(host)
            .type_text("hunter2-supersecret")
            .unwrap();
        assert_exactly_whitelisted("wayland wtype", &dumped_names(&sb.rec));
    }

    #[test]
    fn clipboard_tools_inherit_the_whole_environment_like_atotto() {
        let f = fixture();
        let sb = sandbox(
            "envcb",
            &f,
            &Placement::default(),
            "",
            0,
            &[String::new(), String::new()],
            0,
        );
        write_executable(&sb.bin.join("xclip"), &env_dump_script(&sb.rec));
        let host = host_for(&sb, full_env(false), None);
        CommandClipboard::new(host).set(b"secret").unwrap();
        let dumps = dumped_names(&sb.rec);
        assert_eq!(dumps.len(), 1);
        for (decoy, _) in DECOYS {
            assert!(dumps[0].contains(decoy), "{decoy} should be inherited");
        }
    }

    // ------------------------------------- default host and the process cwd

    const CHILD_ENV: &str = "SYMVAULT_REL_PATH_CHILD";

    /// Re-executed by `relative_and_empty_path_entries_never_receive_the_secret`
    /// with the working directory and `PATH` under test; does nothing otherwise.
    #[test]
    fn relative_path_child_entry() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        let result = LinuxAutotype::new(Arc::new(SystemHost::new())).type_text("child-secret");
        println!(
            "CHILD-RESULT:{}",
            result.err().map(|e| e.message).unwrap_or_default()
        );
    }

    fn capture_script(capture: &Path) -> String {
        format!(
            "#!/bin/sh\ncase \"$1\" in getactivewindow) echo firefox;; *) /bin/cat > '{}';; esac\n",
            capture.display()
        )
    }

    #[test]
    fn relative_and_empty_path_entries_never_receive_the_secret() {
        // (label, PATH with {bin}, where the capturing xdotool is, secret delivered?)
        let shapes: [(&str, &str, &[&str], bool); 8] = [
            ("relative", "rel", &["rel"], false),
            ("dot", ".", &["cwd"], false),
            ("empty-entry", ":{bin}", &["cwd"], false),
            ("empty-path", "", &["cwd"], false),
            (
                "relative-shadows-absolute",
                "rel:{bin}",
                &["rel", "bin"],
                false,
            ),
            ("absolute-control", "{bin}", &["bin"], true),
            ("empty-entry-then-absolute", ":{bin}", &["bin"], true),
            (
                "relative-dir-without-tool-then-absolute",
                "rel:{bin}",
                &["bin"],
                true,
            ),
        ];
        let exe = std::env::current_exe().unwrap();
        for (label, path_spec, locations, delivered) in shapes {
            let f = fixture();
            let sb = sandbox(
                &format!("rel-{label}"),
                &f,
                &Placement::default(),
                "",
                0,
                &[String::new(), String::new()],
                0,
            );
            let capture = sb.root.join("captured-stdin");
            for location in locations {
                let dir = match *location {
                    "rel" => sb.cwd.join("rel"),
                    "cwd" => sb.cwd.clone(),
                    _ => sb.bin.clone(),
                };
                write_executable(&dir.join("xdotool"), &capture_script(&capture));
            }
            let path = path_spec.replace("{bin}", sb.bin.to_str().unwrap());
            let output = Command::new(&exe)
                .args([
                    "process::relative_path_child_entry",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .current_dir(&sb.cwd)
                .env_clear()
                .env("PATH", &path)
                .env(CHILD_ENV, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "{label}: child failed: {stdout}");
            // The libtest line prefix ("test name ... ") precedes the marker.
            let result = stdout
                .split_once("CHILD-RESULT:")
                .and_then(|(_, rest)| rest.lines().next())
                .unwrap_or_else(|| panic!("{label}: child produced no result: {stdout}"));
            if delivered {
                assert_eq!(result, "", "{label}");
                assert_eq!(
                    fs::read_to_string(&capture).unwrap(),
                    "child-secret",
                    "{label}"
                );
            } else {
                assert_eq!(result, "autotype failed: xdotool not installed", "{label}");
                assert!(
                    !capture.exists(),
                    "{label}: the planted executable received the secret"
                );
            }
        }
    }

    #[test]
    fn running_a_relative_hit_directly_reports_gos_errdot_text() {
        let f = fixture();
        let sb = sandbox(
            "errdot",
            &f,
            &Placement {
                bin: &[],
                rel: &["xdotool".to_owned()],
                cwd: &[],
            },
            "",
            0,
            &[String::new(), String::new()],
            0,
        );
        let host = host_for(&sb, HashMap::new(), Some("rel"));
        assert!(!host.tool_exists("xdotool"));
        let error = host
            .run("xdotool", &["type"], b"secret", false, EnvPolicy::Whitelist)
            .unwrap_err();
        assert_eq!(
            error,
            "exec: \"xdotool\": cannot run executable found relative to current directory"
        );
        assert!(read_calls(&sb.rec).is_empty(), "the tool must not have run");
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
