#![cfg(unix)]
#![deny(unsafe_code)]

//! Go↔Rust differential for `symvault set` (cmd/crud/set.go).
//!
//! Every case runs the Go oracle (`SYMVAULT_GO_BINARY`) and the Rust binary in
//! separate disposable HOME/XDG roots, with the same arguments and piped stdin,
//! and compares byte for byte the exit status, stdout and stderr (roots
//! normalised) plus the files the run created in the vault (so "nothing was
//! written" is asserted too). Successful writes are additionally read back with
//! the Rust binary and compared. The PTY cases feed Go and Rust a terminal as
//! stdin to reach the argv-exposure warning. The suite skips with a message
//! when `SYMVAULT_GO_BINARY` is unset.

use std::{
    collections::BTreeMap,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
};

use serde_json::{Value, json};

const RUST: &str = env!("CARGO_BIN_EXE_symvault");
const PASS: &str = "correct horse battery staple";
const WRONG: &str = "wrong wrong wrong wrong";
const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const STRONG: &str = "StrongPassword123!";

struct Case {
    name: &'static str,
    args: Vec<String>,
    stdin: Vec<u8>,
    init: bool,
    passphrase: &'static str,
    reads: Vec<&'static str>,
}

fn case<S: AsRef<str>>(name: &'static str, args: &[S], stdin: &[u8]) -> Case {
    Case {
        name,
        args: args.iter().map(|arg| arg.as_ref().to_owned()).collect(),
        stdin: stdin.to_vec(),
        init: true,
        passphrase: PASS,
        reads: Vec::new(),
    }
}

impl Case {
    fn uninit(mut self) -> Self {
        self.init = false;
        self
    }
    fn wrong(mut self) -> Self {
        self.passphrase = WRONG;
        self
    }
    fn reads(mut self, fields: &[&'static str]) -> Self {
        self.reads = fields.to_vec();
        self
    }
}

fn cases() -> Vec<Case> {
    let totp = |bad: &str| -> Vec<String> {
        [
            "set",
            "w/a.password",
            "--value",
            STRONG,
            "--totp-secret",
            bad,
        ]
        .map(str::to_owned)
        .to_vec()
    };
    vec![
        // (1) plain pre-unlock errors print twice, like Go's RunE + ExecuteRoot.
        case(
            "weak password",
            &["set", "w/a.password", "--value", "abc"],
            b"",
        ),
        case(
            "weak password, default field",
            &["set", "w/a", "--value", "abc"],
            b"",
        ),
        case(
            "weak password uninit (exit 1, not 3)",
            &["set", "w/a.password", "--value", "abc"],
            b"",
        )
        .uninit(),
        case(
            "weak password wrong passphrase",
            &["set", "w/a.password", "--value", "abc"],
            b"",
        )
        .wrong(),
        case("invalid TOTP", &totp("SHORT"), b""),
        case("invalid TOTP base32", &totp(&"!".repeat(32)), b""),
        case("invalid TOTP uninit", &totp("SHORT"), b"").uninit(),
        case("invalid TOTP wrong passphrase", &totp("SHORT"), b"").wrong(),
        case(
            "weak password wins over bad TOTP",
            &[
                "set",
                "w/a.password",
                "--value",
                "abc",
                "--totp-secret",
                "SHORT",
            ],
            b"",
        ),
        case(
            "--stdin-value EOF",
            &["set", "w/a.password", "--stdin-value"],
            b"",
        ),
        case(
            "--stdin-value EOF uninit",
            &["set", "w/a.password", "--stdin-value"],
            b"",
        )
        .uninit(),
        case(
            "--stdin-value weak",
            &["set", "w/a.password", "--stdin-value"],
            b"abc\n",
        ),
        case(
            "--stdin-value bad TOTP",
            &[
                "set",
                "w/a.password",
                "--stdin-value",
                "--totp-secret",
                "SHORT",
            ],
            b"StrongPassword123!\n",
        ),
        case(
            "--stdin-value strong",
            &["set", "w/a.password", "--stdin-value"],
            b"StrongPassword123!\r\n",
        )
        .reads(&["w/a.password"]),
        case(
            "interactive field + bad TOTP",
            &["set", "w/a.note", "--totp-secret", "SHORT"],
            b"hello\n",
        ),
        case(
            "interactive field + bad TOTP uninit",
            &["set", "w/a.note", "--totp-secret", "SHORT"],
            b"hello\n",
        )
        .uninit(),
        // (3) the strength check belongs to the explicit value paths only.
        case(
            "weak --force",
            &["set", "w/a.password", "--value", "abc", "--force"],
            b"",
        )
        .reads(&["w/a.password"]),
        case(
            "weak value on a non-password field",
            &["set", "w/a.pwd", "--value", "abc"],
            b"",
        )
        .reads(&["w/a.pwd"]),
        case(
            "interactive .password weak is accepted",
            &["set", "w/a.password"],
            b"abc\nabc\n",
        )
        .reads(&["w/a.password"]),
        case(
            "interactive .password weak uninit is exit 3",
            &["set", "w/a.password"],
            b"abc\nabc\n",
        )
        .uninit(),
        // (5) interactive sensitive confirmation.
        case("interactive field", &["set", "w/a.note"], b"hello\n").reads(&["w/a.note"]),
        case(
            "sensitive confirmation matches",
            &["set", "w/a.api_key"],
            b"s3cretvalue\ns3cretvalue\n",
        )
        .reads(&["w/a.api_key"]),
        case(
            "sensitive confirmation mismatch is exit 9",
            &["set", "w/a.api_key"],
            b"s3cretvalue\nother\n",
        ),
        case(
            "sensitive confirmation empty is exit 9",
            &["set", "w/a.api_key"],
            b"s3cretvalue\n\n",
        ),
        case(
            "sensitive confirmation EOF",
            &["set", "w/a.api_key"],
            b"s3cretvalue\n",
        ),
        case(
            "sensitive value empty is exit 9",
            &["set", "w/a.api_key"],
            b"\n",
        ),
        case(
            "sensitive value empty --allow-empty",
            &["set", "w/a.api_key", "--allow-empty"],
            b"\n",
        )
        .reads(&["w/a.api_key"]),
        case("sensitive value read EOF", &["set", "w/a.api_key"], b""),
        // (4) no field: Go's CollectEntryData.
        case(
            "collect: all fields",
            &["set", "w/a"],
            b"alice\nStrongPassword123!\nhttps://x.test\n\n",
        )
        .reads(&["w/a.username", "w/a.password", "w/a.url"]),
        case(
            "collect: TOTP prompt",
            &["set", "w/a"],
            b"\nStrongPassword123!\n\nJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\n",
        ),
        case(
            "collect: TOTP prompt without newline",
            &["set", "w/a"],
            b"\nStrongPassword123!\n\nJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        ),
        case(
            "collect: invalid TOTP prompt",
            &["set", "w/a"],
            b"\nStrongPassword123!\n\nSHORT\n",
        ),
        case(
            "collect: weak password refused off a terminal",
            &["set", "w/a"],
            b"\nabc\n\n\n",
        ),
        case(
            "collect: weak password --force",
            &["set", "w/a", "--force"],
            b"\nabc\n\n\n",
        )
        .reads(&["w/a.password"]),
        case(
            "collect: weak password --quiet",
            &["--quiet", "set", "w/a"],
            b"\nabc\n\n\n",
        ),
        case(
            "collect: TOTP flag skips the TOTP prompt",
            &["set", "w/a", "--totp-secret", SECRET, "--totp-issuer", "I"],
            b"\nStrongPassword123!\n\n",
        ),
        case("collect: empty input", &["set", "w/a"], b"\n\n\n\n"),
        case("collect: EOF at username", &["set", "w/a"], b""),
        case("collect: EOF at password", &["set", "w/a"], b"alice\n"),
        case(
            "collect: EOF at url",
            &["set", "w/a"],
            b"\nStrongPassword123!\n",
        ),
        case(
            "collect: trailing dot",
            &["set", "w/a."],
            b"\nStrongPassword123!\n\n\n",
        ),
        case(
            "collect: bad TOTP flag, uninit",
            &["set", "w/a", "--totp-secret", "SHORT"],
            b"\nStrongPassword123!\n\n",
        )
        .uninit(),
        // (6) an empty sensitive value never reaches the vault.
        case(
            "uninit + empty --value",
            &["set", "w/a.password", "--value", ""],
            b"",
        )
        .uninit(),
        case(
            "uninit + empty --value --allow-empty",
            &["set", "w/a.password", "--value", "", "--allow-empty"],
            b"",
        )
        .uninit(),
        case(
            "uninit + empty --stdin-value",
            &["set", "w/a.password", "--stdin-value"],
            b"\n",
        )
        .uninit(),
        case(
            "uninit + valid",
            &["set", "w/a.password", "--value", STRONG],
            b"",
        )
        .uninit(),
        case(
            "empty --value",
            &["set", "w/a.password", "--value", ""],
            b"",
        ),
        case(
            "empty --value, token field",
            &["set", "w/a.api_token", "--value", ""],
            b"",
        ),
        case(
            "empty --value, non-sensitive field",
            &["set", "w/a.note", "--value", ""],
            b"",
        )
        .reads(&["w/a.note"]),
        case(
            "valid",
            &[
                "set",
                "w/a.password",
                "--value",
                STRONG,
                "--totp-secret",
                SECRET,
                "--totp-issuer",
                "I",
                "--totp-account",
                "A",
            ],
            b"",
        )
        .reads(&["w/a.password"]),
        case(
            "--quiet valid",
            &["--quiet", "set", "w/a.note", "--value", "x"],
            b"",
        )
        .reads(&["w/a.note"]),
    ]
}

fn environment(root: &Path, home: &Path, passphrase: &str) -> Vec<(&'static str, String)> {
    let home = home.display().to_string();
    vec![
        ("PATH", env::var("PATH").unwrap_or_default()),
        ("XDG_CONFIG_HOME", format!("{home}/config")),
        ("XDG_DATA_HOME", format!("{home}/data")),
        ("XDG_CACHE_HOME", format!("{home}/cache")),
        ("HOME", home),
        ("SYMVAULT_VAULT", root.display().to_string()),
        ("SYMVAULT_PASSPHRASE", passphrase.to_owned()),
        ("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1".to_owned()),
        ("SYMVAULT_TEST_KEYRING", "memory".to_owned()),
        ("CI", "1".to_owned()),
    ]
}

fn files(root: &Path) -> Option<Vec<String>> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).expect("read dir").flatten() {
            let path = entry.path();
            if path.file_name().is_some_and(|name| name == ".git") {
                continue;
            }
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                out.push(path.strip_prefix(base).unwrap().display().to_string());
            }
        }
    }
    root.is_dir().then(|| {
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    })
}

fn normalise(bytes: &[u8], root: &Path, home: &Path) -> String {
    String::from_utf8_lossy(bytes)
        .replace(&root.display().to_string(), "<ROOT>")
        .replace(&home.display().to_string(), "<HOME>")
}

#[derive(Debug, PartialEq)]
struct Observed {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    created: Option<Vec<String>>,
    reads: BTreeMap<String, (Option<i32>, String)>,
}

fn setup(parent: &Path, init: bool) -> (PathBuf, PathBuf) {
    let root = parent.join("vault");
    let home = parent.join("home");
    fs::create_dir_all(&home).expect("home");
    if init {
        fs::create_dir_all(&root).expect("vault root");
        let init = Command::new(RUST)
            .args(["init", "--auth", "passphrase"])
            .env_clear()
            .envs(environment(&root, &home, PASS))
            .stdin(Stdio::null())
            .output()
            .expect("init");
        assert!(init.status.success(), "init: {init:?}");
    }
    (root, home)
}

fn run_piped(binary: &Path, parent: &Path, case: &Case) -> Observed {
    let (root, home) = setup(parent, case.init);
    let before = files(&root);
    let mut child = Command::new(binary)
        .args(&case.args)
        .env_clear()
        .envs(environment(&root, &home, case.passphrase))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let input = case.stdin.clone();
    let writer = thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let output = child.wait_with_output().expect("wait");
    writer.join().expect("stdin writer");
    let after = files(&root);
    let created = match (before, after) {
        (Some(before), Some(after)) => Some(
            after
                .into_iter()
                .filter(|file| !before.contains(file))
                .collect(),
        ),
        (None, after) => after,
        (Some(_), None) => None,
    };
    let mut reads = BTreeMap::new();
    if output.status.success() {
        for field in &case.reads {
            let read = Command::new(RUST)
                .args(["get", field])
                .env_clear()
                .envs(environment(&root, &home, PASS))
                .stdin(Stdio::null())
                .output()
                .expect("get");
            reads.insert(
                (*field).to_owned(),
                (read.status.code(), normalise(&read.stdout, &root, &home)),
            );
        }
    }
    Observed {
        code: output.status.code(),
        stdout: normalise(&output.stdout, &root, &home),
        stderr: normalise(&output.stderr, &root, &home),
        created,
        reads,
    }
}

fn oracle() -> Option<PathBuf> {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return None;
    };
    let go = PathBuf::from(go);
    assert!(go.is_file(), "SYMVAULT_GO_BINARY is not a file: {go:?}");
    Some(go)
}

#[test]
fn set_matches_the_go_oracle_on_piped_input() {
    let Some(go) = oracle() else {
        return;
    };
    let rust = PathBuf::from(RUST);
    let cases = cases();
    let mut failures = Vec::new();
    for batch in cases.chunks(6) {
        let results: Vec<_> = thread::scope(|scope| {
            batch
                .iter()
                .map(|case| {
                    let (go, rust) = (&go, &rust);
                    scope.spawn(move || {
                        let temp = tempfile::Builder::new()
                            .prefix("symvault-set-diff-")
                            .tempdir()
                            .expect("temp");
                        let go_run = run_piped(go, &temp.path().join("go"), case);
                        let rust_run = run_piped(rust, &temp.path().join("rs"), case);
                        (case.name, go_run, rust_run)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().expect("case thread"))
                .collect()
        });
        for (name, go_run, rust_run) in results {
            if go_run != rust_run {
                failures.push(format!("{name}\n  go:   {go_run:?}\n  rust: {rust_run:?}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

/// Opens a pseudo-terminal as the child's stdin (stdout/stderr are pipes),
/// optionally types a line first, and prints the exit status and stderr.
const PTY_DRIVER: &str = r####"import json, os, pty, subprocess, sys
spec = json.load(open(sys.argv[1]))
master, slave = pty.openpty()
if spec["input"]:
    os.write(master, spec["input"].encode())
proc = subprocess.Popen([spec["binary"]] + spec["args"], env=spec["env"], cwd=spec["cwd"],
                        stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
os.close(slave)
out, err = proc.communicate(timeout=120)
os.close(master)
print(json.dumps({"rc": proc.returncode, "stdout": out.hex(), "stderr": err.hex()}))
"####;

struct PtyCase {
    name: &'static str,
    args: &'static [&'static str],
    input: &'static str,
    init: bool,
}

fn run_pty(binary: &Path, parent: &Path, case: &PtyCase) -> Observed {
    let (root, home) = setup(parent, case.init);
    let before = files(&root);
    let spec = json!({
        "binary": binary,
        "args": case.args,
        "input": case.input,
        "cwd": root.parent().unwrap(),
        "env": environment(&root, &home, PASS).into_iter().collect::<BTreeMap<_, _>>(),
    });
    let spec_path = parent.join("spec.json");
    fs::write(&spec_path, spec.to_string()).expect("spec");
    let driven = Command::new("python3")
        .args(["-I", "-c", PTY_DRIVER])
        .arg(&spec_path)
        .output()
        .expect("python3 is required to drive the pty");
    assert!(
        driven.status.success(),
        "{} pty driver: {}",
        case.name,
        String::from_utf8_lossy(&driven.stderr)
    );
    let driven: Value = serde_json::from_slice(&driven.stdout).expect("driver JSON");
    let decode = |key: &str| -> Vec<u8> {
        let hex = driven[key].as_str().expect("hex");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
            .collect()
    };
    let after = files(&root);
    let created = match (before, after) {
        (Some(before), Some(after)) => Some(
            after
                .into_iter()
                .filter(|file| !before.contains(file))
                .collect(),
        ),
        (None, after) => after,
        (Some(_), None) => None,
    };
    Observed {
        code: driven["rc"].as_i64().map(|code| code as i32),
        stdout: normalise(&decode("stdout"), &root, &home),
        stderr: normalise(&decode("stderr"), &root, &home),
        created,
        reads: BTreeMap::new(),
    }
}

#[test]
fn set_matches_the_go_oracle_on_a_terminal_stdin() {
    let Some(go) = oracle() else {
        return;
    };
    let rust = PathBuf::from(RUST);
    // (2) Go warns about argv exposure right after the stdin read and before
    // any validation, for --value and --totp-secret alike; --stdin-value
    // overwrites SetValue, so a terminal stdin warns for it too.
    let cases = [
        PtyCase {
            name: "--value strong",
            args: &["set", "w/a.password", "--value", STRONG],
            input: "",
            init: true,
        },
        PtyCase {
            name: "--value empty sensitive",
            args: &["set", "w/a.password", "--value", ""],
            input: "",
            init: true,
        },
        PtyCase {
            name: "--value weak",
            args: &["set", "w/a.password", "--value", "abc"],
            input: "",
            init: true,
        },
        PtyCase {
            name: "bad --totp-secret",
            args: &["set", "w/a.note", "--value", "x", "--totp-secret", "SHORT"],
            input: "",
            init: true,
        },
        PtyCase {
            name: "--totp-secret only valid",
            args: &["set", "w/a.note", "--value", "", "--totp-secret", SECRET],
            input: "",
            init: true,
        },
        PtyCase {
            name: "--value strong uninit",
            args: &["set", "w/a.password", "--value", STRONG],
            input: "",
            init: false,
        },
        PtyCase {
            name: "--stdin-value strong",
            args: &["set", "w/a.password", "--stdin-value"],
            input: "StrongPassword123!\n",
            init: true,
        },
        PtyCase {
            name: "--stdin-value weak",
            args: &["set", "w/a.password", "--stdin-value"],
            input: "abc\n",
            init: true,
        },
    ];
    let mut failures = Vec::new();
    for case in &cases {
        let temp = tempfile::Builder::new()
            .prefix("symvault-set-pty-")
            .tempdir()
            .expect("temp");
        let go_run = run_pty(&go, &temp.path().join("go"), case);
        let rust_run = run_pty(&rust, &temp.path().join("rs"), case);
        if go_run != rust_run {
            failures.push(format!(
                "{}\n  go:   {go_run:?}\n  rust: {rust_run:?}",
                case.name
            ));
        }
        if case.args.contains(&"--value") && !case.args.contains(&"") {
            assert!(
                go_run.stderr.contains("Warning: --value is visible"),
                "{}: the oracle must warn on a terminal: {go_run:?}",
                case.name
            );
        }
    }
    assert!(
        failures.is_empty(),
        "pty cases differ:\n{}",
        failures.join("\n")
    );
}
