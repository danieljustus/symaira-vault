#![cfg(unix)]
#![deny(unsafe_code)]

//! Go↔Rust differential for `symvault set` (cmd/crud/set.go).
//!
//! Every case runs the Rust binary live and compares it with the recorded Go
//! oracle (`testdata/port/cli-observations/set_differential.json`; a missing
//! recording fails the test) in separate disposable HOME/XDG roots, with the same arguments and piped stdin,
//! and compares byte for byte the exit status, stdout and stderr (roots
//! normalised) plus the files the run created in the vault (so "nothing was
//! written" is asserted too). Successful writes are additionally read back with
//! the Rust binary and compared. The PTY cases feed Go and Rust a terminal as
//! stdin to reach the argv-exposure warning. The read-back of a Go-written
//! entry was done by the Rust binary at capture time; replay compares the
//! recorded read-back with the Rust binary reading its own write.

#[path = "common/go_oracle_ext.rs"]
mod go_oracle_ext;

use std::{
    collections::BTreeMap,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
};

use go_oracle_ext::Observations;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Pinned Go oracle.
const ORACLE_COMMIT: &str = "c069d3f2b17d704525cedc1bd42840cc6a3e9896";

const RUST: &str = env!("CARGO_BIN_EXE_symvault");
const PASS: &str = "correct horse battery staple";
const WRONG: &str = "wrong wrong wrong wrong";
const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const STRONG: &str = "StrongPassword123!";

struct Case {
    name: String,
    args: Vec<String>,
    stdin: Vec<u8>,
    init: bool,
    passphrase: &'static str,
    /// Whether `SYMVAULT_PASSPHRASE` is exported (without it the command
    /// prompts, or refuses, like a shell without the variable).
    env_pass: bool,
    /// Rewrites the freshly initialised vault before the run.
    mutate: Option<fn(&Path)>,
    reads: Vec<&'static str>,
}

fn case<S: AsRef<str>>(name: &str, args: &[S], stdin: &[u8]) -> Case {
    Case {
        name: name.to_owned(),
        args: args.iter().map(|arg| arg.as_ref().to_owned()).collect(),
        stdin: stdin.to_vec(),
        init: true,
        passphrase: PASS,
        env_pass: true,
        mutate: None,
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
    fn no_env(mut self) -> Self {
        self.env_pass = false;
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
        // (7) the pipe warning: `--no-pipe-warning` and `--quiet` both
        // suppress it, on every prompting path.
        case(
            "pipe warning on a field prompt",
            &["set", "w/a.note"],
            b"hello\n",
        )
        .reads(&["w/a.note"]),
        case(
            "--no-pipe-warning on a field prompt",
            &["--no-pipe-warning", "set", "w/a.note"],
            b"hello\n",
        )
        .reads(&["w/a.note"]),
        case(
            "--no-pipe-warning after the command",
            &["set", "w/a.note", "--no-pipe-warning"],
            b"hello\n",
        )
        .reads(&["w/a.note"]),
        case(
            "--quiet on a field prompt",
            &["--quiet", "set", "w/a.note"],
            b"hello\n",
        )
        .reads(&["w/a.note"]),
        case(
            "--no-pipe-warning on a sensitive prompt",
            &["--no-pipe-warning", "set", "w/a.api_key"],
            b"s3cretvalue\ns3cretvalue\n",
        )
        .reads(&["w/a.api_key"]),
        case(
            "--no-pipe-warning on the entry prompts",
            &["--no-pipe-warning", "set", "w/a"],
            b"alice\nStrongPassword123!\nhttps://x.test\n\n",
        )
        .reads(&["w/a.username", "w/a.password"]),
        case(
            "pipe warning on the unlock prompt",
            &["list"],
            b"wrong wrong wrong wrong\n",
        )
        .no_env(),
        case(
            "--no-pipe-warning on the unlock prompt",
            &["--no-pipe-warning", "list"],
            b"wrong wrong wrong wrong\n",
        )
        .no_env(),
        // (8) piped values are raw bytes: Go stores each invalid UTF-8 byte
        // as U+FFFD.
        case(
            "non-UTF-8 field prompt",
            &["set", "w/a.note"],
            b"caf\xe9 \xe2\x82x\n",
        )
        .reads(&["w/a.note"]),
        case(
            "non-UTF-8 sensitive prompt",
            &["set", "w/a.api_key"],
            b"caf\xe9secret\ncaf\xe9secret\n",
        )
        .reads(&["w/a.api_key"]),
        case(
            "non-UTF-8 --stdin-value",
            &["set", "w/a.note", "--stdin-value"],
            b"caf\xe9 \xe2\x82x\n",
        )
        .reads(&["w/a.note"]),
        case(
            "non-UTF-8 entry prompts",
            &["set", "w/a"],
            b"al\xefce\nStrongPassword123!\nhttps://x.test/\xff\n\n",
        )
        .reads(&["w/a.username", "w/a.url"]),
        case("CRLF field prompt", &["set", "w/a.note"], b"hi\r\n").reads(&["w/a.note"]),
        case(
            "padded field prompt",
            &["set", "w/a.note"],
            b"  hi there \t\n",
        )
        .reads(&["w/a.note"]),
        // (9) Go's `bufio.Reader` over stdin takes what is piped for `set`'s
        // prompts, so a passphrase prompt after them finds end of input;
        // `--value` leaves the pipe to the unlock prompt.
        case(
            "unlock prompt after a field prompt",
            &["set", "w/a.note"],
            b"hello\ncorrect horse battery staple\n",
        )
        .no_env(),
        case(
            "unlock prompt after the entry prompts",
            &["set", "w/a"],
            b"alice\nStrongPassword123!\n\n\ncorrect horse battery staple\n",
        )
        .no_env(),
        case(
            "unlock prompt after --value",
            &["set", "w/a.note", "--value", "x"],
            b"correct horse battery staple\n",
        )
        .no_env()
        .reads(&["w/a.note"]),
        case(
            "unlock prompt after --stdin-value",
            &["set", "w/a.note", "--stdin-value"],
            b"x\ncorrect horse battery staple\n",
        )
        .no_env(),
        case(
            "get does not prompt off a terminal",
            &["get", "w/a.password"],
            b"correct horse battery staple\n",
        )
        .no_env(),
        case(
            "get --print does not prompt off a terminal",
            &["get", "w/a.password", "--print"],
            b"",
        )
        .no_env(),
        case("list prompts off a terminal", &["list"], b"").no_env(),
        case(
            "list with a wrong piped passphrase",
            &["list"],
            b"wrong wrong wrong wrong\n",
        )
        .no_env(),
        case(
            "delete prompts off a terminal",
            &["delete", "w/a", "--yes"],
            b"wrong wrong wrong wrong\n",
        )
        .no_env(),
    ]
}

const OTHER_KEY: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
const AGE_INTRO: &str = "age-encryption.org/v1\n";

/// How `identity.age` and `recipients.txt` are damaged for an open failure.
struct Damage {
    label: &'static str,
    passphrase: &'static str,
    mutate: Option<fn(&Path)>,
}

fn write_recipients(root: &Path, content: &str) {
    fs::write(root.join("recipients.txt"), content).expect("recipients.txt");
}

fn write_identity(root: &Path, content: &[u8]) {
    fs::write(root.join("identity.age"), content).expect("identity.age");
}

fn scrypt_shaped(stanza_args: &str) -> Vec<u8> {
    let mac = "A".repeat(43);
    let body = "A".repeat(43);
    format!("{AGE_INTRO}-> scrypt {stanza_args}\n{body}\n--- {mac}\n").into_bytes()
}

/// Every way Go can fail to open a vault whose identity the passphrase does
/// not open, run through each command that unlocks one: the text, the number
/// of times it is printed and the exit status are Go's.
fn open_failure_cases() -> Vec<Case> {
    let damages = [
        Damage {
            label: "wrong passphrase, no recipients.txt",
            passphrase: WRONG,
            mutate: None,
        },
        Damage {
            label: "wrong passphrase, valid recipients.txt",
            passphrase: WRONG,
            mutate: Some(|root| write_recipients(root, &format!("{OTHER_KEY}\n"))),
        },
        Damage {
            label: "wrong passphrase of the same length, valid recipients.txt",
            passphrase: "x                           ",
            mutate: Some(|root| write_recipients(root, &format!("# keys\n\n{OTHER_KEY}\r\n"))),
        },
        Damage {
            label: "wrong passphrase, empty recipients.txt",
            passphrase: WRONG,
            mutate: Some(|root| write_recipients(root, "")),
        },
        Damage {
            label: "wrong passphrase, garbage recipients.txt",
            passphrase: WRONG,
            mutate: Some(|root| write_recipients(root, "not a key\n")),
        },
        Damage {
            label: "wrong passphrase, valid and garbage recipients.txt",
            passphrase: WRONG,
            mutate: Some(|root| write_recipients(root, &format!("{OTHER_KEY}\nnope\n"))),
        },
        Damage {
            label: "wrong passphrase, comment-only recipients.txt",
            passphrase: WRONG,
            mutate: Some(|root| write_recipients(root, "# only a comment\n")),
        },
        Damage {
            label: "wrong passphrase, symlinked recipients.txt",
            passphrase: WRONG,
            mutate: Some(|root| {
                fs::write(root.join("real.txt"), format!("{OTHER_KEY}\n")).expect("real");
                std::os::unix::fs::symlink(root.join("real.txt"), root.join("recipients.txt"))
                    .expect("symlink");
            }),
        },
        Damage {
            label: "wrong passphrase, recipients.txt is a directory",
            passphrase: WRONG,
            mutate: Some(|root| fs::create_dir(root.join("recipients.txt")).expect("dir")),
        },
        Damage {
            label: "truncated identity, valid recipients.txt",
            passphrase: PASS,
            mutate: Some(|root| {
                let identity = fs::read(root.join("identity.age")).expect("identity");
                write_identity(root, &identity[..identity.len() / 2]);
                write_recipients(root, &format!("{OTHER_KEY}\n"));
            }),
        },
        Damage {
            label: "garbage identity",
            passphrase: PASS,
            mutate: Some(|root| write_identity(root, &b"garbage not age data\n".repeat(5))),
        },
        Damage {
            label: "empty identity",
            passphrase: PASS,
            mutate: Some(|root| write_identity(root, b"")),
        },
        Damage {
            label: "identity without a newline",
            passphrase: PASS,
            mutate: Some(|root| write_identity(root, b"abc")),
        },
        Damage {
            label: "identity with a Latin-1 intro",
            passphrase: PASS,
            mutate: Some(|root| write_identity(root, b"caf\xe9 junk\n")),
        },
        Damage {
            label: "identity that is a private key",
            passphrase: PASS,
            mutate: Some(|root| write_identity(root, b"AGE-SECRET-KEY-1ABCDEF\n")),
        },
        Damage {
            label: "identity with only the intro",
            passphrase: PASS,
            mutate: Some(|root| write_identity(root, AGE_INTRO.as_bytes())),
        },
        Damage {
            label: "identity with a malformed stanza body",
            passphrase: PASS,
            mutate: Some(|root| {
                write_identity(root, format!("{AGE_INTRO}-> foo\n!!!!\n").as_bytes());
            }),
        },
        Damage {
            label: "identity with a malformed closing line",
            passphrase: PASS,
            mutate: Some(|root| {
                write_identity(root, format!("{AGE_INTRO}-> foo\n\n--- AAAA\n").as_bytes());
            }),
        },
        Damage {
            label: "identity for another recipient type",
            passphrase: PASS,
            mutate: Some(|root| {
                let mac = "A".repeat(43);
                write_identity(
                    root,
                    format!("{AGE_INTRO}-> X25519 abc\n{mac}\n--- {mac}\n").as_bytes(),
                );
            }),
        },
        Damage {
            label: "scrypt identity, wrong passphrase",
            passphrase: WRONG,
            mutate: Some(|root| write_identity(root, &scrypt_shaped("AAAAAAAAAAAAAAAAAAAAAA 10"))),
        },
        Damage {
            label: "scrypt identity, work factor too large",
            passphrase: PASS,
            mutate: Some(|root| write_identity(root, &scrypt_shaped("AAAAAAAAAAAAAAAAAAAAAA 30"))),
        },
        Damage {
            label: "scrypt identity, missing work factor",
            passphrase: PASS,
            mutate: Some(|root| write_identity(root, &scrypt_shaped("AAAAAAAAAAAAAAAAAAAAAA"))),
        },
    ];
    let commands: [(&str, &[&str]); 9] = [
        ("get", &["get", "w/a.password"]),
        ("list", &["list"]),
        ("set", &["set", "w/a.password", "--value", STRONG]),
        ("add", &["add", "w/b", "--value", STRONG]),
        ("delete", &["delete", "w/a", "--yes"]),
        ("find", &["find", "a"]),
        ("edit", &["edit", "w/a"]),
        // `unlock` and `verify` print `open vault: load identity: ...` twice,
        // like every other command (SET-004).
        ("unlock", &["unlock"]),
        ("verify", &["verify"]),
    ];
    let mut out = Vec::new();
    for damage in &damages {
        for (command, args) in commands {
            let mut case = case(&format!("{command}: {}", damage.label), args, b"");
            case.passphrase = damage.passphrase;
            case.mutate = damage.mutate;
            out.push(case);
        }
    }
    out
}

fn environment(root: &Path, home: &Path, passphrase: &str) -> Vec<(&'static str, String)> {
    environment_with(root, home, Some(passphrase))
}

fn environment_with(
    root: &Path,
    home: &Path,
    passphrase: Option<&str>,
) -> Vec<(&'static str, String)> {
    let home = home.display().to_string();
    let mut environment = vec![
        ("PATH", env::var("PATH").unwrap_or_default()),
        ("XDG_CONFIG_HOME", format!("{home}/config")),
        ("XDG_DATA_HOME", format!("{home}/data")),
        ("XDG_CACHE_HOME", format!("{home}/cache")),
        ("HOME", home),
        ("SYMVAULT_VAULT", root.display().to_string()),
        ("SYMVAULT_TEST_KEYRING", "memory".to_owned()),
        ("CI", "1".to_owned()),
    ];
    if let Some(passphrase) = passphrase {
        environment.push(("SYMVAULT_PASSPHRASE", passphrase.to_owned()));
        environment.push(("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1".to_owned()));
    }
    environment
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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Observed {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    created: Option<Vec<String>>,
    reads: BTreeMap<String, (Option<i32>, String)>,
}

fn setup(parent: &Path, init: bool, mutate: Option<fn(&Path)>) -> (PathBuf, PathBuf) {
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
        if let Some(mutate) = mutate {
            mutate(&root);
        }
    }
    (root, home)
}

fn run_piped(binary: &Path, parent: &Path, case: &Case) -> Observed {
    let (root, home) = setup(parent, case.init, case.mutate);
    let before = files(&root);
    let mut child = Command::new(binary)
        .args(&case.args)
        .env_clear()
        .envs(environment_with(
            &root,
            &home,
            case.env_pass.then_some(case.passphrase),
        ))
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

#[test]
fn set_matches_the_go_oracle_on_piped_input() {
    let observations = Observations::begin(
        "set_differential",
        "set_matches_the_go_oracle_on_piped_input",
        Some(ORACLE_COMMIT),
    );
    let rust = PathBuf::from(RUST);
    let mut cases = cases();
    cases.extend(open_failure_cases());
    let mut failures = Vec::new();
    for batch in cases.chunks(6) {
        let results: Vec<_> = thread::scope(|scope| {
            batch
                .iter()
                .map(|case| {
                    let (observations, rust) = (&observations, &rust);
                    scope.spawn(move || {
                        let temp = tempfile::Builder::new()
                            .prefix("symvault-set-diff-")
                            .tempdir()
                            .expect("temp");
                        let go_run = observations.observe(&case.name, |go| {
                            serde_json::to_value(run_piped(go, &temp.path().join("go"), case))
                                .expect("Go run json")
                        });
                        let go_run: Observed =
                            serde_json::from_value(go_run).expect("recorded Go run");
                        let rust_run = run_piped(rust, &temp.path().join("rs"), case);
                        (case.name.clone(), go_run, rust_run)
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
    assert_eq!(observations.count(), cases.len());
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
    let (root, home) = setup(parent, case.init, None);
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
    let observations = Observations::begin(
        "set_differential",
        "set_matches_the_go_oracle_on_a_terminal_stdin",
        Some(ORACLE_COMMIT),
    );
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
        let go_run = observations.observe(case.name, |go| {
            serde_json::to_value(run_pty(go, &temp.path().join("go"), case)).expect("Go run json")
        });
        let go_run: Observed = serde_json::from_value(go_run).expect("recorded Go run");
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
    assert_eq!(observations.count(), cases.len());
}

/// Answers prompts like a person at a terminal: the child gets a controlling
/// terminal of its own (stdin is its slave side) while stderr and stdout stay
/// pipes, so the prompts, the line feed Go prints after a hidden read and the
/// terminal's own echo can be told apart.
const PROMPT_DRIVER: &str = r####"import fcntl, json, os, pty, select, subprocess, sys, termios, time
spec = json.load(open(sys.argv[1]))
master, slave = pty.openpty()
proc = subprocess.Popen([spec["binary"]] + spec["args"], env=spec["env"], cwd=spec["cwd"],
                        stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        start_new_session=True,
                        preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
os.close(slave)
steps = [tuple(step) for step in spec["steps"]]
err = b""; out = b""; echo = b""
fe, fo = proc.stderr.fileno(), proc.stdout.fileno()
os.set_blocking(fe, False); os.set_blocking(fo, False)
open_fds = {fe, fo}
deadline = time.time() + 60
while open_fds and time.time() < deadline:
    ready, _, _ = select.select(list(open_fds) + [master], [], [], 0.2)
    for fd in ready:
        try:
            data = os.read(fd, 4096)
        except OSError:
            data = b""
        if fd == master:
            echo += data
            continue
        if not data:
            open_fds.discard(fd)
            continue
        if fd == fe:
            err += data
        else:
            out += data
    if steps and steps[0][0].encode() in err.split(b"\n")[-1]:
        time.sleep(0.15)
        try:
            os.write(master, steps[0][1].encode())
        except OSError:
            pass
        steps.pop(0)
if open_fds:
    proc.kill()
proc.wait()
try:
    while select.select([master], [], [], 0.1)[0]:
        data = os.read(master, 4096)
        if not data:
            break
        echo += data
except OSError:
    pass
os.close(master)
print(json.dumps({"rc": proc.returncode, "stdout": out.hex(), "stderr": err.hex(),
                  "echo": echo.hex(), "left": len(steps)}))
"####;

struct PromptCase {
    name: &'static str,
    args: &'static [&'static str],
    /// `(text expected at the end of stderr, what is typed once it shows)`.
    steps: &'static [(&'static str, &'static str)],
    init: bool,
    /// Exports `SYMVAULT_PASSPHRASE`; without it the unlock prompt appears.
    env_pass: bool,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Prompted {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    echo: String,
    unanswered: i64,
    created: Option<Vec<String>>,
}

fn run_prompted(binary: &Path, parent: &Path, case: &PromptCase) -> Prompted {
    let (root, home) = setup(parent, case.init, None);
    let before = files(&root);
    let spec = json!({
        "binary": binary,
        "args": case.args,
        "steps": case.steps,
        "cwd": root.parent().unwrap(),
        "env": environment_with(&root, &home, case.env_pass.then_some(PASS))
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
    });
    let spec_path = parent.join("spec.json");
    fs::write(&spec_path, spec.to_string()).expect("spec");
    let driven = Command::new("python3")
        .args(["-I", "-c", PROMPT_DRIVER])
        .arg(&spec_path)
        .output()
        .expect("python3 is required to drive the pty");
    assert!(
        driven.status.success(),
        "{} prompt driver: {}",
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
    Prompted {
        code: driven["rc"].as_i64().map(|code| code as i32),
        stdout: normalise(&decode("stdout"), &root, &home),
        stderr: normalise(&decode("stderr"), &root, &home),
        echo: normalise(&decode("echo"), &root, &home),
        unanswered: driven["left"].as_i64().unwrap_or(-1),
        created,
    }
}

type Steps = &'static [(&'static str, &'static str)];

fn answered(
    name: &'static str,
    args: &'static [&'static str],
    steps: Steps,
    init: bool,
) -> PromptCase {
    PromptCase {
        name,
        args,
        steps,
        init,
        env_pass: true,
    }
}

fn locked(name: &'static str, args: &'static [&'static str], steps: Steps) -> PromptCase {
    PromptCase {
        name,
        args,
        steps,
        init: true,
        env_pass: false,
    }
}

const USERNAME: &str = "Username (optional): ";
const STRONG_LINE: &str = "StrongPassword123!\r";
const PASS_LINE: &str = "correct horse battery staple\r";

#[test]
fn set_matches_the_go_oracle_on_answered_prompts() {
    let observations = Observations::begin(
        "set_differential",
        "set_matches_the_go_oracle_on_answered_prompts",
        Some(ORACLE_COMMIT),
    );
    let rust = PathBuf::from(RUST);
    let cases = [
        answered(
            "sensitive field",
            &["set", "w/a.password"],
            &[
                ("Enter value for password: ", STRONG_LINE),
                ("Confirm value for password: ", STRONG_LINE),
            ],
            true,
        ),
        answered(
            "sensitive field, mismatch",
            &["set", "w/a.password"],
            &[
                ("Enter value for password: ", STRONG_LINE),
                ("Confirm value for password: ", "other\r"),
            ],
            true,
        ),
        answered(
            "sensitive field, empty",
            &["set", "w/a.password"],
            &[("Enter value for password: ", "\r")],
            true,
        ),
        answered(
            "sensitive field, empty --allow-empty",
            &["set", "w/a.password", "--allow-empty"],
            &[("Enter value for password: ", "\r")],
            true,
        ),
        answered(
            "sensitive field, empty confirmation",
            &["set", "w/a.password"],
            &[
                ("Enter value for password: ", STRONG_LINE),
                ("Confirm value for password: ", "\r"),
            ],
            true,
        ),
        answered(
            "plain field",
            &["set", "w/a.note"],
            &[("Enter value for note: ", "hello world\r")],
            true,
        ),
        answered(
            "plain field, empty",
            &["set", "w/a.note"],
            &[("Enter value for note: ", "\r")],
            true,
        ),
        answered(
            "plain field, padded",
            &["set", "w/a.note"],
            &[("Enter value for note: ", "  hi there \r")],
            true,
        ),
        answered(
            "entry",
            &["set", "w/b"],
            &[
                (USERNAME, "bob\r"),
                ("Password: ", STRONG_LINE),
                ("URL (optional): ", "https://x.test\r"),
                ("TOTP Secret (optional): ", "\r"),
            ],
            true,
        ),
        answered(
            "entry with a TOTP secret",
            &["set", "w/b"],
            &[
                (USERNAME, "\r"),
                ("Password: ", STRONG_LINE),
                ("URL (optional): ", "\r"),
                (
                    "TOTP Secret (optional): ",
                    "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\r",
                ),
            ],
            true,
        ),
        answered(
            "entry with a bad TOTP secret",
            &["set", "w/b"],
            &[
                (USERNAME, "\r"),
                ("Password: ", STRONG_LINE),
                ("URL (optional): ", "\r"),
                ("TOTP Secret (optional): ", "SHORT\r"),
            ],
            true,
        ),
        answered(
            "entry with --totp-secret",
            &["set", "w/b", "--totp-secret", SECRET],
            &[
                (USERNAME, "\r"),
                ("Password: ", STRONG_LINE),
                ("URL (optional): ", "\r"),
            ],
            true,
        ),
        answered(
            "weak password, use anyway",
            &["set", "w/b"],
            &[
                (USERNAME, "\r"),
                ("Password: ", "abc\r"),
                ("(y/N): ", "y\r"),
                ("URL (optional): ", "\r"),
                ("TOTP Secret (optional): ", "\r"),
            ],
            true,
        ),
        answered(
            "weak password, refused",
            &["set", "w/b"],
            &[
                (USERNAME, "\r"),
                ("Password: ", "abc\r"),
                ("(y/N): ", "n\r"),
            ],
            true,
        ),
        answered(
            "weak password, default answer",
            &["set", "w/b"],
            &[(USERNAME, "\r"), ("Password: ", "abc\r"), ("(y/N): ", "\r")],
            true,
        ),
        answered(
            "weak password, --force",
            &["set", "w/b", "--force"],
            &[
                (USERNAME, "\r"),
                ("Password: ", "abc\r"),
                ("URL (optional): ", "\r"),
                ("TOTP Secret (optional): ", "\r"),
            ],
            true,
        ),
        answered(
            "weak password, --quiet",
            &["--quiet", "set", "w/b"],
            &[
                (USERNAME, "\r"),
                ("Password: ", "abc\r"),
                ("(y/N): ", "y\r"),
                ("URL (optional): ", "\r"),
                ("TOTP Secret (optional): ", "\r"),
            ],
            true,
        ),
        answered(
            "empty password",
            &["set", "w/b"],
            &[
                (USERNAME, "u\r"),
                ("Password: ", "\r"),
                ("URL (optional): ", "\r"),
                ("TOTP Secret (optional): ", "\r"),
            ],
            true,
        ),
        answered(
            "entry, vault not initialised",
            &["set", "w/b"],
            &[
                (USERNAME, "u\r"),
                ("Password: ", STRONG_LINE),
                ("URL (optional): ", "\r"),
                ("TOTP Secret (optional): ", "\r"),
            ],
            false,
        ),
        locked(
            "unlock prompt, right passphrase (get)",
            &["get", "w/a.password"],
            &[("Passphrase: ", PASS_LINE)],
        ),
        locked(
            "unlock prompt, right passphrase (list)",
            &["list"],
            &[("Passphrase: ", PASS_LINE)],
        ),
        locked(
            "unlock prompt, wrong passphrase (list)",
            &["list"],
            &[("Passphrase: ", "wrong wrong wrong wrong\r")],
        ),
        locked(
            "unlock prompt, wrong passphrase (get)",
            &["get", "w/a.password"],
            &[("Passphrase: ", "wrong wrong wrong wrong\r")],
        ),
        locked(
            "unlock prompt, wrong passphrase (set --value)",
            &["set", "w/a.note", "--value", "x"],
            &[("Passphrase: ", "wrong wrong wrong wrong\r")],
        ),
        locked(
            "unlock prompt, empty answer (list)",
            &["list"],
            &[("Passphrase: ", "\r")],
        ),
        locked(
            "unlock prompt after a field prompt",
            &["set", "w/a.note"],
            &[
                ("Enter value for note: ", "hello\r"),
                ("Passphrase: ", PASS_LINE),
            ],
        ),
        locked(
            "unlock prompt after the entry prompts",
            &["set", "w/b"],
            &[
                (USERNAME, "bob\r"),
                ("Password: ", STRONG_LINE),
                ("URL (optional): ", "\r"),
                ("TOTP Secret (optional): ", "\r"),
                ("Passphrase: ", PASS_LINE),
            ],
        ),
        locked(
            "unlock prompt, then the delete confirmation",
            &["delete", "w/a"],
            &[("Passphrase: ", PASS_LINE), ("(y/N): ", "n\r")],
        ),
    ];
    let mut failures = Vec::new();
    for case in &cases {
        let temp = tempfile::Builder::new()
            .prefix("symvault-set-prompt-")
            .tempdir()
            .expect("temp");
        let go_run = observations.observe(case.name, |go| {
            serde_json::to_value(run_prompted(go, &temp.path().join("go"), case))
                .expect("Go run json")
        });
        let go_run: Prompted = serde_json::from_value(go_run).expect("recorded Go run");
        let rust_run = run_prompted(&rust, &temp.path().join("rs"), case);
        assert_eq!(
            go_run.unanswered, 0,
            "{}: the oracle left a prompt unanswered: {go_run:?}",
            case.name
        );
        if go_run != rust_run {
            failures.push(format!(
                "{}\n  go:   {go_run:?}\n  rust: {rust_run:?}",
                case.name
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} prompt cases differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
    assert_eq!(observations.count(), cases.len());
}
