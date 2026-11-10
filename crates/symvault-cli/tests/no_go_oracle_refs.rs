//! Go-oracle reference lint (enabled by the Go removal).
//!
//! Once the Go tree is deleted, nothing under `crates/`, `scripts/`, the
//! `Makefile` or `.github/` may reach for a Go oracle or a Go toolchain: no
//! oracle-binary env var, no "require the oracle" switch, no Go toolchain pin,
//! no `go build|test|run|vet|install`, no `setup-go`, no Go linters, no
//! `Command::new("go")`, no "skipping Go" soft-skip.
//!
//! Patterns (a line matches when any of them does):
//!
//! * `SYMVAULT_[A-Z0-9_]*GO_BINARY`, `SYMVAULT_FFI_GO_DRIVER`, `SYMVAULT_GO_ORACLE`
//! * `[A-Z_]*REQUIRE_GO_ORACLE`
//! * `GOTOOLCHAIN`
//! * `Command::new("go"`, `Command::new(&go`, `Command::new(go)` and `Command::new(go_bin)` (a `go`/`go_*` variable)
//! * absolute Go paths: `/usr/local/go/bin/go`, `<anything>/bin/go`
//! * `shutil.which('go')`, `exec go`
//! * Makefile variable references `$(GO)`, `$(AREA_GO)`, `$(GO_TOOLCHAIN)`, `$(GOROOT)` (a `GO` name segment or a
//!   `GO*` environment name) and a recipe line that starts a command with `go` (`@go \`)
//! * `setup-go`
//! * `\bgo (build|test|run|vet|install)\b`
//! * `golangci`, `govulncheck`
//! * `skipping Go`
//! * list/argv forms: `['go', 'build'|'test'|'run'|'vet'|'env'|'version'|'mod'|'list'|…`
//!   (also with double quotes, or a `go` variable or constant such as `[go, 'env'`, `[GO, "build"`, `[GO_BIN, 'test'`)
//! * `go_compiler`, `pinned_go(`, the `oracle_build` module (`import`/`from`/`oracle_build_timeout`/
//!   `oracle_build.`) and the `oraclebuild` runner
//! * `go.mod` / `go.sum` named as files
//! * Go source trees: `scripts/rust-port/cmd/`, `./internal/`, `./cmd/`, or a string
//!   literal starting with `internal/`
//!
//! The last five (`PATH_PATTERNS`) are about reading or building Go at runtime. They are not
//! applied to comment lines, nor under `crates/`, where frozen-fixture provenance assertions
//! legitimately spell the archived Go paths and `go.mod` hashes.
//!
//! ## Scope and allowlist
//!
//! Scanned: `crates/`, `scripts/`, `.github/` and the `Makefile`. Not scanned
//! (they may legitimately describe the archived Go tree): `docs/**`,
//! `CHANGELOG.md`, `*.go.txt` frozen sources, `testdata/**`,
//! `scripts/rust-port/fixtures/**` and the frozen test fixtures
//! `crates/*/tests/fixtures/**` (bytes pinned by `testdata/port/FROZEN.sha256`;
//! their oracle provenance blocks quote the historical build command). This
//! file spells the patterns and excludes itself.
//!
//! `ALLOWLIST` is empty (P40c-3): no file may build or drive a Go oracle; the
//! size assertion below keeps it that way. `LINE_ALLOW` lists single lines, each tied to its file and compared as the
//! whole trimmed line (a longer line that merely contains an allowed string is still scanned): user-facing guidance
//! of the Rust CLI that must say `go install` / `go build` because it tells the user how to update a binary that was
//! installed that way, a recorded argv a Rust test asserts verbatim, and the module-file names of three digest readers.
//!
//! The matchers are hand-written (this crate has no `regex` dev-dependency and
//! the manifests are owned by the integration branch);
//! `matcher_semantics_fire_on_references_and_not_on_lookalikes` pins them
//! against the regex forms above.
//!
//! Print the hit list grouped by file with
//! `cargo test -p symvault-cli --test no_go_oracle_refs -- --nocapture`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Patterns about reading or building Go at runtime (see the module docs).
const PATH_PATTERNS: [&str; 5] = [
    "go_compiler",
    "pinned_go(",
    "oracle_build",
    "go.mod|go.sum",
    "Go source tree",
];

/// Files exempt from the lint. Empty since the Go removal sweep (P40c-3): every script that used to build or drive a
/// Go oracle now replays committed observations. Recapturing means checking out the tag `legacy/go-oracle`.
const ALLOWLIST: [&str; 0] = [];

/// This file spells the patterns it looks for.
const SELF: &str = "crates/symvault-cli/tests/no_go_oracle_refs.rs";

/// Single lines exempt from the lint: `(file, whole trimmed line)`. Nothing else on the line is exempt, so a real
/// reference hidden next to an allowed string is still reported.
const LINE_ALLOW: [(&str, &str); 11] = [
    // Guidance strings of the Rust CLI for binaries installed with the Go toolchain.
    (
        "crates/symvault-cli/src/update_commands.rs",
        "GO_INSTALL => \"Update via Go: go install github.com/danieljustus/symaira-vault@latest\",",
    ),
    (
        "crates/symvault-cli/src/update_commands.rs",
        "BUILD_FROM_SOURCE => \"Rebuild from source: git pull && go build ./cmd/symvault\",",
    ),
    // A recorded argv the Rust test asserts verbatim (frozen fixture data, never executed).
    (
        "crates/symvault-mcp/tests/execute_with_secret_contract.rs",
        "assert_eq!(command, [\"go\", \"run\", \"<fixture-child-go-source>\"]);",
    ),
    // The replay harness (`go_oracle::output`) intercepts a command whose program is the recorded oracle path; these
    // `Command` values are built for that interception and never spawn a Go binary.
    (
        "crates/symvault-cli/tests/audit_export_commands.rs",
        "Command::new(go)",
    ),
    (
        "crates/symvault-cli/tests/mcp_set_auth_method_differential.rs",
        "let mut init = Command::new(go);",
    ),
    (
        "crates/symvault-cli/tests/setup_wizard_differential.rs",
        "let output = Command::new(go)",
    ),
    // value-gate compares against a release binary of the previous Go version that the operator supplies; no Go
    // toolchain or source is involved.
    (
        "Makefile",
        "@test -n \"$(GO_BIN)\" || { echo \"value-gate: set GO_BIN=<Go release binary> (RUST_BIN defaults to $(RUST_BIN))\" >&2; exit 2; }",
    ),
    (
        "Makefile",
        "python3 -B scripts/rust-port/valuegate.py measure --go \"$(GO_BIN)\" --rust \"$(RUST_BIN)\" --out \"$(VALUE_GATE_OUT)\" $(VALUE_GATE_FLAGS)",
    ),
    // Names of the blobs excluded from the frozen source digest; read from git objects, never from the working tree.
    (
        "scripts/rust-port/fixtures_verify.py",
        "MODULE_FILES = (\"go.mod\", \"go.sum\")",
    ),
    (
        "scripts/rust-port/frozen_generator_replay.py",
        "MODULE_FILES = (\"go.mod\", \"go.sum\")",
    ),
    (
        "scripts/rust-port/mcp_authz_matrix.py",
        "MODULE_FILES = (\"go.mod\", \"go.sum\")",
    ),
];

fn line_allowed(relative: &str, line: &str) -> bool {
    LINE_ALLOW
        .iter()
        .any(|(file, allowed)| *file == relative && line.trim() == *allowed)
}

/// Scan roots: directories (recursive) and single files.
const ROOTS: [&str; 4] = ["crates", "scripts", ".github", "Makefile"];

const TEXT_EXTENSIONS: [&str; 8] = ["rs", "sh", "py", "toml", "json", "yml", "yaml", "mk"];

type Hits = BTreeMap<String, Vec<String>>;

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// `SYMVAULT_[A-Z0-9_]*GO_BINARY`: after the prefix, the maximal run of
/// `[A-Z0-9_]` contains the suffix.
fn symvault_go_binary(line: &str) -> bool {
    line.match_indices("SYMVAULT_").any(|(at, _)| {
        let rest = &line[at + "SYMVAULT_".len()..];
        let run = rest
            .bytes()
            .take_while(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
            .count();
        rest[..run].contains("GO_BINARY")
    })
}

/// `\bgo (build|test|run|vet|install)\b`.
fn go_subcommand(line: &str) -> bool {
    let bytes = line.as_bytes();
    line.match_indices("go ").any(|(at, _)| {
        if at > 0 && is_word(bytes[at - 1]) {
            return false;
        }
        let rest = &line[at + "go ".len()..];
        ["build", "test", "run", "vet", "install"]
            .iter()
            .any(|verb| {
                rest.starts_with(verb)
                    && !rest.as_bytes().get(verb.len()).is_some_and(|b| is_word(*b))
            })
    })
}

const GO_VERBS: [&str; 14] = [
    "build", "test", "run", "vet", "env", "version", "mod", "list", "install", "generate", "tool",
    "get", "work", "fmt",
];

/// Names a Go binary is held in when it is not spelled as the quoted string `go`: `go`, `GO` and the usual
/// `*_bin|binary|exe|cli|path` forms in either case.
fn go_binary_name(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "go" | "gobin" | "go_bin" | "go_binary" | "go_exe" | "go_cli" | "go_path" | "go_cmd"
    )
}

/// Argv/list form: `['go', 'build'`, `[\"go\",\"test\"`, `[go, 'env'`, `(go, \"run\"`, `[GO, \"build\"`,
/// `[GO_BIN, 'test'`.
fn go_argv(line: &str) -> bool {
    let bytes = line.as_bytes();
    let skip = |mut at: usize| {
        while at < bytes.len() && bytes[at] == b' ' {
            at += 1;
        }
        at
    };
    bytes.iter().enumerate().any(|(open, byte)| {
        if !matches!(byte, b'[' | b'(') {
            return false;
        }
        // The first element: a quoted `go`, or an identifier naming the Go binary.
        let start = skip(open + 1);
        let end = match bytes.get(start) {
            Some(q @ (b'\'' | b'"')) => {
                if !line[start + 1..].starts_with("go") || bytes.get(start + 3) != Some(q) {
                    return false;
                }
                start + 4
            }
            Some(b) if is_word(*b) => {
                let run = bytes[start..].iter().take_while(|b| is_word(**b)).count();
                if !go_binary_name(&line[start..start + run]) {
                    return false;
                }
                start + run
            }
            _ => return false,
        };
        let next = skip(end);
        if bytes.get(next) != Some(&b',') {
            return false;
        }
        let rest = &line[skip(next + 1)..];
        let Some(q) = rest.bytes().next().filter(|b| *b == b'\'' || *b == b'"') else {
            return false;
        };
        let word = &rest[1..];
        GO_VERBS
            .iter()
            .any(|verb| word.starts_with(verb) && word.as_bytes().get(verb.len()) == Some(&q))
    })
}

/// `Command::new("go"`, `Command::new(&go`, `Command::new(go)`, `Command::new(go_bin)`: a Go binary spawned from
/// a literal or from a variable named `go` / `go_*`.
fn go_command(line: &str) -> bool {
    line.match_indices("Command::new(").any(|(at, _)| {
        let rest = line[at + "Command::new(".len()..].trim_start_matches(['&', ' ']);
        if rest.starts_with("\"go\"") {
            return true;
        }
        let run = rest.bytes().take_while(|b| is_word(*b)).count();
        let name = &rest[..run];
        name == "go" || (name.starts_with("go_") && go_binary_name(name))
    })
}

/// An absolute or relative path to the Go executable: `/usr/local/go/bin/go`, `$HOME/sdk/go1.26/bin/go`,
/// `.../bin/go.exe`. `/bin/gofmt`, `/bin/go-task` and `/bin/good` are other programs.
fn go_executable_path(line: &str) -> bool {
    line.match_indices("/bin/go").any(|(at, _)| {
        let rest = &line[at + "/bin/go".len()..];
        match rest.bytes().next() {
            None => true,
            Some(b'.') => {
                rest.starts_with(".exe") && !rest.as_bytes().get(4).is_some_and(|b| is_word(*b))
            }
            Some(b) => !is_word(b) && b != b'-',
        }
    })
}

/// `shutil.which('go')`, `which("go")`, `which(['go']`: looking the Go toolchain up on `PATH`.
fn go_lookup(line: &str) -> bool {
    line.match_indices("which(").any(|(at, _)| {
        let rest = line[at + "which(".len()..].trim_start_matches(['[', ' ']);
        rest.starts_with("'go'") || rest.starts_with("\"go\"")
    })
}

/// `exec go` (a shell handing its process over to the Go tool).
fn exec_go(line: &str) -> bool {
    let bytes = line.as_bytes();
    line.match_indices("exec go").any(|(at, _)| {
        let before = at.checked_sub(1).map(|i| bytes[i]);
        let after = bytes.get(at + "exec go".len()).copied();
        !before.is_some_and(|b| is_word(b) || b == b'-')
            && !after.is_some_and(|b| is_word(b) || b == b'-' || b == b'.')
    })
}

/// A Makefile (or shell) reference to the Go toolchain: `$(GO)`, `${GO}`, `$(AREA_GO)`, `$(AREA_HTTP_GO)`,
/// `$(GO_TOOLCHAIN)`, `$(GOROOT)`. A name qualifies when one of its `_` segments is exactly `GO`, or when it is
/// one of Go's own environment names. `$(GOOD)`, `$(CARGO)` and `$(MONGO)` do not.
fn go_make_variable(line: &str) -> bool {
    // GOOS / GOARCH are release-asset naming (target triples), not the toolchain, and stay allowed.
    const GO_ENV: [&str; 9] = [
        "GOROOT",
        "GOPATH",
        "GOFLAGS",
        "GOCACHE",
        "GOMODCACHE",
        "GOBIN",
        "GOWORK",
        "GOPROXY",
        "GOENV",
    ];
    line.match_indices("$").any(|(at, _)| {
        let rest = &line[at + 1..];
        let (open, close) = match rest.bytes().next() {
            Some(b'(') => ('(', ')'),
            Some(b'{') => ('{', '}'),
            _ => return false,
        };
        let inner = &rest[open.len_utf8()..];
        let Some(end) = inner.find(close) else {
            return false;
        };
        let name = &inner[..end];
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            && (name.split('_').any(|segment| segment == "GO") || GO_ENV.contains(&name))
    })
}

/// A Makefile recipe line (starts with a tab) whose command is `go`, with the `@`/`-`/`+` markers stripped:
/// `\t@go \\`, `\tgo`. Anything after `go` may sit on a continuation line.
fn go_recipe_start(line: &str) -> bool {
    let Some(body) = line.strip_prefix('\t') else {
        return false;
    };
    let body = body.trim_start_matches(['@', '-', '+', ' ']);
    body.strip_prefix("go")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '\t', '\\']))
}

/// The oracle build harness: `import oracle_build`, `from oracle_build`,
/// `oracle_build_timeout`, `oracle_build.attr` and the `oraclebuild` runner. A bare
/// file name (`scripts/rust-port/oracle_build.py` in a path filter) is not a use.
fn oracle_build(line: &str) -> bool {
    line.contains("oraclebuild")
        || line.contains("import oracle_build")
        || line.contains("from oracle_build")
        || line.contains("oracle_build_timeout")
        || (line.contains("oracle_build.")
            && !line.contains("oracle_build.py")
            && !line.contains("oracle_build.go"))
}

/// `go.mod` / `go.sum` as a file name (not `go.module`, `ago.mod`).
fn go_module_file(line: &str) -> bool {
    let bytes = line.as_bytes();
    ["go.mod", "go.sum"].iter().any(|name| {
        line.match_indices(name).any(|(at, _)| {
            let before = at.checked_sub(1).map(|i| bytes[i]);
            let after = bytes.get(at + name.len()).copied();
            !before.is_some_and(|b| is_word(b) || b == b'-')
                && !after.is_some_and(|b| is_word(b) || b == b'-')
        })
    })
}

/// Go source trees read at runtime: `scripts/rust-port/cmd/`, `./internal/`,
/// `./cmd/` or a string literal that starts with `internal/`.
fn go_source_tree(line: &str) -> bool {
    line.contains("scripts/rust-port/cmd/")
        || line.contains("./internal/")
        || line.contains("./cmd/")
        || line.contains("'internal/")
        || line.contains("\"internal/")
}

/// Names of the patterns `line` matches.
fn matches(line: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    let mut check = |name: &'static str, hit: bool| {
        if hit {
            found.push(name);
        }
    };
    check("SYMVAULT_*GO_BINARY", symvault_go_binary(line));
    check(
        "SYMVAULT_FFI_GO_DRIVER",
        line.contains("SYMVAULT_FFI_GO_DRIVER"),
    );
    check("SYMVAULT_GO_ORACLE", line.contains("SYMVAULT_GO_ORACLE"));
    check("*REQUIRE_GO_ORACLE", line.contains("REQUIRE_GO_ORACLE"));
    check("GOTOOLCHAIN", line.contains("GOTOOLCHAIN"));
    check("Command::new(go)", go_command(line));
    check("setup-go", line.contains("setup-go"));
    check("go build|test|run|vet|install", go_subcommand(line));
    check("golangci", line.contains("golangci"));
    check("govulncheck", line.contains("govulncheck"));
    check("skipping Go", line.contains("skipping Go"));
    check("go argv list", go_argv(line));
    check("go executable path", go_executable_path(line));
    check("go PATH lookup", go_lookup(line));
    check("exec go", exec_go(line));
    check("go make variable", go_make_variable(line));
    check("go recipe line", go_recipe_start(line));
    check("go_compiler", line.contains("go_compiler"));
    check("pinned_go(", line.contains("pinned_go("));
    check("oracle_build", oracle_build(line));
    check("go.mod|go.sum", go_module_file(line));
    check("Go source tree", go_source_tree(line));
    found
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn excluded(relative: &str) -> bool {
    relative.ends_with(".go.txt")
        || relative.contains("/target/")
        || relative.starts_with("scripts/rust-port/fixtures/")
        || (relative.starts_with("crates/") && relative.contains("/tests/fixtures/"))
        || relative == SELF
        || ALLOWLIST.contains(&relative)
}

fn scannable(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "Makefile")
        || path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| TEXT_EXTENSIONS.contains(&ext))
}

fn scan_file(path: &Path, root: &Path, hits: &mut Hits, scanned: &mut usize) {
    let relative = path
        .strip_prefix(root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    if excluded(&relative) || !scannable(path) {
        return;
    }
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    *scanned += 1;
    for (number, line) in text.lines().enumerate() {
        if line_allowed(&relative, line) {
            continue;
        }
        let comment = {
            let t = line.trim_start();
            t.starts_with('#') || t.starts_with("//")
        };
        for pattern in matches(line) {
            if PATH_PATTERNS.contains(&pattern) && (comment || relative.starts_with("crates/")) {
                continue;
            }
            hits.entry(relative.clone())
                .or_default()
                .push(format!("{}: {pattern}", number + 1));
        }
    }
}

fn scan(path: &Path, root: &Path, hits: &mut Hits, scanned: &mut usize) {
    if path.is_dir() {
        if matches!(
            path.file_name().and_then(|n| n.to_str()),
            Some("target" | ".git")
        ) {
            return;
        }
        let mut entries: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        for entry in entries {
            scan(&entry, root, hits, scanned);
        }
    } else {
        scan_file(path, root, hits, scanned);
    }
}

/// Tracked plus untracked-but-not-ignored files under `sub`, as git sees them.
/// Git-ignored local run output (`.github/admin/`, `.github/audit/`, ...) is
/// never shipped and must not fail a local gate run in a used checkout. `None`
/// without a usable git; the caller then walks the filesystem.
fn git_files(root: &Path, sub: &str) -> Option<Vec<PathBuf>> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
        ])
        .arg(sub)
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let files: Vec<PathBuf> = output
        .stdout
        .split(|b| *b == 0)
        .filter(|name| !name.is_empty())
        .map(|name| root.join(String::from_utf8_lossy(name).as_ref()))
        .filter(|path| path.is_file())
        .collect();
    (!files.is_empty()).then_some(files)
}

fn hits_under(roots: &[&str]) -> (Hits, usize) {
    let root = repo_root();
    let mut hits = Hits::new();
    let mut scanned = 0;
    for sub in roots {
        let path = root.join(sub);
        assert!(path.exists(), "scan root {sub} is missing");
        match git_files(&root, sub) {
            Some(mut files) => {
                files.sort();
                for file in files {
                    scan_file(&file, &root, &mut hits, &mut scanned);
                }
            }
            None => scan(&path, &root, &mut hits, &mut scanned),
        }
    }
    (hits, scanned)
}

fn render(hits: &Hits) -> String {
    hits.iter()
        .map(|(file, lines)| format!("{file} ({}):\n  {}", lines.len(), lines.join("\n  ")))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn crates_scripts_makefile_and_workflows_have_no_go_oracle_references() {
    let (hits, scanned) = hits_under(&ROOTS);
    assert!(scanned > 100, "scanner saw only {scanned} files");
    let total: usize = hits.values().map(Vec::len).sum();
    assert!(
        hits.is_empty(),
        "{total} Go oracle reference(s) in {} file(s):\n{}",
        hits.len(),
        render(&hits)
    );
}

/// Guard: the scanner must see the roots it claims to (Makefile and `.github`
/// included), so the lint cannot pass by looking at nothing.
#[test]
fn scan_roots_cover_makefile_workflows_crates_and_scripts() {
    let root = repo_root();
    for required in [
        "Makefile",
        ".github/workflows/ci.yml",
        "crates/symvault-cli/tests/edit_differential.rs",
        "scripts/rust-port/check_config_cli.sh",
    ] {
        assert!(root.join(required).is_file(), "{required} missing");
        let (_, scanned) = hits_under(&[required]);
        assert_eq!(scanned, 1, "{required} is not scanned");
    }
    let (hits, scanned) = hits_under(&ROOTS);
    assert!(scanned > 100, "scanner saw only {scanned} files");
    // The allowlist is empty; were an entry ever added it must name a real file that still needs its exemption.
    for allowed in ALLOWLIST {
        let path = root.join(allowed);
        assert!(path.is_file(), "stale allowlist entry {allowed}");
        assert!(!hits.contains_key(allowed), "{allowed} was scanned");
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.lines().any(|line| !matches(line).is_empty()),
            "{allowed} no longer has a Go reference: drop it from ALLOWLIST"
        );
    }
    assert_eq!(
        ALLOWLIST.len(),
        0,
        "the Go-oracle allowlist must stay empty"
    );
}

/// Mutation controls: each pattern fires on a planted reference and stays quiet
/// on look-alikes.
#[test]
fn matcher_semantics_fire_on_references_and_not_on_lookalikes() {
    let fires = [
        (
            "let _ = env::var(\"SYMVAULT_GO_BINARY\");",
            "SYMVAULT_*GO_BINARY",
        ),
        ("env SYMVAULT_GO_BINARY_c069d3f2=$x", "SYMVAULT_*GO_BINARY"),
        ("SYMVAULT_PARITY_GO_BINARY=1", "SYMVAULT_*GO_BINARY"),
        ("SYMVAULT_FFI_GO_DRIVER=x", "SYMVAULT_FFI_GO_DRIVER"),
        ("SYMVAULT_GO_ORACLE=1", "SYMVAULT_GO_ORACLE"),
        ("export SYMVAULT_REQUIRE_GO_ORACLE=1", "*REQUIRE_GO_ORACLE"),
        ("REQUIRE_GO_ORACLE", "*REQUIRE_GO_ORACLE"),
        ("GOTOOLCHAIN=go1.26.6", "GOTOOLCHAIN"),
        ("Command::new(\"go\")", "Command::new(go)"),
        ("Command::new(&go)", "Command::new(go)"),
        (
            "let out = Command::new(go).arg(\"version\");",
            "Command::new(go)",
        ),
        ("Command::new(go_bin).arg(\"build\")", "Command::new(go)"),
        ("Command::new( &go_cli )", "Command::new(go)"),
        ("let go = \"/usr/local/go/bin/go\";", "go executable path"),
        ("GO=$(HOME)/sdk/go1.26.6/bin/go", "go executable path"),
        (
            "p = Path('/opt/toolchain/bin/go.exe')",
            "go executable path",
        ),
        ("checked([GO, \"build\", \"-o\", out])", "go argv list"),
        ("run([GO_BIN, 'test', './...'])", "go argv list"),
        ("run((go_path, \"vet\"))", "go argv list"),
        ("go = shutil.which('go')", "go PATH lookup"),
        ("if shutil.which([\"go\"]):", "go PATH lookup"),
        ("exec go \"$@\"", "exec go"),
        ("  exec go", "exec go"),
        ("\t$(GO) generate ./...", "go make variable"),
        (
            "\t@$(AREA_GO) $(AREA_ORACLE) python3 x.py",
            "go make variable",
        ),
        ("\t$(AREA_HTTP_GO) $(PY)", "go make variable"),
        ("TOOLCHAIN := ${GO_TOOLCHAIN}", "go make variable"),
        ("\tGOROOT=$(GOROOT) make x", "go make variable"),
        ("\t@go \\", "go recipe line"),
        ("\tgo", "go recipe line"),
        ("\t-go \\", "go recipe line"),
        ("uses: actions/setup-go@v5", "setup-go"),
        ("\tgo build ./...", "go build|test|run|vet|install"),
        ("run: go test ./...", "go build|test|run|vet|install"),
        ("(go run ./cmd/x)", "go build|test|run|vet|install"),
        ("go vet", "go build|test|run|vet|install"),
        ("sudo go install x", "go build|test|run|vet|install"),
        ("golangci-lint run", "golangci"),
        ("govulncheck ./...", "govulncheck"),
        ("echo skipping Go oracle", "skipping Go"),
        ("checked(['go', 'build', '-o', out], tree)", "go argv list"),
        (
            "checked([\"go\",\"test\",\"-c\"], cwd=tree)",
            "go argv list",
        ),
        ("subprocess.run(['go','env','GOVERSION'])", "go argv list"),
        ("run([ 'go' , 'version'])", "go argv list"),
        ("check_output(('go', 'list', '-f', x))", "go argv list"),
        ("checked([go, 'build', '.'])", "go argv list"),
        ("checked([\"go\", \"mod\", \"download\"])", "go argv list"),
        ("x = go_compiler(tree)", "go_compiler"),
        (
            "go, env, compiler = pinned_go(os.environ.copy(), source)",
            "pinned_go(",
        ),
        ("from oracle_build import build_go", "oracle_build"),
        (
            "Build scripts/rust-port/cmd/oraclebuild first",
            "oracle_build",
        ),
        ("(tree / 'go.mod').read_text()", "go.mod|go.sum"),
        ("git diff -- go.sum", "go.mod|go.sum"),
        (
            "checked(['cargo'], './scripts/rust-port/cmd/httpseed')",
            "Go source tree",
        ),
        ("path = 'internal/mcp/server/x.go'", "Go source tree"),
        ("p = ROOT / \"internal/vault\"", "Go source tree"),
        ("cmd = ['./cmd/symvault']", "Go source tree"),
    ];
    for (line, pattern) in fires {
        assert!(
            matches(line).contains(&pattern),
            "`{line}` should match {pattern}, got {:?}",
            matches(line)
        );
    }
    let quiet = [
        "cargo test -p symvault-cli",
        "let ago = build(go_to_rust);",
        "mongo build",
        "go builder",
        "go tested",
        "go_build_dir",
        "SYMVAULT_GO_BIN",
        "SYMVAULT_VAULT=/x",
        "SYMVAULT_BINARY",
        "REQUIRE_ORACLE",
        "GOTOOL",
        "Command::new(\"golang\")",
        "Command::new(\"cargo\")",
        "setup-rust",
        "cargo-golangi",
        "for implementation in ['go','rust']:",
        "assert receipt['go'] == receipt['rust']",
        "names = ('go', 'rust')",
        "checked(['cargo', 'build'])",
        "x = ['ago', 'build']",
        "x = ['go-rust', 'build']",
        "x = ['go', 'rust', 'build']",
        "x = ['go', 'builder']",
        "go.module and ago.mod",
        "cargo-go.sum",
        "let internal = 1; // crate internal/",
        "crates/symvault-core/src/internal/mod.rs",
        "README for cmd/",
        "- 'scripts/rust-port/oracle_build.py'",
        "Command::new(good)",
        "Command::new(gopher)",
        "Command::new(go_to_rust)",
        "Command::new(\"gofmt-check\")",
        "let p = \"/usr/local/go/bin/gofmt\";",
        "/usr/bin/go-task run",
        "/usr/bin/good",
        "/bin/gold",
        "cp x /usr/bin/go_to",
        "x = [GOLD, 'build']",
        "x = ['GO_TO', \"build\"]",
        "x = [GO, \"builder\"]",
        "x = (go_tests, 'run')",
        "y = shutil.which('gofmt')",
        "y = shutil.which('cargo')",
        "which(good)",
        "exec good",
        "exec gofmt",
        "exec cargo",
        "regexec go",
        "\t$(GOOD) x",
        "\t$(CARGO) test",
        "\t$(MONGO) x",
        "\t$(CARGO_TARGET_DIR)/debug",
        "X := $(ARGO_X)",
        "\t$(GOLDEN_FILE)",
        "\t@gofmt -l .",
        "\t@good \\",
        "\tgo-task x",
        "    go to the next section",
    ];
    for line in quiet {
        assert!(
            matches(line).is_empty(),
            "`{line}` matched {:?}",
            matches(line)
        );
    }
}

#[test]
fn scanner_detects_planted_references_in_every_scan_root_kind() {
    let dir = std::env::temp_dir().join(format!("no-go-oracle-refs-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("crates")).unwrap();
    fs::create_dir_all(dir.join(".github/workflows")).unwrap();
    fs::create_dir_all(dir.join("scripts/rust-port/fixtures/gen")).unwrap();
    fs::write(
        dir.join("crates/x.rs"),
        "let _ = env::var(\"SYMVAULT_GO_BINARY\");\n",
    )
    .unwrap();
    fs::write(dir.join("crates/ok.rs"), "let _ = 1;\n").unwrap();
    fs::write(
        dir.join("scripts/rust-port/argv.py"),
        "# checked(['go', 'build'])\nchecked(['go', 'build', '.'])\nopen('go.mod')\n",
    )
    .unwrap();
    fs::write(
        dir.join("crates/prov.rs"),
        "let f = \"internal/vault/x.go\"; // go.mod\n",
    )
    .unwrap();
    fs::write(dir.join("Makefile"), "t:\n\tgo test ./...\n").unwrap();
    fs::write(
        dir.join(".github/workflows/ci.yml"),
        "steps:\n  - uses: actions/setup-go@v5\n  - run: golangci-lint run\n",
    )
    .unwrap();
    fs::write(
        dir.join("scripts/rust-port/fixtures/gen/main.sh"),
        "go build\n",
    )
    .unwrap();
    let mut hits = Hits::new();
    let mut scanned = 0;
    for sub in ["crates", ".github", "scripts", "Makefile"] {
        scan(&dir.join(sub), &dir, &mut hits, &mut scanned);
    }
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(scanned, 6, "excluded fixture dir must not be scanned");
    let flat: Vec<String> = hits
        .iter()
        .flat_map(|(file, lines)| lines.iter().map(move |l| format!("{file}:{l}")))
        .collect();
    assert_eq!(
        flat,
        vec![
            ".github/workflows/ci.yml:2: setup-go",
            ".github/workflows/ci.yml:3: golangci",
            "Makefile:2: go build|test|run|vet|install",
            "Makefile:2: go recipe line",
            "crates/x.rs:1: SYMVAULT_*GO_BINARY",
            "scripts/rust-port/argv.py:1: go argv list",
            "scripts/rust-port/argv.py:2: go argv list",
            "scripts/rust-port/argv.py:3: go.mod|go.sum",
        ]
    );
}

/// The line allowance is per file and per whole trimmed line: it cannot hide a second reference that shares a line
/// with an allowed string.
#[test]
fn line_allow_is_exact_per_file_and_does_not_hide_a_second_reference() {
    let (file, allowed) = LINE_ALLOW[0];
    assert!(line_allowed(file, allowed));
    assert!(line_allowed(file, &format!("        {allowed}   ")));
    assert!(
        !line_allowed("scripts/x.py", allowed),
        "allowed only in its own file"
    );
    assert!(!line_allowed(file, &format!("{allowed} // more")));
    let planted = r#"Command::new("go").arg("build"); // go install github.com/danieljustus/symaira-vault@latest"#;
    assert!(!line_allowed(file, planted));
    assert!(
        matches(planted).contains(&"Command::new(go)"),
        "{:?}",
        matches(planted)
    );
    // The same planted line is reported by a scan of the allowed file itself.
    let dir = std::env::temp_dir().join(format!("no-go-oracle-line-allow-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let source = dir.join(file);
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(&source, format!("{allowed}\n{planted}\n")).unwrap();
    let mut hits = Hits::new();
    let mut scanned = 0;
    scan(&dir.join("crates"), &dir, &mut hits, &mut scanned);
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(scanned, 1);
    let lines: Vec<&String> = hits.get(file).into_iter().flatten().collect();
    assert!(
        lines.iter().all(|l| l.starts_with("2:"))
            && lines.iter().any(|l| l.ends_with("Command::new(go)")),
        "only the planted line 2 is reported: {lines:?}"
    );
}

/// Every allowed line still exists verbatim in its file (a stale entry must be removed).
#[test]
fn line_allow_entries_exist_verbatim() {
    let root = repo_root();
    for (file, allowed) in LINE_ALLOW {
        let text = fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert!(
            text.lines().any(|line| line.trim() == allowed),
            "stale LINE_ALLOW entry for {file}: {allowed}"
        );
        assert!(
            !matches(allowed).is_empty(),
            "{file}: entry no longer needs its exemption: {allowed}"
        );
    }
}
