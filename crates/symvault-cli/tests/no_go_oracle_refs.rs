//! Go-oracle reference lint (enabled at Go removal).
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
//! * `Command::new("go"` and `Command::new(&go`
//! * `setup-go`
//! * `\bgo (build|test|run|vet|install)\b`
//! * `golangci`, `govulncheck`
//! * `skipping Go`
//!
//! The matchers are hand-written (this crate has no `regex` dev-dependency and
//! the manifests are owned by the integration branch);
//! `matcher_semantics_fire_on_references_and_not_on_lookalikes` pins them
//! against the regex forms above.
//!
//! ## Allowlist (kept minimal, each entry dies with the Go tree)
//!
//! Capture-side code that records Go output once and is never part of a replay
//! gate: the two shared recorders, the two capture scripts, and this lint (which
//! must spell the patterns). Everything else -- including every other test, the
//! `Makefile` and `.github/` -- must be clean.
//!
//! Excluded from the scan: `scripts/rust-port/cmd/**` and
//! `scripts/rust-port/internal/**` (the Go generators themselves), `*.go.txt`
//! frozen sources, docs, and `target/`.
//!
//! The test is `#[ignore]`d until the other branches that still carry hits have
//! landed; run it with `cargo test -p symvault-cli --test no_go_oracle_refs --
//! --ignored --nocapture` to print the current hit list grouped by file.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Capture-side files (see the module documentation).
const ALLOWLIST: [&str; 5] = [
    "crates/symvault-cli/tests/common/go_oracle.rs",
    "crates/symvault-cli/tests/common/go_oracle_ext.rs",
    "crates/symvault-cli/tests/no_go_oracle_refs.rs",
    "scripts/rust-port/check_config_rewrite.sh",
    "scripts/rust-port/check_output_modes_cli.sh",
];

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
    check(
        "Command::new(go)",
        line.contains("Command::new(\"go\"") || line.contains("Command::new(&go"),
    );
    check("setup-go", line.contains("setup-go"));
    check("go build|test|run|vet|install", go_subcommand(line));
    check("golangci", line.contains("golangci"));
    check("govulncheck", line.contains("govulncheck"));
    check("skipping Go", line.contains("skipping Go"));
    found
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn excluded(relative: &str) -> bool {
    relative.starts_with("scripts/rust-port/cmd/")
        || relative.starts_with("scripts/rust-port/internal/")
        || relative.ends_with(".go.txt")
        || relative.contains("/target/")
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
        for pattern in matches(line) {
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

fn hits_under(roots: &[&str]) -> (Hits, usize) {
    let root = repo_root();
    let mut hits = Hits::new();
    let mut scanned = 0;
    for sub in roots {
        let path = root.join(sub);
        assert!(path.exists(), "scan root {sub} is missing");
        scan(&path, &root, &mut hits, &mut scanned);
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
#[ignore = "enabled at Go removal"]
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

/// Always-on guard: the scanner must see the roots it claims to (Makefile and
/// `.github` included), so the ignored test cannot pass by looking at nothing.
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
    // The allowlist names real files and is exactly the documented capture side.
    for allowed in ALLOWLIST {
        assert!(
            root.join(allowed).is_file(),
            "stale allowlist entry {allowed}"
        );
        assert!(!hits.contains_key(allowed), "{allowed} was scanned");
    }
    assert_eq!(ALLOWLIST.len(), 5, "allowlist grew: document the new entry");
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
        ("uses: actions/setup-go@v5", "setup-go"),
        ("\tgo build ./...", "go build|test|run|vet|install"),
        ("run: go test ./...", "go build|test|run|vet|install"),
        ("(go run ./cmd/x)", "go build|test|run|vet|install"),
        ("go vet", "go build|test|run|vet|install"),
        ("sudo go install x", "go build|test|run|vet|install"),
        ("golangci-lint run", "golangci"),
        ("govulncheck ./...", "govulncheck"),
        ("echo skipping Go oracle", "skipping Go"),
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
    fs::create_dir_all(dir.join("scripts/rust-port/cmd/gen")).unwrap();
    fs::write(
        dir.join("crates/x.rs"),
        "let _ = env::var(\"SYMVAULT_GO_BINARY\");\n",
    )
    .unwrap();
    fs::write(dir.join("crates/ok.rs"), "let _ = 1;\n").unwrap();
    fs::write(dir.join("Makefile"), "t:\n\tgo test ./...\n").unwrap();
    fs::write(
        dir.join(".github/workflows/ci.yml"),
        "steps:\n  - uses: actions/setup-go@v5\n  - run: golangci-lint run\n",
    )
    .unwrap();
    fs::write(dir.join("scripts/rust-port/cmd/gen/main.sh"), "go build\n").unwrap();
    let mut hits = Hits::new();
    let mut scanned = 0;
    for sub in ["crates", ".github", "scripts", "Makefile"] {
        scan(&dir.join(sub), &dir, &mut hits, &mut scanned);
    }
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(scanned, 4, "excluded generator dir must not be scanned");
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
            "crates/x.rs:1: SYMVAULT_*GO_BINARY",
        ]
    );
}
