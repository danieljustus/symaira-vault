#[path = "common/go_oracle.rs"]
mod go_oracle;

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");

/// English month abbreviations of Go's `Jan 2006` page-date layout.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Tokens of a page's `.TH` line with quoting removed.
fn th_tokens(page: &str) -> Vec<String> {
    let line = page
        .lines()
        .find(|line| line.starts_with(".TH "))
        .expect("page has a .TH header");
    line.replace('"', "")
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// Asserts the `.TH` header matches the Go oracle's `doc.GenManHeader`
/// (title, section, source, manual); only the wall-clock date is normalised.
fn assert_header_matches_oracle(page: &str, owner: &str) {
    let mut tokens = th_tokens(page);
    assert!(
        tokens.len() >= 5,
        "{owner}: truncated .TH header: {tokens:?}"
    );
    assert_eq!(tokens[0], ".TH", "{owner}: missing .TH macro");
    assert!(
        MONTHS.contains(&tokens[3].as_str()),
        "{owner}: date month missing: {tokens:?}"
    );
    assert!(
        tokens[4].parse::<i32>().is_ok(),
        "{owner}: date year missing: {tokens:?}"
    );
    tokens[3] = "<MONTH>".to_owned();
    tokens[4] = "<YEAR>".to_owned();
    assert_eq!(
        tokens,
        [
            ".TH", "SYMVAULT", "1", "<MONTH>", "<YEAR>", "Symaira", "Vault", "Symaira", "Vault",
            "Manual",
        ],
        "{owner}: .TH header does not carry the Go oracle's header"
    );
}

#[test]
fn generate_manpages_writes_command_pages_and_reports_absolute_directory() {
    let temp = TempDir::new().expect("temp directory");
    let unused = temp.path().join("unused");
    fs::create_dir(&unused).expect("create path component");
    let output_dir = temp.path().join("man");
    let requested_dir = unused.join("..").join("man");
    let output = Command::new(BINARY)
        .args(["--quiet", "generate", "manpages"])
        .arg(&requested_dir)
        .output()
        .expect("run symvault generate manpages");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("Generated manpages in {}\n", output_dir.display()),
        "the Go command reports the absolute output path even with --quiet"
    );

    let pages: Vec<_> = fs::read_dir(&output_dir)
        .expect("read generated pages")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "1"))
        .collect();
    assert!(
        pages.len() > 1,
        "expected root and nested man pages, got {pages:?}"
    );
    let root_page = pages
        .iter()
        .find(|path| path.file_name().is_some_and(|name| name == "symvault.1"))
        .expect("root man page");
    let root_contents = fs::read_to_string(root_page).expect("read root man page");
    assert!(root_contents.contains(".SH NAME"), "missing NAME section");
    assert!(root_contents.contains("symvault"), "missing command name");
    assert_header_matches_oracle(&root_contents, "root page");
}

#[test]
fn generate_manpages_reports_directory_creation_errors() {
    let temp = TempDir::new().expect("temp directory");
    let obstruction = temp.path().join("file");
    fs::write(&obstruction, "not a directory").expect("create path obstruction");
    let output_dir = obstruction.join("man");
    let output = Command::new(BINARY)
        .args(["generate", "manpages"])
        .arg(&output_dir)
        .output()
        .expect("run symvault generate manpages");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("Error: create manpage directory:"),
        "unexpected error: {stderr}"
    );
    assert!(Path::new(&obstruction).is_file());
}

fn run(binary: &Path, root: &Path, args: &[&str]) -> Output {
    run_with_env(binary, root, args, &[])
}

fn run_with_env(binary: &Path, root: &Path, args: &[&str], environment: &[(&str, &str)]) -> Output {
    let home = root.join("home");
    fs::create_dir_all(&home).expect("home directory");
    let mut command = Command::new(binary);
    command
        .args(args)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .current_dir(root);
    for (name, value) in environment {
        command.env(name, value);
    }
    go_oracle::output(&mut command).expect("run generate manpages")
}

/// Starts the replay session of one test: the Go answers (stdout, stderr,
/// status and the generated man-page tree) come from
/// `testdata/port/cli-transcripts/cli_generate_manpages.json`.
fn oracle(test: &str) -> (go_oracle::GoOracle, PathBuf) {
    let oracle = go_oracle::GoOracle::begin(
        "cli_generate_manpages",
        test,
        Some(go_oracle::CONFIG_CLI_ORACLE),
    );
    let binary = oracle.binary();
    (oracle, binary)
}

fn page_date(root: &Path) -> Vec<String> {
    let page = fs::read_to_string(root.join("man/symvault-generate-manpages.1"))
        .expect("read generated manpage");
    let tokens = th_tokens(&page);
    assert!(tokens.len() >= 5, "truncated .TH header: {tokens:?}");
    tokens[3..5].to_vec()
}

#[test]
fn empty_source_date_epoch_matches_the_go_default() {
    let (oracle, go_binary) = oracle("empty_source_date_epoch_matches_the_go_default");
    let go_root = TempDir::new().expect("go temp root");
    let rust_root = TempDir::new().expect("rust temp root");
    let args = ["generate", "manpages", "man"];
    let environment = [("SOURCE_DATE_EPOCH", ""), ("TZ", "UTC")];
    let go = run_with_env(&go_binary, go_root.path(), &args, &environment);
    let rust = run_with_env(BINARY.as_ref(), rust_root.path(), &args, &environment);

    assert_eq!(go.status.code(), Some(0), "Go stderr: {:?}", go.stderr);
    assert_eq!(
        rust.status.code(),
        Some(0),
        "Rust stderr: {:?}",
        rust.stderr
    );
    assert!(go.stderr.is_empty(), "Go stderr: {:?}", go.stderr);
    assert!(rust.stderr.is_empty(), "Rust stderr: {:?}", rust.stderr);
    assert_eq!(page_date(rust_root.path()), page_date(go_root.path()));
    assert_eq!(oracle.calls(), 1);
}

#[cfg(unix)]
#[test]
fn source_date_epoch_uses_local_timezone_at_month_boundary() {
    let (oracle, go_binary) = oracle("source_date_epoch_uses_local_timezone_at_month_boundary");
    let go_root = TempDir::new().expect("go temp root");
    let rust_root = TempDir::new().expect("rust temp root");
    let args = ["generate", "manpages", "man"];
    // 2026-09-30 12:00 UTC is already October 1 in Pacific/Kiritimati.
    let environment = [
        ("SOURCE_DATE_EPOCH", "1790769600"),
        ("TZ", "Pacific/Kiritimati"),
    ];
    let go = run_with_env(&go_binary, go_root.path(), &args, &environment);
    let rust = run_with_env(BINARY.as_ref(), rust_root.path(), &args, &environment);

    assert_eq!(go.status.code(), Some(0), "Go stderr: {:?}", go.stderr);
    assert_eq!(
        rust.status.code(),
        Some(0),
        "Rust stderr: {:?}",
        rust.stderr
    );
    assert_eq!(page_date(go_root.path()), vec!["Oct", "2026"]);
    assert_eq!(page_date(rust_root.path()), page_date(go_root.path()));
    assert_eq!(oracle.calls(), 1);
}

/// Strips each run's own root prefix so the two report lines can be compared.
fn normalize_root(text: &str, root: &Path) -> String {
    let physical = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let text = text.replace(physical.to_string_lossy().as_ref(), "<root>");
    text.replace(&root.display().to_string(), "<root>")
}

fn page_names(root: &Path) -> BTreeSet<String> {
    fs::read_dir(root.join("man"))
        .expect("read generated pages")
        .map(|entry| entry.expect("directory entry"))
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "1")
        })
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

/// Differential evidence against the recorded Go oracle (replay-or-fail); the
/// header expectations are additionally spelled out in
/// `assert_header_matches_oracle`.
#[test]
fn generate_manpages_matches_the_go_oracle() {
    let (oracle, go_binary) = oracle("generate_manpages_matches_the_go_oracle");
    let go_binary = go_binary.as_path();

    let go_root = TempDir::new().expect("go temp root");
    let rust_root = TempDir::new().expect("rust temp root");
    fs::write(go_root.path().join("obstruction"), "not a directory").expect("go obstruction");
    fs::write(rust_root.path().join("obstruction"), "not a directory").expect("rust obstruction");

    // Exit status and signal behaviour first, per the comparison order.
    let cases: [&[&str]; 5] = [
        &["generate", "manpages", "./man"],
        &["generate", "manpages"],
        &["generate", "manpages", "./man", "extra"],
        &["generate", "manpages", "./man", "--nope"],
        &["generate", "manpages", "./obstruction/man"],
    ];
    for case in cases {
        let go = run(go_binary, go_root.path(), case);
        let rust = run(BINARY.as_ref(), rust_root.path(), case);
        assert_eq!(
            go.status.code(),
            rust.status.code(),
            "{case:?}: exit status differs\ngo stderr={:?}\nrust stderr={:?}",
            String::from_utf8_lossy(&go.stderr),
            String::from_utf8_lossy(&rust.stderr)
        );
    }

    // stdout and stderr of the successful run.
    let go = run(
        go_binary,
        go_root.path(),
        &["generate", "manpages", "./man"],
    );
    let rust = run(
        BINARY.as_ref(),
        rust_root.path(),
        &["generate", "manpages", "./man"],
    );
    assert_eq!(go.status.code(), Some(0), "oracle run failed");
    assert_eq!(rust.status.code(), Some(0), "port run failed");
    assert!(go.stderr.is_empty(), "oracle stderr: {:?}", go.stderr);
    assert!(rust.stderr.is_empty(), "port stderr: {:?}", rust.stderr);
    assert_eq!(
        normalize_root(&String::from_utf8_lossy(&rust.stdout), rust_root.path()),
        normalize_root(&String::from_utf8_lossy(&go.stdout), go_root.path()),
        "stdout differs from the oracle"
    );

    // The port may lag the oracle on unported commands, but must never invent
    // a page the oracle does not write, and the shared page headers must match.
    let go_pages = page_names(go_root.path());
    let rust_pages = page_names(rust_root.path());
    assert!(!go_pages.is_empty() && !rust_pages.is_empty());
    let extra: Vec<_> = rust_pages.difference(&go_pages).collect();
    assert!(
        extra.is_empty(),
        "port generated pages the Go oracle does not: {extra:?}"
    );

    let shared = "symvault-generate-manpages.1";
    assert!(go_pages.contains(shared) && rust_pages.contains(shared));
    assert_header_matches_oracle(
        &fs::read_to_string(go_root.path().join("man").join(shared)).expect("oracle page"),
        "oracle page",
    );
    assert_header_matches_oracle(
        &fs::read_to_string(rust_root.path().join("man").join(shared)).expect("port page"),
        "port page",
    );

    // Full-text golden: every page both sides wrote is compared byte for byte
    // once the wall-clock dates (`.TH` month/year, cobra's HISTORY line) are
    // masked.
    let mut differing = Vec::new();
    let mut declared_seen = BTreeSet::new();
    for name in rust_pages.intersection(&go_pages) {
        let go_text = normalize_root(
            &fs::read_to_string(go_root.path().join("man").join(name)).expect("go page"),
            go_root.path(),
        );
        let rust_text = normalize_root(
            &fs::read_to_string(rust_root.path().join("man").join(name)).expect("rust page"),
            rust_root.path(),
        );
        let (go_text, rust_text) = (mask_dates(&go_text), mask_dates(&rust_text));
        if let Some((_, added)) = DECLARED_ADDITIONS.iter().find(|(page, _)| page == name) {
            // Declared divergence: the port documents `--allow-legacy-kdf`, which
            // the pinned Go oracle (fca3f894) predates. Go's page must be a
            // line-subsequence of Rust's and the extra lines exactly `added`.
            assert_eq!(
                extra_lines(&go_text, &rust_text),
                Some(
                    added
                        .iter()
                        .map(|line| (*line).to_owned())
                        .collect::<Vec<_>>()
                ),
                "{name}: declared divergence changed"
            );
            declared_seen.insert(name.clone());
        } else if go_text != rust_text {
            differing.push(name.clone());
        }
    }
    eprintln!(
        "man pages compared: {}; declared: {}; differing: {differing:?}",
        rust_pages.len(),
        declared_seen.len()
    );
    assert!(
        differing.is_empty(),
        "pages differ from the recorded Go pages: {differing:?}"
    );
    assert_eq!(declared_seen.len(), DECLARED_ADDITIONS.len());
    assert_eq!(oracle.calls(), 6);
}

/// Pages on which the port is ahead of the pinned Go oracle, with the exact lines
/// the port adds (see the comment at the use site).
const DECLARED_ADDITIONS: [(&str, &[&str]); 1] = [(
    "symvault-migrate-kdf.1",
    &[
        ".PP",
        "Older Argon2 budgets require --allow-legacy-kdf. This local migration retains",
        "identity/config backups and rewrites the same identity with current defaults.",
        "",
        "\\fB--allow-legacy-kdf\\fP[=false]",
        "\tAllow one exclusive historical-budget read for local Argon2 policy migration",
        "",
        ".PP",
    ],
)];

/// The lines of `rust` that remain after greedily matching every line of `go`
/// in order; `None` when `go` is not a subsequence of `rust`.
fn extra_lines(go: &str, rust: &str) -> Option<Vec<String>> {
    let mut go_lines = go.lines().peekable();
    let mut extra = Vec::new();
    for line in rust.lines() {
        if go_lines.peek() == Some(&line) {
            go_lines.next();
        } else {
            extra.push(line.to_owned());
        }
    }
    go_lines.peek().is_none().then_some(extra)
}

/// Masks the generation date: the `.TH` month/year and cobra's
/// `<d>-<Mon>-<yyyy> Auto generated by spf13/cobra` HISTORY line.
fn mask_dates(page: &str) -> String {
    page.lines()
        .map(|line| {
            if line.starts_with(".TH ") {
                let mut tokens: Vec<String> = line.split(' ').map(str::to_owned).collect();
                if tokens.len() > 4 {
                    tokens[3] = "<MONTH>".into();
                    tokens[4] = "<YEAR>".into();
                }
                tokens.join(" ")
            } else if line.contains("Auto generated by spf13/cobra") {
                "<HISTORY>".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
