use std::{
    collections::BTreeSet,
    env, fs,
    path::Path,
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
    let home = root.join("home");
    fs::create_dir_all(&home).expect("home directory");
    Command::new(binary)
        .args(args)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .current_dir(root)
        .output()
        .expect("run generate manpages")
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

/// Differential evidence against the Go oracle. Skipped unless the caller
/// exports `SYMVAULT_GO_BINARY`; the expectations themselves are checked by
/// `assert_header_matches_oracle` even when no oracle binary is available.
#[test]
fn generate_manpages_matches_the_go_oracle() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = Path::new(&go_binary);

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
}
