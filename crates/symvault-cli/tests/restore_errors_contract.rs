//! IO-002: replay the Go-derived `restore-errors.json` corpus through the Rust
//! `restore` path. Each case compares the user-visible error text and the full
//! resulting file tree (including anything an escape would have created
//! outside the destination) with what production Go recorded.
#[path = "../src/backup_commands.rs"]
#[allow(dead_code)]
mod backup_commands;

use base64::Engine as _;
use flate2::{Compression, write::GzEncoder};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    unix_only: bool,
    wrap: String,
    tar_b64: String,
    #[serde(default)]
    pre: Vec<Pre>,
    dest: String,
    #[serde(default)]
    missing: bool,
    error: String,
    #[serde(default)]
    error_prefix: String,
    #[serde(default)]
    os_error: bool,
    tree: Vec<Node>,
}

/// Go truncates and writes a restored file in place, so a member whose data
/// ends early leaves a partial file behind. Rust stages each member and
/// renames it into place, so it never publishes (or clobbers with) a partial
/// member. This is an unapproved divergence recorded in the contract matrix,
/// not a parity claim: the paths below exist in Go's tree and not in Rust's.
const GO_PARTIAL_FILES: &[(&str, &str)] = &[
    ("truncated-member-data", "vault/entries/cut"),
    ("exact-limit-member-truncated", "vault/entries/big"),
];

#[derive(Deserialize)]
struct Pre {
    path: String,
    kind: String,
    #[serde(default)]
    mode: u32,
    #[serde(default)]
    data: String,
    #[serde(default)]
    target: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct Node {
    path: String,
    kind: String,
    #[serde(default)]
    mode: u32,
    #[serde(default)]
    size: i64,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    target: String,
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn wrapped(wrap: &str, tar: &[u8]) -> Vec<u8> {
    match wrap {
        "gzip" => gzip(tar),
        "raw" => tar.to_vec(),
        "gzip-cut" => {
            let packed = gzip(tar);
            packed[..packed.len() / 2].to_vec()
        }
        "gzip-corrupt" => {
            let mut packed = gzip(tar);
            let middle = packed.len() / 2;
            packed[middle] ^= 0xff;
            packed
        }
        "empty" => Vec::new(),
        "gzip-short-header" => gzip(tar)[..6].to_vec(),
        other => panic!("unknown wrap {other}"),
    }
}

#[cfg(unix)]
fn perm(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn perm(_: &fs::Metadata) -> u32 {
    0
}

fn snapshot(root: &Path) -> Vec<Node> {
    fn visit(root: &Path, dir: &Path, out: &mut Vec<Node>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let meta = fs::symlink_metadata(&path).unwrap();
            if rel == "input.tar.gz" {
                continue;
            }
            if meta.file_type().is_symlink() {
                out.push(Node {
                    path: rel,
                    kind: "symlink".into(),
                    mode: 0,
                    size: 0,
                    sha256: String::new(),
                    target: fs::read_link(&path)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                });
            } else if meta.is_dir() {
                out.push(Node {
                    path: rel,
                    kind: "dir".into(),
                    mode: perm(&meta),
                    size: 0,
                    sha256: String::new(),
                    target: String::new(),
                });
                visit(root, &path, out);
            } else {
                let data = fs::read(&path).unwrap();
                out.push(Node {
                    path: rel,
                    kind: "file".into(),
                    mode: perm(&meta),
                    size: data.len() as i64,
                    sha256: hex::encode(Sha256::digest(&data)),
                    target: String::new(),
                });
            }
        }
    }
    let mut out = Vec::new();
    visit(root, root, &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn seed(root: &Path, items: &[Pre]) {
    for item in items {
        let path = root.join(&item.path);
        private_dirs(path.parent().unwrap());
        match item.kind.as_str() {
            "file" => {
                fs::write(&path, &item.data).unwrap();
                set_mode(&path, item.mode);
            }
            "dir" => {
                private_dirs(&path);
                set_mode(&path, item.mode);
            }
            #[cfg(unix)]
            "symlink" => std::os::unix::fs::symlink(&item.target, &path).unwrap(),
            other => panic!("unsupported pre kind {other}"),
        }
    }
}

/// `os.MkdirAll(path, 0700)`, the way the Go generator seeds its roots.
fn private_dirs(path: &Path) {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).unwrap();
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) {}

/// Read-only directories seeded by a case must not block cleaning up its root.
#[cfg(unix)]
fn make_writable(root: &Path) {
    if let Ok(entries) = fs::read_dir(root) {
        set_mode(root, 0o700);
        for entry in entries.flatten() {
            let path = entry.path();
            if fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                make_writable(&path);
            }
        }
    }
}

#[cfg(not(unix))]
fn make_writable(_: &Path) {}

/// The part of an OS-derived message that is not host-specific text.
fn stable_prefix(message: &str) -> &str {
    message.rsplit_once(": ").map_or(message, |(head, _)| head)
}

fn run_case(case: &Case) -> Result<(), String> {
    let root = tempfile::tempdir().unwrap();
    let root_path: PathBuf = root.path().canonicalize().unwrap();
    fs::create_dir_all(root_path.join("outside")).unwrap();
    set_mode(&root_path.join("outside"), 0o700);
    seed(&root_path, &case.pre);
    let tar = base64::engine::general_purpose::STANDARD
        .decode(&case.tar_b64)
        .unwrap();
    let archive = root_path.join("input.tar.gz");
    if !case.missing {
        fs::write(&archive, wrapped(&case.wrap, &tar)).unwrap();
    }
    let dest = root_path.join(&case.dest);

    let actual = match backup_commands::restore(&dest, &archive) {
        Ok(()) => String::new(),
        Err(error) => error
            .replace(dest.to_string_lossy().as_ref(), "$DEST")
            .replace(root_path.to_string_lossy().as_ref(), "$ROOT"),
    };
    let mut problems = Vec::new();
    let matches = if !case.error_prefix.is_empty() {
        actual.starts_with(&case.error_prefix) && case.error.starts_with(&case.error_prefix)
    } else if case.os_error && !cfg!(unix) {
        stable_prefix(&actual) == stable_prefix(&case.error)
    } else {
        actual == case.error
    };
    if !matches {
        problems.push(format!(
            "error differs\n    go:   {:?}\n    rust: {:?}",
            case.error, actual
        ));
    }
    let mut tree = snapshot(&root_path);
    make_writable(&root_path);
    let mut expected = case.tree.clone();
    for (name, path) in GO_PARTIAL_FILES {
        if *name == case.name {
            let before = expected.len();
            expected.retain(|node| node.path != *path);
            assert_eq!(
                before,
                expected.len() + 1,
                "{name}: Go partial file missing"
            );
        }
    }
    if !cfg!(unix) {
        for node in tree.iter_mut().chain(expected.iter_mut()) {
            node.mode = 0;
        }
    }
    if tree != expected {
        problems.push(format!(
            "tree differs\n    go:   {expected:?}\n    rust: {tree:?}"
        ));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!("{}: {}", case.name, problems.join("\n  ")))
    }
}

#[test]
fn restore_errors_and_side_effects_match_go_corpus() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/sync/restore-errors.json"
    ))
    .unwrap();
    assert_eq!(fixture.cases.len(), 88, "corpus size changed");
    let mut failures = Vec::new();
    let mut executed = 0;
    for case in &fixture.cases {
        if case.unix_only && !cfg!(unix) {
            continue;
        }
        executed += 1;
        if let Err(message) = run_case(case) {
            failures.push(message);
        }
    }
    assert!(executed >= 70, "only {executed} cases executed");
    assert!(
        failures.is_empty(),
        "{} of {} cases diverge from Go:\n{}",
        failures.len(),
        executed,
        failures.join("\n")
    );
}

fn corpus_case(name: &str) -> Case {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/sync/restore-errors.json"
    ))
    .unwrap();
    fixture
        .cases
        .into_iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("missing corpus case {name}"))
}

/// Negative controls: the comparator must fail when Go's recorded text or
/// side effects are changed, otherwise a green corpus proves nothing.
#[test]
fn comparator_rejects_a_changed_error_message() {
    let mut case = corpus_case("unsafe-name/a//b");
    run_case(&case).expect("unmodified case matches");
    case.error = case.error.replace("path traversal", "unsafe path");
    assert!(run_case(&case).unwrap_err().contains("error differs"));
}

#[test]
fn comparator_rejects_a_changed_file_tree() {
    let mut case = corpus_case("valid-modes-clamped");
    run_case(&case).expect("unmodified case matches");
    case.tree.retain(|node| node.path != "vault/identity.age");
    assert!(run_case(&case).unwrap_err().contains("tree differs"));
}

#[test]
fn partial_member_exception_is_bounded_to_the_recorded_paths() {
    let case = corpus_case("truncated-member-data");
    // Go left an empty file behind; the exception subtracts exactly that path.
    assert!(
        case.tree
            .iter()
            .any(|node| node.path == "vault/entries/cut")
    );
    let mut tampered = corpus_case("truncated-member-data");
    tampered
        .tree
        .retain(|node| node.path != "vault/entries/cut");
    // Without the Go-side partial file the exception assertion itself fails.
    let result = std::panic::catch_unwind(|| run_case(&tampered));
    assert!(result.is_err(), "exception must not hide an absent Go path");
}
