//! IO-002 / #1499: replay the Go-derived `restore-gzip-multistream.json`
//! corpus through the Rust restore path. Go's `gzip.Reader` is multistream, so
//! a tar stream split across gzip members restores as one stream and bytes
//! after a member are parsed as the next member header. Every case hands Rust
//! the exact bytes production Go received (`gz_b64`) and compares the
//! user-visible error text and the complete resulting file tree.
#[path = "../src/backup_commands.rs"]
#[allow(dead_code)]
mod backup_commands;

use base64::Engine as _;
use flate2::read::GzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const EXPECTED_CASES: usize = 61;
const FIXTURE: &str = include_str!("../../../testdata/port/sync/restore-gzip-multistream.json");

/// Go writes a restored file in place, so a member cut short leaves a partial
/// file; Rust stages and renames, leaving nothing (the unapproved divergence
/// recorded in the IO-002 row, see `restore_errors_contract.rs`). Bounded to
/// the one case below and checked against Go's recorded tree.
const GO_PARTIAL_FILES: &[(&str, &str)] = &[(
    "multistream/damaged/truncated-third-member",
    "vault/entries/b",
)];

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Clone, Deserialize)]
struct Case {
    name: String,
    tar_b64: String,
    gz_b64: String,
    dest: String,
    error: String,
    tree: Vec<Node>,
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
}

fn decode(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap()
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
            if rel == "input.tar.gz" {
                continue;
            }
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                out.push(Node {
                    path: rel,
                    kind: "dir".into(),
                    mode: perm(&meta),
                    size: 0,
                    sha256: String::new(),
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
                });
            }
        }
    }
    let mut out = Vec::new();
    visit(root, root, &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn run_case(case: &Case) -> Result<(), String> {
    let root = tempfile::tempdir().unwrap();
    let root_path: PathBuf = root.path().canonicalize().unwrap();
    fs::create_dir_all(root_path.join("outside")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root_path.join("outside"), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let archive = root_path.join("input.tar.gz");
    fs::write(&archive, decode(&case.gz_b64)).unwrap();
    let dest = root_path.join(&case.dest);
    let actual = match backup_commands::restore(&dest, &archive) {
        Ok(()) => String::new(),
        Err(error) => error
            .replace(dest.to_string_lossy().as_ref(), "$DEST")
            .replace(root_path.to_string_lossy().as_ref(), "$ROOT"),
    };
    let mut tree = snapshot(&root_path);
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
    let mut problems = Vec::new();
    if actual != case.error {
        problems.push(format!(
            "error differs\n    go:   {:?}\n    rust: {actual:?}",
            case.error
        ));
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

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).unwrap()
}

fn corpus_case(name: &str) -> Case {
    fixture()
        .cases
        .into_iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("missing corpus case {name}"))
}

#[test]
fn gzip_multistream_restore_matches_go_corpus() {
    let fixture = fixture();
    assert_eq!(fixture.cases.len(), EXPECTED_CASES, "corpus size changed");
    let failures: Vec<String> = fixture
        .cases
        .iter()
        .filter_map(|case| run_case(case).err())
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} cases diverge from Go:\n{}",
        failures.len(),
        fixture.cases.len(),
        failures.join("\n")
    );
}

/// The corpus must separate the decoders: for every split case a single-member
/// reader (the pre-#1499 `GzDecoder`) sees fewer bytes than the tar payload
/// Go restored. Without this a green replay could not tell the two apart.
#[test]
fn split_cases_are_invisible_to_a_single_member_decoder() {
    let mut checked = 0;
    for case in fixture().cases {
        if !case.name.starts_with("multistream/split/") || case.name.contains("ignored") {
            continue;
        }
        let tar = decode(&case.tar_b64);
        let mut seen = Vec::new();
        // Errors are expected (a truncated stream); only the prefix matters.
        let _ = GzDecoder::new(decode(&case.gz_b64).as_slice()).read_to_end(&mut seen);
        let empty_leading = case.name.ends_with("empty-first-member");
        let empty_trailing = case.name.ends_with("empty-last-member");
        if empty_trailing {
            assert_eq!(seen, tar, "{}: nothing follows the data", case.name);
        } else {
            assert!(
                seen.len() < tar.len() || empty_leading,
                "{}: single-member decoder already sees the whole stream",
                case.name
            );
        }
        checked += 1;
    }
    assert!(checked >= 14, "only {checked} split cases checked");
}

/// Negative controls: the comparator must fail when Go's recorded text or
/// side effects change.
#[test]
fn comparator_rejects_a_changed_error_message() {
    let mut case = corpus_case("multistream/open-trailing/ten-zero-bytes");
    run_case(&case).expect("unmodified case matches");
    assert_eq!(
        case.error,
        "restore failed: read archive: gzip: invalid header"
    );
    case.error = "restore failed: read archive: unexpected EOF".into();
    assert!(run_case(&case).unwrap_err().contains("error differs"));
}

#[test]
fn comparator_rejects_a_changed_file_tree() {
    let mut case = corpus_case("multistream/split/inside-payload");
    run_case(&case).expect("unmodified case matches");
    case.tree.retain(|node| node.path != "vault/entries/b");
    assert!(run_case(&case).unwrap_err().contains("tree differs"));
}

/// Bytes after the tar end marker are never read by Go (tar stops first), so
/// they are ignored rather than rejected.
#[test]
fn bytes_after_the_end_marker_are_ignored_like_go() {
    for name in [
        "multistream/trailing/ascii-garbage",
        "multistream/trailing/512-zero-bytes",
        "multistream/damaged/crc-single-member",
    ] {
        let case = corpus_case(name);
        assert_eq!(case.error, "", "{name}: Go accepts it");
        run_case(&case).unwrap();
    }
}
