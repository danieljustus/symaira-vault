//! ADR 0037 R11 and R12 (IO-002): the optional gzip header fields of the
//! first and a later member (`restore-gzip-header-flags.json`) and the 1 MiB
//! cap on the tar special headers `g` and `K` (`restore-tar-special-caps.json`),
//! recorded at the archived oracle `legacy/go-oracle` (`ce2390d7`) from the
//! production Go `admin.RestoreBackup` (detached program
//! `scripts/rust-port/restore_r11_r12.go.txt`). Every case hands Rust the exact
//! bytes production Go received (`gz_b64`) and compares the user-visible error
//! text and the complete resulting file tree.
#[path = "../src/backup_commands.rs"]
#[allow(dead_code)]
mod backup_commands;

use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

const GZIP_HEADER_CASES: usize = 42;
const TAR_CAP_CASES: usize = 14;
const GZIP_HEADER_FIXTURE: &str =
    include_str!("../../../testdata/port/sync/restore-gzip-header-flags.json");
const TAR_CAP_FIXTURE: &str =
    include_str!("../../../testdata/port/sync/restore-tar-special-caps.json");
const ORACLE_COMMIT: &str = "ce2390d748818a4beb413e97183b7795efa99411";

const GO_PARTIAL_FILES: &[(&str, &str)] = &[];

#[derive(Deserialize)]
struct Fixture {
    oracle: Oracle,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Oracle {
    commit: String,
    go_version: String,
    program_sha256: String,
}

#[derive(Clone, Deserialize)]
struct Case {
    name: String,
    gz_b64: String,
    dest: String,
    error: String,
    /// Go's inflater reports `flate: corrupt input before offset N`, which
    /// flate2 cannot reproduce: only the stage is compared (divergence (2) of
    /// the IO-002 row).
    #[serde(default)]
    error_prefix: String,
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
    let error_matches = if case.error_prefix.is_empty() {
        actual == case.error
    } else {
        actual.starts_with(&case.error_prefix)
    };
    if !error_matches {
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

fn fixture(text: &str) -> Fixture {
    let fixture: Fixture = serde_json::from_str(text).unwrap();
    assert_eq!(fixture.oracle.commit, ORACLE_COMMIT);
    assert_eq!(fixture.oracle.go_version, "go1.26.6");
    assert_eq!(fixture.oracle.program_sha256.len(), 64);
    fixture
}

fn replay(fixture: &Fixture) {
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

fn corpus_case(text: &str, name: &str) -> Case {
    fixture(text)
        .cases
        .into_iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("missing corpus case {name}"))
}

/// R11: FEXTRA, FNAME, FCOMMENT, FHCRC and the other header bytes of the first
/// member, then of a later member.
#[test]
fn gzip_header_flags_restore_matches_go_corpus() {
    let fixture = fixture(GZIP_HEADER_FIXTURE);
    assert_eq!(fixture.cases.len(), GZIP_HEADER_CASES, "corpus size changed");
    let accepted = fixture.cases.iter().filter(|c| c.error.is_empty()).count();
    assert!(
        accepted >= 20 && fixture.cases.len() - accepted >= 15,
        "the corpus must contain both accepted and rejected headers"
    );
    replay(&fixture);
}

/// R12: the body cap of the `g` and `K` special headers.
#[test]
fn tar_special_header_caps_restore_matches_go_corpus() {
    let fixture = fixture(TAR_CAP_FIXTURE);
    assert_eq!(fixture.cases.len(), TAR_CAP_CASES, "corpus size changed");
    for boundary in ["over-cap-by-one", "over-cap-by-512"] {
        for kind in ["pax-global", "gnu-longlink"] {
            let case = corpus_case(TAR_CAP_FIXTURE, &format!("tar-special-cap/{kind}/{boundary}"));
            assert_eq!(
                case.error, "restore failed: read archive: archive/tar: header field too long",
                "{}",
                case.name
            );
        }
    }
    replay(&fixture);
}

/// Negative controls: the comparator must fail when Go's recorded text or
/// side effects change.
#[test]
fn comparator_rejects_a_changed_error_message() {
    let mut case = corpus_case(GZIP_HEADER_FIXTURE, "gzip-header/header/fhcrc-wrong");
    run_case(&case).expect("unmodified case matches");
    assert_eq!(case.error, "restore failed: read gzip: gzip: invalid header");
    case.error = "restore failed: read gzip: unexpected EOF".into();
    assert!(run_case(&case).unwrap_err().contains("error differs"));
}

#[test]
fn comparator_rejects_a_changed_file_tree() {
    let mut case = corpus_case(GZIP_HEADER_FIXTURE, "gzip-header/header/fname");
    run_case(&case).expect("unmodified case matches");
    case.tree.retain(|node| node.path != "vault/entries/b");
    assert!(run_case(&case).unwrap_err().contains("tree differs"));
}
