//! IO-002 "complete CLI" contract: byte-differential replay of the frozen Go
//! oracle corpus `testdata/port/cli/export-backup-restore.json` through the
//! real `symvault` binary for `export`, `backup ARCHIVE` and `restore ARCHIVE`
//! (argv, confirmation, output-file handling, stdout/stderr, exit status and the
//! complete resulting file tree).
//!
//! The corpus is produced by `scripts/rust-port/cmd/exportcligen` from the
//! pinned Go binary (see `scripts/rust-port/check_export_cli.sh`). Every case
//! runs in a disposable root (HOME/XDG/cwd/vault) with a fixed umask and test
//! passphrase; vault seeds are frozen Go-written vaults, so nothing depends on a
//! random identity. All differences are collected before the test fails.
//!
//! Approved divergences (docs/adr/0030-approved-restore-and-import-divergences.md)
//! are not special-cased here: the corpus avoids inputs on which they show.
//!
//! Normalization rules (identical to the generator's, documented in the
//! fixture's `normalization` block): sandbox root -> `$ROOT`; audit-log
//! `ts`/`kid`/`hmac`/`argv_hash` placeholders; archives and manifests that a
//! command changed are compared by member list / "changed" state, not bytes.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/port/cli/export-backup-restore.json"
);
const PINNED_COMMIT: &str = "bf7f687bb8f57316e8333965635e733b8f567c72";
/// Exact number of recorded scenarios; a changed corpus must change this.
const CASE_COUNT: usize = 173;
const PASSPHRASE: &str = "correct horse battery staple";
const ROOT_MARKER: &str = "$ROOT";
/// Paths Go leaves behind and Rust deliberately does not: (case id, tree path,
/// reason). A cut-short member is written in place by Go and staged then
/// renamed by Rust, so no partial file appears
/// (docs/adr/0030-approved-restore-and-import-divergences.md, decision 1; the
/// restore-errors corpus pins the same class as `GO_PARTIAL_FILES`). The replay
/// requires the path to be absent in Rust, so a port that starts matching Go
/// here makes this entry stale and fails.
const APPROVED_GO_ONLY_PATHS: &[(&str, &str, &str)] = &[(
    "restore-archive-truncated-gzip",
    "vault/entries/unicode/ünï.age",
    "ADR 0030 decision 1: no partial file for a cut-short member",
)];
const PLACEHOLDER_ARCHIVE: &str = "<generated-archive>";
const PLACEHOLDER_REWRITE: &str = "<rewritten>";

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    go_version: String,
    goos: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_files: Vec<String>,
    generator_digest: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSpec {
    path: String,
    kind: String,
    #[serde(default)]
    mode: u32,
    #[serde(default)]
    data: String,
    #[serde(default)]
    b64: String,
    #[serde(default)]
    target: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    argv: Vec<String>,
    stdin: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    exit: i32,
    stdout: String,
    stderr: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Node {
    path: String,
    kind: String,
    mode: u32,
    size: i64,
    sha256: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    normalized: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Member {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    mode: i64,
    size: i64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ArchiveListing {
    path: String,
    complete: bool,
    members: Vec<Member>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    desc: String,
    class: String,
    #[serde(default)]
    seed: String,
    #[serde(default)]
    pre: Vec<FileSpec>,
    #[serde(default)]
    env: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    unset: Vec<String>,
    steps: Vec<Step>,
    #[serde(default)]
    stderr_tail_from: String,
    results: Vec<Expected>,
    tree: Vec<Node>,
    removed: Vec<String>,
    archives: Vec<ArchiveListing>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    seeds: std::collections::BTreeMap<String, Vec<FileSpec>>,
    cases: Vec<Case>,
}

fn load_fixture() -> Fixture {
    let raw = std::fs::read_to_string(FIXTURE).expect("read export/backup/restore fixture");
    // Repository rule: fixture loaders normalize CRLF to LF.
    serde_json::from_str(&raw.replace("\r\n", "\n")).expect("parse export/backup/restore fixture")
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `provenance.Digest`: sha256 over name NUL content NUL for each file in order.
fn provenance_digest(root: &Path, names: &[String]) -> String {
    let mut hasher = Sha256::new();
    for name in names {
        let content =
            std::fs::read(root.join(name)).unwrap_or_else(|error| panic!("read {name}: {error}"));
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
        hasher.update(&content);
        hasher.update([0u8]);
    }
    hex::encode(hasher.finalize())
}

#[test]
fn fixture_is_bound_to_the_pinned_oracle_and_checkout() {
    let fixture = load_fixture();
    assert_eq!(fixture.schema_version, 1);
    let oracle = &fixture.oracle;
    assert_eq!(oracle.commit, PINNED_COMMIT, "pinned oracle commit");
    assert_eq!(oracle.commit_sha, PINNED_COMMIT, "resolved oracle commit");
    assert_eq!(oracle.commit_sha.len(), 40, "oracle commit is a full sha");
    assert_eq!(oracle.go_version, "go1.26.6");
    assert_eq!(oracle.goos, "darwin", "recording platform");
    for required in [
        "cmd/admin/backup.go",
        "cmd/admin/export.go",
        "internal/exporter/csv.go",
        "internal/exporter/json.go",
        "internal/fsutil/createsensitiveoutput.go",
    ] {
        assert!(
            oracle.source_files.iter().any(|name| name == required),
            "source_files must pin {required}"
        );
    }
    let mut sorted = oracle.source_files.clone();
    sorted.sort();
    assert_eq!(sorted, oracle.source_files, "source_files stored sorted");

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Dependency manifests are recorded but never enforced (provenance.EnforcedSources).
    let enforced: Vec<String> = oracle
        .source_files
        .iter()
        .filter(|name| !matches!(name.as_str(), "go.mod" | "go.sum"))
        .cloned()
        .collect();
    assert_eq!(
        provenance_digest(&root, &enforced),
        oracle.source_digest,
        "Go contract source changed since fixture capture - re-freeze \
         testdata/port/cli/export-backup-restore.json (see scripts/rust-port/check_export_cli.sh)"
    );
    assert_eq!(
        provenance_digest(&root, &oracle.generator_files),
        oracle.generator_digest,
        "exportcligen changed since fixture capture - regenerate the fixture deliberately"
    );
}

#[test]
fn corpus_covers_every_command_and_flag_surface() {
    let fixture = load_fixture();
    assert_eq!(fixture.cases.len(), CASE_COUNT, "recorded case count");
    let mut ids = std::collections::BTreeSet::new();
    for case in &fixture.cases {
        assert!(ids.insert(case.id.clone()), "duplicate case id {}", case.id);
        assert_eq!(case.steps.len(), case.results.len(), "{}: results", case.id);
        assert!(!case.desc.is_empty(), "{}: description", case.id);
    }
    let argv_has = |token: &str| {
        fixture.cases.iter().any(|case| {
            case.steps
                .iter()
                .any(|step| step.argv.iter().any(|arg| arg == token))
        })
    };
    for command in ["export", "backup", "restore"] {
        assert!(argv_has(command), "no case runs {command}");
    }
    // Every flag of the three commands, each by at least one case.
    for flag in [
        "--format",
        "--mapping",
        "--output",
        "--yes",
        "-y",
        "--exclude-git",
        "--vault",
        "--quiet",
    ] {
        assert!(
            fixture
                .cases
                .iter()
                .any(|case| case.steps.iter().any(|step| {
                    step.argv
                        .iter()
                        .any(|arg| arg == flag || arg.starts_with(&format!("{flag}=")))
                })),
            "no case uses {flag}"
        );
    }
    // Negative controls must be a substantial share of the corpus.
    let failing = fixture
        .cases
        .iter()
        .filter(|case| case.results.iter().any(|result| result.exit != 0))
        .count();
    assert!(
        failing * 4 >= fixture.cases.len(),
        "too few failing cases: {failing}"
    );
}

#[cfg(unix)]
mod replay {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::{Read, Write};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use base64::Engine as _;

    const STEP_TIMEOUT: Duration = Duration::from_secs(20);

    struct Sandbox {
        _dir: tempfile::TempDir,
        root: PathBuf,
    }

    impl Sandbox {
        fn new() -> Self {
            let dir = tempfile::TempDir::new().expect("sandbox root");
            let root = dir.path().to_path_buf();
            for name in ["home", "work", "tmp"] {
                let path = root.join(name);
                std::fs::create_dir(&path).unwrap();
                set_mode(&path, 0o700);
            }
            Self { _dir: dir, root }
        }

        fn expand(&self, text: &str) -> String {
            let root = self.root.to_string_lossy();
            text.replace("{ROOT}", &root)
                .replace("{HOME}", &self.root.join("home").to_string_lossy())
                .replace("{WORK}", &self.root.join("work").to_string_lossy())
                .replace("{VAULT}", &self.root.join("vault").to_string_lossy())
        }

        fn normalize(&self, text: &str) -> String {
            let mut roots = vec![self.root.to_string_lossy().into_owned()];
            if let Ok(resolved) = std::fs::canonicalize(&self.root) {
                let resolved = resolved.to_string_lossy().into_owned();
                if resolved != roots[0] {
                    roots.insert(0, resolved);
                }
            }
            roots.iter().fold(text.to_owned(), |text, root| {
                text.replace(root.as_str(), ROOT_MARKER)
            })
        }

        fn environment(&self, case: &Case) -> BTreeMap<String, String> {
            let root = self.root.to_string_lossy().into_owned();
            let home = self.root.join("home").to_string_lossy().into_owned();
            let mut env = BTreeMap::new();
            for (key, value) in [
                ("PATH", "/usr/bin:/bin".to_owned()),
                ("HOME", home.clone()),
                ("USERPROFILE", home),
                ("XDG_CONFIG_HOME", format!("{root}/xdg-config")),
                ("XDG_DATA_HOME", format!("{root}/xdg-data")),
                ("XDG_CACHE_HOME", format!("{root}/xdg-cache")),
                ("TMPDIR", format!("{root}/tmp")),
                ("NO_COLOR", "1".to_owned()),
                ("LC_ALL", "C".to_owned()),
                ("TZ", "UTC".to_owned()),
                ("CI", "1".to_owned()),
                ("SYMVAULT_TEST_KEYRING", "memory".to_owned()),
                ("SYMVAULT_VAULT", format!("{root}/vault")),
                ("SYMVAULT_PASSPHRASE", PASSPHRASE.to_owned()),
                ("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1".to_owned()),
            ] {
                env.insert(key.to_owned(), value);
            }
            for (key, value) in &case.env {
                env.insert(key.clone(), self.expand(value));
            }
            for key in &case.unset {
                env.remove(key);
            }
            env
        }

        /// Mirrors the generator: directories are created writable and get their
        /// final mode last, deepest first.
        fn materialize(&self, specs: &[FileSpec]) {
            let mut dirs: Vec<(PathBuf, u32)> = Vec::new();
            for spec in specs {
                let path = self.root.join(&spec.path);
                match spec.kind.as_str() {
                    "dir" => {
                        make_dirs(&path);
                        dirs.push((path, spec.mode));
                    }
                    "file" => {
                        if let Some(parent) = path.parent() {
                            make_dirs(parent);
                        }
                        let data = if spec.b64.is_empty() {
                            spec.data.clone().into_bytes()
                        } else {
                            base64::engine::general_purpose::STANDARD
                                .decode(&spec.b64)
                                .expect("fixture base64")
                        };
                        std::fs::write(&path, data).unwrap();
                        set_mode(&path, spec.mode);
                    }
                    "symlink" => {
                        if let Some(parent) = path.parent() {
                            make_dirs(parent);
                        }
                        symlink(self.expand(&spec.target), &path).unwrap();
                    }
                    other => panic!("unknown spec kind {other}"),
                }
            }
            for (path, mode) in dirs.into_iter().rev() {
                set_mode(&path, mode);
            }
        }

        fn run_step(&self, binary: &str, case: &Case, step: &Step) -> Result<Expected, String> {
            let mut command = Command::new("/bin/sh");
            command
                .arg("-c")
                .arg("umask 022; exec \"$0\" \"$@\"")
                .arg(binary);
            for arg in &step.argv {
                command.arg(self.expand(arg));
            }
            command
                .current_dir(self.root.join("work"))
                .env_clear()
                .envs(self.environment(case))
                // cargo-llvm-cov points instrumented binaries at an absolute
                // profile path; without it they drop `default_*.profraw` into
                // the compared working tree.
                .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|path| ("LLVM_PROFILE_FILE", path)))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(if step.stdin.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                });
            let mut child = command.spawn().map_err(|error| format!("spawn: {error}"))?;
            let writer = step.stdin.clone().map(|input| {
                let mut stdin = child.stdin.take().expect("piped stdin");
                std::thread::spawn(move || {
                    // The process may exit without reading its input.
                    let _ = stdin.write_all(input.as_bytes());
                })
            });
            let mut stdout = child.stdout.take().expect("piped stdout");
            let mut stderr = child.stderr.take().expect("piped stderr");
            let out_reader = std::thread::spawn(move || {
                let mut buffer = Vec::new();
                let _ = stdout.read_to_end(&mut buffer);
                buffer
            });
            let err_reader = std::thread::spawn(move || {
                let mut buffer = Vec::new();
                let _ = stderr.read_to_end(&mut buffer);
                buffer
            });
            let deadline = Instant::now() + STEP_TIMEOUT;
            let status = loop {
                if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                    break status;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{:?} timed out", step.argv));
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            if let Some(writer) = writer {
                let _ = writer.join();
            }
            let decode = |bytes: Vec<u8>, what: &str| {
                String::from_utf8(bytes)
                    .map(|text| self.normalize(&text))
                    .map_err(|_| format!("{what} of {:?} is not valid UTF-8", step.argv))
            };
            Ok(Expected {
                exit: status.code().unwrap_or(-1),
                stdout: decode(out_reader.join().unwrap(), "stdout")?,
                stderr: decode(err_reader.join().unwrap(), "stderr")?,
            })
        }

        /// Records the whole root. `before` is the raw digest of every file in the
        /// pre-run snapshot; it decides the changed-archive/manifest rules.
        fn snapshot(
            &self,
            before: Option<&BTreeMap<String, String>>,
        ) -> (Vec<Node>, BTreeMap<String, String>) {
            let mut nodes = Vec::new();
            let mut raw = BTreeMap::new();
            self.visit(&self.root, before, &mut nodes, &mut raw);
            nodes.sort_by(|a, b| a.path.cmp(&b.path));
            (nodes, raw)
        }

        fn visit(
            &self,
            dir: &Path,
            before: Option<&BTreeMap<String, String>>,
            nodes: &mut Vec<Node>,
            raw: &mut BTreeMap<String, String>,
        ) {
            let meta = std::fs::symlink_metadata(dir).unwrap();
            let restore = meta.permissions().mode() & 0o777;
            let widened = restore & 0o500 != 0o500;
            if widened {
                set_mode(dir, 0o700);
            }
            let mut names: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            for name in names {
                let path = dir.join(&name);
                let rel = path
                    .strip_prefix(&self.root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let meta = std::fs::symlink_metadata(&path).unwrap();
                let perm = meta.permissions().mode() & 0o777;
                let file_type = meta.file_type();
                if file_type.is_symlink() {
                    let target = std::fs::read_link(&path).unwrap();
                    nodes.push(Node {
                        path: rel,
                        kind: "symlink".into(),
                        mode: 0,
                        size: 0,
                        sha256: String::new(),
                        target: self.normalize(&target.to_string_lossy()),
                        normalized: String::new(),
                    });
                } else if file_type.is_dir() {
                    nodes.push(Node {
                        path: rel,
                        kind: "dir".into(),
                        mode: perm,
                        size: 0,
                        sha256: String::new(),
                        target: String::new(),
                        normalized: String::new(),
                    });
                    self.visit(&path, before, nodes, raw);
                } else if file_type.is_file() {
                    let readable = perm & 0o400 != 0;
                    if !readable {
                        set_mode(&path, 0o600);
                    }
                    let content = std::fs::read(&path).unwrap();
                    if !readable {
                        set_mode(&path, perm);
                    }
                    let file_name = name.to_string_lossy();
                    let content_digest = digest(&content);
                    raw.insert(rel.clone(), content_digest.clone());
                    let changed = before.is_some_and(|before| {
                        before.get(&rel).map(String::as_str) != Some(content_digest.as_str())
                    });
                    let (size, sha256, normalized) = if file_name == "audit-symvault.log" {
                        let normalized = normalize_audit_log(&content);
                        (
                            normalized.len() as i64,
                            digest(&normalized),
                            "audit-log".to_owned(),
                        )
                    } else if file_name == "manifest.age" && changed {
                        (
                            -1,
                            PLACEHOLDER_REWRITE.to_owned(),
                            "manifest-rewritten".to_owned(),
                        )
                    } else if is_archive_name(&file_name) && changed {
                        (
                            -1,
                            PLACEHOLDER_ARCHIVE.to_owned(),
                            "generated-archive".to_owned(),
                        )
                    } else {
                        (content.len() as i64, content_digest, String::new())
                    };
                    nodes.push(Node {
                        path: rel,
                        kind: "file".into(),
                        mode: perm,
                        size,
                        sha256,
                        target: String::new(),
                        normalized,
                    });
                } else {
                    nodes.push(Node {
                        path: rel,
                        kind: "other".into(),
                        mode: perm,
                        size: 0,
                        sha256: String::new(),
                        target: String::new(),
                        normalized: String::new(),
                    });
                }
            }
            if widened {
                set_mode(dir, restore);
            }
        }

        fn archive_listings(&self, nodes: &[Node]) -> Vec<ArchiveListing> {
            let mut listings = Vec::new();
            for node in nodes {
                if node.kind != "file" || !is_archive_name(&node.path) {
                    continue;
                }
                let path = self.root.join(&node.path);
                let perm = std::fs::symlink_metadata(&path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                if perm & 0o400 == 0 {
                    set_mode(&path, 0o600);
                }
                let content = std::fs::read(&path).unwrap();
                if perm & 0o400 == 0 {
                    set_mode(&path, perm);
                }
                let mut listing = list_archive(&content);
                listing.path = node.path.clone();
                listings.push(listing);
            }
            listings
        }
    }

    /// `os.MkdirAll(path, 0700)` as the generator's materializer does.
    fn make_dirs(path: &Path) {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .unwrap();
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn is_archive_name(name: &str) -> bool {
        name.ends_with(".tar.gz") || name.ends_with(".tgz")
    }

    /// The generator's audit-log rule: per-write values replaced, keys sorted.
    fn normalize_audit_log(content: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(content);
        let mut out = Vec::new();
        for line in text.split_inclusive('\n') {
            let line = line.trim_end_matches('\n');
            if line.is_empty() {
                continue;
            }
            let mut object: BTreeMap<String, serde_json::Value> = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("audit line {line:?}: {error}"));
            for (key, placeholder) in [
                ("ts", "<ts>"),
                ("kid", "<kid>"),
                ("hmac", "<hmac>"),
                ("argv_hash", "<argv_hash>"),
            ] {
                if object.contains_key(key) {
                    object.insert(key.into(), serde_json::Value::String(placeholder.into()));
                }
            }
            out.push(b'{');
            for (index, (key, value)) in object.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(serde_json::to_string(key).unwrap().as_bytes());
                out.push(b':');
                out.extend_from_slice(serde_json::to_string(value).unwrap().as_bytes());
            }
            out.extend_from_slice(b"}\n");
        }
        out
    }

    /// Reads a gzip tar member list; `complete` is false when the stream ended
    /// in an error (the members read before it are kept).
    fn list_archive(content: &[u8]) -> ArchiveListing {
        let mut listing = ArchiveListing {
            path: String::new(),
            complete: false,
            members: Vec::new(),
        };
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(content));
        let Ok(entries) = archive.entries() else {
            return listing;
        };
        for entry in entries {
            let Ok(mut entry) = entry else {
                return listing;
            };
            let header = entry.header().clone();
            let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
            let kind = match header.entry_type() {
                tar::EntryType::Regular | tar::EntryType::Continuous => "file".to_owned(),
                tar::EntryType::Directory => "dir".to_owned(),
                tar::EntryType::Symlink => "symlink".to_owned(),
                other => format!("type-{}", other.as_byte()),
            };
            let mut body = Vec::new();
            // Go's reader fails a member whose data stops short of its size.
            if entry.read_to_end(&mut body).is_err()
                || body.len() as u64 != header.size().unwrap_or(0)
            {
                return listing;
            }
            let body = if name.rsplit('/').next() == Some("audit-symvault.log") {
                normalize_audit_log(&body)
            } else {
                body
            };
            listing.members.push(Member {
                name,
                kind,
                mode: i64::from(header.mode().unwrap_or(0)),
                size: body.len() as i64,
                sha256: digest(&body),
            });
        }
        listing.complete = true;
        listing
    }

    fn delta(before: &[Node], after: &[Node]) -> (Vec<Node>, Vec<String>) {
        let prior: BTreeMap<&str, &Node> = before
            .iter()
            .map(|node| (node.path.as_str(), node))
            .collect();
        let present: BTreeSet<&str> = after.iter().map(|node| node.path.as_str()).collect();
        let changed = after
            .iter()
            .filter(|node| {
                prior
                    .get(node.path.as_str())
                    .is_none_or(|old| *old != *node)
            })
            .cloned()
            .collect();
        let removed = before
            .iter()
            .filter(|node| !present.contains(node.path.as_str()))
            .map(|node| node.path.clone())
            .collect();
        (changed, removed)
    }

    /// Exact comparison, or - for a case with `stderr_tail_from` - comparison
    /// of everything before that marker (which both sides must contain).
    fn compare_stderr(marker: &str, actual: &str, expected: &str) -> Option<String> {
        let mismatch = || Some(format!("stderr {actual:?} want {expected:?}"));
        if marker.is_empty() {
            return (actual != expected).then(mismatch).flatten();
        }
        match (actual.find(marker), expected.find(marker)) {
            (Some(at), Some(want)) if actual[..at] == expected[..want] => None,
            _ => mismatch(),
        }
    }

    /// Names the first differing member (index, got, want) and any length or
    /// completeness difference, instead of dumping both member lists.
    fn describe_archive_diff(got: &ArchiveListing, want: &ArchiveListing) -> String {
        let render = |member: Option<&Member>| {
            member.map_or_else(
                || "<none>".to_owned(),
                |member| {
                    format!(
                        "{}:{}:{:o}:{}:{}",
                        member.name,
                        member.kind,
                        member.mode,
                        member.size,
                        &member.sha256[..member.sha256.len().min(8)]
                    )
                },
            )
        };
        let mut parts = vec![format!(
            "complete got {} want {}, members got {} want {}",
            got.complete,
            want.complete,
            got.members.len(),
            want.members.len()
        )];
        let longest = got.members.len().max(want.members.len());
        let mut shown = 0;
        for index in 0..longest {
            let (g, w) = (got.members.get(index), want.members.get(index));
            if g != w {
                parts.push(format!("[{index}] got {} want {}", render(g), render(w)));
                shown += 1;
                if shown == 3 {
                    break;
                }
            }
        }
        parts.join("; ")
    }

    fn describe_node(node: &Node) -> String {
        format!(
            "{} {} mode={:o} size={} sha={} target={:?} norm={:?}",
            node.path, node.kind, node.mode, node.size, node.sha256, node.target, node.normalized
        )
    }

    pub struct Difference {
        pub class: String,
        pub case: String,
        pub what: String,
    }

    pub fn replay_case(
        binary: &str,
        seeds: &BTreeMap<String, Vec<FileSpec>>,
        case: &Case,
    ) -> Vec<Difference> {
        let mut found = Vec::new();
        let mut note = |what: String| {
            found.push(Difference {
                class: case.class.clone(),
                case: case.id.clone(),
                what,
            });
        };
        let sandbox = Sandbox::new();
        if !case.seed.is_empty() {
            sandbox.materialize(&seeds[&case.seed]);
        }
        sandbox.materialize(&case.pre);
        let (before_nodes, before_raw) = sandbox.snapshot(None);

        for (index, (step, expected)) in case.steps.iter().zip(&case.results).enumerate() {
            match sandbox.run_step(binary, case, step) {
                Ok(actual) => {
                    if actual.exit != expected.exit {
                        note(format!(
                            "step {index} {:?}: exit {} want {}",
                            step.argv, actual.exit, expected.exit
                        ));
                    }
                    if actual.stdout != expected.stdout {
                        note(format!(
                            "step {index} {:?}: stdout {:?} want {:?}",
                            step.argv, actual.stdout, expected.stdout
                        ));
                    }
                    if let Some(message) =
                        compare_stderr(&case.stderr_tail_from, &actual.stderr, &expected.stderr)
                    {
                        note(format!("step {index} {:?}: {message}", step.argv));
                    }
                }
                Err(error) => note(format!("step {index}: {error}")),
            }
        }

        let (after_nodes, _) = sandbox.snapshot(Some(&before_raw));
        let (tree, removed) = delta(&before_nodes, &after_nodes);
        let want_tree: BTreeMap<&str, &Node> = case
            .tree
            .iter()
            .map(|node| (node.path.as_str(), node))
            .collect();
        let got_tree: BTreeMap<&str, &Node> =
            tree.iter().map(|node| (node.path.as_str(), node)).collect();
        for (path, want) in &want_tree {
            let approved = APPROVED_GO_ONLY_PATHS
                .iter()
                .any(|(id, approved, _)| *id == case.id && approved == path);
            match got_tree.get(path) {
                None if approved => {}
                Some(_) if approved => note(format!(
                    "tree: {path} exists although {} lists it as an approved Go-only path; \
                     remove the entry from APPROVED_GO_ONLY_PATHS",
                    case.id
                )),
                None => note(format!("tree: missing {}", describe_node(want))),
                Some(got) if got != want => note(format!(
                    "tree: {path}\n      got  {}\n      want {}",
                    describe_node(got),
                    describe_node(want)
                )),
                Some(_) => {}
            }
        }
        for (path, got) in &got_tree {
            if !want_tree.contains_key(path) {
                note(format!("tree: unexpected {}", describe_node(got)));
            }
        }
        let want_removed: BTreeSet<&String> = case.removed.iter().collect();
        let got_removed: BTreeSet<&String> = removed.iter().collect();
        if want_removed != got_removed {
            note(format!(
                "removed: got {got_removed:?} want {want_removed:?}"
            ));
        }
        let listings = sandbox.archive_listings(&tree);
        let want_listings: BTreeMap<&str, &ArchiveListing> = case
            .archives
            .iter()
            .map(|listing| (listing.path.as_str(), listing))
            .collect();
        let got_listings: BTreeMap<&str, &ArchiveListing> = listings
            .iter()
            .map(|listing| (listing.path.as_str(), listing))
            .collect();
        for (path, want) in &want_listings {
            match got_listings.get(path) {
                None => note(format!("archive {path}: not listed")),
                Some(got) if got != want => {
                    note(format!(
                        "archive {path}: {}",
                        describe_archive_diff(got, want)
                    ));
                }
                Some(_) => {}
            }
        }
        for path in got_listings.keys() {
            if !want_listings.contains_key(path) {
                note(format!("archive {path}: unexpected listing"));
            }
        }
        found
    }
}

#[cfg(unix)]
#[test]
fn export_backup_restore_match_frozen_go_oracle() {
    let fixture = load_fixture();
    assert_eq!(fixture.cases.len(), CASE_COUNT, "recorded case count");
    // EXPORT_CLI_BINARY points the replay at another build (used to measure the
    // red state against the base revision); the gate itself uses the crate's binary.
    let binary = std::env::var("EXPORT_CLI_BINARY")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_symvault").to_owned());
    let binary = binary.as_str();
    // EXPORT_CLI_CASE=<id> narrows a debugging run; the full run is the gate.
    let only = std::env::var("EXPORT_CLI_CASE").ok();
    let mut differences = Vec::new();
    let mut executed = 0usize;
    for case in &fixture.cases {
        if only.as_deref().is_some_and(|id| id != case.id) {
            continue;
        }
        executed += 1;
        differences.extend(replay::replay_case(binary, &fixture.seeds, case));
    }
    if only.is_none() {
        assert_eq!(executed, CASE_COUNT, "every recorded case must execute");
    }
    if differences.is_empty() {
        return;
    }
    let mut by_class: std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>> =
        std::collections::BTreeMap::new();
    for difference in &differences {
        by_class
            .entry(difference.class.as_str())
            .or_default()
            .insert(difference.case.as_str());
    }
    let summary: Vec<String> = by_class
        .iter()
        .map(|(class, cases)| format!("{class}: {} case(s)", cases.len()))
        .collect();
    let differing: std::collections::BTreeSet<&str> = differences
        .iter()
        .map(|difference| difference.case.as_str())
        .collect();
    let mut report = format!(
        "{} difference(s) in {} of {} case(s)\nby class: {}\n",
        differences.len(),
        differing.len(),
        executed,
        summary.join("; ")
    );
    for difference in &differences {
        report.push_str(&format!(
            "- [{}] {}: {}\n",
            difference.class, difference.case, difference.what
        ));
    }
    panic!("{report}");
}

#[cfg(not(unix))]
#[test]
fn export_backup_restore_replay_is_unix_only() {
    // The corpus records Unix permission bits, errno wording and symlink
    // pre-state; the Windows restore variant left the supported scope with
    // #1550/#1551 (docs/adr/0030-approved-restore-and-import-divergences.md).
    eprintln!("SKIP export/backup/restore replay: fixture recorded on a Unix host");
}
