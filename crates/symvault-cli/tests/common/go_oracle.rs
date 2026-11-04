//! Replay harness for the Go-oracle CLI differentials.
//!
//! Default mode is **replay**: a call to the Go "binary" is answered from the
//! committed transcript `testdata/port/cli-transcripts/<test file>.json`
//! (stdout, stderr, exit status and the normalized file-system delta the Go
//! process produced). A call without a recorded counterpart, a recorded call
//! that the test no longer makes, and a missing transcript are test FAILURES,
//! never skips.
//!
//! The transcripts were recorded once from the pinned Go oracle; there is no
//! capture mode any more. Recapturing needs the archived Go tree (tag
//! `legacy/go-oracle`, see `docs/rust-port/go-oracle-archive.md`).
//!
//! Temp directories differ per run, so every temp root that appears in a
//! request is replaced by a stable `<ROOT:n>` placeholder (n = order of first
//! appearance in the test) in the recorded request, output and delta, and
//! substituted back with the current run's roots on replay.
#![allow(dead_code)]

use std::{
    cell::RefCell,
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
    rc::Rc,
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Oracle revision the config-cli transcripts were recorded from.
pub const CONFIG_CLI_ORACLE: &str = "fca3f89401833b5e14ec4ec74ef736b0f63bca74";

/// A test-supplied output normalization (see [`GoOracle::stable_under`]).
pub type Normalizer = fn(&[u8]) -> Vec<u8>;

/// Written by the Rust CLI for the vault directory it ran in; its `vault_id`
/// binds to that directory's path and inode, so a recorded copy would never
/// validate in another run.
const LIVE_MARKER: &str = ".symvault-rust";
const SENTINEL: &str = "/nonexistent/symvault-go-oracle-replay";
const MAX_RECORDED_FILE: u64 = 8 * 1024 * 1024;

/// UTF-8 text when possible, base64 otherwise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Bytes {
    Text { text: String },
    Base64 { b64: String },
}

impl Bytes {
    fn encode(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(text) => Self::Text {
                text: text.to_owned(),
            },
            Err(_) => Self::Base64 {
                b64: B64.encode(bytes),
            },
        }
    }

    fn decode(&self) -> Vec<u8> {
        match self {
            Self::Text { text } => text.as_bytes().to_vec(),
            Self::Base64 { b64 } => B64.decode(b64).expect("transcript base64"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub args: Vec<String>,
    /// Environment the test set explicitly (`null` = removed).
    pub env: BTreeMap<String, Option<String>>,
    pub cwd: Option<String>,
    pub stdin: Option<Bytes>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub stdout: Bytes,
    pub stderr: Bytes,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsOp {
    pub root: usize,
    pub path: String,
    /// `file`, `dir`, `symlink` or `remove`.
    pub op: String,
    pub mode: Option<u32>,
    pub content: Option<Bytes>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub key: String,
    pub request: Request,
    pub response: Response,
    pub fs_delta: Vec<FsOp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Oracle {
    pub commit: String,
    pub go_version: String,
    pub goos: String,
    pub goarch: String,
    pub vcs_modified: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transcript {
    pub schema: u32,
    pub oracle: Oracle,
    /// Free-form statement about which host the recording is valid for.
    pub platform_note: String,
    /// Host operating systems (`std::env::consts::OS`) this recording may be
    /// replayed on. A test may narrow or widen it (`TestRecord`). Tests whose
    /// transcript excludes the host must be gated with
    /// `#[cfg_attr(not(target_os = ...), ignore = "SKIP (...)")]`
    /// (checked by `cli_transcript_platforms`); replaying one anyway fails.
    #[serde(default = "default_replay_platforms")]
    pub replay_platforms: Vec<String>,
    pub tests: BTreeMap<String, TestRecord>,
}

fn default_replay_platforms() -> Vec<String> {
    vec!["macos".to_owned()]
}

/// A frozen set-up step (typically `symvault init`, whose keys are random).
/// Replay installs the recorded tree instead of re-running the step, so the
/// recorded Go calls see exactly the state they were recorded against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seed {
    pub name: String,
    pub fs_delta: Vec<FsOp>,
    /// What the set-up command printed (normalized); replay compares the live
    /// run against it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<SeedOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedOutput {
    pub stdout: Bytes,
    pub stderr: Bytes,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestRecord {
    pub seeds: Vec<Seed>,
    pub calls: Vec<Entry>,
    /// Overrides the transcript's `replay_platforms` for this test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_platforms: Option<Vec<String>>,
}

struct State {
    file: String,
    test: String,
    go_path: PathBuf,
    roots: Vec<PathBuf>,
    /// Canonical spelling of each root (equals the raw one when identical).
    real_roots: Vec<PathBuf>,
    /// Local TCP ports (decimal text) in order of first appearance.
    ports: Vec<String>,
    recorded: Vec<Entry>,
    consumed: Vec<bool>,
    /// The recording of this test (the source of truth).
    prior: TestRecord,
    seeds_used: Vec<String>,
    apply_effects: bool,
}

thread_local! {
    static CURRENT: RefCell<Option<Rc<RefCell<State>>>> = const { RefCell::new(None) };
}

pub struct GoOracle {
    state: Rc<RefCell<State>>,
    oracle: Option<Oracle>,
}

fn transcript_path(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/port/cli-transcripts")
        .join(format!("{file}.json"))
}

fn load(file: &str) -> Option<Transcript> {
    let path = transcript_path(file);
    let bytes = fs::read(&path).ok()?;
    Some(serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
}

/// macOS per-user temporary directory (`/var/folders/..../T`), independent of
/// `TMPDIR`. Tests that need the root-owned `/var` -> `/private/var` alias
/// allocate their fixtures here so they work under any `TMPDIR`.
pub fn darwin_user_temp_dir() -> Option<PathBuf> {
    static DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        if !cfg!(target_os = "macos") {
            return None;
        }
        let output = Command::new("/usr/bin/getconf")
            .arg("DARWIN_USER_TEMP_DIR")
            .output()
            .ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        let text = text.trim();
        (output.status.success() && !text.is_empty()).then(|| PathBuf::from(text))
    })
    .clone()
}

fn temp_bases() -> Vec<String> {
    let raw = env::temp_dir();
    let mut bases = Vec::new();
    let candidates = [Some(raw.clone()), fs::canonicalize(&raw).ok()]
        .into_iter()
        .chain(
            darwin_user_temp_dir()
                .map(|user| {
                    let canonical = fs::canonicalize(&user).ok();
                    [Some(user), canonical]
                })
                .into_iter()
                .flatten(),
        );
    for candidate in candidates.flatten() {
        let text = candidate.to_string_lossy().trim_end_matches('/').to_owned();
        if !text.is_empty() && !bases.contains(&text) {
            bases.push(text);
        }
    }
    bases
}

impl GoOracle {
    /// Start one test. `file` is the test file stem, `test` the test function.
    /// `expected_commit` pins the oracle revision the recording must come from.
    pub fn begin(file: &str, test: &str, expected_commit: Option<&str>) -> Self {
        let transcript = load(file).unwrap_or_else(|| {
            panic!(
                "go_oracle: transcript {} is missing; recapture it from the archived Go oracle \
                 (tag legacy/go-oracle)",
                transcript_path(file).display()
            )
        });
        let prior = transcript.tests.get(test).cloned().unwrap_or_else(|| {
            panic!(
                "go_oracle: transcript {} has no entry for test `{test}`; recapture",
                transcript_path(file).display()
            )
        });
        if let Some(expected) = expected_commit {
            assert_eq!(
                transcript.oracle.commit, expected,
                "go_oracle: transcript oracle commit differs from the pinned one"
            );
        }
        let platforms = prior
            .replay_platforms
            .as_ref()
            .unwrap_or(&transcript.replay_platforms);
        let host = env::consts::OS;
        assert!(
            platforms.iter().any(|p| p == host),
            "go_oracle: SKIP ({} recording) on {host}: {file}::{test} replays only on \
             {platforms:?}; gate the test with #[cfg_attr(not(target_os = ...), ignore = \
             \"SKIP (...)\")]",
            transcript.oracle.goos
        );
        note_platform(file, &transcript);
        let recorded = prior.calls.clone();
        let consumed = vec![false; recorded.len()];
        let state = Rc::new(RefCell::new(State {
            file: file.to_owned(),
            test: test.to_owned(),
            go_path: PathBuf::from(SENTINEL),
            roots: Vec::new(),
            real_roots: Vec::new(),
            ports: Vec::new(),
            recorded,
            consumed,
            prior,
            seeds_used: Vec::new(),
            apply_effects: true,
        }));
        CURRENT.with(|c| *c.borrow_mut() = Some(state.clone()));
        Self {
            state,
            oracle: Some(transcript.oracle),
        }
    }

    /// Kept for call-site compatibility. A test's own output normalization
    /// only mattered when recapturing; replay compares what Rust prints with
    /// the recorded answer exactly.
    pub fn stable_under(&self, _normalize: Normalizer) {}

    /// Path to give to `Command::new` for the Go side.
    pub fn binary(&self) -> PathBuf {
        self.state.borrow().go_path.clone()
    }

    pub fn oracle(&self) -> &Oracle {
        self.oracle.as_ref().expect("oracle metadata")
    }

    /// Register a temp directory that the Go process may print or modify but
    /// that no Go request mentions (e.g. a bare remote). Order matters: call it
    /// at the same point of the test in both modes.
    pub fn track(&self, path: &Path) {
        let text = path.to_string_lossy().into_owned();
        self.state.borrow_mut().scan(text.as_bytes());
    }

    /// Register a loopback port the Go process may print although no request
    /// mentions it (the port lives in a fixture file).
    pub fn track_port(&self, port: u16) {
        self.state.borrow_mut().register_port(&port.to_string());
    }

    /// `false` skips applying the recorded file-system effects of the Go
    /// calls issued until the next `effects(true)`; use it when the test
    /// re-creates the effect with a real tool (see `replaying`).
    pub fn effects(&self, apply: bool) {
        self.state.borrow_mut().apply_effects = apply;
    }

    /// Go calls are always answered from the transcript.
    pub fn replaying(&self) -> bool {
        true
    }

    /// Install one recorded set-up step whose result was random. `roots` are
    /// every directory the step creates or changes. Returns `None`: the step
    /// is never re-run (a missing recording fails the test).
    pub fn seed<R>(&self, name: &str, roots: &[&Path], setup: impl FnOnce() -> R) -> Option<R> {
        self.freeze(name, roots, setup)
    }

    /// Like [`seed`] for a Rust set-up command (typically `symvault init`):
    /// the command runs live in every mode, its output and the file-system
    /// shape it produced are compared with the recording (exit status,
    /// normalized stdout/stderr, file set, modes, age/JSON/YAML structure),
    /// and only then the recorded state is installed so that the recorded Go
    /// calls see exactly what they saw when recorded. A Rust command that stops
    /// behaving like the recording therefore fails the test instead of being
    /// papered over by the frozen state. Returns the live output.
    pub fn seed_run(&self, name: &str, roots: &[&Path], setup: impl FnOnce() -> Output) -> Output {
        self.live_seed(name, roots, true, setup)
    }

    /// Like [`seed_run`] for a step whose stdout the test compares itself
    /// (e.g. against Go): only the file-system shape is checked here.
    pub fn pin(&self, name: &str, roots: &[&Path], step: impl FnOnce() -> Output) -> Output {
        self.live_seed(name, roots, false, step)
    }

    fn live_seed(
        &self,
        name: &str,
        roots: &[&Path],
        check_output: bool,
        setup: impl FnOnce() -> Output,
    ) -> Output {
        let mut st = self.state.borrow_mut();
        for root in roots {
            let text = root.to_string_lossy().into_owned();
            st.scan(text.as_bytes());
        }
        let nth = st.seeds_used.iter().filter(|used| *used == name).count();
        let recorded = st
            .prior
            .seeds
            .iter()
            .filter(|s| s.name == name)
            .nth(nth)
            .cloned();
        assert!(
            recorded.is_some(),
            "go_oracle: {}::{} has no recorded seed `{name}`; recapture",
            st.file,
            st.test
        );
        let tracked: Vec<(usize, PathBuf)> = roots
            .iter()
            .map(|r| {
                let index = st
                    .roots
                    .iter()
                    .position(|known| r.starts_with(known))
                    .or_else(|| st.real_roots.iter().position(|real| r.starts_with(real)))
                    .expect("seed root registered");
                (index, st.roots[index].clone())
            })
            .collect();
        let before: Vec<_> = tracked
            .iter()
            .map(|(_, r)| snapshot(r, GitMode::Full))
            .collect();
        drop(st);
        let output = setup();
        let mut st = self.state.borrow_mut();
        let mut live_ops = Vec::new();
        let mut created: Vec<(PathBuf, bool, usize, String)> = Vec::new();
        for ((index, root), before) in tracked.iter().zip(&before) {
            let after = snapshot(root, GitMode::Full);
            live_ops.extend(delta(&st, *index, before, &after));
            for (path, node) in &after {
                if !before.contains_key(path) {
                    let full = if path.is_empty() {
                        root.clone()
                    } else {
                        root.join(path)
                    };
                    created.push((full, matches!(node, Node::Dir { .. }), *index, path.clone()));
                }
            }
        }
        let (code, signal) = status_parts(&output.status);
        let live_output = SeedOutput {
            stdout: Bytes::encode(&st.normalize(&output.stdout)),
            stderr: Bytes::encode(&st.normalize(&output.stderr)),
            exit_code: code,
            signal,
        };
        let mut problems = Vec::new();
        let seed = match recorded {
            Some(seed) => {
                problems.extend(shape_diff(&live_ops, &seed.fs_delta));
                if check_output {
                    match &seed.output {
                        Some(recorded_output) => {
                            problems.extend(output_diff(recorded_output, &live_output));
                        }
                        None => problems.push(format!(
                            "recording of seed `{name}` carries no command output; recapture"
                        )),
                    }
                }
                Some(seed)
            }
            None => None,
        };
        let seed = match (seed, problems.is_empty()) {
            (_, false) => panic!(
                "go_oracle: {}::{} live `{name}` differs from the recording:\n  {}",
                st.file,
                st.test,
                problems.join("\n  ")
            ),
            (Some(seed), true) => {
                // Install the recorded state (random keys and clocks) over
                // the live one. Directories keep their identity (the data
                // safety marker binds to the vault's inode), live files the
                // recording lacks (git objects) are dropped, and the marker
                // the live run wrote for this very directory stays.
                let recorded_paths: Vec<(usize, &str)> = seed
                    .fs_delta
                    .iter()
                    .map(|op| (op.root, op.path.as_str()))
                    .collect();
                let mut stale: Vec<&(PathBuf, bool, usize, String)> = created
                    .iter()
                    .filter(|(_, _, root, rel)| !recorded_paths.contains(&(*root, rel.as_str())))
                    .collect();
                stale.sort_by_key(|(path, ..)| std::cmp::Reverse(path.as_os_str().len()));
                for (path, is_dir, ..) in stale {
                    let _ = if *is_dir {
                        fs::remove_dir_all(path)
                    } else {
                        fs::remove_file(path)
                    };
                }
                let live_markers: Vec<(usize, &str)> = live_ops
                    .iter()
                    .filter(|op| op.path.ends_with(LIVE_MARKER))
                    .map(|op| (op.root, op.path.as_str()))
                    .collect();
                let install: Vec<FsOp> = seed
                    .fs_delta
                    .iter()
                    .filter(|op| !live_markers.contains(&(op.root, op.path.as_str())))
                    .cloned()
                    .collect();
                apply(&st, &install);
                seed
            }
            (None, true) => unreachable!("checked above"),
        };
        let _ = seed;
        st.seeds_used.push(name.to_owned());
        output
    }

    fn freeze<R>(&self, name: &str, roots: &[&Path], _setup: impl FnOnce() -> R) -> Option<R> {
        let mut st = self.state.borrow_mut();
        for root in roots {
            let text = root.to_string_lossy().into_owned();
            st.scan(text.as_bytes());
        }
        // The nth use of a name installs the nth seed recorded under it.
        let nth = st.seeds_used.iter().filter(|used| *used == name).count();
        let recorded = st
            .prior
            .seeds
            .iter()
            .filter(|s| s.name == name)
            .nth(nth)
            .cloned();
        let Some(seed) = recorded else {
            panic!(
                "go_oracle: {}::{} has no recorded seed `{name}`; recapture",
                st.file, st.test
            );
        };
        apply(&st, &seed.fs_delta);
        st.seeds_used.push(name.to_owned());
        None
    }

    /// Number of recorded Go calls answered so far.
    pub fn calls(&self) -> usize {
        let state = self.state.borrow();
        state.consumed.iter().filter(|c| **c).count()
    }
}

/// Hex runs of 64 characters (vault ids, digests) are fresh per run.
fn mask_hex64(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let run = bytes[i..]
            .iter()
            .take_while(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            .count();
        let boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if run >= 64 && boundary {
            out.extend_from_slice(b"<hex>");
            i += run;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

fn shape_mask(bytes: &[u8]) -> Vec<u8> {
    mask_hex64(&mask_volatile(bytes))
}

fn output_diff(recorded: &SeedOutput, live: &SeedOutput) -> Vec<String> {
    let mut problems = Vec::new();
    if (recorded.exit_code, recorded.signal) != (live.exit_code, live.signal) {
        problems.push(format!(
            "exit status: recorded {:?}/{:?}, live {:?}/{:?}",
            recorded.exit_code, recorded.signal, live.exit_code, live.signal
        ));
    }
    for (stream, old, new) in [
        ("stdout", &recorded.stdout, &live.stdout),
        ("stderr", &recorded.stderr, &live.stderr),
    ] {
        let (old, new) = (shape_mask(&old.decode()), shape_mask(&new.decode()));
        if old != new {
            problems.push(format!(
                "{stream}: recorded {:?}, live {:?}",
                String::from_utf8_lossy(&old),
                String::from_utf8_lossy(&new)
            ));
        }
    }
    problems
}

/// `Some(relative)` for a path below a `.git` directory.
fn git_internal(path: &str) -> Option<String> {
    let mut parts = path.split('/');
    let mut seen = Vec::new();
    for part in parts.by_ref() {
        seen.push(part);
        if part == ".git" {
            return Some(parts.collect::<Vec<_>>().join("/"));
        }
    }
    None
}

/// Entries of a frozen set-up step that must match the live run. Repository
/// internals (object ids, index, logs, host templates) are random or
/// host-dependent, so only the structural files are compared.
fn significant(op: &FsOp) -> bool {
    match git_internal(&op.path) {
        None => true,
        Some(inner) => matches!(
            inner.as_str(),
            "" | "HEAD" | "config" | "objects" | "refs" | "COMMIT_EDITMSG"
        ),
    }
}

fn age_stanza_type(bytes: &[u8]) -> Option<String> {
    // Every recipient stanza: its type plus the deterministic `k=v` arguments
    // (KDF cost parameters). Random salts, ephemeral keys and bodies are
    // dropped; the count and order of non-grease stanzas are kept.
    let text = bytes.strip_prefix(b"age-encryption.org/v1\n")?;
    let mut stanzas = Vec::new();
    for line in text.split(|b| *b == b'\n') {
        if line.starts_with(b"---") {
            break;
        }
        let Some(rest) = line.strip_prefix(b"-> ") else {
            continue;
        };
        let rest = std::str::from_utf8(rest).ok()?;
        let mut parts = rest.split_whitespace();
        let kind = parts.next()?;
        if kind.ends_with("-grease") {
            // age adds random grease stanzas (random type and arguments).
            continue;
        }
        let mut shape = vec![kind.to_string()];
        shape.extend(parts.filter(|arg| arg.contains('=')).map(str::to_string));
        stanzas.push(shape.join(" "));
    }
    (!stanzas.is_empty()).then(|| stanzas.join("\n"))
}

fn content_matches(path: &str, recorded: &[u8], live: &[u8]) -> bool {
    if recorded == live {
        return true;
    }
    if path.ends_with(".age") || recorded.starts_with(b"age-encryption.org/v1\n") {
        // Ciphertext is random: same age container and recipient stanza type.
        return age_stanza_type(recorded).is_some()
            && age_stanza_type(recorded) == age_stanza_type(live);
    }
    if path.ends_with("/HEAD") || (path.ends_with("/config") && git_internal(path).is_some()) {
        // Host git defaults (initial branch, templates) differ.
        return true;
    }
    shape_mask(recorded) == shape_mask(live)
}

/// Differences between a live set-up run and its recorded delta. Both sides
/// are already normalized (temp roots become `<ROOT:n>`).
fn shape_diff(live: &[FsOp], recorded: &[FsOp]) -> Vec<String> {
    let index = |ops: &[FsOp]| -> BTreeMap<(usize, String), FsOp> {
        ops.iter()
            .filter(|op| significant(op))
            .map(|op| ((op.root, op.path.clone()), op.clone()))
            .collect()
    };
    let (live, recorded) = (index(live), index(recorded));
    let mut problems = Vec::new();
    for key in recorded.keys().filter(|k| !live.contains_key(*k)) {
        problems.push(format!("missing in live run: {}", key.1));
    }
    for key in live.keys().filter(|k| !recorded.contains_key(*k)) {
        problems.push(format!("not in recording: {}", key.1));
    }
    for (key, rec) in &recorded {
        let Some(now) = live.get(key) else { continue };
        if (&rec.op, rec.mode) != (&now.op, now.mode) {
            problems.push(format!(
                "{}: recorded {} mode {:?}, live {} mode {:?}",
                key.1,
                rec.op,
                rec.mode.map(|m| format!("{m:o}")),
                now.op,
                now.mode.map(|m| format!("{m:o}"))
            ));
        } else if let (Some(old), Some(new)) = (&rec.content, &now.content)
            && !content_matches(&key.1, &old.decode(), &new.decode())
        {
            problems.push(format!(
                "{}: content differs (recorded {:?}, live {:?})",
                key.1,
                String::from_utf8_lossy(&old.decode())
                    .chars()
                    .take(120)
                    .collect::<String>(),
                String::from_utf8_lossy(&new.decode())
                    .chars()
                    .take(120)
                    .collect::<String>()
            ));
        }
    }
    problems
}

fn note_platform(file: &str, transcript: &Transcript) {
    let host = env::consts::OS;
    let recorded = if transcript.oracle.goos == "darwin" {
        "macos"
    } else {
        transcript.oracle.goos.as_str()
    };
    if host != recorded {
        let _ = writeln!(
            std::io::stderr(),
            "go_oracle: NOTE {file}: replaying a {} recording on {host} ({})",
            transcript.oracle.goos,
            transcript.platform_note
        );
    }
}

impl Drop for GoOracle {
    fn drop(&mut self) {
        CURRENT.with(|c| *c.borrow_mut() = None);
        if std::thread::panicking() {
            return;
        }
        let state = self.state.borrow();
        let unused: Vec<usize> = state
            .consumed
            .iter()
            .enumerate()
            .filter(|(_, c)| !**c)
            .map(|(i, _)| i)
            .collect();
        assert!(
            unused.is_empty(),
            "go_oracle: {}::{} did not replay recorded entries {unused:?} (stale \
             transcript; recapture)",
            state.file,
            state.test
        );
        assert_eq!(
            state.seeds_used.len(),
            state.prior.seeds.len(),
            "go_oracle: {}::{} did not install every recorded seed (stale transcript)",
            state.file,
            state.test
        );
        let oracle = self.oracle.as_ref().expect("oracle");
        let _ = writeln!(
            std::io::stderr(),
            "go_oracle: replayed {} cases for {}::{} (oracle {} {} {}/{})",
            state.recorded.len(),
            state.file,
            state.test,
            &oracle.commit[..12.min(oracle.commit.len())],
            oracle.go_version,
            oracle.goos,
            oracle.goarch
        );
        assert!(
            !state.recorded.is_empty(),
            "go_oracle: {}::{} replayed zero cases",
            state.file,
            state.test
        );
    }
}

/// Masks per-invocation values (fresh age keys, token ids, wall-clock
/// timestamps, `.tmp-<n>` suffixes) so that a recapture can be compared with
/// the committed entry. Never applied to what replay returns.
pub fn mask_volatile(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let digits = |s: &[u8], n: usize| s.len() >= n && s[..n].iter().all(u8::is_ascii_digit);
    while i < bytes.len() {
        let rest = &bytes[i..];
        if rest.starts_with(b"age1") {
            let run = rest[4..]
                .iter()
                .take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                .count();
            if run >= 50 {
                out.extend_from_slice(b"age1<masked>");
                i += 4 + run;
                continue;
            }
        }
        if rest.starts_with(b"tok-")
            && digits(&rest[4..], 8)
            && rest.get(12) == Some(&b'-')
            && rest.len() >= 21
            && rest[13..21].iter().all(u8::is_ascii_hexdigit)
        {
            out.extend_from_slice(b"tok-<id>");
            i += 21;
            continue;
        }
        // import-20261103-3e2770c7
        if rest.starts_with(b"import-")
            && digits(&rest[7..], 8)
            && rest.get(15) == Some(&b'-')
            && rest.len() >= 24
            && rest[16..24].iter().all(u8::is_ascii_hexdigit)
        {
            out.extend_from_slice(b"import-<id>");
            i += 24;
            continue;
        }
        // JSON string values that are fresh on every run.
        let mut volatile_value = None;
        for key in [
            &b"\"Modified\":\""[..],
            b"\"kid\":\"",
            b"\"hmac\":\"",
            b"\"argv_hash\":\"",
        ] {
            if rest.starts_with(key) {
                volatile_value = Some(key.len());
            }
        }
        if let Some(prefix) = volatile_value {
            let end = rest[prefix..]
                .iter()
                .position(|b| *b == b'"')
                .map_or(rest.len(), |p| prefix + p);
            out.extend_from_slice(&rest[..prefix]);
            out.extend_from_slice(b"<v>");
            i += end;
            continue;
        }
        if rest.starts_with(b".tmp-") {
            let run = rest[5..].iter().take_while(|b| b.is_ascii_digit()).count();
            if run > 0 {
                out.extend_from_slice(b".tmp-<n>");
                i += 5 + run;
                continue;
            }
        }
        // 2026-11-03T22:23:36[.123456]Z
        if digits(rest, 4)
            && rest.get(4) == Some(&b'-')
            && digits(&rest[5..], 2)
            && rest.get(7) == Some(&b'-')
            && digits(&rest[8..], 2)
            && rest.get(10) == Some(&b'T')
            && digits(&rest[11..], 2)
            && rest.get(13) == Some(&b':')
            && digits(&rest[14..], 2)
            && rest.get(16) == Some(&b':')
            && digits(&rest[17..], 2)
        {
            let mut end = 19;
            if rest.get(end) == Some(&b'.') {
                end += 1;
                end += rest[end..]
                    .iter()
                    .take_while(|b| b.is_ascii_digit())
                    .count();
            }
            if rest.get(end) == Some(&b'Z') {
                out.extend_from_slice(b"<ts>");
                i += end + 1;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn volatile_equal(stable: Option<Normalizer>, old: &[u8], new: &[u8]) -> bool {
    let masked = |b: &[u8]| {
        let m = mask_volatile(b);
        match stable {
            Some(normalize) => normalize(&m),
            None => m,
        }
    };
    masked(old) == masked(new)
}

// ---------------------------------------------------------------------------
// Normalization.

fn replace_bytes(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

/// Replace `needle` only where it is a whole decimal number.
fn replace_number(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        let whole = haystack[i..].starts_with(needle)
            && (i == 0 || !haystack[i - 1].is_ascii_digit())
            && haystack
                .get(i + needle.len())
                .is_none_or(|b| !b.is_ascii_digit());
        if whole {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

fn is_component_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

impl State {
    /// Register every temp root and loopback port mentioned in `text`.
    fn scan(&mut self, text: &[u8]) {
        for needle in [&b"127.0.0.1:"[..], b"localhost:", b"[::1]:"] {
            let mut i = 0;
            while i + needle.len() <= text.len() {
                if text[i..].starts_with(needle) {
                    let start = i + needle.len();
                    let digits = text[start..]
                        .iter()
                        .take_while(|b| b.is_ascii_digit())
                        .count();
                    if digits >= 4 {
                        let port =
                            String::from_utf8_lossy(&text[start..start + digits]).into_owned();
                        self.register_port(&port);
                    }
                    i = start;
                } else {
                    i += 1;
                }
            }
        }
        for base in temp_bases() {
            let needle = format!("{base}/");
            let needle = needle.as_bytes();
            let mut i = 0;
            while i + needle.len() <= text.len() {
                if text[i..].starts_with(needle) {
                    let start = i + needle.len();
                    let mut end = start;
                    while end < text.len() && is_component_char(text[end]) {
                        end += 1;
                    }
                    if end > start {
                        let component = String::from_utf8_lossy(&text[start..end]).into_owned();
                        let raw = PathBuf::from(&base).join(&component);
                        self.register(&raw);
                    }
                    i = end.max(i + 1);
                } else {
                    i += 1;
                }
            }
        }
    }

    fn register_port(&mut self, port: &str) {
        if !self.ports.iter().any(|known| known == port) {
            self.ports.push(port.to_owned());
        }
    }

    fn register(&mut self, raw: &Path) {
        // Equivalent spellings (/var vs /private/var) map to one root.
        let real = fs::canonicalize(raw).ok();
        for (index, known) in self.roots.iter().enumerate() {
            if known == raw || self.real_roots[index] == raw {
                return;
            }
            if let Some(real) = &real
                && &self.real_roots[index] == real
            {
                return;
            }
        }
        // A root that does not exist yet is canonicalized through its parent.
        let real = real.unwrap_or_else(|| {
            raw.parent()
                .and_then(|p| fs::canonicalize(p).ok())
                .map(|p| p.join(raw.file_name().unwrap_or_default()))
                .unwrap_or_else(|| raw.to_path_buf())
        });
        self.roots.push(raw.to_path_buf());
        self.real_roots.push(real);
    }

    /// (spelling, placeholder) pairs, longest spelling first.
    fn mapping(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut pairs = Vec::new();
        for (index, root) in self.roots.iter().enumerate() {
            pairs.push((
                root.to_string_lossy().into_owned().into_bytes(),
                format!("<ROOT:{index}>").into_bytes(),
            ));
            let real = &self.real_roots[index];
            if real != root {
                pairs.push((
                    real.to_string_lossy().into_owned().into_bytes(),
                    format!("<ROOT:{index}:real>").into_bytes(),
                ));
            }
        }
        pairs.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
        pairs
    }

    fn normalize(&self, bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        for (from, to) in self.mapping() {
            out = replace_bytes(&out, &from, &to);
        }
        for (index, port) in self.ports.iter().enumerate() {
            out = replace_number(&out, port.as_bytes(), format!("<PORT:{index}>").as_bytes());
        }
        scrub_tmpfile(&out)
    }

    fn denormalize(&self, bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        // Longest placeholder first so `<ROOT:1:real>` wins over `<ROOT:1>`.
        let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = self
            .mapping()
            .into_iter()
            .map(|(real, placeholder)| (placeholder, real))
            .collect();
        // The recording may carry `<ROOT:n:real>` (captured under an aliased
        // TMPDIR such as /var -> /private/var) while this run's TMPDIR has no
        // alias, so `mapping()` has no `:real` entry for the root: both
        // spellings are then the same path.
        for (index, real) in self.real_roots.iter().enumerate() {
            let placeholder = format!("<ROOT:{index}:real>").into_bytes();
            if !pairs.iter().any(|(from, _)| *from == placeholder) {
                pairs.push((
                    placeholder,
                    real.to_string_lossy().into_owned().into_bytes(),
                ));
            }
        }
        pairs.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
        for (from, to) in pairs {
            out = replace_bytes(&out, &from, &to);
        }
        for (index, port) in self.ports.iter().enumerate() {
            out = replace_bytes(&out, format!("<PORT:{index}>").as_bytes(), port.as_bytes());
        }
        assert!(
            !contains(&out, b"<PORT:"),
            "go_oracle: recorded output refers to a port that this run never used"
        );
        assert!(
            !contains(&out, b"<ROOT:"),
            "go_oracle: recorded output refers to a temp root that this run never used: {:?}",
            String::from_utf8_lossy(&out)
        );
        out
    }
}

/// Placeholder for the per-process scratch files and directories the CLI itself
/// creates below the temp dir (`<temp>/symvault-file-<pid>-<seq>`, the editor
/// buffer `<temp>/symvault-edit-<random>.json`): their names embed a pid or a
/// random number and are neither requested nor printed by any call, so they
/// cannot be tracked as roots. Recorded paths keep only `<TMPFILE>`; replay leaves the
/// placeholder as is.
pub const TMPFILE: &str = "<TMPFILE>";

fn scrub_tmpfile(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for (base, stem) in temp_bases()
        .into_iter()
        .flat_map(|base| [(base.clone(), "symvault-file-"), (base, "symvault-edit-")])
    {
        let needle = format!("{base}/{stem}");
        let needle = needle.as_bytes();
        let mut scrubbed = Vec::with_capacity(out.len());
        let mut i = 0;
        while i < out.len() {
            if out[i..].starts_with(needle) {
                let mut end = i + needle.len();
                while end < out.len() && (out[end].is_ascii_digit() || out[end] == b'-') {
                    end += 1;
                }
                if end > i + needle.len() {
                    scrubbed.extend_from_slice(TMPFILE.as_bytes());
                    i = end;
                    continue;
                }
            }
            scrubbed.push(out[i]);
            i += 1;
        }
        out = scrubbed;
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Long environment values (synthetic secret corpora) are recorded by digest
/// so the transcript never carries secret-shaped literals.
fn env_value(state: &State, os: &std::ffi::OsStr) -> String {
    let text = text_of(state, os);
    if text.len() > 64 {
        format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes())))
    } else {
        text
    }
}

fn text_of(state: &State, os: &std::ffi::OsStr) -> String {
    String::from_utf8_lossy(&state.normalize(os.to_string_lossy().as_bytes())).into_owned()
}

// ---------------------------------------------------------------------------
// File-system snapshots.

#[derive(Clone, PartialEq, Eq)]
enum Node {
    Dir { mode: u32 },
    File { mode: u32, content: Vec<u8> },
    Symlink { target: String },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GitMode {
    /// Ignore `.git` (Go's repository state cannot be replayed).
    Skip,
    /// Only `.git/config`, which Go-written remote settings live in.
    ConfigOnly,
    /// Everything but sample hooks (frozen seeds).
    Full,
}

fn snapshot(root: &Path, git: GitMode) -> BTreeMap<String, Node> {
    let mut map = BTreeMap::new();
    if fs::symlink_metadata(root).is_ok() {
        walk(root, root, git, &mut map);
    }
    map
}

fn mode_bits(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

fn walk(root: &Path, dir: &Path, git: GitMode, map: &mut BTreeMap<String, Node>) {
    let rel = |p: &Path| {
        p.strip_prefix(root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/")
    };
    let meta = fs::symlink_metadata(dir).expect("metadata");
    map.insert(
        rel(dir),
        Node::Dir {
            mode: mode_bits(&meta),
        },
    );
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        // Go's git state cannot be replayed (object ids embed capture-time
        // clocks); calls carry `.git/config` only, frozen seeds carry the rest.
        if path.file_name().is_some_and(|n| n == ".git") {
            match git {
                GitMode::Skip => continue,
                GitMode::ConfigOnly => {
                    let config = path.join("config");
                    if let Ok(meta) = fs::symlink_metadata(&config)
                        && meta.is_file()
                    {
                        map.insert(
                            rel(&config),
                            Node::File {
                                mode: mode_bits(&meta),
                                content: fs::read(&config).unwrap_or_default(),
                            },
                        );
                    }
                    continue;
                }
                GitMode::Full => {}
            }
        }
        if path.file_name().is_some_and(|n| n == "hooks")
            && path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".git"))
        {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&path)
                .map(|t| t.to_string_lossy().into_owned())
                .unwrap_or_default();
            map.insert(rel(&path), Node::Symlink { target });
        } else if meta.is_dir() {
            walk(root, &path, git, map);
        } else if meta.is_file() {
            assert!(
                meta.len() <= MAX_RECORDED_FILE,
                "go_oracle: {} is too large to record",
                path.display()
            );
            let content = fs::read(&path).unwrap_or_default();
            map.insert(
                rel(&path),
                Node::File {
                    mode: mode_bits(&meta),
                    content,
                },
            );
        }
    }
}

fn delta(
    state: &State,
    index: usize,
    before: &BTreeMap<String, Node>,
    after: &BTreeMap<String, Node>,
) -> Vec<FsOp> {
    let mut ops = Vec::new();
    for (path, node) in after {
        if before.get(path) == Some(node) {
            continue;
        }
        let op = match node {
            Node::Dir { mode } => FsOp {
                root: index,
                path: path.clone(),
                op: "dir".into(),
                mode: Some(*mode),
                content: None,
            },
            Node::File { mode, content } => FsOp {
                root: index,
                path: path.clone(),
                op: "file".into(),
                mode: Some(*mode),
                content: Some(Bytes::encode(&state.normalize(content))),
            },
            Node::Symlink { target } => FsOp {
                root: index,
                path: path.clone(),
                op: "symlink".into(),
                mode: None,
                content: Some(Bytes::encode(&state.normalize(target.as_bytes()))),
            },
        };
        ops.push(op);
    }
    let mut removed: Vec<&String> = before.keys().filter(|p| !after.contains_key(*p)).collect();
    removed.sort_by_key(|p| std::cmp::Reverse(p.len()));
    for path in removed {
        ops.push(FsOp {
            root: index,
            path: path.clone(),
            op: "remove".into(),
            mode: None,
            content: None,
        });
    }
    ops
}

fn apply(state: &State, ops: &[FsOp]) {
    for op in ops {
        let root = state
            .roots
            .get(op.root)
            .unwrap_or_else(|| panic!("go_oracle: delta refers to unknown root {}", op.root));
        let path = if op.path.is_empty() {
            root.clone()
        } else {
            root.join(&op.path)
        };
        match op.op.as_str() {
            "dir" => {
                fs::create_dir_all(&path).expect("replay dir");
                set_mode(&path, op.mode);
            }
            "file" => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).expect("replay parent");
                }
                let _ = fs::remove_file(&path);
                let content = op.content.as_ref().expect("file content").decode();
                fs::write(&path, state.denormalize(&content)).expect("replay file");
                set_mode(&path, op.mode);
            }
            "symlink" => {
                #[cfg(unix)]
                {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).expect("replay parent");
                    }
                    let _ = fs::remove_file(&path);
                    let target = op.content.as_ref().expect("target").decode();
                    let target = state.denormalize(&target);
                    std::os::unix::fs::symlink(
                        String::from_utf8_lossy(&target).into_owned(),
                        &path,
                    )
                    .expect("replay symlink");
                }
            }
            "remove" => {
                if fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
                    let _ = fs::remove_dir_all(&path);
                } else {
                    let _ = fs::remove_file(&path);
                }
            }
            other => panic!("go_oracle: unknown fs op {other}"),
        }
    }
}

fn set_mode(path: &Path, mode: Option<u32>) {
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("replay mode");
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

// ---------------------------------------------------------------------------
// Command interception.

fn raw_status(code: Option<i32>, signal: Option<i32>) -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        match (code, signal) {
            (Some(code), _) => std::process::ExitStatus::from_raw((code & 0xff) << 8),
            (None, Some(signal)) => std::process::ExitStatus::from_raw(signal),
            (None, None) => panic!("transcript response has neither exit code nor signal"),
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        let _ = signal;
        std::process::ExitStatus::from_raw(code.expect("exit code") as u32)
    }
}

fn status_parts(status: &std::process::ExitStatus) -> (Option<i32>, Option<i32>) {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        (status.code(), status.signal())
    }
    #[cfg(not(unix))]
    {
        (status.code(), None)
    }
}

/// True when `program` is the Go oracle of the running test (the recorded
/// side). Lets a test harden only the Rust side of a pair without
/// changing the recorded Go request keys.
pub fn is_oracle_binary(program: &Path) -> bool {
    current().is_some_and(|state| state.borrow().go_path == program)
}

fn current() -> Option<Rc<RefCell<State>>> {
    CURRENT.with(|c| c.borrow().clone())
}

/// Drop-in for `Command::output()`. Commands that do not run the Go oracle
/// are executed normally (and their temp roots are registered so that the
/// placeholder numbering is the same as when the transcript was recorded).
pub fn output(command: &mut Command) -> std::io::Result<Output> {
    output_with_input(command, None)
}

/// Like [`output`], feeding `stdin` to the process.
pub fn output_with_input(command: &mut Command, stdin: Option<&[u8]>) -> std::io::Result<Output> {
    let Some(state) = current() else {
        return run_real(command, stdin);
    };
    let program = command.get_program().to_owned();
    let is_go = program == state.borrow().go_path.as_os_str();
    {
        let mut st = state.borrow_mut();
        let mut mentioned: Vec<Vec<u8>> = Vec::new();
        for arg in command.get_args() {
            mentioned.push(arg.to_string_lossy().into_owned().into_bytes());
        }
        for (_, value) in command.get_envs() {
            if let Some(value) = value {
                mentioned.push(value.to_string_lossy().into_owned().into_bytes());
            }
        }
        if let Some(dir) = command.get_current_dir() {
            mentioned.push(dir.to_string_lossy().into_owned().into_bytes());
        }
        if let Some(stdin) = stdin {
            mentioned.push(stdin.to_vec());
        }
        for text in mentioned {
            st.scan(&text);
        }
    }
    if !is_go {
        return run_real(command, stdin);
    }

    let request = {
        let st = state.borrow();
        Request {
            args: command.get_args().map(|a| text_of(&st, a)).collect(),
            env: command
                .get_envs()
                .map(|(k, v)| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.map(|v| env_value(&st, v)),
                    )
                })
                .collect(),
            cwd: command.get_current_dir().map(|d| {
                String::from_utf8_lossy(&st.normalize(d.to_string_lossy().as_bytes())).into_owned()
            }),
            stdin: stdin.map(|s| Bytes::encode(&st.normalize(s))),
        }
    };
    let key = {
        let canonical = serde_json::to_vec(&request).expect("request json");
        hex::encode(Sha256::digest(canonical))
    };

    let mut st = state.borrow_mut();
    let position = st
        .recorded
        .iter()
        .enumerate()
        .position(|(i, e)| !st.consumed[i] && e.key == key);
    let Some(position) = position else {
        let stale = st
            .recorded
            .iter()
            .enumerate()
            .filter(|(i, _)| !st.consumed[*i])
            .map(|(i, e)| format!("  #{i}: {:?}", e.request.args))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "go_oracle: no recorded Go call for {}::{} with request {request:#?}\n\
             unconsumed recorded calls:\n{stale}\nrecapture with the pinned oracle \
             (tag legacy/go-oracle)",
            st.file, st.test
        );
    };
    st.consumed[position] = true;
    let entry = st.recorded[position].clone();
    if st.apply_effects {
        apply(&st, &entry.fs_delta);
    }
    let response = &entry.response;
    Ok(Output {
        status: raw_status(response.exit_code, response.signal),
        stdout: st.denormalize(&response.stdout.decode()),
        stderr: st.denormalize(&response.stderr.decode()),
    })
}

fn run_real(command: &mut Command, stdin: Option<&[u8]>) -> std::io::Result<Output> {
    match stdin {
        None => command.output(),
        Some(input) => {
            use std::process::Stdio;
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let mut pipe = child.stdin.take().expect("stdin pipe");
            let input = input.to_vec();
            let writer = std::thread::spawn(move || {
                let _ = pipe.write_all(&input);
            });
            let output = child.wait_with_output()?;
            let _ = writer.join();
            Ok(output)
        }
    }
}

/// Environment variables are passed through unchanged; helper kept for tests
/// that need to assert nothing leaks into the request.
pub fn os(value: &str) -> OsString {
    OsString::from(value)
}
