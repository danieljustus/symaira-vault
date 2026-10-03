use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};
use symvault_sync::NETWORK_MESSAGE;
use symvault_sync::git::{CommitOptions, GitRepository};
use tempfile::{TempDir, tempdir};

#[derive(Debug, Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct GitIoFixture {
    schema_version: u32,
    oracle: GitIoOracle,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct GitIoOracle {
    commit: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator: String,
    generator_digest: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    input: Value,
    expected: Value,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("../../../testdata/port/sync/sync.json")).unwrap()
}

fn git_io_fixture() -> GitIoFixture {
    serde_json::from_str(include_str!("../../../testdata/port/sync/git-io.json")).unwrap()
}

fn git_io_case(id: &str) -> Case {
    git_io_fixture()
        .cases
        .into_iter()
        .find(|case| case.id == id)
        .unwrap()
}

fn expected_bool(expected: &Value, key: &str) -> bool {
    expected[key]
        .as_bool()
        .unwrap_or_else(|| panic!("fixture field {key} is not a bool"))
}

fn assert_pull_projection(result: &symvault_sync::git::PullResult, expected: &Value) {
    assert_eq!(result.success, expected_bool(expected, "success"));
    assert_eq!(result.skipped, expected_bool(expected, "skipped"));
    assert_eq!(
        result.remote_url.is_some(),
        expected_bool(expected, "has_remote")
    );
}

fn assert_push_projection(result: &symvault_sync::git::PushResult, expected: &Value) {
    assert_eq!(result.success, expected_bool(expected, "success"));
    assert_eq!(result.skipped, expected_bool(expected, "skipped"));
    assert_eq!(
        result.remote_url.is_some(),
        expected_bool(expected, "has_remote")
    );
}

fn case(id: &str) -> Case {
    fixture()
        .cases
        .into_iter()
        .find(|case| case.id == id)
        .unwrap()
}

fn git(cwd: &Path, args: &[&str]) -> Output {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn pair() -> (TempDir, GitRepository, PathBuf) {
    let root = tempdir().expect("temporary root");
    let remote = root.path().join("remote.git");
    git(root.path(), &["init", "--bare", remote.to_str().unwrap()]);
    git(&remote, &["symbolic-ref", "HEAD", "refs/heads/master"]);

    let local_path = root.path().join("local");
    let repo = GitRepository::init(&local_path).expect("init local");
    repo.add_remote("origin", remote.to_str().unwrap())
        .expect("add origin");
    fs::write(local_path.join("entry.age"), b"base").expect("write base");
    repo.commit(CommitOptions {
        message: "base".into(),
        author: Some("Fixture".into()),
        email: Some("fixture@example.com".into()),
        ..Default::default()
    })
    .expect("commit base");
    assert!(repo.push("origin").success, "push base");
    (root, repo, remote)
}

fn push_remote_change(root: &TempDir, remote: &Path, contents: &[u8]) {
    let other = root.path().join("other");
    git(
        root.path(),
        &["clone", remote.to_str().unwrap(), other.to_str().unwrap()],
    );
    git(&other, &["config", "user.name", "Other"]);
    git(&other, &["config", "user.email", "other@example.com"]);
    fs::write(other.join("entry.age"), contents).expect("write remote change");
    git(&other, &["add", "--all"]);
    git(&other, &["commit", "-m", "remote"]);
    git(&other, &["push", "origin", "HEAD"]);
}

fn diverge_local_and_remote(repo: &GitRepository, root: &TempDir, remote: &Path) {
    fs::write(repo.root().join("entry.age"), b"local").expect("write local change");
    repo.commit(CommitOptions {
        message: "local".into(),
        author: Some("Fixture".into()),
        email: Some("fixture@example.com".into()),
        ..Default::default()
    })
    .expect("commit local");
    push_remote_change(root, remote, b"remote");
}

#[test]
fn go_git_io_fixture_is_source_bound() {
    let fixture = git_io_fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle.commit,
        "28fd35315cf4989821a96bb08279c999c693e8d9"
    );
    assert_eq!(fixture.oracle.release, "unreleased");
    assert!(!fixture.oracle.source_files.is_empty());
    assert!(
        fixture
            .oracle
            .source_files
            .iter()
            .all(|path| path.starts_with("internal/git/"))
    );
    assert!(
        fixture
            .oracle
            .source_files
            .iter()
            .any(|path| path.ends_with("process_tree_unix.go"))
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(
        fixture.oracle.generator,
        "scripts/rust-port/cmd/gitio/main.go"
    );
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert_eq!(fixture.cases.len(), 5);
    let ids: BTreeSet<_> = fixture.cases.iter().map(|case| case.id.as_str()).collect();
    let expected: BTreeSet<_> = [
        "GIT-002-go-offline",
        "GIT-002-go-auth",
        "GIT-002-go-ssh-precedence",
        "GIT-002-go-askpass",
        "GIT-002-go-timeout",
    ]
    .into_iter()
    .collect();
    assert_eq!(ids, expected);
}

#[test]
fn divergent_pull_matches_go_oracle_projection() {
    let expected = case("GIT-002-local-bare");
    let input = expected.input;
    let expected = expected.expected;
    let entry = input["entry"].as_str().unwrap();
    let remote_name = input["remote"].as_str().unwrap();
    let branch = input["branch"].as_str().unwrap();
    let temp = tempdir().unwrap();
    let remote = temp.path().join("remote.git");
    let local = temp.path().join("local");
    let other = temp.path().join("other");

    git(temp.path(), &["init", "--bare", remote.to_str().unwrap()]);
    git(
        temp.path(),
        &[
            "-C",
            remote.to_str().unwrap(),
            "symbolic-ref",
            "HEAD",
            "refs/heads/master",
        ],
    );
    let repo = GitRepository::init(&local).unwrap();
    repo.add_remote(remote_name, remote.to_str().unwrap())
        .unwrap();
    fs::write(
        local.join(entry),
        input["first_bytes"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    repo.commit(CommitOptions {
        message: input["first_commit"].as_str().unwrap().into(),
        ..Default::default()
    })
    .unwrap();
    let push = repo.push(remote_name);
    assert_eq!(push.success, expected["push_success"]);
    assert_eq!(push.skipped, expected["push_skipped"]);
    assert!(push.remote_url.is_some() == expected["push_has_remote"]);
    let upstream = format!("{remote_name}/{branch}");
    git(&local, &["branch", "--set-upstream-to", &upstream, branch]);

    fs::write(
        local.join(entry),
        input["local_bytes"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    repo.commit(CommitOptions {
        message: input["local_commit"].as_str().unwrap().into(),
        ..Default::default()
    })
    .unwrap();
    fs::write(local.join(".device-id"), b"test-device\n").unwrap();

    git(
        temp.path(),
        &["clone", remote.to_str().unwrap(), other.to_str().unwrap()],
    );
    fs::write(
        other.join(entry),
        input["remote_bytes"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    git(&other, &["config", "user.name", "Other"]);
    git(&other, &["config", "user.email", "other@example.com"]);
    git(&other, &["add", "--all"]);
    git(
        &other,
        &["commit", "-m", input["remote_commit"].as_str().unwrap()],
    );
    git(&other, &["push", remote_name, "HEAD"]);

    let pull = repo.pull(remote_name);
    assert_eq!(pull.success, expected["pull_success"]);
    assert_eq!(pull.updated, expected["pull_updated"]);
    assert_eq!(pull.skipped, expected["pull_skipped"]);
    assert!(pull.remote_url.is_some() == expected["pull_has_remote"]);
    assert_eq!(
        pull.error.is_some(),
        !expected["pull_error"].as_str().unwrap().is_empty()
    );
    assert_eq!(
        sha256(&fs::read(local.join(entry)).unwrap()),
        expected["final_sha256"]
    );
    assert_eq!(
        fs::read(local.join("entry.conflict-test-device.age")).unwrap(),
        input["local_bytes"].as_str().unwrap().as_bytes()
    );
}

#[test]
fn pull_preserves_preexisting_merge_index_and_conflict_state() {
    let (root, repo, remote) = pair();
    diverge_local_and_remote(&repo, &root, &remote);
    git(repo.root(), &["fetch", "origin"]);
    let merge = Command::new("git")
        .arg("-C")
        .arg(repo.root())
        .args(["merge", "origin/master"])
        .output()
        .expect("git merge");
    assert!(!merge.status.success(), "fixture merge must be conflicted");

    let git_dir = repo.root().join(".git");
    let merge_head = fs::read(git_dir.join("MERGE_HEAD")).expect("MERGE_HEAD");
    let merge_msg = fs::read(git_dir.join("MERGE_MSG")).expect("MERGE_MSG");
    let index = fs::read(git_dir.join("index")).expect("index");
    let conflict = fs::read(repo.root().join("entry.age")).expect("conflict file");

    let result = repo.pull("origin");
    assert!(!result.success);
    assert!(result.error.is_some());
    assert_eq!(fs::read(git_dir.join("MERGE_HEAD")).unwrap(), merge_head);
    assert_eq!(fs::read(git_dir.join("MERGE_MSG")).unwrap(), merge_msg);
    assert_eq!(fs::read(git_dir.join("index")).unwrap(), index);
    assert_eq!(fs::read(repo.root().join("entry.age")).unwrap(), conflict);
    let status = git(repo.root(), &["status", "--porcelain"]).stdout;
    assert!(String::from_utf8_lossy(&status).contains("UU entry.age"));
}

#[test]
fn pull_aborts_merge_state_created_by_this_invocation() {
    let (root, repo, remote) = pair();
    diverge_local_and_remote(&repo, &root, &remote);
    let before = fs::read(repo.root().join("entry.age")).expect("local version");

    let result = repo.pull("origin");
    assert!(!result.success);
    assert!(result.error.is_some());
    assert!(!repo.root().join(".git/MERGE_HEAD").exists());
    assert!(!repo.root().join(".git/MERGE_MSG").exists());
    assert_eq!(fs::read(repo.root().join("entry.age")).unwrap(), before);
    let unresolved = git(repo.root(), &["diff", "--name-only", "--diff-filter=U"]).stdout;
    assert!(unresolved.is_empty(), "pull left unresolved index state");
}

fn auth_server(status: &str) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind auth server");
    let port = listener.local_addr().unwrap().port();
    let status = status.to_owned();
    let handle = thread::spawn(move || {
        // Windows runners can take several seconds to spawn the Git processes
        // that reach this listener; the loop still exits on the first request.
        let deadline = Instant::now() + Duration::from_secs(30);
        listener.set_nonblocking(true).expect("set nonblocking");
        while Instant::now() < deadline {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(10));
                continue;
            };
            stream.set_nonblocking(false).expect("blocking auth socket");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("bound auth request read");
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .expect("bound auth response write");
            // A single read can leave part of Git's GET headers unread. Closing
            // that socket resets the connection on Windows before curl observes
            // the 401, incorrectly exercising a transport failure instead.
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 64 * 1024, "oversized auth request");
                let mut byte = [0];
                stream.read_exact(&mut byte).expect("complete auth headers");
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"GET "), "expected bodyless Git GET");
            let response = format!(
                "HTTP/1.1 {status}\r\nWWW-Authenticate: Basic realm=fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .expect("auth response");
            stream
                .shutdown(Shutdown::Write)
                .expect("complete auth reply");
            return;
        }
        panic!("Git never reached the bounded auth server");
    });
    (port, handle)
}

#[test]
fn auth_remote_waits_for_fragmented_headers_before_replying() {
    let (port, server) = auth_server("401 Unauthorized");
    let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connect auth fixture");
    client
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("bound premature reply check");
    let partial = format!(
        "GET /repo.git/info/refs HTTP/1.1\r\nHost: localhost\r\nX-Padding: {}",
        "x".repeat(4096)
    );
    client
        .write_all(partial.as_bytes())
        .expect("partial headers");
    let error = client
        .read(&mut [0])
        .expect_err("no reply before header terminator");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    client
        .write_all(b"\r\nConnection: close\r\n\r\n")
        .expect("finish headers");
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("bound final reply");
    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .expect("complete HTTP response without reset");
    assert_eq!(
        response,
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    server.join().expect("auth fixture server");
}

#[test]
fn pull_projects_auth_failure_from_a_real_http_remote() {
    let contract = git_io_case("GIT-002-go-auth");
    let (_root, repo, _remote) = pair();
    let (port, server) = auth_server("401 Unauthorized");
    let remote = format!("http://127.0.0.1:{port}/repo.git");
    git(repo.root(), &["remote", "set-url", "origin", &remote]);
    // An empty repository-local helper resets inherited Git Credential Manager
    // helpers on Windows, letting the loopback 401 reach this contract.
    git(repo.root(), &["config", "credential.helper", ""]);
    let result = repo.pull("origin");
    server.join().expect("auth server");
    let error = result.error.as_ref().expect("auth error").to_string();
    assert_pull_projection(&result, &contract.expected);
    assert_eq!(contract.expected["error_class"], "authentication");
    assert!(error.contains("authentication failed"), "{error}");
}

#[test]
fn pull_projects_connection_failure_as_offline_from_a_real_remote() {
    let contract = git_io_case("GIT-002-go-offline");
    let (_root, repo, _remote) = pair();
    git(
        repo.root(),
        &[
            "remote",
            "set-url",
            "origin",
            "http://127.0.0.1:1/unreachable.git",
        ],
    );
    let result = repo.pull("origin");
    let error = result.error.as_ref().expect("offline error").to_string();
    assert_pull_projection(&result, &contract.expected);
    assert_eq!(contract.expected["error_class"], "offline");
    assert!(error.contains(NETWORK_MESSAGE), "{error}");
}

// Compile a dependency-free native helper once per test process. This keeps
// frozen Rust replay independent of Go and avoids shell emulation on Windows.
fn native_git_helper() -> &'static Path {
    static ROOT: std::sync::OnceLock<(TempDir, PathBuf)> = std::sync::OnceLock::new();
    let root = ROOT.get_or_init(|| {
        let root = tempdir().expect("native Git fixture directory");
        let directory = root.path().join("native helper's files");
        fs::create_dir(&directory).expect("helper path with spaces and apostrophe");
        let source = directory.join("helper.rs");
        fs::write(
            &source,
            include_str!("fixtures/git_transport_helper.rs.txt"),
        )
        .expect("write fixed helper source");
        let helper = directory.join(if cfg!(windows) {
            "git-helper.exe"
        } else {
            "git-helper"
        });
        let output = Command::new("rustc")
            .args(["--edition=2024", "--crate-name", "git_fixture_helper"])
            .arg(&source)
            .arg("-o")
            .arg(&helper)
            .output()
            .expect("compile native helper");
        assert!(
            output.status.success(),
            "native helper compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        (root, helper)
    });
    root.1.as_path()
}

fn fixture_shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', "/").replace('\'', "'\\''"))
}

fn native_ssh_command(mode: &str, marker: &Path) -> String {
    format!(
        "{} {} {}",
        fixture_shell_quote(native_git_helper().to_str().expect("UTF-8 fixture path")),
        fixture_shell_quote(mode),
        fixture_shell_quote(marker.to_str().expect("UTF-8 marker path"))
    )
}

fn fixture_child_alive(pid: &str) -> bool {
    let parsed: u32 = pid.parse().expect("fixture PID is decimal");
    assert!(parsed > 1, "invalid synthetic PID");
    if cfg!(windows) {
        let output = Command::new("tasklist")
            .args(["/fi", &format!("PID eq {parsed}"), "/fo", "csv", "/nh"])
            .output()
            .expect("query actual native process");
        assert!(output.status.success(), "native process query failed");
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .flexible(true)
            .from_reader(output.stdout.as_slice());
        return reader.byte_records().any(|row| {
            let row = row.expect("native tasklist CSV");
            row.get(1).is_some_and(|value| value == pid.as_bytes())
        });
    }
    Command::new("kill")
        .args(["-0", pid])
        .status()
        .expect("query owned descendant")
        .success()
}

#[test]
fn push_projects_known_hosts_failure_before_auth_from_ssh_remote() {
    let contract = git_io_case("GIT-002-go-ssh-precedence");
    let (root, repo, _remote) = pair();
    let helper = native_ssh_command("known-hosts", &root.path().join("known-hosts.marker"));
    git(
        repo.root(),
        &[
            "remote",
            "set-url",
            "origin",
            "ssh://git@example.invalid/repo.git",
        ],
    );
    git(repo.root(), &["config", "core.sshCommand", &helper]);
    let result = repo.push("origin");
    let error = result
        .error
        .as_ref()
        .expect("SSH configuration error")
        .to_string();
    assert_push_projection(&result, &contract.expected);
    assert_eq!(contract.expected["error_class"], "ssh_configuration");
    assert!(error.contains("SSH configuration error"), "{error}");
}

#[test]
fn pull_preserves_configured_askpass_and_suppresses_terminal_prompt() {
    let (root, repo, _remote) = pair();
    let (port, server) = auth_server("401 Unauthorized");
    let marker = root.path().join("askpass-called");
    let helper = root.path().join(if cfg!(windows) {
        "askpass-helper.exe"
    } else {
        "askpass-helper"
    });
    fs::copy(native_git_helper(), &helper).expect("copy native askpass helper");
    let remote = format!("http://127.0.0.1:{port}/repo.git");
    git(repo.root(), &["remote", "set-url", "origin", &remote]);
    git(repo.root(), &["config", "credential.helper", ""]);
    // Git executes askpass directly, with its prompt as one argument.
    git(
        repo.root(),
        &["config", "core.askPass", helper.to_str().unwrap()],
    );
    let result = repo.pull("origin");
    server.join().expect("auth server");
    assert!(result.error.is_some());
    assert_eq!(
        fs::read_to_string(marker).expect("askpass marker"),
        "called"
    );
}

#[test]
fn push_replays_go_askpass_environment_projection() {
    if std::env::var_os("GIT_IO_ASKPASS_CHILD").is_none() {
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .env("GIT_IO_ASKPASS_CHILD", "1")
            .env("GIT_ASKPASS", "/bin/false")
            .args(["--exact", "push_replays_go_askpass_environment_projection"])
            .status()
            .expect("rerun askpass projection in isolated environment");
        assert!(status.success(), "askpass child exited with {status}");
        return;
    }

    let contract = git_io_case("GIT-002-go-askpass");
    let (root, repo, _remote) = pair();
    let marker = root.path().join("askpass.marker");
    let helper = native_ssh_command("askpass-env", &marker);
    git(
        repo.root(),
        &[
            "remote",
            "set-url",
            "origin",
            "ssh://git@example.invalid/repo.git",
        ],
    );
    git(repo.root(), &["config", "core.sshCommand", &helper]);

    let result = repo.push("origin");
    let observed = fs::read_to_string(marker).expect("askpass environment marker");
    assert_push_projection(&result, &contract.expected);
    assert_eq!(contract.expected["error_class"], "other");
    assert_eq!(
        contract.expected["observed"].as_str().unwrap(),
        observed.trim()
    );
}

#[test]
fn push_timeout_replays_go_descendant_cleanup_projection() {
    let contract = git_io_case("GIT-002-go-timeout");
    assert_eq!(contract.input["timeout_seconds"], 20);
    assert_eq!(contract.expected["timed_out"], true);
    assert_eq!(contract.expected["descendant_cleanup"], true);
    let (root, repo, _remote) = pair();
    let marker = root.path().join("ssh-descendant.pid");
    let helper = native_ssh_command("timeout", &marker);
    git(
        repo.root(),
        &[
            "remote",
            "set-url",
            "origin",
            "ssh://git@example.invalid/repo.git",
        ],
    );
    git(repo.root(), &["config", "core.sshCommand", &helper]);

    let started = Instant::now();
    let result = repo.push("origin");
    assert!(started.elapsed() < Duration::from_secs(22));
    let error = result.error.as_ref().expect("timeout error").to_string();
    assert_push_projection(&result, &contract.expected);
    assert_eq!(contract.expected["error_class"], "timeout");
    assert!(error.contains("timed out"), "{error}");
    let pid = fs::read_to_string(marker)
        .expect("SSH helper recorded descendant")
        .trim()
        .to_owned();
    let gone = (0..80).any(|_| {
        let alive = fixture_child_alive(&pid);
        if alive {
            thread::sleep(Duration::from_millis(25));
            false
        } else {
            true
        }
    });
    if !gone {
        let _ = if cfg!(windows) {
            Command::new("taskkill")
                .args(["/PID", &pid, "/T", "/F"])
                .status()
        } else {
            Command::new("kill").args(["-KILL", &pid]).status()
        };
    }
    assert!(gone, "timed-out SSH descendant {pid} is still alive");
}
