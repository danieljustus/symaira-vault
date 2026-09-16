use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
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

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).expect("write helper");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("make helper executable");
    }
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
    assert!(!fixture.oracle.commit.is_empty());
    assert_eq!(fixture.oracle.release, "working-tree");
    assert!(!fixture.oracle.source_files.is_empty());
    assert!(
        fixture
            .oracle
            .source_files
            .iter()
            .all(|path| path.starts_with("internal/git/"))
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(
        fixture.oracle.generator,
        "scripts/rust-port/cmd/gitio/main.go"
    );
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert_eq!(fixture.cases.len(), 3);
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
        let deadline = Instant::now() + Duration::from_secs(3);
        listener.set_nonblocking(true).expect("set nonblocking");
        while Instant::now() < deadline {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(10));
                continue;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let response = format!(
                "HTTP/1.1 {status}\r\nWWW-Authenticate: Basic realm=fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes());
            break;
        }
    });
    (port, handle)
}

#[test]
fn pull_projects_auth_failure_from_a_real_http_remote() {
    let contract = git_io_case("GIT-002-go-auth");
    let (_root, repo, _remote) = pair();
    let (port, server) = auth_server("401 Unauthorized");
    let remote = format!("http://127.0.0.1:{port}/repo.git");
    git(repo.root(), &["remote", "set-url", "origin", &remote]);
    let result = repo.pull("origin");
    server.join().expect("auth server");
    let error = result.error.expect("auth error").to_string();
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
    let error = result.error.expect("offline error").to_string();
    assert_eq!(contract.expected["error_class"], "offline");
    assert!(error.contains(NETWORK_MESSAGE), "{error}");
}

#[test]
fn push_projects_known_hosts_failure_before_auth_from_ssh_remote() {
    let (root, repo, _remote) = pair();
    let helper = root.path().join("ssh-known-hosts.sh");
    write_executable(
        &helper,
        "#!/bin/sh\nprintf '%s\\n' 'known_hosts: fixture failure' >&2\nexit 1\n",
    );
    git(
        repo.root(),
        &[
            "remote",
            "set-url",
            "origin",
            "ssh://git@example.invalid/repo.git",
        ],
    );
    git(
        repo.root(),
        &["config", "core.sshCommand", helper.to_str().unwrap()],
    );
    let result = repo.push("origin");
    let error = result.error.expect("SSH configuration error").to_string();
    assert!(error.contains("SSH configuration error"), "{error}");
}

#[test]
fn pull_preserves_configured_askpass_and_suppresses_terminal_prompt() {
    let (root, repo, _remote) = pair();
    let (port, server) = auth_server("401 Unauthorized");
    let marker = root.path().join("askpass-called");
    let helper = root.path().join("askpass.sh");
    write_executable(
        &helper,
        &format!(
            "#!/bin/sh\nprintf '%s' called > {}\nexit 1\n",
            marker.display()
        ),
    );
    let remote = format!("http://127.0.0.1:{port}/repo.git");
    git(repo.root(), &["remote", "set-url", "origin", &remote]);
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
#[cfg(unix)]
fn pull_timeout_kills_ssh_descendant_through_productive_repository_path() {
    let contract = git_io_case("GIT-002-rust-process-contract");
    assert_eq!(contract.input["terminal_prompt"], "0");
    assert_eq!(contract.input["passphrase_env"], "removed");
    assert_eq!(contract.expected["askpass"], "inherited");
    assert_eq!(contract.expected["descendant_cleanup"], "process-group");
    let (root, repo, _remote) = pair();
    let marker = root.path().join("ssh-descendant.pid");
    let helper = root.path().join("ssh-hang.sh");
    write_executable(
        &helper,
        &format!(
            "#!/bin/sh\n(sleep 60) &\nprintf '%s\\n' \"$!\" > {}\nwait\n",
            marker.display()
        ),
    );
    git(
        repo.root(),
        &[
            "remote",
            "set-url",
            "origin",
            "ssh://git@example.invalid/repo.git",
        ],
    );
    git(
        repo.root(),
        &["config", "core.sshCommand", helper.to_str().unwrap()],
    );

    let result = repo.pull("origin");
    let error = result.error.expect("timeout error").to_string();
    assert!(error.contains("timed out"), "{error}");
    let pid = fs::read_to_string(marker)
        .expect("SSH helper recorded descendant")
        .trim()
        .to_owned();
    let gone = (0..80).any(|_| {
        let alive = Command::new("kill")
            .args(["-0", &pid])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        if alive {
            thread::sleep(Duration::from_millis(25));
            false
        } else {
            true
        }
    });
    assert!(gone, "timed-out SSH descendant {pid} is still alive");
}
