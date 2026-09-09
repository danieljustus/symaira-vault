use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};
use symvault_sync::git::{CommitOptions, GitRepository};
use tempfile::tempdir;

#[derive(Debug, Deserialize)]
struct Fixture {
    cases: Vec<Case>,
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

fn case(id: &str) -> Case {
    fixture()
        .cases
        .into_iter()
        .find(|case| case.id == id)
        .unwrap()
}

fn git(cwd: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
