#![deny(unsafe_code)]

use serde::Deserialize;
use std::{
    fs,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use symvault_platform::{AgentRateLimiter, QUOTA_FILE_NAME, QuotaCounter, QuotaError};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    oracle: Oracle,
    cases: Vec<QuotaCase>,
    wrapper_cases: Vec<WrapperCase>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
    goos: String,
}

#[derive(Debug, Deserialize)]
struct QuotaCase {
    name: String,
    counts: std::collections::BTreeMap<String, i64>,
    after_reset: std::collections::BTreeMap<String, i64>,
    raw_after_write: String,
    raw_after_reset: String,
    dir_mode: u32,
    file_mode: u32,
    closed_check: [i64; 2],
}

#[derive(Debug, Deserialize)]
struct WrapperCase {
    name: String,
    unknown_before: bool,
    has_after_set: bool,
    first_allow: bool,
    second_allow: bool,
    other_agent_allow: bool,
    #[serde(rename = "has_after_cleanup")]
    has_after_clean: bool,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/quotas/contract.json");
    serde_json::from_slice(CONTENT).expect("decode Go-generated persistent quota fixture")
}

fn unique_dir(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("symvault-{label}-{}", std::process::id()))
}

#[test]
fn persistent_quota_fixture_has_pinned_provenance() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "caadd5e");
    assert_eq!(fixture.oracle.release, "v0.22.1");
    assert_eq!(fixture.oracle.source_files.len(), 8);
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert_eq!(fixture.oracle.goos, "darwin");
    assert_eq!(fixture.cases.len(), 1);
    assert_eq!(fixture.wrapper_cases.len(), 1);
}

#[test]
fn persistent_quota_fixture_matches_public_rust_wrapper() {
    let fixture = fixture();
    let expected = &fixture.cases[0];
    assert_eq!(expected.name, "persistent_counter");
    let dir = unique_dir("quota-contract");
    let _ = fs::remove_dir_all(&dir);
    let mut quota = QuotaCounter::new(&dir).unwrap();
    assert_eq!(quota.increment("read_entry").unwrap(), 1);
    assert_eq!(quota.increment("read_entry").unwrap(), 2);
    assert_eq!(quota.increment("write_entry").unwrap(), 1);
    assert_eq!(expected.counts.get("read_entry"), Some(&2));
    assert_eq!(expected.counts.get("write_entry"), Some(&1));
    assert_eq!(expected.after_reset.get("after_reset"), Some(&1));
    assert_eq!(quota.check("read_entry", 2).unwrap(), (false, 2));
    assert_eq!(
        fs::read_to_string(dir.join(QUOTA_FILE_NAME)).unwrap(),
        expected.raw_after_write
    );

    quota.reset().unwrap();
    assert_eq!(
        fs::read_to_string(dir.join(QUOTA_FILE_NAME)).unwrap(),
        expected.raw_after_reset
    );
    assert_eq!(quota.increment("after_reset").unwrap(), 1);
    quota.close().unwrap();
    assert!(matches!(
        quota.check("after_reset", 10),
        Err(QuotaError::Closed)
    ));
    assert_eq!(expected.closed_check, [0, 0]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(dir.join(QUOTA_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, expected.dir_mode);
        assert_eq!(file_mode, expected.file_mode);
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn persistent_quota_rejects_malformed_state_and_zero_limit() {
    let dir = unique_dir("quota-errors");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(QUOTA_FILE_NAME),
        br#"{"counters":{"read_entry":"bad"}}"#,
    )
    .unwrap();
    let quota = QuotaCounter::new(&dir).unwrap();
    assert!(matches!(
        quota.increment("read_entry"),
        Err(QuotaError::Malformed(_))
    ));
    assert_eq!(quota.check("read_entry", 0).unwrap(), (false, 0));
    let parent_file = unique_dir("quota-not-a-directory");
    let _ = fs::remove_dir_all(&parent_file);
    fs::write(&parent_file, b"file").unwrap();
    assert!(matches!(
        QuotaCounter::new(parent_file.join("child")),
        Err(QuotaError::Io { .. })
    ));
    let _ = fs::remove_file(parent_file);
}

#[test]
fn public_agent_rate_limiter_fixture_matches_rust_wrapper() {
    let expected = &fixture().wrapper_cases[0];
    assert_eq!(expected.name, "public_registry");
    let limiter = AgentRateLimiter::new();
    assert_eq!(limiter.allow("unknown"), expected.unknown_before);
    limiter.set_limits("agent-a", 1, 1);
    assert_eq!(limiter.has_limits("agent-a"), expected.has_after_set);
    assert_eq!(limiter.allow("agent-a"), expected.first_allow);
    assert_eq!(limiter.allow("agent-a"), expected.second_allow);
    assert_eq!(limiter.allow("agent-b"), expected.other_agent_allow);
    limiter.cleanup();
    assert_eq!(limiter.has_limits("agent-a"), expected.has_after_clean);
}

#[test]
fn quota_cross_process_updates_are_not_lost() {
    if std::env::var_os("SYMVAULT_QUOTA_WORKER").is_some() {
        return;
    }
    let dir = unique_dir("quota-process");
    let _ = fs::remove_dir_all(&dir);
    let start = dir.join("start");
    let quota = QuotaCounter::new(&dir).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "quota_cross_process_worker", "--nocapture"])
        .env("SYMVAULT_QUOTA_WORKER", &dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    fs::write(&start, b"go").unwrap();
    for _ in 0..64 {
        quota.increment("read_entry").unwrap();
    }
    let status = child.wait().unwrap();
    assert!(status.success(), "quota worker failed: {status}");
    assert_eq!(quota.check("read_entry", 129).unwrap(), (true, 128));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn quota_cross_process_worker() {
    let Some(dir) = std::env::var_os("SYMVAULT_QUOTA_WORKER") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let start = dir.join("start");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !start.exists() {
        assert!(
            Instant::now() < deadline,
            "parent did not release quota worker"
        );
        thread::sleep(Duration::from_millis(1));
    }
    let quota = QuotaCounter::new(&dir).unwrap();
    for _ in 0..64 {
        quota.increment("read_entry").unwrap();
    }
}
