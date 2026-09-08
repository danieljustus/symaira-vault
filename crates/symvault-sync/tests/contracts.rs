use flate2::{Compression, write::GzEncoder};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    process::Command,
    time::{Duration, SystemTime},
};
use symvault_sync::{
    archive,
    git::{CommitOptions, GitRepository},
    importer, intake,
    reconcile::{ReconcileInput, reconcile},
};
use tempfile::tempdir;

fn git(cwd: &std::path::Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(cwd)
            .args(args)
            .output()
            .unwrap()
            .status
            .success(),
        "git {:?}",
        args
    );
}

#[test]
fn git_lifecycle_matches_local_bare_remote_contract() {
    let t = tempdir().unwrap();
    let remote = t.path().join("remote.git");
    let local = t.path().join("local");
    let other = t.path().join("other");
    git(t.path(), &["init", "--bare", remote.to_str().unwrap()]);
    let repo = GitRepository::init(&local).unwrap();
    repo.add_remote("origin", remote.to_str().unwrap()).unwrap();
    fs::write(local.join("identity.age"), b"private").unwrap();
    fs::write(local.join("secret.age"), b"one").unwrap();
    let c = repo
        .commit(CommitOptions {
            message: "first".into(),
            author: Some("Fixture".into()),
            email: Some("fixture@example.com".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(c.is_some());
    assert_eq!(repo.log(10).unwrap()[0].message, "first");
    assert!(
        repo.status()
            .unwrap()
            .iter()
            .all(|s| s.path != "identity.age")
    );
    assert!(repo.push("origin").success);
    git(
        t.path(),
        &["clone", remote.to_str().unwrap(), other.to_str().unwrap()],
    );
    fs::write(other.join("secret.age"), b"two").unwrap();
    git(&other, &["config", "user.name", "Other"]);
    git(&other, &["config", "user.email", "other@example.com"]);
    git(&other, &["add", "--all"]);
    git(&other, &["commit", "-m", "remote"]);
    git(&other, &["push", "origin", "HEAD"]);
    let pull = repo.pull("origin");
    assert!(pull.success, "pull failed: {pull:?}");
    assert_eq!(fs::read(local.join("secret.age")).unwrap(), b"two");
}

#[test]
fn reconciliation_is_order_independent_and_lossless_on_conflict() {
    let input = ReconcileInput {
        base: BTreeMap::from([("a".into(), b"base".to_vec())]),
        local: BTreeMap::from([
            ("a".into(), b"local".to_vec()),
            ("new".into(), b"n".to_vec()),
        ]),
        remote: BTreeMap::from([
            ("a".into(), b"remote".to_vec()),
            ("r".into(), b"r".to_vec()),
        ]),
    };
    let output = reconcile(&input);
    assert_eq!(output.files["a"], b"local");
    assert_eq!(output.files["a.conflict-remote"], b"remote");
    assert_eq!(output.conflicts.len(), 1);
    assert_eq!(output.changed, vec!["a", "a.conflict-remote", "new", "r"]);
}

#[test]
fn backup_restore_preserves_manifest_modes_and_rejects_traversal() {
    let t = tempdir().unwrap();
    let src = t.path().join("src");
    let dst = t.path().join("dst");
    fs::create_dir(&src).unwrap();
    fs::create_dir(src.join("entries")).unwrap();
    fs::write(src.join("entries/a.age"), b"ciphertext").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(src.join("entries/a.age"), fs::Permissions::from_mode(0o640)).unwrap();
    }
    let archive_path = t.path().join("backup.tar.gz");
    let manifest = archive::backup(&src, &archive_path, false).unwrap();
    assert!(manifest.iter().any(|x| x.path == "entries/a.age"));
    let restored = archive::restore(&archive_path, &dst, false).unwrap();
    assert_eq!(
        restored
            .iter()
            .find(|x| x.path == "entries/a.age")
            .unwrap()
            .sha256,
        manifest
            .iter()
            .find(|x| x.path == "entries/a.age")
            .unwrap()
            .sha256
    );
    assert_eq!(fs::read(dst.join("entries/a.age")).unwrap(), b"ciphertext");
    assert_eq!(
        restored
            .iter()
            .find(|x| x.path == "entries/a.age")
            .unwrap()
            .mode,
        manifest
            .iter()
            .find(|x| x.path == "entries/a.age")
            .unwrap()
            .mode
    );
    let evil = t.path().join("evil.tar.gz");
    let f = fs::File::create(&evil).unwrap();
    let mut gz = GzEncoder::new(f, Compression::default());
    let mut header = [0u8; 512];
    header[..10].copy_from_slice(b"../escape\0");
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(b"00000000006\0");
    header[136..148].copy_from_slice(b"00000000000\0");
    header[156] = b'0';
    header[148..156].fill(b' ');
    let checksum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    let checksum_text = format!("{checksum:06o}");
    header[148..154].copy_from_slice(checksum_text.as_bytes());
    header[154] = 0;
    header[155] = b' ';
    gz.write_all(&header).unwrap();
    gz.write_all(b"escape").unwrap();
    gz.write_all(&[0u8; 506]).unwrap();
    gz.write_all(&[0u8; 1024]).unwrap();
    gz.finish().unwrap();
    assert!(archive::restore(&evil, t.path().join("bad"), false).is_err());
    assert!(!t.path().join("escape").exists());
}

#[test]
fn import_and_intake_adapters_are_bounded_and_deterministic() {
    let csv=b"title,username,password,url\nExample,alice,secret,https://example.test\nExample,bob,secret2,https://example.test\n";
    let entries = importer::parse(importer::Format::Csv, csv).unwrap();
    assert_eq!(entries[0].path, "Example");
    assert_eq!(entries[1].path, "Example");
    let bw=serde_json::to_vec(&json!({"folders":[{"id":"f","name":"Work"}],"items":[{"type":1,"name":"Login","folderId":"f","login":{"username":"u","password":"p","uris":[{"uri":"https://x"}]}}]})).unwrap();
    let b = importer::parse_bitwarden(&bw).unwrap();
    assert_eq!(b[0].path, "Work/Login");
    assert_eq!(b[0].data["username"], "u");
    let fuzz = tempdir().unwrap();
    for n in 0..256 {
        let bytes = (0..n % 97)
            .map(|x| ((x * 31) % 256) as u8)
            .collect::<Vec<_>>();
        let _ = importer::parse_bitwarden(&bytes);
        let _ = importer::parse_1pux(&bytes);
        let _ = intake::source_type("x", &bytes);
        let _ = intake::suggestions(&bytes, intake::SourceType::Other, "../../x.pem");
        let archive_path = fuzz.path().join(format!("{n}.tar.gz"));
        fs::write(&archive_path, &bytes).unwrap();
        let _ = archive::restore(&archive_path, fuzz.path().join(format!("dest-{n}")), false);
    }
    let t = tempdir().unwrap();
    let inbox = t.path().join("inbox");
    let spool = t.path().join("spool");
    fs::create_dir(&inbox).unwrap();
    fs::write(
        inbox.join("creds.env"),
        b"USERNAME=alice\nPASSWORD=secret\n",
    )
    .unwrap();
    let opts = intake::Options {
        debounce: Duration::ZERO,
        ..Default::default()
    };
    let mut watcher = intake::Watcher::new(&inbox, opts).unwrap();
    let s = intake::Spool::new(&spool).unwrap();
    let now = SystemTime::now() + Duration::from_secs(1);
    let results = watcher.scan_at(now, &s).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, "ok");
    assert_eq!(watcher.scan_at(now, &s).unwrap().len(), 0);
    let json = serde_json::to_string(&results[0]).unwrap();
    assert!(!json.contains("alice"));
    assert!(!json.contains("secret"));
}

struct Sink {
    paths: BTreeSet<String>,
    calls: Vec<String>,
}
impl intake::QuarantineSink for Sink {
    fn write(
        &mut self,
        path: &str,
        _: &BTreeMap<String, String>,
        _: &[u8],
        _: &intake::Provenance,
    ) -> std::io::Result<()> {
        self.paths.insert(path.into());
        self.calls.push(path.into());
        Ok(())
    }
    fn contains_hash(&self, _: &str) -> bool {
        false
    }
}
#[test]
fn quarantine_is_review_gated_and_dry_run_has_no_side_effect() {
    let r = intake::FileResult {
        file: "x".into(),
        status: "ok".into(),
        reason: None,
        provenance: Some(intake::Provenance {
            source_path: "x".into(),
            source_name: "x.txt".into(),
            source_type: intake::SourceType::Text,
            size: 3,
            sha256: "hash".into(),
            mtime: 0,
        }),
        suggestions: vec![],
    };
    let mut sink = Sink {
        paths: BTreeSet::new(),
        calls: Vec::new(),
    };
    let p = intake::quarantine(&mut sink, &[(r.clone(), b"abc".to_vec())], "id", true).unwrap();
    assert_eq!(p, vec!["quarantine/id/x"]);
    assert!(sink.calls.is_empty());
    let p = intake::quarantine(&mut sink, &[(r, b"abc".to_vec())], "id", false).unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!(sink.calls.len(), 1);
}

#[test]
fn go_oracle_fixture_covers_import_and_sniff_contracts() {
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/go-oracle.json")).unwrap();
    assert_eq!(oracle[0]["value"], "Work/Example-Name-");
    assert_eq!(
        importer::normalize_path(" /Work/Example Name../ "),
        oracle[0]["value"]
    );
    let csv = b"title,username,password,url\nExample,fixture-user,fixture-pass,https://example.test\nExample,second-user,second-pass,https://example.test\n";
    let csv_entries = importer::parse(importer::Format::Csv, csv).unwrap();
    assert_eq!(csv_entries.len(), 2);
    assert_eq!(
        csv_entries[0].path,
        oracle[2]["value"]["entries"][0]["Path"].as_str().unwrap()
    );
    assert_eq!(
        csv_entries[1].path,
        oracle[2]["value"]["entries"][1]["Path"].as_str().unwrap()
    );
    let bw = serde_json::to_vec(&json!({
        "folders": [{"id": "f", "name": "Work"}],
        "items": [{"type": 1, "name": "Login", "folderId": "f", "notes": "fixture-note",
            "login": {"username": "fixture-user", "password": "fixture-pass",
                "uris": [{"uri": "https://example.test"}]}}]
    }))
    .unwrap();
    let bw_entries = importer::parse_bitwarden(&bw).unwrap();
    assert_eq!(
        bw_entries[0].path,
        oracle[3]["value"]["entries"][0]["Path"].as_str().unwrap()
    );
    assert_eq!(
        bw_entries[0].data["username"],
        oracle[3]["value"]["entries"][0]["Data"]["username"]
    );
    for (name, data, expected) in [
        (
            "fixture.bin",
            b"USERNAME=fixture-user\nPASSWORD=fixture-pass\n".as_slice(),
            "env",
        ),
        (
            "fixture.bin",
            b"{\"username\":\"fixture-user\"}".as_slice(),
            "json",
        ),
        ("fixture.bin", &[0, 1, 2, 3][..], "other"),
    ] {
        let observed = format!("{:?}", intake::source_type(name, data)).to_ascii_lowercase();
        assert_eq!(observed, expected);
    }
}
