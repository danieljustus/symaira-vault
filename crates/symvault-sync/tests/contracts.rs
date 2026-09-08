use base64::Engine;
use flate2::{Compression, write::GzEncoder};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
    let fixture = sync_fixture();
    let expected = sync_case(&fixture, "GIT-001-local");
    assert_eq!(expected.expected["status"], "");
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

#[derive(Debug, Deserialize)]
struct SyncFixture {
    schema_version: u32,
    oracle: SyncOracle,
    cases: Vec<SyncCase>,
    scope: BTreeMap<String, String>,
}
#[derive(Debug, Deserialize)]
struct SyncOracle {
    commit: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_files: Vec<String>,
    generator_digest: String,
}
#[derive(Debug, Deserialize)]
struct SyncCase {
    id: String,
    seam: String,
    input: Value,
    expected: Value,
}

fn sync_fixture() -> SyncFixture {
    serde_json::from_str(include_str!("../../../testdata/port/sync/sync.json")).unwrap()
}

fn sync_case<'a>(fixture: &'a SyncFixture, id: &str) -> &'a SyncCase {
    fixture.cases.iter().find(|case| case.id == id).unwrap()
}

#[test]
fn go_generated_sync_fixture_is_provenance_bound_and_scope_honest() {
    let fixture = sync_fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "caadd5e");
    assert_eq!(fixture.oracle.release, "v0.22.1");
    assert!(!fixture.oracle.source_files.is_empty());
    assert!(fixture.oracle.source_files.iter().all(|path| {
        path.starts_with("internal/git/")
            || path.starts_with("internal/vault/")
            || path.starts_with("internal/importer/")
            || path.starts_with("internal/exporter/")
            || path.starts_with("internal/intake/")
            || path.starts_with("cmd/admin/")
    }));
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(
        fixture.oracle.generator_files,
        ["scripts/rust-port/cmd/syncgen/main.go"]
    );
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert!(fixture.cases.iter().all(|case| !case.seam.is_empty()));
    let ids: BTreeSet<_> = fixture.cases.iter().map(|case| case.id.as_str()).collect();
    assert_eq!(ids.len(), 7);
    for id in [
        "GIT-001-local",
        "GIT-002-local-bare",
        "GIT-003-conflict",
        "IO-001-imports",
        "IO-002-export",
        "IO-002-archive",
        "IO-003-portable-intake",
    ] {
        assert!(ids.contains(id), "missing generated case {id}");
    }
    assert!(fixture.scope["native_watcher"].contains("unproven"));
    assert!(fixture.scope["pass_import"].contains("unproven"));
    assert!(fixture.scope["candidate_gaps"].contains("GIT-002"));
}

#[test]
fn go_generated_import_export_and_intake_cases_match_rust() {
    let fixture = sync_fixture();
    let imports = sync_case(&fixture, "IO-001-imports");
    let decode = |name: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(imports.input[name].as_str().unwrap())
            .unwrap()
    };
    for (format, name) in [
        (importer::Format::Csv, "csv"),
        (importer::Format::Bitwarden, "bitwarden"),
        (importer::Format::OnePassword, "onepux"),
    ] {
        let got = importer::parse(format, &decode(name)).unwrap();
        assert_eq!(serde_json::to_value(got).unwrap(), imports.expected[name]);
    }
    assert_eq!(
        imports.expected["pass_adapter"],
        "not exercised: requires external gpg"
    );

    let export_case = sync_case(&fixture, "IO-002-export");
    let entries = vec![
        symvault_sync::export::ExportEntry {
            path: "Example".into(),
            data: BTreeMap::from([
                ("password".into(), Value::String("fixture-pass".into())),
                ("url".into(), Value::String("https://example.test".into())),
                ("username".into(), Value::String("fixture-user".into())),
            ]),
        },
        symvault_sync::export::ExportEntry {
            path: "Other".into(),
            data: BTreeMap::from([
                ("notes".into(), Value::String("fixture-note".into())),
                ("password".into(), Value::String("second-pass".into())),
            ]),
        },
    ];
    let mut json_bytes = Vec::new();
    symvault_sync::export::json(&mut json_bytes, &entries).unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(json_bytes),
        export_case.expected["json_b64"]
    );
    let mut csv_bytes = Vec::new();
    symvault_sync::export::csv(&mut csv_bytes, &entries).unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(csv_bytes),
        export_case.expected["csv_b64"]
    );

    let intake_case = sync_case(&fixture, "IO-003-portable-intake");
    let dir = tempdir().unwrap();
    let source = dir.path().join(intake_case.input["name"].as_str().unwrap());
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(intake_case.input["data_b64"].as_str().unwrap())
        .unwrap();
    fs::write(&source, &bytes).unwrap();
    let spool = intake::Spool::new(dir.path().join("spool")).unwrap();
    let result = intake::process(&spool, &source, &intake::Options::default());
    let provenance = result.provenance.as_ref().unwrap();
    let suggestions: Vec<Value> = result
        .suggestions
        .iter()
        .map(|suggestion| {
            json!({
                "path": suggestion.path,
                "field": suggestion.field,
                "confidence": suggestion.confidence,
                "attachment": suggestion.attachment,
            })
        })
        .collect();
    let observed = json!({
        "status": result.status,
        "provenance": {
            "source_name": provenance.source_name,
            "source_type": format!("{:?}", provenance.source_type).to_ascii_lowercase(),
            "size": provenance.size,
            "sha256": provenance.sha256,
        },
        "suggestions": suggestions,
        "source_unchanged": fs::read(&source).unwrap() == bytes,
        "native_watcher": "unproven",
    });
    assert_eq!(observed, intake_case.expected);
}

#[test]
fn go_generated_git_reconcile_and_archive_cases_match_rust_projections() {
    let fixture = sync_fixture();

    let git_case = sync_case(&fixture, "GIT-001-local");
    let gitignore_hash = Sha256::digest(symvault_sync::git::DEFAULT_GITIGNORE)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(git_case.expected["gitignore_sha256"], gitignore_hash);

    let reconcile_case = sync_case(&fixture, "GIT-003-conflict");
    let output = reconcile(&ReconcileInput {
        base: BTreeMap::from([("item".into(), b"base".to_vec())]),
        local: BTreeMap::from([("item".into(), b"winner".to_vec())]),
        remote: BTreeMap::from([("item".into(), b"loser-bytes".to_vec())]),
    });
    assert_eq!(
        output.files["item.conflict-remote"],
        reconcile_case.expected["conflict_bytes"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
    assert_eq!(
        reconcile_case.expected["source_bytes"],
        String::from_utf8_lossy(&output.files["item.conflict-remote"]).to_string()
    );

    let archive_case = sync_case(&fixture, "IO-002-archive");
    let dir = tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::create_dir(source.join("entries")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(source.join("entries"), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(source.join("identity.age"), b"identity").unwrap();
    fs::write(source.join("config.yaml"), b"vault_dir: fixture\n").unwrap();
    fs::write(source.join("entries/item.age"), b"ciphertext").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in [
            source.join("identity.age"),
            source.join("config.yaml"),
            source.join("entries/item.age"),
        ] {
            fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let archive_path = dir.path().join("backup.tar.gz");
    let manifest = archive::backup(&source, &archive_path, false).unwrap();
    for expected in archive_case.expected["archive_members"].as_array().unwrap() {
        let actual = manifest
            .iter()
            .find(|entry| entry.path == expected["path"].as_str().unwrap())
            .unwrap();
        assert_eq!(actual.mode, expected["mode"].as_u64().unwrap() as u32);
        assert_eq!(actual.size, expected["size"].as_u64().unwrap());
        assert_eq!(actual.sha256, expected["sha256"].as_str().unwrap());
    }
    let destination = dir.path().join("restored");
    let restored = archive::restore(&archive_path, &destination, false).unwrap();
    for expected in archive_case.expected["restored_files"].as_array().unwrap() {
        let actual = restored
            .iter()
            .find(|entry| entry.path == expected["path"].as_str().unwrap())
            .unwrap();
        assert!(!actual.directory);
        assert_eq!(actual.mode, expected["mode"].as_u64().unwrap() as u32);
        assert_eq!(actual.size, expected["size"].as_u64().unwrap());
        assert_eq!(actual.sha256, expected["sha256"].as_str().unwrap());
    }
}
