//! Actual immutable Go resource observations; recipes avoid storing huge blobs.
use super::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema_version: u8,
    policy: String,
    oracle: Oracle,
    cases: Vec<Observation>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Oracle {
    commit: String,
    commit_sha: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_files: Vec<String>,
    generator_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipe {
    id: String,
    kind: String,
    count: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    recipe: Recipe,
    recipe_input_sha256: String,
    outcome: String,
    accepted_reads: usize,
    data_fields: usize,
    backup_codes: usize,
}

fn input(recipe: &Recipe) -> Vec<u8> {
    let count = recipe.count;
    match recipe.kind.as_str() {
        "ordinary" => br#"{"data":{"fixture":"ordinary-control"}}"#.to_vec(),
        "metadata" => format!(
            r#"{{"data":{{}},"meta":{{"tags":[{}]}}}}"#,
            vec![r#""public""#; count].join(",")
        )
        .into_bytes(),
        "duplicates" => format!(
            r#"{{"data":{{}},"future":{{{}}}}}"#,
            vec![r#""same":0"#; count].join(",")
        )
        .into_bytes(),
        "depth" => format!(
            r#"{{"data":{{}},"future":{}0{}}}"#,
            "[".repeat(count),
            "]".repeat(count)
        )
        .into_bytes(),
        "string" => format!(r#"{{"data":{{}},"future":"{}"}}"#, "x".repeat(count)).into_bytes(),
        "values" => {
            let array = format!("[{}]", vec!["0"; 1024].join(","));
            format!(
                r#"{{"data":{{}},"future":[{}]}}"#,
                vec![array; count].join(",")
            )
            .into_bytes()
        }
        "backup" => format!(
            r#"{{"data":{{"backup_codes":"{}"}}}}"#,
            r#"public\n"#.repeat(count)
        )
        .into_bytes(),
        "plaintext" => {
            let mut fields: Vec<_> = (0..16)
                .map(|i| format!(r#""p{i:02}":"{}""#, "x".repeat(1024 * 1024)))
                .collect();
            let raw = format!(r#"{{"data":{{}},"future":{{{}}}}}"#, fields.join(","));
            let excess = raw.len() - count;
            fields[15] = format!(r#""p15":"{}""#, "x".repeat(1024 * 1024 - excess));
            format!(r#"{{"data":{{}},"future":{{{}}}}}"#, fields.join(",")).into_bytes()
        }
        "batch" => {
            let fields: Vec<_> = (0..4)
                .map(|i| {
                    format!(
                        r#""p{i}":"{}""#,
                        "public-fixture".repeat((1024 * 1024) / 14)
                    )
                })
                .collect();
            format!(r#"{{"data":{{{}}}}}"#, fields.join(",")).into_bytes()
        }
        "ciphertext" | "logical" | "listing" => recipe.kind.as_bytes().to_vec(),
        kind => panic!("unknown resource recipe: {kind}"),
    }
}

#[test]
fn actual_go_resource_policy_observations_match_rust() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture: Fixture = serde_json::from_slice(
        &fs::read(root.join("testdata/port/store/read-resource-policy.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.policy, "vault-read-resources-v2");
    assert_eq!(fixture.oracle.commit, fixture.oracle.commit_sha);
    assert_eq!(fixture.oracle.commit_sha.len(), 40);
    assert_eq!(fixture.oracle.release, "unreleased-vault-read-resources-v2");
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert!(
        fixture
            .oracle
            .source_files
            .contains(&"internal/vault/read_admission.go".into())
    );
    assert_eq!(
        fixture.oracle.generator_files,
        [
            "scripts/rust-port/cmd/entrypolicygen/main.go",
            "scripts/rust-port/refresh-read-policy-fixtures.py"
        ]
    );
    let mut generator_digest = Sha256::new();
    for file in &fixture.oracle.generator_files {
        generator_digest.update(file.as_bytes());
        generator_digest.update([0]);
        generator_digest.update(fs::read(root.join(file)).unwrap());
        generator_digest.update([0]);
    }
    assert_eq!(
        format!("{:x}", generator_digest.finalize()),
        fixture.oracle.generator_digest
    );
    // Validate sizes before reconstructing any potentially large fixture input.
    let expected_recipes = [
        ("ordinary", "ordinary", 0),
        ("metadata-array-exact", "metadata", 1024),
        ("metadata-array-over", "metadata", 1025),
        ("unknown-duplicates-exact", "duplicates", 4094),
        ("unknown-duplicates-over", "duplicates", 4095),
        ("unknown-depth-exact", "depth", 33),
        ("unknown-depth-over", "depth", 34),
        ("unknown-string-exact", "string", 1048576),
        ("unknown-string-over", "string", 1048577),
        ("raw-values-below", "values", 63),
        ("raw-values-over", "values", 64),
        ("backup-codes-exact", "backup", 1024),
        ("backup-codes-over", "backup", 1025),
        ("plaintext-exact", "plaintext", 16777216),
        ("plaintext-over", "plaintext", 16777217),
        ("ciphertext-over", "ciphertext", 25165825),
        ("shared-read-session", "batch", 14),
        ("logical-depth-over", "logical", 65),
        ("physical-list-depth-over", "listing", 65),
    ];
    assert_eq!(
        fixture
            .cases
            .iter()
            .map(|case| (
                case.recipe.id.as_str(),
                case.recipe.kind.as_str(),
                case.recipe.count
            ))
            .collect::<Vec<_>>(),
        expected_recipes
    );
    let identity = symvault_crypto::parse_identity(
        "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL",
    )
    .unwrap();
    for case in fixture.cases {
        let raw = input(&case.recipe);
        assert_eq!(
            format!("{:x}", Sha256::digest(&raw)),
            case.recipe_input_sha256,
            "{} byte recipe",
            case.recipe.id
        );
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("entries")).unwrap();
        fs::write(
            temp.path().join("config.yaml"),
            b"vault:\n  format_version: 2\n",
        )
        .unwrap();
        fs::write(temp.path().join("identity.age"), b"synthetic marker").unwrap();
        // Open before simulated synchronization changes the tree. This covers
        // enumeration through a long-lived Store on non-Unix platforms too.
        let store = Store::open(temp.path(), &identity).unwrap();
        let logical = if matches!(case.recipe.kind.as_str(), "logical" | "listing") {
            format!("{}control", "a/".repeat(case.recipe.count - 1))
        } else {
            "control".to_owned()
        };
        let path = temp.path().join("entries").join(format!("{logical}.age"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        match case.recipe.kind.as_str() {
            "ciphertext" => fs::File::create(&path)
                .unwrap()
                .set_len(case.recipe.count as u64)
                .unwrap(),
            "listing" => {
                fs::File::create(&path).unwrap();
            }
            _ => {
                let bytes = if case.recipe.kind == "logical" {
                    input(&Recipe {
                        id: String::new(),
                        kind: "ordinary".into(),
                        count: 0,
                    })
                } else {
                    raw
                };
                let recipient =
                    symvault_crypto::parse_recipient(&symvault_crypto::recipient_string(&identity))
                        .unwrap();
                fs::write(
                    &path,
                    symvault_crypto::encrypt(&bytes, &[recipient]).unwrap(),
                )
                .unwrap();
            }
        }
        let reader = store.read_session(&identity);
        let mut reads = 0;
        let mut outcome = "accepted";
        let count = if case.recipe.kind == "batch" {
            case.recipe.count
        } else {
            1
        };
        if case.recipe.kind == "listing" {
            match store.files() {
                Ok(_) => {}
                Err(error) if error.is_resource_failure() => outcome = "resource_limit",
                Err(error) => panic!("{}: {error}", case.recipe.id),
            }
        } else {
            for _ in 0..count {
                match reader.get(&logical) {
                    Ok(entry) => {
                        reads += 1;
                        if case.recipe.kind == "ordinary" {
                            assert_eq!(entry.data["fixture"], "ordinary-control");
                            assert_eq!(entry.data.len(), case.data_fields);
                            assert_eq!(case.backup_codes, 0);
                        }
                    }
                    Err(error) if error.is_resource_failure() => {
                        outcome = "resource_limit";
                        break;
                    }
                    Err(error) => panic!("{}: {error}", case.recipe.id),
                }
            }
        }
        assert_eq!(
            outcome, case.outcome,
            "{} resource decision",
            case.recipe.id
        );
        assert_eq!(
            reads, case.accepted_reads,
            "{} successful reads",
            case.recipe.id
        );
    }
}
