use super::*;

#[test]
fn policy_limits_reject_before_derivation_and_preserve_historical_validation() {
    let exact = Argon2idParams {
        time: 4,
        memory_kib: 128 * 1024,
        threads: 4,
    };
    argon2_resources::validate(exact, ReadMode::Automatic).unwrap();
    parse_argon2id_params("t=16,m=2097152,p=16").unwrap();
    for params in [
        Argon2idParams {
            time: 5,
            memory_kib: 32,
            threads: 1,
        },
        Argon2idParams {
            time: 1,
            memory_kib: 128 * 1024 + 1,
            threads: 1,
        },
        Argon2idParams {
            time: 1,
            memory_kib: 64,
            threads: 5,
        },
    ] {
        let error = derive(
            b"public fixture",
            b"0123456789abcdef",
            params,
            ReadMode::Automatic,
        )
        .unwrap_err();
        assert_eq!(error.class(), FailureClass::ResourcePolicy);
    }
    for value in [
        "t=1,t=2,p=1",
        "t=1,m=32,p=1,p=2",
        "t=+1,m=32,p=1",
        "t=1, m=32,p=1",
    ] {
        assert_eq!(
            parse_argon2id_params(value).unwrap_err().class(),
            FailureClass::MalformedEnvelope
        );
    }
}

fn stanza(params: &str) -> Stanza {
    Stanza {
        tag: ARGON2ID_TAG.to_owned(),
        args: vec![
            STANDARD_NO_PAD.encode(b"0123456789abcdef"),
            params.to_owned(),
        ],
        body: vec![0; 44],
    }
}

#[test]
fn entire_stanza_set_is_checked_before_kdf_and_adapter_preserves_errors() {
    let exact = stanza("t=4,m=131072,p=4");
    preflight_argon2id(std::slice::from_ref(&exact), ReadMode::Automatic).unwrap();
    for stanzas in [
        vec![stanza("t=4,m=131072,p=4"), exact],
        (0..3)
            .map(|_| stanza("t=3,m=65536,p=4"))
            .collect::<Vec<_>>(),
        (0..5).map(|_| stanza("t=1,m=32,p=1")).collect::<Vec<_>>(),
    ] {
        let identity = ArgonIdentity {
            passphrase: SecretBytes::new(b"public fixture"),
            mode: ReadMode::Automatic,
            error: Cell::new(None),
        };
        assert!(
            age::Identity::unwrap_stanzas(&identity, &stanzas)
                .unwrap()
                .is_err()
        );
        assert_eq!(
            identity.error.get().unwrap().class(),
            FailureClass::ResourcePolicy
        );
    }
    let mut malformed = stanza("t=16,m=2097152,p=16");
    malformed.body.push(0);
    assert_eq!(
        preflight_argon2id(&[malformed], ReadMode::LegacyMigration)
            .unwrap_err()
            .class(),
        FailureClass::MalformedEnvelope
    );
}

#[test]
fn actual_historical_go_envelopes_remain_readable_only_with_explicit_policy() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../testdata/port/crypto/kdf-policy-v1.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["oracle_commit"],
        "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let passphrase = SecretBytes::new(fixture["passphrase"].as_str().unwrap().as_bytes());
    for (index, case) in cases.iter().enumerate() {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(case["ciphertext"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&raw)),
            case["sha256"].as_str().unwrap()
        );
        assert_eq!(inspect_argon2id_policy(&raw).unwrap(), index < 3);
        let automatic = decrypt_argon2id(&raw, &passphrase);
        if index < 3 {
            assert_eq!(automatic.unwrap_err().class(), FailureClass::ResourcePolicy);
        } else {
            assert_eq!(
                automatic.unwrap(),
                fixture["identity"].as_str().unwrap().as_bytes()
            );
        }
        let identity = decrypt_identity_for_legacy_kdf_migration(&raw, &passphrase).unwrap();
        assert_eq!(
            recipient_string(&identity),
            recipient_string(&parse_identity(fixture["identity"].as_str().unwrap()).unwrap())
        );
        assert_eq!(
            decrypt_identity_for_legacy_kdf_migration(
                &raw,
                &SecretBytes::new(b"wrong public fixture")
            )
            .unwrap_err()
            .class(),
            FailureClass::WrongPassphraseOrKey
        );
    }
}
