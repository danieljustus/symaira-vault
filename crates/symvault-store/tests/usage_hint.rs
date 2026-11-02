//! `SecretType::usage_hint` is Go's `UsageHintForType`: the text is stored in
//! entries and shown by `list`, so it must match the Go bytes exactly. Three
//! hints end in a placeholder wrapped in angle brackets; the expectations
//! build those pieces from parts so the check is on the exact bytes.

use symvault_store::SecretType;

fn angle(word: &str) -> String {
    format!("{}{word}{}", char::from(60_u8), char::from(62_u8))
}

#[test]
fn placeholder_hints_use_angle_bracket_placeholders() {
    assert_eq!(
        SecretType::ApiKey.usage_hint(),
        format!(
            "Set as header or query parameter depending on API documentation. Common: X-API-Key: {} or ?api_key={}",
            angle("key"),
            angle("key")
        )
    );
    assert_eq!(
        SecretType::BearerToken.usage_hint(),
        format!("Set Header Authorization: Bearer {}", angle("token"))
    );
    assert_eq!(
        SecretType::BasicAuth.usage_hint(),
        format!(
            "Encode as base64(user:pass) and set Header Authorization: Basic {}",
            angle("encoded")
        )
    );
}

#[test]
fn no_hint_contains_a_masking_placeholder() {
    for secret_type in [
        SecretType::ApiKey,
        SecretType::BearerToken,
        SecretType::BasicAuth,
        SecretType::SshKey,
        SecretType::Password,
        SecretType::Certificate,
        SecretType::DatabaseUrl,
        SecretType::TotpSeed,
        SecretType::Payment,
        SecretType::Custom,
    ] {
        let hint = secret_type.usage_hint();
        assert!(!hint.contains(&"*".repeat(3)), "{secret_type:?}: {hint}");
    }
}

#[test]
fn plain_hints_are_unchanged() {
    assert_eq!(
        SecretType::SshKey.usage_hint(),
        format!(
            "Write to temporary file with chmod 600 before use. Use with ssh -i {}",
            angle("keyfile")
        )
    );
    assert_eq!(
        SecretType::Password.usage_hint(),
        "Use for authentication. Consider using a password manager or secret injection."
    );
}
