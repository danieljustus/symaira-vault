#![deny(unsafe_code)]

#[path = "../src/utility_commands.rs"]
mod utility_commands;

use std::io::Cursor;

#[test]
fn generate_validation_and_deterministic_charset_match_go_contract() {
    assert_eq!(
        utility_commands::generate_password(0, false).unwrap_err(),
        "length must be greater than zero"
    );
    assert!(
        utility_commands::generate_password(1025, false)
            .unwrap_err()
            .contains("at most 1024")
    );
    let mut reader = Cursor::new((0..64).map(|value| value as u8).collect::<Vec<_>>());
    let password = utility_commands::generate_password_with_reader(32, true, &mut reader).unwrap();
    assert_eq!(password.as_str(), "abcdefghjkmnpqrstuvwxyzABCDEFGHJ");
}

#[test]
fn generate_rendering_matches_text_json_yaml_and_store_contracts() {
    let mut output = Vec::new();
    utility_commands::render_password(
        &mut output,
        "fixture-secret",
        utility_commands::OutputOptions {
            format: "text",
            json: false,
            quiet: false,
        },
    )
    .unwrap();
    assert_eq!(output, b"fixture-secret\n");

    let mut output = Vec::new();
    utility_commands::render_password(
        &mut output,
        "fixture-secret",
        utility_commands::OutputOptions {
            format: "text",
            json: true,
            quiet: false,
        },
    )
    .unwrap();
    assert_eq!(output, b"{\"password\":\"fixture-secret\"}\n");

    let mut output = Vec::new();
    utility_commands::render_stored(
        &mut output,
        "work/account.password",
        "entries/work/account.password.age",
        "fixture-secret",
        utility_commands::OutputOptions {
            format: "json",
            json: false,
            quiet: false,
        },
        false,
    )
    .unwrap();
    assert_eq!(
        output,
        b"{\"stored\":true,\"path\":\"work/account.password\",\"file\":\"entries/work/account.password.age\"}\n"
    );

    let mut output = Vec::new();
    utility_commands::render_stored(
        &mut output,
        "work/account.password",
        "entries/work/account.password.age",
        "fixture-secret",
        utility_commands::OutputOptions {
            format: "yaml",
            json: false,
            quiet: false,
        },
        true,
    )
    .unwrap();
    let yaml = String::from_utf8(output).unwrap();
    assert!(yaml.contains("stored: true"));
    assert!(yaml.contains("password: fixture-secret"));
}

#[test]
fn quiet_stored_output_is_empty_and_unknown_format_is_rejected() {
    let mut output = Vec::new();
    utility_commands::render_stored(
        &mut output,
        "work/account.password",
        "entries/work/account.password.age",
        "fixture-secret",
        utility_commands::OutputOptions {
            format: "text",
            json: false,
            quiet: true,
        },
        false,
    )
    .unwrap();
    assert!(output.is_empty());

    let error = utility_commands::render_password(
        &mut Vec::new(),
        "fixture-secret",
        utility_commands::OutputOptions {
            format: "toml",
            json: false,
            quiet: false,
        },
    )
    .unwrap_err();
    assert!(error.contains("unsupported output format"));
}
