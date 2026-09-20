#[path = "../src/audit_commands.rs"]
mod audit_commands;
use std::{fs, path::Path, process::Command};

#[test]
fn audit_tail_filter_and_render_match_go_without_vault_access() {
    let root = std::env::temp_dir().join(format!("vault-audit-view-{}", std::process::id()));
    fs::create_dir_all(root.join(".symvault")).unwrap();
    fs::write(root.join(".symvault/audit-fixture.log"), concat!(
        "not json\n",
        "{\"ts\":\"2020-01-01T00:00:00Z\",\"agent\":\"fixture\",\"action\":\"old\",\"ok\":true}\n",
        "{\"ts\":\"2020-01-01T00:00:00Z\",\"agent\":\"fixture\",\"action\":\"failed <&>\",\"path\":\"long/synthetic/attachment/entry/with/more\",\"ok\":false}\n",
        "{\"action\":\"partial\"}\n"
    )).unwrap();
    for (json, failed, since) in [(true, true, ""), (false, false, ""), (true, false, "1h")] {
        let mut actual = Vec::new();
        audit_commands::view(&root, "fixture", 2, since, failed, json, &mut actual).unwrap();
        if let Ok(oracle) = std::env::var("SYMVAULT_GO_BINARY") {
            let mut command = Command::new(oracle);
            command
                .args(["audit", "--agent", "fixture", "--tail", "2"])
                .env("HOME", &root)
                .env("USERPROFILE", &root)
                .env("CI", "1");
            if json {
                command.arg("--json");
            }
            if failed {
                command.arg("--failed");
            }
            if !since.is_empty() {
                command.args(["--since", since]);
            }
            let expected = command.output().unwrap();
            assert!(
                expected.status.success(),
                "{}",
                String::from_utf8_lossy(&expected.stderr)
            );
            assert_eq!(
                actual,
                if json {
                    expected.stdout
                } else {
                    expected.stderr
                }
            );
        }
        if since.is_empty() {
            assert!(String::from_utf8_lossy(&actual).contains("partial"));
        } else {
            assert_eq!(actual, b"null\n");
        }
    }
    assert!(
        audit_commands::view(
            Path::new("/unused"),
            "../outside",
            20,
            "",
            false,
            false,
            &mut Vec::new()
        )
        .is_err()
    );
    fs::remove_dir_all(root).unwrap();
}
