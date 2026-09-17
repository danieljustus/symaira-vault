use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn temporary_root(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    env::temp_dir().join(format!("symvault-share-differential-{label}-{suffix}"))
}

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run share list")
}

fn assert_status(go: &Output, rust: &Output, case: &str) {
    assert_eq!(
        rust.status,
        go.status,
        "{case}: status differs\ngo stderr={:?}\nrust stderr={:?}",
        String::from_utf8_lossy(&go.stderr),
        String::from_utf8_lossy(&rust.stderr)
    );
    assert_eq!(rust.stderr, go.stderr, "{case}: stderr differs");
}

fn sorted_json(bytes: &[u8]) -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_slice(bytes).expect("share JSON");
    if let Some(grants) = value.as_array_mut() {
        grants.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    }
    value
}

fn sorted_yaml(bytes: &[u8]) -> serde_yaml_ng::Value {
    let mut value: serde_yaml_ng::Value = serde_yaml_ng::from_slice(bytes).expect("share YAML");
    if let Some(grants) = value.as_sequence_mut() {
        grants.sort_by(|left, right| {
            left.get("id")
                .and_then(serde_yaml_ng::Value::as_str)
                .cmp(&right.get("id").and_then(serde_yaml_ng::Value::as_str))
        });
    }
    value
}

fn sorted_text(bytes: &[u8]) -> String {
    let text = String::from_utf8(bytes.to_vec()).expect("share text");
    let mut lines: Vec<_> = text.lines().collect();
    if lines.len() < 4 {
        return text;
    }
    let Some(blank) = lines.iter().position(|line| line.is_empty()) else {
        return text;
    };
    lines[1..blank].sort_unstable();
    let mut normalized = lines.join("\n");
    if text.ends_with('\n') {
        normalized.push('\n');
    }
    normalized
}

fn assert_same(go: &Output, rust: &Output, args: &[&str], case: &str) {
    assert_status(go, rust, case);
    if args.contains(&"--output") && args.contains(&"json") {
        assert_eq!(
            sorted_json(&rust.stdout),
            sorted_json(&go.stdout),
            "{case}: JSON differs\ngo={}\nrust={}",
            String::from_utf8_lossy(&go.stdout),
            String::from_utf8_lossy(&rust.stdout)
        );
    } else if args.contains(&"--output") && args.contains(&"yaml") {
        assert_eq!(
            sorted_yaml(&rust.stdout),
            sorted_yaml(&go.stdout),
            "{case}: YAML differs"
        );
    } else if !rust.stdout.is_empty() || !go.stdout.is_empty() {
        assert_eq!(
            sorted_text(&rust.stdout),
            sorted_text(&go.stdout),
            "{case}: text differs\ngo={}\nrust={}",
            String::from_utf8_lossy(&go.stdout),
            String::from_utf8_lossy(&rust.stdout)
        );
    }
}

fn normalized_revoke_listing(bytes: &[u8]) -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_slice(bytes).expect("share JSON");
    for grant in value.as_array_mut().expect("share grant array") {
        if let Some(revoked_at) = grant.get_mut("revoked_at") {
            if !revoked_at.is_null() {
                *revoked_at = serde_json::Value::String("<dynamic>".to_owned());
            }
        }
    }
    value
}

#[test]
fn share_list_matches_go_for_formats_and_filters() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let root = temporary_root("vault");
    let home = temporary_root("home");
    fs::create_dir_all(&root).expect("vault root");
    fs::create_dir_all(&home).expect("home");
    fs::write(
        root.join("mcp-shares.json"),
        br#"{"version":1,"grants":[{"id":"grant-a","from_agent":"source","to_agent":"target","secret_path":"prod/github","secret_field":"password","nonce":"n1","status":"approved","created_at":"2025-02-03T04:05:06Z","expires_at":"2099-01-01T00:00:00Z","approved_at":"2025-02-03T04:06:00Z","approved_by":"source","ttl":3600000000000},{"id":"grant-b","from_agent":"other","to_agent":"target","secret_path":"prod/api","status":"revoked","created_at":"2024-01-02T03:04:05Z","revoked_at":"2024-01-02T03:05:00Z"},{"id":"grant-c","from_agent":"other","to_agent":"source","secret_path":"expired","status":"approved","created_at":"2024-01-02T03:04:05Z","expires_at":"2000-01-01T00:00:00Z"}]}"#,
    )
    .expect("share store");

    let cases: &[&[&str]] = &[
        &["share", "list"],
        &["--output", "json", "share", "list"],
        &["--output", "yaml", "share", "list"],
        &["share", "list", "--status", "approved"],
        &["--output", "json", "share", "list", "--from", "source"],
        &["--quiet", "share", "list"],
    ];
    for args in cases {
        let go = run(&go_binary, args, &root, &home);
        let rust = run(&rust_binary, args, &root, &home);
        assert_same(&go, &rust, args, &format!("share list {args:?}"));
    }

    // PrintResult disables HTML escaping for JSON. Keep this one-grant probe
    // byte-exact so the order-normalized multi-grant cases cannot hide that
    // contract or YAML quoting differences.
    fs::write(
        root.join("mcp-shares.json"),
        r#"{"version":1,"grants":[{"id":"special","from_agent":"source","to_agent":"target","secret_path":"<&> ","status":"approved","created_at":"2025-02-03T04:05:06Z"}]}"#.as_bytes(),
    )
    .expect("special share store");
    for args in [
        &["--output", "json", "share", "list"][..],
        &["--output", "yaml", "share", "list"][..],
    ] {
        let go = run(&go_binary, args, &root, &home);
        let rust = run(&rust_binary, args, &root, &home);
        assert_status(&go, &rust, &format!("share list special {args:?}"));
        assert_eq!(rust.stdout, go.stdout, "special {args:?}: stdout differs");
    }
    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(home);
}

#[test]
fn share_revoke_matches_go_and_persists_metadata() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let fixture = br#"{"version":1,"grants":[{"id":"grant-a","from_agent":"source","to_agent":"target","secret_path":"prod/github","secret_field":"password","nonce":"n1","status":"approved","created_at":"2025-02-03T04:05:06Z","expires_at":"2099-01-01T00:00:00Z","approved_at":"2025-02-03T04:06:00Z","approved_by":"source","ttl":3600000000000},{"id":"grant-b","from_agent":"other","to_agent":"target","secret_path":"prod/api","status":"approved","created_at":"2024-01-02T03:04:05Z"}]}"#;
    let go_root = temporary_root("revoke-go");
    let go_home = temporary_root("revoke-go-home");
    let rust_root = temporary_root("revoke-rust");
    let rust_home = temporary_root("revoke-rust-home");
    for (root, home) in [(&go_root, &go_home), (&rust_root, &rust_home)] {
        fs::create_dir_all(root).expect("revoke vault root");
        fs::create_dir_all(home).expect("revoke home");
        fs::write(root.join("mcp-shares.json"), fixture).expect("revoke share store");
    }

    let operations: &[&[&str]] = &[
        &["share", "revoke", "grant-a"],
        &["share", "revoke", "grant-a"],
        &["share", "revoke", "missing"],
        &["--quiet", "share", "revoke", "grant-b"],
    ];
    for args in operations {
        let go = run(&go_binary, args, &go_root, &go_home);
        let rust = run(&rust_binary, args, &rust_root, &rust_home);
        let case = format!("share revoke {args:?}");
        assert_status(&go, &rust, &case);
        assert_eq!(rust.stdout, go.stdout, "{case}: stdout differs");
    }

    let list_args = ["--output", "json", "share", "list"];
    let go = run(&go_binary, &list_args, &go_root, &go_home);
    let rust = run(&rust_binary, &list_args, &rust_root, &rust_home);
    assert_status(&go, &rust, "share revoke persisted list");
    assert_eq!(
        normalized_revoke_listing(&rust.stdout),
        normalized_revoke_listing(&go.stdout),
        "share revoke persisted metadata differs"
    );

    let _ = fs::remove_dir_all(go_root);
    let _ = fs::remove_dir_all(go_home);
    let _ = fs::remove_dir_all(rust_root);
    let _ = fs::remove_dir_all(rust_home);
}
