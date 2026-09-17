#![deny(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = env::temp_dir().join(format!("symvault-policy-cli-{label}-{suffix}"));
        fs::create_dir_all(&path).expect("temporary directory");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(binary: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("CI", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("NO_COLOR", "1")
        .output()
        .expect("run policy CLI")
}

fn assert_same(go: &Output, rust: &Output, case: &str) {
    assert_eq!(rust.status, go.status, "{case}: status differs");
    assert_eq!(rust.stdout, go.stdout, "{case}: stdout differs");
    assert_eq!(rust.stderr, go.stderr, "{case}: stderr differs");
}

#[test]
fn policy_validate_and_list_match_go() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go = PathBuf::from(go);
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = TempDir::new("home");
    let fixture = TempDir::new("fixture");

    let valid = fixture.0.join("valid.yaml");
    fs::write(
        &valid,
        b"version: v1\ndescription: Local policy\nrules:\n  - name: allow-read\n    priority: 10\n    action: allow\n",
    )
    .expect("valid policy");
    let valid_args = ["policy", "validate", valid.to_str().expect("valid path")];
    assert_same(
        &run(&go, &home.0, &valid_args),
        &run(&rust, &home.0, &valid_args),
        "valid policy validation",
    );

    let invalid = fixture.0.join("invalid.yaml");
    fs::write(
        &invalid,
        b"description: Missing version\nrules:\n  - name: deny-all\n    action: deny\n",
    )
    .expect("invalid policy");
    let invalid_args = [
        "policy",
        "validate",
        invalid.to_str().expect("invalid path"),
    ];
    assert_same(
        &run(&go, &home.0, &invalid_args),
        &run(&rust, &home.0, &invalid_args),
        "invalid policy validation",
    );

    let list_root = fixture.0.join("list-root");
    fs::create_dir_all(&list_root).expect("list root");
    let no_directory_args = [
        "--vault",
        list_root.to_str().expect("list root"),
        "policy",
        "list",
    ];
    assert_same(
        &run(&go, &home.0, &no_directory_args),
        &run(&rust, &home.0, &no_directory_args),
        "missing policy directory",
    );

    let only_directory_root = fixture.0.join("only-directory-root");
    fs::create_dir_all(only_directory_root.join("policies/nested"))
        .expect("nested policy directory");
    let only_directory_args = [
        "--vault",
        only_directory_root.to_str().expect("only-directory root"),
        "policy",
        "list",
    ];
    assert_same(
        &run(&go, &home.0, &only_directory_args),
        &run(&rust, &home.0, &only_directory_args),
        "policy directory containing only a subdirectory",
    );

    fs::create_dir_all(list_root.join("policies/nested")).expect("policy directory");
    fs::write(list_root.join("policies/b.yaml"), b"ignored by list").expect("policy b");
    fs::write(list_root.join("policies/a.txt"), b"included by Go list").expect("non-policy file");
    let populated_args = [
        "--vault",
        list_root.to_str().expect("list root"),
        "policy",
        "list",
    ];
    assert_same(
        &run(&go, &home.0, &populated_args),
        &run(&rust, &home.0, &populated_args),
        "populated policy directory",
    );

    let home_policy = home.0.join("tilde-policy.yaml");
    fs::write(
        &home_policy,
        b"version: v1\ndescription: Home policy\nrules:\n  - name: allow-read\n    priority: 10\n    action: allow\n",
    )
    .expect("home policy");
    let tilde_args = ["policy", "validate", "~/tilde-policy.yaml"];
    assert_same(
        &run(&go, &home.0, &tilde_args),
        &run(&rust, &home.0, &tilde_args),
        "tilde policy path",
    );

    let source = fixture.0.join("dev.yaml");
    fs::write(
        &source,
        b"version: v1\ndescription: Applied policy\nrules:\n  - name: allow-read\n    priority: 10\n    action: allow\n",
    )
    .expect("source policy");
    let apply_root = fixture.0.join("apply-root");
    fs::create_dir_all(&apply_root).expect("apply root");
    let apply_args = [
        "--vault",
        apply_root.to_str().expect("apply root"),
        "policy",
        "apply",
        source.to_str().expect("source policy"),
    ];
    assert_same(
        &run(&go, &home.0, &apply_args),
        &run(&rust, &home.0, &apply_args),
        "apply valid policy",
    );

    let go_remove_root = fixture.0.join("go-remove-root");
    let rust_remove_root = fixture.0.join("rust-remove-root");
    for root in [&go_remove_root, &rust_remove_root] {
        fs::create_dir_all(root.join("policies")).expect("remove policy directory");
        fs::write(root.join("policies/dev.yaml"), b"applied policy").expect("applied policy");
    }
    let go_remove_args = [
        "--vault",
        go_remove_root.to_str().expect("Go remove root"),
        "policy",
        "remove",
        "dev.yaml",
    ];
    let rust_remove_args = [
        "--vault",
        rust_remove_root.to_str().expect("Rust remove root"),
        "policy",
        "remove",
        "dev.yaml",
    ];
    assert_same(
        &run(&go, &home.0, &go_remove_args),
        &run(&rust, &home.0, &rust_remove_args),
        "remove applied policy",
    );
}
