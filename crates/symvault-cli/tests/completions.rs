#[cfg(unix)]
use std::io::Write;
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;

use serde_json::Value;

fn has_flag(command: &Value, kind: &str, name: &str) -> bool {
    command[kind]
        .as_array()
        .is_some_and(|flags| flags.iter().any(|flag| flag["name"] == name))
}

#[cfg(unix)]
fn check_shell_syntax(shell: &str, script: &[u8]) {
    let mut child = match Command::new(shell)
        .arg("-n")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("start {shell} syntax check: {error}"),
    };
    child
        .stdin
        .take()
        .expect("syntax checker stdin")
        .write_all(script)
        .expect("write completion script to syntax checker");
    let result = child.wait_with_output().expect("wait for syntax checker");
    assert!(
        result.status.success(),
        "{shell} rejected generated script: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn shell_completions_are_generated_from_the_cli_and_match_go_commands_and_flags() {
    let oracle: Value =
        serde_json::from_str(include_str!("../../../testdata/port/cli/command-tree.json"))
            .expect("Go command-tree fixture");
    assert!(
        !oracle["oracle"]["commit_sha"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
    let commands = oracle["commands"].as_array().expect("Go commands");
    let root = commands
        .iter()
        .find(|command| command["path"] == "symvault")
        .expect("Go root command");
    let add = commands
        .iter()
        .find(|command| command["path"] == "symvault add")
        .expect("Go add command");
    let add_name = add["name"].as_str().expect("Go add command name");
    assert_eq!(add_name, "add");
    assert!(has_flag(root, "persistent_flags", "vault"));
    assert!(has_flag(add, "local_flags", "length"));

    for (shell, marker) in [
        ("bash", "-F __start_symvault"),
        ("zsh", "#compdef symvault"),
        ("fish", "complete -c symvault"),
        ("powershell", "Register-ArgumentCompleter"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_symvault"))
            .args(["completion", shell])
            .output()
            .unwrap_or_else(|error| panic!("run Rust {shell} completion: {error}"));
        assert!(
            output.status.success(),
            "Rust {shell} completion failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty(), "Rust {shell} emitted no script");
        let script = String::from_utf8(output.stdout).expect("completion output is UTF-8");
        assert!(
            script.contains(marker),
            "Rust {shell} did not emit a shell script"
        );
        for expected in ["symvault", "__complete"] {
            assert!(
                script.contains(expected),
                "Rust {shell} script omits {expected}"
            );
        }
        let artifacts: Value =
            serde_json::from_str(include_str!("../../../testdata/port/cli/artifacts.json"))
                .unwrap();
        assert_eq!(
            script,
            artifacts["completions"][format!("{shell}/descriptions")]
                .as_str()
                .unwrap()
        );
        #[cfg(unix)]
        if shell == "bash" || shell == "zsh" {
            check_shell_syntax(shell, script.as_bytes());
        }
    }
}

#[test]
fn bare_completion_and_no_descriptions_follow_go_command_behavior() {
    let binary = env!("CARGO_BIN_EXE_symvault");
    let bare = Command::new(binary).arg("completion").output().unwrap();
    assert!(bare.status.success());
    assert!(bare.stderr.is_empty());
    assert!(String::from_utf8_lossy(&bare.stdout).contains("Usage:"));

    let full = Command::new(binary)
        .args(["completion", "fish"])
        .output()
        .unwrap();
    let plain = Command::new(binary)
        .args(["completion", "fish", "--no-descriptions"])
        .output()
        .unwrap();
    assert!(plain.status.success());
    assert!(plain.stderr.is_empty());
    assert!(!plain.stdout.is_empty());
    assert_ne!(full.stdout, plain.stdout);
    assert!(String::from_utf8_lossy(&plain.stdout).contains("__completeNoDesc"));
    assert!(!String::from_utf8_lossy(&plain.stdout).contains("Add a new password entry"));
}

#[test]
fn complete_actual_go_inventory_matches_public_rust_stdout_stderr_and_exit() {
    let artifact: Value =
        serde_json::from_str(include_str!("../../../testdata/port/cli/artifacts.json")).unwrap();
    let cases = artifact["entry_completions"].as_array().unwrap();
    assert_eq!(cases.len(), 537);
    let absent: Vec<_> = cases.iter().filter(|c| c["state"] == "absent").collect();
    assert_eq!(absent.len(), 503);
    assert_eq!(
        absent
            .iter()
            .filter(|c| c["name"].as_str().unwrap().starts_with("parser/"))
            .count(),
        82
    );
    let home = tempfile::tempdir().unwrap();
    let mut executed = std::collections::BTreeSet::new();
    for case in absent {
        let args: Vec<_> = case["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        let result = Command::new(env!("CARGO_BIN_EXE_symvault"))
            .args(["--vault", "absent-vault", "__complete"])
            .args(&args)
            .current_dir(home.path())
            .env_clear()
            .envs(
                ["PATH", "SystemRoot", "WINDIR", "TEMP", "TMP"]
                    .into_iter()
                    .filter_map(|name| std::env::var_os(name).map(|value| (name, value))),
            )
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_DATA_HOME", home.path().join("data"))
            .env("XDG_CACHE_HOME", home.path().join("cache"))
            .env("SYMVAULT_TEST_KEYRING", "memory")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(0), "{}", case["name"]);
        assert_eq!(
            result.stdout,
            case["stdout"].as_str().unwrap().as_bytes(),
            "{}",
            case["name"]
        );
        assert_eq!(
            result.stderr,
            case["stderr"].as_str().unwrap().as_bytes(),
            "{}",
            case["name"]
        );
        assert!(executed.insert(case["name"].as_str().unwrap()));
    }
    assert_eq!(executed.len(), 503);
    assert!(!home.path().join("absent-vault").exists());
}
