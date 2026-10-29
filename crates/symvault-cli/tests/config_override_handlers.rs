//! Handler-level regressions for root overrides, isolated from user state/services.
use std::{
    fs,
    path::Path,
    process::{Command, Output, Stdio},
};

struct Sandbox {
    root: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        let config = home.join(".config/symaira-vault");
        fs::create_dir_all(&config).unwrap();
        fs::write(config.join("config.yaml"),
            "defaultProfile: first\nprofiles:\n  first:\n    vault: ~/first\n  second:\n    vault: ~/second\n").unwrap();
        Self { root }
    }

    fn home(&self) -> std::path::PathBuf {
        self.root.path().canonicalize().unwrap()
    }

    fn run(&self, args: &[&str], path: &Path) -> Output {
        let home = self.home();
        let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
        command
            .args(args)
            .env_clear()
            .current_dir(&home)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("PATH", path)
            .env("TMPDIR", &home)
            .env("TMP", &home)
            .env("TEMP", &home)
            .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
            .env("SYMVAULT_PASSPHRASE", "synthetic-test-passphrase")
            .stdin(Stdio::null());
        if let Some(system) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system);
        }
        command.output().unwrap()
    }
}

fn success(output: &Output) -> String {
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn init_honours_profile_vault_precedence_and_blank_fallback() {
    for (flags, selected) in [
        (vec!["--profile", "second"], "second"),
        (
            vec!["--profile", "second", "--vault", "~/explicit"],
            "explicit",
        ),
        (vec!["--profile", ""], "first"),
    ] {
        let sandbox = Sandbox::new();
        let mut args = vec!["init", "--auth", "passphrase"];
        args.extend(flags);
        let path = std::env::var_os("PATH").unwrap_or_default();
        let output = sandbox.run(&args, Path::new(&path));
        success(&output);
        assert!(sandbox.home().join(selected).join("identity.age").is_file());
        assert!(sandbox.home().join(selected).join("config.yaml").is_file());
        for other in ["first", "second", "explicit", "fallback"] {
            if other != selected {
                assert!(!sandbox.home().join(other).exists(), "wrong vault {other}");
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn mcp_service_honours_profile_for_install_status_and_uninstall() {
    use std::os::unix::fs::PermissionsExt;
    for (flags, selected) in [
        (vec!["--profile", "second"], "second"),
        (
            vec!["--profile", "second", "--vault", "~/explicit"],
            "explicit",
        ),
        (vec!["--profile", ""], "first"),
    ] {
        let sandbox = Sandbox::new();
        let home = sandbox.home();
        let bin = home.join("bin");
        fs::create_dir(&bin).unwrap();
        let calls = home.join("calls");
        for helper in ["launchctl", "systemctl"] {
            let shim = bin.join(helper);
            // A literal log path survives the installer's cleared environment.
            fs::write(
                &shim,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexit 0\n",
                    calls.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let service_file = if cfg!(target_os = "macos") {
            home.join("LaunchAgents/com.symvault.mcp.plist")
        } else {
            home.join(".config/systemd/user/symvault-mcp.service")
        };
        for action in ["install", "status"] {
            let mut args = vec!["mcp", action];
            args.extend(flags.iter().copied());
            let text = success(&sandbox.run(&args, &bin));
            assert!(
                text.contains(&format!("Vault:        {}", home.join(selected).display())),
                "{text}"
            );
            assert!(service_file.is_file());
        }
        assert!(
            fs::read_to_string(&service_file)
                .unwrap()
                .contains(&home.join(selected).to_string_lossy().to_string())
        );
        // Uninstall has no vault output and uses a fixed service filename in Go
        // too. Prove its profile resolution runs before any service side effect.
        for action in ["install", "status", "uninstall"] {
            let before = fs::read(&calls).unwrap();
            let output = sandbox.run(&["mcp", action, "--profile", "missing"], &bin);
            assert!(!output.status.success(), "{action}: {output:?}");
            assert!(String::from_utf8_lossy(&output.stderr).contains("missing"));
            assert_eq!(fs::read(&calls).unwrap(), before);
            assert!(service_file.is_file());
        }
        let mut args = vec!["mcp", "uninstall"];
        args.extend(flags);
        success(&sandbox.run(&args, &bin));
        assert!(!service_file.exists());
        assert!(!fs::read_to_string(&calls).unwrap().is_empty());
        // Explicit vault bypasses even an unknown profile, for every handler.
        for action in ["install", "status", "uninstall"] {
            success(&sandbox.run(
                &[
                    "mcp",
                    action,
                    "--profile",
                    "missing",
                    "--vault",
                    "~/explicit",
                ],
                &bin,
            ));
        }
    }
}
