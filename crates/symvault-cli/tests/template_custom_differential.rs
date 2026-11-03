//! Differential test: `template generate` with custom
//! `~/.config/symvault/templates/<kind>.tmpl` files, Go binary vs native.
//! The Go answers (stdout, stderr, status and the `--output` file) are replayed
//! from `testdata/port/cli-transcripts/template_custom_differential.json`; every
//! scenario uses its own disposable HOME.

#[path = "common/go_oracle.rs"]
mod go_oracle;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn command(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env_remove("SYMVAULT_PROFILE")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .current_dir(home);
    go_oracle::output(&mut command).expect("run CLI")
}

fn assert_success(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed: {:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Scenario {
    name: &'static str,
    kind: &'static str,
    template: &'static [u8],
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "range-refs-sorted",
        kind: "mine",
        template: b"# {{.Name | upper}}\n{{range $k, $v := .Refs}}{{$k}}={{index $.Values $k | printf \"%q\"}} <- {{$v}}\n{{end}}",
    },
    Scenario {
        name: "builtin-override",
        kind: "env",
        template: b"custom {{.Name}}:{{- range $k, $v := .Values}}\n  {{$k | lower}}: {{$v | b64enc}} / {{$v | b64url}}{{end}}\n",
    },
    Scenario {
        name: "tojson-and-escapes",
        kind: "dump",
        template: b"{{tojson .}}\n{{.Name | html}} {{.Name | js}} {{.Name | urlquery}}\n{{with index .Values \"TOKEN\"}}{{. | tojson}}{{else}}none{{end}}\n",
    },
    Scenario {
        name: "define-and-template",
        kind: "nest",
        template: b"{{define \"row\"}}[{{.}}]{{end}}{{range .Values}}{{template \"row\" .}}{{end}}{{/* c */}}\n{{block \"tail\" .Name}}tail:{{.}}{{end}}\n",
    },
    Scenario {
        name: "parse-error",
        kind: "bad",
        template: b"line one\n{{if .Name}}\nunterminated {{.Name",
    },
    Scenario {
        name: "parse-error-unknown-func",
        kind: "badfn",
        template: b"x\n{{ nosuchfunc .Name }}\n",
    },
    Scenario {
        name: "exec-error-missing-field",
        kind: "badfield",
        template: b"head\n{{.Nope}}\n",
    },
    Scenario {
        name: "exec-error-index",
        kind: "badindex",
        template: b"{{index .Refs 3}}",
    },
    Scenario {
        name: "exec-error-func",
        kind: "badcall",
        template: b"{{printf \"%d\" .Name | len | slice .Name 1 99}}",
    },
    Scenario {
        name: "missing-map-key",
        kind: "missingkey",
        template: b"<{{.Values.ABSENT}}>|{{index .Values \"ABSENT\"}}|{{len .Refs}}",
    },
    Scenario {
        name: "non-utf8-bytes-in-template",
        kind: "bytes",
        template: b"a\xffb {{.Name}} \xc3\x28 {{printf \"%q\" .Name}}\n",
    },
];

fn setup(
    test: &str,
) -> (
    go_oracle::GoOracle,
    PathBuf,
    PathBuf,
    PathBuf,
    tempfile::TempDir,
) {
    let oracle = go_oracle::GoOracle::begin(
        "template_custom_differential",
        test,
        Some(go_oracle::CONFIG_CLI_ORACLE),
    );
    let go = oracle.binary();
    let native = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let tmp = tempfile::Builder::new()
        .prefix("symvault-template-custom-")
        .tempdir()
        .expect("tempdir");
    (oracle, go, native, tmp.path().to_path_buf(), tmp)
}

fn seed(native: &Path, root: &Path, home: &Path) {
    assert_success(
        &command(native, &["init", "--auth", "passphrase"], root, home),
        "init",
    );
    assert_success(
        &command(
            native,
            &[
                "set",
                "work/item.password",
                "--value",
                "<strong&secret>123!",
                "--force",
            ],
            root,
            home,
        ),
        "set password",
    );
    assert_success(
        &command(
            native,
            &[
                "set",
                "work/otp",
                "--value",
                "x",
                "--force",
                "--totp-secret",
                "JBSWY3DPEHPK3PXPJBSWY3DPEH",
                "--totp-issuer",
                "Example",
                "--totp-account",
                "me@example.com",
            ],
            root,
            home,
        ),
        "set totp",
    );
}

fn comparable_stderr(raw: &[u8], home: &Path) -> String {
    String::from_utf8_lossy(raw).replace(home.to_str().unwrap(), "<HOME>")
}

#[test]
fn custom_templates_match_go_cli() {
    let (oracle, go, native, base, _guard) = setup("custom_templates_match_go_cli");
    let root = base.join("vault");
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    seed(&native, &root, &home);

    let refs: &[&[&str]] = &[
        &["TOKEN=work/item.password", "İΣ=op://work/item/password"],
        &["Z=work/item.password", "A=work/item.password"],
        &["OTP=work/otp.totp", "PW=work/item.password"],
        &["--prefix", "work/"],
        &["--dry-run", "TOKEN=work/item.password", "OTP=work/otp.totp"],
    ];
    let mut executed = 0usize;
    for scenario in SCENARIOS {
        // Fresh template directory per scenario so state never leaks.
        let templates = home.join(".config/symvault/templates");
        let _ = fs::remove_dir_all(&templates);
        fs::create_dir_all(&templates).unwrap();
        fs::write(
            templates.join(format!("{}.tmpl", scenario.kind)),
            scenario.template,
        )
        .unwrap();
        for (index, ref_args) in refs.iter().enumerate() {
            for mode in ["text", "json", "output", "output-json"] {
                let out_go = base.join(format!("go-{}-{index}-{mode}.out", scenario.name));
                let out_native = base.join(format!("native-{}-{index}-{mode}.out", scenario.name));
                let build = |out: &Path| -> Vec<String> {
                    let mut args = vec![
                        "template".to_owned(),
                        "generate".to_owned(),
                        "--type".to_owned(),
                        scenario.kind.to_owned(),
                        "--name".to_owned(),
                        "sample".to_owned(),
                    ];
                    if mode.contains("json") {
                        args.push("--json".to_owned());
                    }
                    if mode.starts_with("output") {
                        args.push("--output".to_owned());
                        args.push(out.to_str().unwrap().to_owned());
                    }
                    args.extend(ref_args.iter().map(|s| (*s).to_owned()));
                    args
                };
                let go_args = build(&out_go);
                let native_args = build(&out_native);
                let go_refs: Vec<&str> = go_args.iter().map(String::as_str).collect();
                let native_refs: Vec<&str> = native_args.iter().map(String::as_str).collect();
                let go_out = command(&go, &go_refs, &root, &home);
                let native_out = command(&native, &native_refs, &root, &home);
                let label = format!("{} refs#{index} {mode}", scenario.name);
                let sanitize = |raw: &[u8], file: &Path| {
                    let text = raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    let hex = |s: &str| s.bytes().map(|b| format!("{b:02x}")).collect::<String>();
                    text.replace(&hex(file.to_str().unwrap()), "OUT")
                        .replace(&hex(home.to_str().unwrap()), "HOME")
                };
                assert_eq!(
                    sanitize(&native_out.stdout, &out_native),
                    sanitize(&go_out.stdout, &out_go),
                    "{label}: stdout"
                );
                assert_eq!(
                    comparable_stderr(&native_out.stderr, &home),
                    comparable_stderr(&go_out.stderr, &home),
                    "{label}: stderr"
                );
                assert_eq!(
                    native_out.status.code(),
                    go_out.status.code(),
                    "{label}: exit"
                );
                assert_eq!(
                    fs::read(&out_native).ok(),
                    fs::read(&out_go).ok(),
                    "{label}: output file bytes"
                );
                executed += 1;
            }
        }
    }
    assert_eq!(executed, SCENARIOS.len() * refs.len() * 4);
    assert_eq!(oracle.calls(), executed);
}

#[test]
fn unreadable_custom_template_directory_matches_go() {
    let (oracle, go, native, base, _guard) =
        setup("unreadable_custom_template_directory_matches_go");
    let root = base.join("vault");
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    seed(&native, &root, &home);
    // A directory named like a template makes Go's loader fail; Go then falls
    // back to the built-in templates (see LoadCustomTemplates callers).
    let templates = home.join(".config/symvault/templates");
    fs::create_dir_all(templates.join("env.tmpl")).unwrap();
    let args = [
        "template",
        "generate",
        "--type",
        "env",
        "TOKEN=work/item.password",
    ];
    let go_out = command(&go, &args, &root, &home);
    let native_out = command(&native, &args, &root, &home);
    assert_eq!(native_out.stdout, go_out.stdout, "stdout");
    assert_eq!(
        comparable_stderr(&native_out.stderr, &home),
        comparable_stderr(&go_out.stderr, &home),
        "stderr"
    );
    assert_eq!(native_out.status.code(), go_out.status.code(), "exit");
    assert_eq!(oracle.calls(), 1);
}
