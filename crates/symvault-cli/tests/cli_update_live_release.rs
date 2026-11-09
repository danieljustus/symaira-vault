#![cfg(target_os = "macos")]
//! ADR 0037 R4 (CLI-006): `update check`, `update apply` and `update info` on a
//! stable (checkable) build, i.e. the live-release and network branches that
//! the dev-build corpus (`cli_update_*_nonrelease`) cannot reach.
//!
//! **Why a stable binary.** A dev build never reads the release cache or the
//! network. Both sides therefore run a binary stamped `1.0.0`: the Go oracle
//! with `-X main.version=1.0.0`, Rust built by this test with
//! `SYMVAULT_VERSION=1.0.0` into a private target directory under
//! `CARGO_TARGET_TMPDIR` (`SYMVAULT_STABLE_BINARY` names a prebuilt one).
//!
//! **Why a sandbox.** The release endpoint is a hard-coded `https://api.github.com`
//! URL, and Go's hardened client ignores `HTTPS_PROXY` (the first probe of this
//! test fetched the live release). So every run is wrapped in `sandbox-exec`
//! with a profile that denies all non-loopback network access: a branch that
//! needs the network fails the same way on every machine, and no case can
//! reach GitHub. The "fake release server" is a loopback HTTP server for the
//! release assets that a seeded cache points at; it is reachable only because
//! Go checks the host of redirects, not of the first URL (see `DECLARED`).
//!
//! The release cache is seeded under the sandbox `XDG_CACHE_HOME` with a
//! far-future timestamp (fresh for Go and Rust), a past one (stale) or a tag
//! that is not a stable release.
//!
//! What is *not* reachable hermetically: the HTTP-status and decode branches of
//! the `api.github.com` response (rate limit, 404, malformed JSON, draft,
//! prerelease), because they sit behind TLS. Rust covers them in
//! `update_commands.rs::http_tests` against a loopback server; Go's own unit
//! tests cover them in the Go tree.
//!
//! Recorded from the Go oracle (`legacy/go-oracle`, `ce2390d7`) into
//! `testdata/port/cli-observations/cli_update_live_release.json`. Recapture: see
//! docs/rust-port/go-oracle-archive.md ("Recapture"); the oracle binary must be
//! stamped `main.version=1.0.0`.
//!
//! Normalisation (both sides): the sandbox dir becomes `<HOME>`, the server port
//! `<PORT>`, and a transport failure (Go `Get "<url>": dial tcp: lookup ...: no
//! such host` against reqwest's `error sending request for url (<url>)`) is
//! reduced to `<TRANSPORT>`. The wording of a network error is the HTTP stack's,
//! not the product's.

#[path = "common/go_oracle_ext.rs"]
mod go_oracle_ext;

use std::{
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
    thread,
};

use go_oracle_ext::Observations;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ORACLE: &str = "ce2390d748818a4beb413e97183b7795efa99411";
const NO_NETWORK: &str = "(version 1)\n(allow default)\n(deny network*)\n\
(allow network* (remote ip \"localhost:*\"))\n(allow network* (local ip \"localhost:*\"))\n";

/// What a seeded cache looks like.
#[derive(Clone, Copy)]
enum Cache {
    None,
    /// Fresh cache, tag `v1.5.0`, with the named asset set.
    Fresh(Assets),
    /// Same, but the tag is `tag`.
    Tagged(&'static str, Assets),
    /// Timestamp in the past: the cache is ignored.
    Stale,
}

#[derive(Clone, Copy)]
enum Assets {
    Empty,
    /// Archive for the host platform and a `checksums.txt` served by the
    /// loopback server under `/<route>/checksums.txt`.
    Served(&'static str),
    /// Archive and checksums on `https://github.com/...` (unreachable here).
    Github,
    /// Archive and checksums on `https://example.invalid/...`.
    OtherHost,
    /// Only a platform archive, no checksums asset.
    NoChecksums,
    /// Only a `checksums.txt`, no platform archive.
    OnlyChecksums,
    /// Archive for another architecture only.
    WrongArch,
    /// Archive for another OS only.
    WrongOs,
    /// Upper-case names that still match after lower-casing.
    UpperGithub,
}

struct Case {
    name: &'static str,
    args: &'static [&'static str],
    cache: Cache,
}

const fn case(name: &'static str, args: &'static [&'static str], cache: Cache) -> Case {
    Case { name, args, cache }
}

const CASES: &[Case] = &[
    // --- network branches: nothing cached, every fetch is refused by the sandbox ---
    case("check-nocache", &["update", "check"], Cache::None),
    case(
        "check-nocache-json",
        &["update", "check", "--json"],
        Cache::None,
    ),
    case(
        "check-nocache-quiet",
        &["update", "check", "--quiet"],
        Cache::None,
    ),
    case(
        "check-nocache-output-json",
        &["update", "check", "--output", "json"],
        Cache::None,
    ),
    case("check-stale", &["update", "check"], Cache::Stale),
    case(
        "check-force-over-fresh",
        &["update", "check", "--force"],
        Cache::Fresh(Assets::Empty),
    ),
    case(
        "check-prerelease-tag",
        &["update", "check"],
        Cache::Tagged("v1.5.0-rc1", Assets::Empty),
    ),
    case("apply-nocache", &["update", "apply"], Cache::None),
    case(
        "apply-nocache-json",
        &["update", "apply", "--json"],
        Cache::None,
    ),
    case(
        "apply-dry-run-nocache",
        &["update", "apply", "--dry-run"],
        Cache::None,
    ),
    case(
        "apply-force-over-fresh",
        &["update", "apply", "--force"],
        Cache::Fresh(Assets::Empty),
    ),
    // --- a fresh cache decides without the network ---
    case(
        "check-update",
        &["update", "check"],
        Cache::Fresh(Assets::Empty),
    ),
    case(
        "check-update-json",
        &["update", "check", "--json"],
        Cache::Fresh(Assets::Empty),
    ),
    case(
        "check-update-output-json",
        &["update", "check", "--output", "json"],
        Cache::Fresh(Assets::Empty),
    ),
    case(
        "check-update-quiet",
        &["update", "check", "--quiet"],
        Cache::Fresh(Assets::Empty),
    ),
    case(
        "check-current",
        &["update", "check"],
        Cache::Tagged("v1.0.0", Assets::Empty),
    ),
    case(
        "check-current-json",
        &["update", "check", "--json"],
        Cache::Tagged("v1.0.0", Assets::Empty),
    ),
    case(
        "check-older-release",
        &["update", "check"],
        Cache::Tagged("v0.9.0", Assets::Empty),
    ),
    case(
        "check-next-major",
        &["update", "check"],
        Cache::Tagged("v2.0.0", Assets::Empty),
    ),
    case(
        "apply-current",
        &["update", "apply"],
        Cache::Tagged("v1.0.0", Assets::Empty),
    ),
    case(
        "apply-current-json",
        &["update", "apply", "--json"],
        Cache::Tagged("v1.0.0", Assets::Empty),
    ),
    case(
        "apply-older-release",
        &["update", "apply"],
        Cache::Tagged("v0.9.0", Assets::Empty),
    ),
    case(
        "apply-dry-run-update",
        &["update", "apply", "--dry-run"],
        Cache::Tagged("v2.0.0", Assets::Empty),
    ),
    case(
        "apply-dry-run-update-json",
        &["update", "apply", "--dry-run", "--json"],
        Cache::Fresh(Assets::Empty),
    ),
    case(
        "info-cached",
        &["update", "info"],
        Cache::Fresh(Assets::Empty),
    ),
    case("info-nocache", &["update", "info"], Cache::None),
    case(
        "info-json-nocache",
        &["update", "info", "--json"],
        Cache::None,
    ),
    case(
        "info-output-json-cached",
        &["update", "info", "--output", "json"],
        Cache::Fresh(Assets::Empty),
    ),
    // --- apply with an update available: the release-asset branches ---
    case(
        "apply-no-assets",
        &["update", "apply"],
        Cache::Fresh(Assets::Empty),
    ),
    case(
        "apply-no-assets-json",
        &["update", "apply", "--json"],
        Cache::Fresh(Assets::Empty),
    ),
    case(
        "apply-no-checksums-asset",
        &["update", "apply"],
        Cache::Fresh(Assets::NoChecksums),
    ),
    case(
        "apply-only-checksums-asset",
        &["update", "apply"],
        Cache::Fresh(Assets::OnlyChecksums),
    ),
    case(
        "apply-wrong-arch",
        &["update", "apply"],
        Cache::Fresh(Assets::WrongArch),
    ),
    case(
        "apply-wrong-os",
        &["update", "apply"],
        Cache::Fresh(Assets::WrongOs),
    ),
    case(
        "apply-github-assets",
        &["update", "apply"],
        Cache::Fresh(Assets::Github),
    ),
    case(
        "apply-github-assets-json",
        &["update", "apply", "--json"],
        Cache::Fresh(Assets::Github),
    ),
    case(
        "apply-github-assets-upper",
        &["update", "apply"],
        Cache::Fresh(Assets::UpperGithub),
    ),
    case(
        "apply-other-host",
        &["update", "apply"],
        Cache::Fresh(Assets::OtherHost),
    ),
    case(
        "apply-served-checksums-404",
        &["update", "apply"],
        Cache::Fresh(Assets::Served("404")),
    ),
    case(
        "apply-served-checksums-empty",
        &["update", "apply"],
        Cache::Fresh(Assets::Served("empty")),
    ),
    case(
        "apply-served-checksums-garbage",
        &["update", "apply"],
        Cache::Fresh(Assets::Served("garbage")),
    ),
    case(
        "apply-served-checksums-ok",
        &["update", "apply"],
        Cache::Fresh(Assets::Served("ok")),
    ),
    case(
        "apply-served-checksums-ok-json",
        &["update", "apply", "--json"],
        Cache::Fresh(Assets::Served("ok")),
    ),
    case(
        "apply-served-checksums-redirect",
        &["update", "apply"],
        Cache::Fresh(Assets::Served("redirect")),
    ),
];

/// Cases whose Go result depends on Go not checking the host of the *first*
/// asset URL (it checks redirects only): Go downloads from the loopback server
/// or from `example.invalid`, Rust refuses the URL before any request. Rust is
/// stricter on purpose (a cached release record is attacker-influenced input
/// for a command that replaces the running executable), so these are declared
/// divergences with the exact Rust text asserted. Go's recorded text still has
/// to be present and different, so the declaration cannot go stale.
const DECLARED_HOST_CHECK: &[&str] = &[
    "apply-other-host",
    "apply-served-checksums-404",
    "apply-served-checksums-empty",
    "apply-served-checksums-garbage",
    "apply-served-checksums-ok",
    "apply-served-checksums-ok-json",
    "apply-served-checksums-redirect",
];
const RUST_HOST_REFUSAL: &str = "Error: apply update: apply update: updateapply: release asset URL must use HTTPS on a GitHub host\n";

// ---------------------------------------------------------------------------

fn arch() -> (&'static str, &'static str) {
    match std::env::consts::ARCH {
        "aarch64" => ("darwin", "arm64"),
        _ => ("darwin", "amd64"),
    }
}

fn asset(name: &str, url: &str, size: u64) -> Value {
    json!({"Name": name, "BrowserDownloadURL": url, "Size": size})
}

fn assets_json(kind: Assets, port: u16) -> Value {
    let (os, arch) = arch();
    let other_arch = if arch == "arm64" { "amd64" } else { "arm64" };
    let archive = format!("symvault_1.5.0_{os}_{arch}.tar.gz");
    let gh = "https://github.com/danieljustus/symaira-vault/releases/download/v1.5.0";
    let local = |route: &str, file: &str| format!("http://127.0.0.1:{port}/{route}/{file}");
    let list = match kind {
        Assets::Empty => vec![],
        Assets::Served(route) => vec![
            asset(&archive, &local("ok", "asset.tar.gz"), 21),
            asset("checksums.txt", &local(route, "checksums.txt"), 10),
        ],
        Assets::Github => vec![
            asset(&archive, &format!("{gh}/{archive}"), 21),
            asset("checksums.txt", &format!("{gh}/checksums.txt"), 10),
        ],
        Assets::OtherHost => vec![
            asset(&archive, "https://example.invalid/a.tar.gz", 21),
            asset("checksums.txt", "https://example.invalid/c.txt", 10),
        ],
        Assets::NoChecksums => vec![asset(&archive, &format!("{gh}/{archive}"), 21)],
        Assets::OnlyChecksums => vec![asset("checksums.txt", &format!("{gh}/checksums.txt"), 10)],
        Assets::WrongArch => vec![
            asset(
                &format!("symvault_1.5.0_{os}_{other_arch}.tar.gz"),
                &format!("{gh}/x.tar.gz"),
                21,
            ),
            asset("checksums.txt", &format!("{gh}/checksums.txt"), 10),
        ],
        Assets::WrongOs => vec![
            asset(
                &format!("symvault_1.5.0_linux_{arch}.tar.gz"),
                &format!("{gh}/x.tar.gz"),
                21,
            ),
            asset("checksums.txt", &format!("{gh}/checksums.txt"), 10),
        ],
        Assets::UpperGithub => vec![
            asset(
                &format!("SYMVAULT_DARWIN_{}.ZIP", arch.to_uppercase()),
                &format!("{gh}/a.zip"),
                21,
            ),
            asset("checksums.txt", &format!("{gh}/checksums.txt"), 10),
        ],
    };
    Value::Array(list)
}

fn cache_file(home: &Path) -> PathBuf {
    let digest = hex::encode(Sha256::digest(b"danieljustus\0symaira-vault"));
    home.join("cache/symaira/updatecheck")
        .join(format!("{digest}.json"))
}

fn seed_cache(home: &Path, cache: Cache, port: u16) -> Option<Vec<u8>> {
    let (tag, assets, timestamp) = match cache {
        Cache::None => return None,
        Cache::Fresh(assets) => ("v1.5.0", assets, "2099-01-01T00:00:00Z"),
        Cache::Tagged(tag, assets) => (tag, assets, "2099-01-01T00:00:00Z"),
        Cache::Stale => ("v1.5.0", Assets::Empty, "2000-01-01T00:00:00Z"),
    };
    let record = json!({
        "Timestamp": timestamp,
        "Release": {
            "TagName": tag,
            "Body": "",
            "HTMLURL": format!("https://github.com/danieljustus/symaira-vault/releases/tag/{tag}"),
            "Assets": assets_json(assets, port),
        }
    });
    let path = cache_file(home);
    std::fs::create_dir_all(path.parent().unwrap()).expect("cache dir");
    let bytes = serde_json::to_vec(&record).unwrap();
    std::fs::write(&path, &bytes).expect("seed cache");
    Some(bytes)
}

/// Loopback release-asset server. Routes mirror `Assets::Served`.
fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            thread::spawn(move || {
                let mut buffer = [0u8; 4096];
                let read = stream.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
                let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let me = stream.local_addr().unwrap().port();
                let (status, location, body): (&str, Option<String>, &[u8]) = match path.as_str() {
                    p if p.starts_with("/404") => ("404 Not Found", None, b""),
                    p if p.starts_with("/redirect") => (
                        "302 Found",
                        Some(format!("http://127.0.0.1:{me}/ok/checksums.txt")),
                        b"",
                    ),
                    "/ok/checksums.txt" => (
                        "200 OK",
                        None,
                        b"0000000000000000000000000000000000000000000000000000000000000000  x.tar.gz\n",
                    ),
                    "/empty/checksums.txt" => ("200 OK", None, b""),
                    "/garbage/checksums.txt" => ("200 OK", None, b"not a checksum line\n"),
                    "/ok/asset.tar.gz" => ("200 OK", None, b"not really an archive"),
                    _ => ("500 Internal Server Error", None, b""),
                };
                let mut head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                if let Some(location) = location {
                    head.push_str(&format!("Location: {location}\r\n"));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
            });
        }
    });
    port
}

fn replace_all(text: &str, from: &str, to: &str) -> String {
    if from.is_empty() {
        text.to_owned()
    } else {
        text.replace(from, to)
    }
}

/// A transport failure keeps its product-owned prefix; the HTTP stack's wording
/// after it becomes `<TRANSPORT>`.
///
/// * Go:   `... request latest release: Get "<url>": dial tcp: lookup ...`
/// * Rust: `... request latest release: error sending request for url (<url>)`
///   `... request "checksums.txt": error sending request for url (<url>)`
fn transport(line: &str) -> String {
    for marker in ["Get \"", "error sending request for url ("] {
        if let Some(at) = line.find(marker) {
            let head = &line[..at];
            // `request asset: ` (Go) and `request "<name>": ` (Rust) name the
            // same step; only the step survives.
            let head = match head.rfind("request ") {
                Some(r) if head[r..].starts_with("request \"") => {
                    format!("{}request <ASSET>: ", &head[..r])
                }
                Some(r) if head[r..].starts_with("request asset: ") => {
                    format!("{}request <ASSET>: ", &head[..r])
                }
                _ => head.to_owned(),
            };
            return format!("{head}<TRANSPORT>");
        }
    }
    line.to_owned()
}

fn normalise(bytes: &[u8], home: &Path, port: u16) -> String {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    if let Ok(real) = std::fs::canonicalize(home) {
        text = replace_all(&text, &real.to_string_lossy(), "<HOME>");
    }
    text = replace_all(&text, &home.to_string_lossy(), "<HOME>");
    text = replace_all(&text, &format!("127.0.0.1:{port}"), "127.0.0.1:<PORT>");
    text.split_inclusive('\n')
        .map(|line| {
            let body = line.strip_suffix('\n').unwrap_or(line);
            let mut out = transport(body);
            if line.ends_with('\n') {
                out.push('\n');
            }
            out
        })
        .collect()
}

fn sha(path: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(path).expect("read binary")))
}

fn observe(binary: &Path, case: &Case) -> Value {
    let guard = tempfile::Builder::new()
        .prefix("symvault-r4-")
        .tempdir()
        .expect("sandbox");
    let home = guard.path().join("home");
    std::fs::create_dir_all(home.join("bin")).expect("bin dir");
    let installed = home.join("bin/symvault");
    std::fs::copy(binary, &installed).expect("install binary");
    let before = sha(&installed);
    let profile = home.join("no-network.sb");
    std::fs::write(&profile, NO_NETWORK).expect("profile");
    let port = serve();
    let seeded = seed_cache(&home, case.cache, port);

    let output = Command::new("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(&profile)
        .arg(&installed)
        .args(case.args)
        .current_dir(&home)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("LANG", "C")
        .env("TZ", "UTC")
        .env("CI", "1")
        .output()
        .expect("run symvault");
    let after = std::fs::read(cache_file(&home)).ok();
    json!({
        "exit": output.status.code(),
        "stdout": normalise(&output.stdout, &home, port),
        "stderr": normalise(&output.stderr, &home, port),
        "binary_unchanged": sha(&installed) == before,
        "cache_unchanged": after == seeded,
    })
}

/// A Rust binary stamped `1.0.0`, built once per test run.
fn stable_rust() -> PathBuf {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            if let Some(path) = std::env::var_os("SYMVAULT_STABLE_BINARY") {
                return PathBuf::from(path);
            }
            let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("stable-1.0.0");
            let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let status = Command::new(cargo)
                .args([
                    "build",
                    "--locked",
                    "--quiet",
                    "--bin",
                    "symvault",
                    "--manifest-path",
                ])
                .arg(&manifest)
                .arg("--target-dir")
                .arg(&target)
                .env("SYMVAULT_VERSION", "1.0.0")
                .env("CARGO_INCREMENTAL", "0")
                .status()
                .expect("cargo build of the 1.0.0 binary");
            assert!(status.success(), "building the 1.0.0 Rust binary failed");
            target.join("debug/symvault")
        })
        .clone()
}

#[test]
fn update_live_release_matches_go() {
    let obs = Observations::begin(
        "cli_update_live_release",
        "update_live_release_matches_go",
        Some(ORACLE),
    );
    let rust = if obs.capturing() {
        PathBuf::new()
    } else {
        stable_rust()
    };
    let mut compared = 0;
    for case in CASES {
        let go = obs.observe(case.name, |go_binary| observe(go_binary, case));
        if obs.capturing() {
            continue;
        }
        if case.name == "check-nocache" {
            // A Go run that had reached the network would report "up to date".
            assert_eq!(go["exit"], 1, "Go must fail closed without a network: {go}");
        }
        let native = observe(&rust, case);
        if DECLARED_HOST_CHECK.contains(&case.name) {
            assert_ne!(
                native["stderr"], go["stderr"],
                "{}: Rust now matches Go; drop it from DECLARED_HOST_CHECK",
                case.name
            );
            assert_eq!(native["exit"], go["exit"], "{}: exit", case.name);
            assert_eq!(native["stdout"], go["stdout"], "{}: stdout", case.name);
            assert_eq!(native["binary_unchanged"], true, "{}", case.name);
            assert_eq!(
                native["stderr"], RUST_HOST_REFUSAL,
                "{}: declared Rust text",
                case.name
            );
        } else {
            assert_eq!(native, go, "{}: {:?}", case.name, case.args);
        }
        compared += 1;
    }
    if !obs.capturing() {
        assert_eq!(compared, CASES.len());
    }
    assert_eq!(obs.count(), CASES.len());
}
