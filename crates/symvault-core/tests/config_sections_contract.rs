//! CFG-002 (sections) and CFG-003 (deprecation warnings): the loader's
//! section-presence contract, against the Go oracle.
//!
//! Every section — vault, git, mcp, update, clipboard — carries its own
//! defaults and only the fields a document names override them. Presence, not
//! value, decides: an explicit zero, false or `null` beats the default, an
//! absent field does not. The loader also raises a warning for three
//! deprecated keys; the texts are ours on both sides, so they are pinned.
//!
//! Each Go case was loaded in a fresh process, because
//! `clipboard.printByDefault` warns once per process. The fresh process is
//! modelled here by a fresh [`WarningState`]; the `twice` case reuses one state
//! across two loads, and the process-wide guard is exercised on its own in
//! `config_sections_process_guard.rs`.

use serde::Deserialize;
use symvault_core::config::{Config, WarningState};

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct SyncSnapshot {
    method: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct VaultSnapshot {
    path: String,
    default_recipients: Vec<String>,
    confirm_remove: bool,
    auth_method: String,
    use_touch_id: bool,
    legacy_mode: Option<bool>,
    search_index: bool,
    search_workers: i64,
    search_index_cache: bool,
    config_cache_entries: i64,
    pseudonymize_paths: bool,
    scrypt_work_factor: i64,
    auto_migrate_kdf: bool,
    auto_heal_zero_key: bool,
    format_version: i64,
    last_rotated: String,
    argon2id_time: i64,
    argon2id_memory: i64,
    argon2id_threads: i64,
    listing_cache_ttl_ns: i64,
    manifest_generation: i64,
    sync: Option<SyncSnapshot>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct GitSnapshot {
    auto_push: bool,
    auto_pull: bool,
    auto_pull_interval_ns: i64,
    commit_template: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct OauthSnapshot {
    access_token_ttl_ns: i64,
    refresh_token_ttl_ns: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct McpSnapshot {
    port: i64,
    bind: String,
    stdio: bool,
    http_token_file: String,
    read_header_timeout_ns: i64,
    read_timeout_ns: i64,
    write_timeout_ns: i64,
    shutdown_timeout_ns: i64,
    approval_timeout_ns: i64,
    rate_limit: i64,
    metrics_auth_required: bool,
    tls_cert_file: String,
    tls_key_file: String,
    tls_client_ca_file: String,
    mtls_enabled: bool,
    allow_insecure_bind: bool,
    oauth: Option<OauthSnapshot>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct UpdateSnapshot {
    cache_ttl_ns: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct ClipboardSnapshot {
    auto_clear_duration: i64,
    copy_by_default: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct Snapshot {
    auth_method: String,
    effective_auth_method: String,
    vault: Option<VaultSnapshot>,
    git: Option<GitSnapshot>,
    mcp: Option<McpSnapshot>,
    update: Option<UpdateSnapshot>,
    clipboard: Option<ClipboardSnapshot>,
}

#[derive(Debug, Deserialize)]
struct Load {
    warnings: Vec<String>,
    rejected: bool,
    snapshot: Option<Snapshot>,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    #[allow(dead_code)]
    description: String,
    input: String,
    /// A second document loaded after `input` in the same process; `loads`
    /// then holds exactly two results, `input` and then `follow_up`.
    #[serde(default)]
    follow_up: String,
    loads: Vec<Load>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    cases: Vec<Case>,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/config/sections.json");
    serde_json::from_slice(CONTENT).expect("sections fixture parses")
}

fn ns(duration: std::time::Duration) -> i64 {
    i64::try_from(duration.as_nanos()).expect("duration fits i64 nanoseconds")
}

/// What a consumer observes of an accepted config.
///
/// Go always fills `mcp.oauth` when the section is present, with the default
/// TTLs; Rust leaves it `None` and its consumer falls back to the same
/// defaults, so the effective value is compared.
fn snapshot_of(config: &Config) -> Snapshot {
    Snapshot {
        auth_method: config.auth_method.as_str().to_owned(),
        effective_auth_method: config.effective_auth_method().as_str().to_owned(),
        vault: config.vault.as_ref().map(|v| VaultSnapshot {
            path: v.path.clone(),
            default_recipients: v.default_recipients.clone(),
            confirm_remove: v.confirm_remove,
            auth_method: v.auth_method.as_str().to_owned(),
            use_touch_id: v.use_touch_id,
            legacy_mode: v.legacy_mode,
            search_index: v.search_index,
            search_workers: v.search_workers,
            search_index_cache: v.search_index_cache,
            config_cache_entries: v.config_cache_entries,
            pseudonymize_paths: v.pseudonymize_paths,
            scrypt_work_factor: v.scrypt_work_factor,
            auto_migrate_kdf: v.auto_migrate_kdf,
            auto_heal_zero_key: v.auto_heal_zero_key,
            format_version: v.format_version,
            last_rotated: v.last_rotated.clone().unwrap_or_default(),
            argon2id_time: v.argon2id_time,
            argon2id_memory: v.argon2id_memory,
            argon2id_threads: v.argon2id_threads,
            listing_cache_ttl_ns: ns(v.listing_cache_ttl),
            manifest_generation: v.manifest_generation,
            sync: v.sync.as_ref().map(|s| SyncSnapshot {
                method: s.method.clone(),
            }),
        }),
        git: config.git.as_ref().map(|g| GitSnapshot {
            auto_push: g.auto_push,
            auto_pull: g.auto_pull,
            auto_pull_interval_ns: ns(g.auto_pull_interval),
            commit_template: g.commit_template.clone(),
        }),
        mcp: config.mcp.as_ref().map(|m| {
            let oauth = m.oauth.clone().unwrap_or_default();
            McpSnapshot {
                port: m.port,
                bind: m.bind.clone(),
                stdio: m.stdio,
                http_token_file: m.http_token_file.clone(),
                read_header_timeout_ns: ns(m.read_header_timeout),
                read_timeout_ns: ns(m.read_timeout),
                write_timeout_ns: ns(m.write_timeout),
                shutdown_timeout_ns: ns(m.shutdown_timeout),
                approval_timeout_ns: ns(m.approval_timeout),
                rate_limit: m.rate_limit,
                metrics_auth_required: m.metrics_auth_required,
                tls_cert_file: m.tls_cert_file.clone(),
                tls_key_file: m.tls_key_file.clone(),
                tls_client_ca_file: m.tls_client_ca_file.clone(),
                mtls_enabled: m.mtls_enabled,
                allow_insecure_bind: m.allow_insecure_bind,
                oauth: Some(OauthSnapshot {
                    access_token_ttl_ns: ns(oauth.access_token_ttl),
                    refresh_token_ttl_ns: ns(oauth.refresh_token_ttl),
                }),
            }
        }),
        update: config.update.as_ref().map(|u| UpdateSnapshot {
            cache_ttl_ns: ns(u.cache_ttl),
        }),
        clipboard: config.clipboard.as_ref().map(|c| ClipboardSnapshot {
            auto_clear_duration: c.auto_clear_duration,
            copy_by_default: c.copy_by_default,
        }),
    }
}

/// Fields Go's loader drops from the document and Rust reads.
///
/// `mergeVaultConfig` never copies `listing_cache_ttl` or `manifest_generation`
/// out of the document, so after `Load` they are always zero in Go: a value the
/// operator or a previous save wrote is silently discarded. Rust keeps them,
/// and `manifest_generation` is the on-disk rollback counter, so dropping it
/// would weaken rollback detection for no compatibility gain. The difference is
/// adjudicated and recorded rather than ported; each divergence is asserted
/// exactly so it can neither widen nor silently close.
fn mask_adjudicated(snapshot: &mut Snapshot) {
    if let Some(vault) = snapshot.vault.as_mut() {
        vault.listing_cache_ttl_ns = 0;
        vault.manifest_generation = 0;
        // Go keeps an explicitly empty `vault.authMethod` as the empty string;
        // Rust's method type has no such state and reads it as the default.
        // Every consumer resolves the empty string to a passphrase too, and the
        // effective method is compared separately above.
        if vault.auth_method.is_empty() {
            vault.auth_method = "passphrase".to_owned();
        }
    }
}

/// Inputs Go accepts and Rust deliberately rejects.
///
/// Go's merge ignores an `authMethod` it cannot normalize, so a typo such as
/// `retina` silently runs the vault with a passphrase. That is the same silent
/// discard CFG-003 step two closed for session durations, and Rust's method
/// type cannot carry the raw text either. The stricter side is kept and the
/// difference recorded; the Go behavior is a separate oracle change.
const ADJUDICATED_STRICTER: [&str; 2] = ["auth_top_invalid", "auth_vault_invalid"];

/// Residual ordering divergence, asserted exactly.
///
/// Go checks `mcp.bind` only after every section has merged, so a document
/// that carries both an empty `mcp.bind` and `clipboard.printByDefault` is
/// rejected *after* the clipboard merge consumed the once-per-process warning;
/// a later valid load stays silent. Rust rejects `mcp.bind` before it parses
/// the clipboard section, so the guard is untouched and the later load warns.
/// The rejection itself agrees; only the warning on the next load differs.
const ADJUDICATED_WARNING_ORDER: [&str; 1] = ["mcp_empty_bind_with_print_by_default"];

#[test]
fn fixture_has_pinned_provenance_and_schema() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.release, "unreleased");
    assert_eq!(fixture.oracle.commit_sha.len(), 40);
    assert!(
        fixture
            .oracle
            .commit_sha
            .starts_with(&fixture.oracle.commit)
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    for source in [
        "internal/config/config_merge.go",
        "internal/config/config_load.go",
        "internal/config/warn.go",
    ] {
        assert!(
            fixture.oracle.source_files.contains(&source.to_owned()),
            "{source} missing from provenance"
        );
    }
    assert!(fixture.cases.len() >= 100, "fixture lost cases");
}

#[test]
fn sections_match_go_oracle() {
    for case in &fixture().cases {
        let state = WarningState::default();
        for (index, expected) in case.loads.iter().enumerate() {
            let document = if index == 1 && !case.follow_up.is_empty() {
                &case.follow_up
            } else {
                &case.input
            };
            let result = Config::load_from_bytes_with_warnings_in(document.as_bytes(), &state);
            let label = format!("{} (load {index})", case.name);
            if ADJUDICATED_STRICTER.contains(&case.name.as_str()) {
                assert!(!expected.rejected, "{label}: Go is expected to accept it");
                assert!(
                    result.is_err(),
                    "{label}: the adjudicated rejection closed or widened"
                );
                continue;
            }
            if expected.rejected {
                assert!(
                    result.is_err(),
                    "{label}: Go rejected this input, Rust accepted it"
                );
                continue;
            }
            let (config, warnings) = result.unwrap_or_else(|error| {
                panic!("{label}: Go accepted this input, Rust failed: {error}")
            });
            if ADJUDICATED_WARNING_ORDER.contains(&case.name.as_str()) {
                assert!(
                    expected.warnings.is_empty(),
                    "{label}: Go is expected to stay silent after its earlier consumption"
                );
                assert_eq!(
                    warnings,
                    vec![
                        "clipboard.printByDefault is deprecated; use clipboard.copyByDefault instead"
                            .to_owned()
                    ],
                    "{label}: the adjudicated warning-order divergence closed or widened"
                );
                continue;
            }
            assert_eq!(warnings, expected.warnings, "warnings for {label}");
            let mut actual = snapshot_of(&config);
            let mut want = expected
                .snapshot
                .clone()
                .expect("accepted case has a snapshot");
            mask_adjudicated(&mut actual);
            mask_adjudicated(&mut want);
            assert_eq!(actual, want, "snapshot for {label}");
        }
    }
}

/// The adjudicated divergence is real on the Go side: the oracle fixture shows
/// the values dropped, and Rust keeps them. If either side moves, this fails.
#[test]
fn the_adjudicated_vault_divergence_is_exactly_the_two_dropped_fields() {
    let cases = fixture().cases;
    let find = |name: &str| cases.iter().find(|case| case.name == name).expect("case");

    let case = find("vault_listing_cache_ttl");
    let go = case.loads[0]
        .snapshot
        .as_ref()
        .unwrap()
        .vault
        .as_ref()
        .unwrap();
    let rust = snapshot_of(&Config::load_from_bytes(case.input.as_bytes()).unwrap())
        .vault
        .unwrap();
    assert_eq!(go.listing_cache_ttl_ns, 0, "Go drops listing_cache_ttl");
    assert_eq!(rust.listing_cache_ttl_ns, 300_000_000_000);

    let case = find("vault_manifest_generation");
    let go = case.loads[0]
        .snapshot
        .as_ref()
        .unwrap()
        .vault
        .as_ref()
        .unwrap();
    let rust = snapshot_of(&Config::load_from_bytes(case.input.as_bytes()).unwrap())
        .vault
        .unwrap();
    assert_eq!(go.manifest_generation, 0, "Go drops manifest_generation");
    assert_eq!(rust.manifest_generation, 7);
}

/// Negative control for the harness itself: the comparison must fail when a
/// field differs, otherwise every case above would pass vacuously.
#[test]
fn the_comparison_detects_a_wrong_default() {
    let case = fixture()
        .cases
        .into_iter()
        .find(|case| case.name == "git_explicit_false")
        .unwrap();
    let go = case.loads[0].snapshot.clone().unwrap();
    let config = Config::load_from_bytes(case.input.as_bytes()).unwrap();
    assert_eq!(snapshot_of(&config), go, "baseline agrees");
    let mut mutated = snapshot_of(&config);
    mutated.git.as_mut().unwrap().auto_push = true;
    assert_ne!(
        mutated, go,
        "an ignored explicit false must be visible to the comparison"
    );
}

/// A warning that stops being emitted would return the loader to silently
/// discarding what the operator wrote, so each of the three is pinned by name.
#[test]
fn every_deprecation_warning_is_pinned() {
    let fixture = fixture();
    let seen: std::collections::BTreeSet<String> = fixture
        .cases
        .iter()
        .flat_map(|case| case.loads.iter())
        .flat_map(|load| load.warnings.iter().cloned())
        .collect();
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        vec![
            "approval_required is deprecated and will be removed in a future version".to_owned(),
            "clipboard.printByDefault is deprecated; use clipboard.copyByDefault instead"
                .to_owned(),
            "envWhitelist is deprecated and will be removed in a future version; use envAllowlist instead"
                .to_owned(),
        ]
    );
    // Rejected loads carry their warnings in the fixture, but Rust returns an
    // error with no channel for them; that residual is recorded in the matrix.
    let rejected_with_warnings = fixture
        .cases
        .iter()
        .filter(|case| {
            case.loads
                .iter()
                .any(|load| load.rejected && !load.warnings.is_empty())
        })
        .map(|case| case.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        rejected_with_warnings,
        vec![
            "warning_then_rejection",
            "mcp_empty_bind_with_print_by_default"
        ]
    );
}
