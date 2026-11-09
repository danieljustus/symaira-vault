//! SESSION-001 cache lifecycle replayed from the Go-derived fixture:
//! idle/maximum TTL, touch versus non-refreshing probes, revoke, corrupted
//! records, keyring failure and concurrent access.
#![deny(unsafe_code)]

#[path = "support/session_cache_replay.rs"]
mod replay;

const MEMORY_SCENARIOS: [&str; 18] = [
    "idle_ttl_touch_then_evict",
    "nonpositive_ttl_is_expired_without_eviction",
    "maximum_lifetime_is_absolute",
    "probes_do_not_refresh_or_evict",
    "touch_scope_passphrase_vs_identity",
    "identity_expiry_follows_session_metadata",
    "revoke_and_clear",
    "revoke_with_delete_failures",
    "corrupted_session_record",
    "incomplete_session_record",
    "last_access_defaults_to_saved_at",
    "tampered_and_misaddressed_ciphertext",
    "wrap_key_states",
    "corrupted_identity_record",
    "legacy_plaintext_lifecycle",
    "keyring_failures",
    "go_sealed_vector",
    "record_shape",
];
const FALLBACK_SCENARIOS: [&str; 4] = [
    "fallback_miss_does_not_activate",
    "fallback_activates_on_set_failure",
    "fallback_activates_on_get_failure",
    "fallback_activates_on_delete_failure",
];
const CONCURRENCY_CASES: [&str; 3] = [
    "concurrent_touch_and_probe_keep_live_session",
    "concurrent_revoke_during_loads",
    "concurrent_saves_recover_by_sequential_save",
];

fn observation_steps(scenario: &replay::Scenario) -> usize {
    scenario
        .steps
        .iter()
        .filter(|step| {
            !matches!(
                step.op.as_str(),
                "edit" | "raw_set" | "raw_delete" | "set_fault"
            )
        })
        .count()
}

#[test]
fn cache_fixture_has_the_complete_scenario_set() {
    let contract = replay::contract();
    assert_eq!(contract.schema_version, 1);
    let memory: Vec<_> = contract
        .scenarios
        .iter()
        .filter(|scenario| scenario.backend == "memory")
        .map(|scenario| scenario.name.as_str())
        .collect();
    assert_eq!(memory, MEMORY_SCENARIOS);
    let fallback: Vec<_> = contract
        .scenarios
        .iter()
        .filter(|scenario| scenario.backend == "fallback")
        .map(|scenario| scenario.name.as_str())
        .collect();
    assert_eq!(fallback, FALLBACK_SCENARIOS);
    let concurrency: Vec<_> = contract
        .concurrency
        .iter()
        .map(|case| case.name.as_str())
        .collect();
    assert_eq!(concurrency, CONCURRENCY_CASES);
    let steps: usize = contract.scenarios.iter().map(observation_steps).sum();
    assert_eq!(steps, 169, "observed Go steps across both backends");
}

#[test]
fn memory_backend_scenarios_replay_go_observations() {
    let contract = replay::contract();
    let mut replayed = 0;
    let mut expected = 0;
    for scenario in contract
        .scenarios
        .iter()
        .filter(|scenario| scenario.backend == "memory")
    {
        expected += observation_steps(scenario);
        replayed += replay::replay(scenario, &replay::memory_harness());
    }
    assert_eq!(replayed, expected);
    assert!(replayed > 100, "replayed only {replayed} observations");
}

#[test]
fn concurrent_access_keeps_the_go_invariants() {
    let contract = replay::contract();
    for case in &contract.concurrency {
        // Repeat: a race that only sometimes violates an invariant must not
        // pass on one lucky schedule.
        for _ in 0..5 {
            replay::replay_concurrency(case);
        }
    }
}

#[test]
fn session_cache_is_keyring_only_and_never_touches_the_filesystem() {
    let contract = replay::contract();
    assert_eq!(contract.storage.backend, "keyring");
    assert!(contract.storage.filesystem_imports.is_empty());
    assert_eq!(contract.storage.on_disk_files, 0);
    // The Rust side makes the same promise statically: the session module has
    // no filesystem access, so there are no cache file modes to match.
    let source = include_str!("../src/session.rs");
    let production = source.split("#[cfg(test)]").next().unwrap();
    for banned in ["std::fs", "File::", "OpenOptions", "std::os::unix"] {
        assert!(!production.contains(banned), "session.rs uses {banned}");
    }
}

/// A keyring whose next `Get` of the wrap key fails once with a transient
/// backend error (everything else passes through to memory).
struct TransientWrapKeyGetFault {
    inner: symvault_core::session::MemoryKeyring,
    armed: std::sync::atomic::AtomicBool,
}

impl symvault_core::session::Keyring for TransientWrapKeyGetFault {
    fn get(&self, key: &str) -> Result<Vec<u8>, symvault_core::session::SessionError> {
        if key.ends_with("|wrap-key") && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(symvault_core::session::SessionError::Keyring(
                "transient get failure".into(),
            ));
        }
        self.inner.get(key)
    }
    fn set(&self, key: &str, value: &[u8]) -> Result<(), symvault_core::session::SessionError> {
        self.inner.set(key, value)
    }
    fn delete(&self, key: &str) -> Result<(), symvault_core::session::SessionError> {
        self.inner.delete(key)
    }
}

/// Rust-only pin of a documented Go-parity residual risk (not a fix target):
/// Go's `getOrCreateWrapKey` treats *any* wrap-key `Get` failure, not just
/// absence, as "unusable" and generates a new key on the next save. A transient
/// keyring fault therefore replaces the wrap key, and a previously sealed
/// identity can no longer be opened. If this test starts failing, the behaviour
/// diverged from Go (`session.go`) and SESSION-001 must be re-evaluated.
#[test]
fn transient_wrap_key_get_fault_then_save_replaces_the_key_and_orphans_the_sealed_identity() {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use symvault_core::session::{Keyring, SessionManager};

    const TTL: Duration = Duration::from_secs(3600);
    const MAX: Duration = Duration::from_secs(8 * 3600);
    let wrap_key = "symvault:v|wrap-key";

    let keyring = Arc::new(TransientWrapKeyGetFault {
        inner: symvault_core::session::MemoryKeyring::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
    });
    let manager = SessionManager::with_system_clock(keyring.clone());

    manager
        .save_identity("v", b"AGE-SECRET-KEY-sealed-before-fault", TTL, MAX)
        .unwrap();
    let original_wrap_key = keyring.get(wrap_key).unwrap();
    assert_eq!(
        manager.load_identity("v", false).unwrap(),
        b"AGE-SECRET-KEY-sealed-before-fault"
    );

    // The next save sees the wrap key `Get` fail once, treats the key as
    // unusable and writes a fresh one. `save_passphrase` leaves the identity
    // record untouched, so it stays sealed under the old key.
    keyring.armed.store(true, Ordering::SeqCst);
    manager
        .save_passphrase("v", b"new-passphrase", TTL, MAX)
        .unwrap();
    assert!(
        !keyring.armed.load(Ordering::SeqCst),
        "the fault must have been consumed by the save"
    );

    let replaced_wrap_key = keyring.get(wrap_key).unwrap();
    assert_ne!(
        replaced_wrap_key, original_wrap_key,
        "a transient Get failure makes the save replace the wrap key (Go parity)"
    );
    assert_eq!(manager.load_passphrase("v").unwrap(), b"new-passphrase");
    assert!(
        manager.load_identity("v", false).is_err(),
        "the identity sealed under the replaced wrap key must no longer open"
    );
}
