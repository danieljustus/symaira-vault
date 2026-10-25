//! SESSION-001 keyring-unavailable behaviour: the process-lifetime memory
//! fallback replayed from the Go-derived cache fixture. The in-memory and
//! concurrency scenarios of the same fixture are replayed by `symvault-core`.
#![deny(unsafe_code)]

#[path = "../../symvault-core/tests/support/session_cache_replay.rs"]
mod replay;

use std::sync::Arc;
use symvault_platform::{FallbackKeyring, Keyring, SessionManager};

fn fallback_harness() -> replay::Harness {
    let primary = Arc::new(replay::FaultyKeyring::default());
    let keyring = FallbackKeyring::new(primary.clone() as Arc<dyn Keyring>, false);
    let observer = keyring.clone();
    replay::Harness {
        manager: SessionManager::new(keyring, Arc::new(replay::TestClock)),
        primary,
        fallback_active: Some(Box::new(move || observer.is_fallback_active())),
    }
}

#[test]
fn fallback_scenarios_replay_go_observations() {
    let contract = replay::contract();
    let scenarios: Vec<_> = contract
        .scenarios
        .iter()
        .filter(|scenario| scenario.backend == "fallback")
        .collect();
    let names: Vec<_> = scenarios
        .iter()
        .map(|scenario| scenario.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "fallback_miss_does_not_activate",
            "fallback_activates_on_set_failure",
            "fallback_activates_on_get_failure",
            "fallback_activates_on_delete_failure",
        ]
    );
    let mut replayed = 0;
    for scenario in scenarios {
        replayed += replay::replay(scenario, &fallback_harness());
    }
    assert_eq!(replayed, 16, "fallback observations replayed");
}
