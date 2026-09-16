//! GIT-002 differential: replays the Go offline-classification corpus.

use serde::Deserialize;
use symvault_sync::{NETWORK_MESSAGE, OFFLINE_ERROR_MARKERS, PushError, is_offline_error};

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    network_message: String,
    markers: Vec<String>,
    subsumed_markers: Vec<String>,
    offline_cases: Vec<OfflineCase>,
    format_cases: Vec<FormatCase>,
    unpinned_scope: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
}

#[derive(Debug, Deserialize)]
struct OfflineCase {
    name: String,
    why: String,
    message: String,
    offline: bool,
}

#[derive(Debug, Deserialize)]
struct FormatCase {
    name: String,
    why: String,
    message: String,
    cause: String,
    has_cause: bool,
    rendered: String,
}

fn load() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/sync/git-offline.json"
    );
    let bytes = std::fs::read(path).expect("read GIT-002 offline fixture");
    serde_json::from_slice(&bytes).expect("parse GIT-002 offline fixture")
}

#[test]
fn fixture_pins_the_expected_oracle() {
    let fx = load();
    assert_eq!(fx.oracle.commit, "caadd5e");
    assert_eq!(
        fx.oracle.commit_sha,
        "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
    );
}

#[test]
fn classification_matches_go_oracle() {
    let fx = load();
    assert!(!fx.offline_cases.is_empty());
    for case in &fx.offline_cases {
        assert_eq!(
            is_offline_error(&case.message),
            case.offline,
            "case {}: classified {} but the oracle says {} ({})",
            case.name,
            is_offline_error(&case.message),
            case.offline,
            case.why
        );
    }
}

/// A classifier corpus that only contains positives proves it says yes. Both
/// outcomes have to be represented, and the negatives are the ones that matter:
/// misclassifying a configuration error as a network blip tells the user to
/// check their connection when their credentials are wrong.
#[test]
fn both_outcomes_are_covered() {
    let fx = load();
    let offline = fx.offline_cases.iter().filter(|c| c.offline).count();
    let not_offline = fx.offline_cases.len() - offline;
    assert!(offline >= 15, "too few positive cases: {offline}");
    assert!(not_offline >= 6, "too few negative cases: {not_offline}");

    for expected in [
        "auth_failure_is_not_offline",
        "known_hosts_is_not_offline",
        "http_401_is_not_offline",
    ] {
        let case = fx
            .offline_cases
            .iter()
            .find(|c| c.name == expected)
            .unwrap_or_else(|| panic!("corpus lost the {expected} negative"));
        assert!(!case.offline);
        assert!(!is_offline_error(&case.message));
    }
}

#[test]
fn error_formatting_matches_go_oracle() {
    let fx = load();
    assert_eq!(fx.network_message, NETWORK_MESSAGE);
    for case in &fx.format_cases {
        let err = if case.has_cause {
            PushError::with_cause(&case.message, &case.cause)
        } else {
            PushError::new(&case.message)
        };
        assert_eq!(
            err.to_string(),
            case.rendered,
            "case {}: rendered form differs ({})",
            case.name,
            case.why
        );
    }
}

/// The fixture states what it does not cover. If that note disappears, the
/// unpinned precedence asymmetry would look pinned, which is worse than the
/// gap itself.
#[test]
fn unpinned_scope_is_still_declared() {
    let fx = load();
    assert!(
        fx.unpinned_scope
            .iter()
            .any(|n| n.contains("classifyPushError")),
        "the fixture must keep declaring that classifyPushError precedence is unpinned"
    );
    assert!(
        fx.unpinned_scope
            .iter()
            .any(|n| n.contains("IsOfflineError FIRST")),
        "the fixture must keep recording the push/pull precedence asymmetry"
    );
}

/// The marker list itself, in the oracle's order.
#[test]
fn marker_list_matches_go_oracle() {
    let fx = load();
    assert_eq!(
        fx.markers, OFFLINE_ERROR_MARKERS,
        "the marker list drifted from the oracle's, in content or in order"
    );
    for marker in &fx.markers {
        assert!(
            is_offline_error(marker),
            "marker {marker:?} does not classify its own text as offline"
        );
    }
}

/// Six of the markers can never decide a classification: any message containing
/// them also contains a shorter marker, so removing one changes no answer.
///
/// That is why a mutation deleting `i/o timeout` survives the corpus — it is an
/// equivalent mutant, not a coverage hole. Recording the subsumption set turns
/// that into a pinned property: if the generic markers were ever narrowed, the
/// specific ones would stop being redundant and this test would fail, which is
/// exactly when someone needs to look.
#[test]
fn subsumed_markers_match_the_computed_set() {
    let fx = load();

    let mut computed: Vec<String> = OFFLINE_ERROR_MARKERS
        .iter()
        .filter(|marker| {
            OFFLINE_ERROR_MARKERS.iter().any(|other| {
                other != *marker && other.len() < marker.len() && marker.contains(*other)
            })
        })
        .map(|m| (*m).to_string())
        .collect();
    computed.sort();

    assert_eq!(
        computed, fx.subsumed_markers,
        "the set of markers that can never decide a classification differs from the oracle's"
    );

    // The claim is behavioral, so check it behaviorally too.
    for marker in &fx.subsumed_markers {
        let shorter_hit = OFFLINE_ERROR_MARKERS
            .iter()
            .any(|other| other != marker && other.len() < marker.len() && marker.contains(*other));
        assert!(
            shorter_hit,
            "marker {marker:?} is listed as subsumed but nothing shorter matches it"
        );
    }
}
