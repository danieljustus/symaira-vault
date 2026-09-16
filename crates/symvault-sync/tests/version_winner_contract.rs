//! GIT-003 differential: replays the Go version-winner corpus.
//!
//! The corpus carries the oracle's own marshaled metadata bytes, so the test
//! checks two things that are easy to conflate: that Rust picks the same winner,
//! and that Rust's canonical JSON is byte-identical to the oracle's. The second
//! is not decoration — the third tier of the rule decides by comparing those
//! bytes, so an encoding drift would silently change the winner on ties.

use serde::Deserialize;
use serde_json::value::RawValue;
use symvault_store::EntryMetadata;
use symvault_sync::winner_by_version;

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    why: String,
    path: String,
    a: Box<RawValue>,
    b: Box<RawValue>,
    a_canonical: String,
    b_canonical: String,
    tier: String,
    winner_forward: String,
    winner_swapped: String,
    order_independent: bool,
    winner_canonical: String,
    loser_canonical: String,
}

fn load() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/sync/version-winner.json"
    );
    let bytes = std::fs::read(path).expect("read GIT-003 winner fixture");
    serde_json::from_slice(&bytes).expect("parse GIT-003 winner fixture")
}

fn operand(value: &RawValue) -> EntryMetadata {
    serde_json::from_str(value.get()).expect("fixture operand deserializes")
}

/// Which operand a result is, by value. Operands can be byte-identical, in
/// which case "a" is the stable label — the same convention the generator uses.
fn label(result: &EntryMetadata, a: &EntryMetadata, b: &EntryMetadata) -> String {
    if result == a {
        "a".to_string()
    } else if result == b {
        "b".to_string()
    } else {
        panic!("result is neither operand");
    }
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

/// The encoding the third tier compares must match the oracle byte-for-byte.
#[test]
fn canonical_json_matches_go_byte_for_byte() {
    let fx = load();
    for case in &fx.cases {
        for (side, value, expected) in [
            ("a", &case.a, &case.a_canonical),
            ("b", &case.b, &case.b_canonical),
        ] {
            let decoded = operand(value);
            let reencoded = serde_json::to_string(&decoded).expect("re-encode");
            // Compared against the compact bytes json.Marshal produced, which
            // is the form the third tier actually orders. The embedded operand
            // is re-indented when the fixture is written, and a re-encoded
            // serde_json::Value would sort its keys — both would hide exactly
            // the field-order drift this test exists to catch.
            assert_eq!(
                &reencoded, expected,
                "case {} operand {}: canonical JSON drifted from the oracle, which would silently change every tiebreak",
                case.name, side
            );
        }
    }
}

#[test]
fn winner_matches_go_oracle() {
    let fx = load();
    assert!(!fx.cases.is_empty());

    for case in &fx.cases {
        let a = operand(&case.a);
        let b = operand(&case.b);

        let (winner, loser) = winner_by_version(&case.path, &a, &b);
        assert_eq!(
            label(winner, &a, &b),
            case.winner_forward,
            "case {}: wrong winner ({})",
            case.name,
            case.why
        );

        assert_eq!(
            serde_json::to_string(winner).expect("encode winner"),
            case.winner_canonical,
            "case {}: winner metadata differs",
            case.name
        );
        assert_eq!(
            serde_json::to_string(loser).expect("encode loser"),
            case.loser_canonical,
            "case {}: loser metadata differs",
            case.name
        );

        // Same pair, arguments swapped.
        let (swapped, _) = winner_by_version(&case.path, &b, &a);
        assert_eq!(
            label(swapped, &a, &b),
            case.winner_swapped,
            "case {}: wrong winner with arguments swapped ({})",
            case.name,
            case.why
        );
    }
}

/// Order independence is a property, not a per-case accident: every case with a
/// non-empty path must give the same answer both ways round, and the empty-path
/// case must not.
#[test]
fn order_independence_holds_exactly_where_the_oracle_says() {
    let fx = load();
    let mut saw_dependent = false;

    for case in &fx.cases {
        assert_eq!(
            case.order_independent,
            case.winner_forward == case.winner_swapped,
            "case {}: the fixture contradicts itself",
            case.name
        );

        if case.path.is_empty() {
            assert!(
                !case.order_independent,
                "case {}: an empty path short-circuits to the first argument and cannot be order-independent",
                case.name
            );
            saw_dependent = true;
        } else {
            assert!(
                case.order_independent,
                "case {}: a non-empty path must decide by content alone ({})",
                case.name, case.why
            );
        }

        let a = operand(&case.a);
        let b = operand(&case.b);
        let (forward, _) = winner_by_version(&case.path, &a, &b);
        let (swapped, _) = winner_by_version(&case.path, &b, &a);
        assert_eq!(
            (label(forward, &a, &b) == label(swapped, &a, &b)),
            case.order_independent,
            "case {}: Rust's order dependence differs from the oracle's",
            case.name
        );
    }

    assert!(
        saw_dependent,
        "the corpus must keep covering the order-dependent empty-path branch"
    );
}

/// Every tier of the rule has to be exercised, or a whole branch could be wrong
/// and the sweep would still pass.
#[test]
fn every_tier_is_covered() {
    let fx = load();
    for tier in ["version", "updated", "tiebreak"] {
        assert!(
            fx.cases.iter().any(|c| c.tier == tier),
            "no case exercises the {tier} tier"
        );
    }
    assert!(fx.cases.len() >= 12, "corpus shrank unexpectedly");
}

/// Why one mutant is equivalent rather than an uncovered case.
///
/// The final tiebreak is `ja <= jb`. Weakening it to `ja < jb` changes the
/// branch taken only when the two canonical encodings are equal — and equal
/// encodings mean equal values, so the returned pair swaps two members that
/// compare equal. There is no observation that separates them, which is what
/// this test records: for byte-identical operands the winner and the loser are
/// themselves equal, so `<` and `<=` cannot be told apart through this API.
///
/// Stated as a test rather than a comment so the claim fails if the type ever
/// grows a field that makes equal encodings distinguishable.
#[test]
fn identical_operands_make_the_tiebreak_comparison_unobservable() {
    let fx = load();
    let case = fx
        .cases
        .iter()
        .find(|c| c.name == "identical_metadata_first_argument_wins")
        .expect("fixture keeps the identical-operand case");

    assert_eq!(
        case.a_canonical, case.b_canonical,
        "precondition: the operands encode identically"
    );

    let a = operand(&case.a);
    let b = operand(&case.b);
    assert_eq!(a, b, "equal encodings must mean equal values");

    let (winner, loser) = winner_by_version(&case.path, &a, &b);
    assert_eq!(
        winner, loser,
        "with identical operands the two results are equal, so which branch ran is unobservable"
    );
}
