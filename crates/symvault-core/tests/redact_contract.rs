#![deny(unsafe_code)]

use std::sync::{Arc, Mutex};

use serde::Deserialize;
use symvault_core::redact::{
    AuditEvent, BLOCKED_TEXT, Detector, EntropyDetector, ExactValueDetector, MARKER,
    MIN_ENTROPY_BITS_PER_CHAR, MIN_EXACT_VALUE_LEN, MIN_TOKEN_LEN, ScanOptions, Scanner, is_truthy,
    shannon_entropy,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    constants: Constants,
    exact_value_cases: Vec<ExactValueCase>,
    entropy_cases: Vec<EntropyCase>,
    scanner_cases: Vec<ScannerCase>,
    truthy_cases: Vec<TruthyCase>,
}

#[derive(Debug, Deserialize)]
struct Constants {
    marker: String,
    blocked_text: String,
    min_exact_value_len: usize,
    min_token_len: usize,
    min_entropy_bits_per_char: f64,
}

#[derive(Debug, Deserialize)]
struct ExactValueCase {
    name: String,
    secrets: Vec<String>,
    input: String,
    expected_redacted: String,
    expected_count: usize,
}

#[derive(Debug, Deserialize)]
struct EntropyCase {
    name: String,
    input: String,
    expected_redacted: String,
    expected_count: usize,
}

#[derive(Debug, Deserialize)]
struct ScannerCase {
    name: String,
    detectors: Vec<String>,
    #[serde(default)]
    secrets: Vec<String>,
    strict: bool,
    #[serde(default)]
    correlation_id: String,
    #[serde(default)]
    channel: String,
    input: String,
    expected_text: String,
    expected_blocked: bool,
    findings: Vec<FixtureFinding>,
    audit_events: Vec<FixtureAuditEvent>,
}

#[derive(Debug, Deserialize)]
struct FixtureFinding {
    detector: String,
    confidence: String,
    count: usize,
}

#[derive(Debug, Deserialize)]
struct FixtureAuditEvent {
    detector: String,
    channel: String,
    confidence: String,
    redacted_count: usize,
    blocked: bool,
    #[serde(default)]
    correlation_id: String,
}

#[derive(Debug, Deserialize)]
struct TruthyCase {
    input: String,
    expected: bool,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/core/redact-contract.json");
    serde_json::from_slice(CONTENT).expect("decode Go-generated redact fixture")
}

#[test]
fn constants_match_go_oracle() {
    let fix = fixture();
    assert_eq!(fix.schema_version, 1);
    assert_eq!(fix.constants.marker, MARKER);
    assert_eq!(fix.constants.blocked_text, BLOCKED_TEXT);
    assert_eq!(fix.constants.min_exact_value_len, MIN_EXACT_VALUE_LEN);
    assert_eq!(fix.constants.min_token_len, MIN_TOKEN_LEN);
    assert!((fix.constants.min_entropy_bits_per_char - MIN_ENTROPY_BITS_PER_CHAR).abs() < 1e-9);
}

#[test]
fn exact_value_cases_match_go_oracle() {
    let fix = fixture();
    for tc in fix.exact_value_cases {
        let detector = ExactValueDetector::new(&tc.secrets);
        let (redacted, count) = detector.redact(&tc.input).expect("redact exact value");
        assert_eq!(
            redacted, tc.expected_redacted,
            "case {}: redacted mismatch",
            tc.name
        );
        assert_eq!(count, tc.expected_count, "case {}: count mismatch", tc.name);

        // Security assertion: never leak original secrets
        for sec in &tc.secrets {
            if sec.len() >= MIN_EXACT_VALUE_LEN {
                assert!(
                    !redacted.contains(sec),
                    "case {}: secret {:?} leaked in output {:?}",
                    tc.name,
                    sec,
                    redacted
                );
            }
        }
    }
}

#[test]
fn entropy_cases_match_go_oracle() {
    let fix = fixture();
    let detector = EntropyDetector::new();
    for tc in fix.entropy_cases {
        let (redacted, count) = detector.redact(&tc.input).expect("redact entropy");
        assert_eq!(
            redacted, tc.expected_redacted,
            "case {}: redacted mismatch",
            tc.name
        );
        assert_eq!(count, tc.expected_count, "case {}: count mismatch", tc.name);
    }
}

#[test]
fn scanner_cases_match_go_oracle() {
    let fix = fixture();
    for tc in fix.scanner_cases {
        let mut detectors: Vec<Box<dyn Detector>> = Vec::new();
        for dname in &tc.detectors {
            match dname.as_str() {
                "exact_value" => detectors.push(Box::new(ExactValueDetector::new(&tc.secrets))),
                "entropy_heuristic" => detectors.push(Box::new(EntropyDetector::new())),
                other => panic!("unknown detector in fixture: {other}"),
            }
        }

        let mut scanner = Scanner::new(detectors).with_channel(&tc.channel);
        let events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = Arc::clone(&events);
        scanner.set_audit(move |e: &AuditEvent| {
            events_clone.lock().unwrap().push(e.clone());
        });

        let opts = ScanOptions {
            strict: tc.strict,
            correlation_id: if tc.correlation_id.is_empty() {
                None
            } else {
                Some(tc.correlation_id.clone())
            },
        };

        let result = scanner.scan(&tc.input, &opts).expect("scan succeeds");
        assert_eq!(
            result.text, tc.expected_text,
            "case {}: text mismatch",
            tc.name
        );
        assert_eq!(
            result.blocked, tc.expected_blocked,
            "case {}: blocked mismatch",
            tc.name
        );

        assert_eq!(
            result.findings.len(),
            tc.findings.len(),
            "case {}: findings length mismatch",
            tc.name
        );
        for (actual, expected) in result.findings.iter().zip(&tc.findings) {
            assert_eq!(actual.detector, expected.detector, "case {}", tc.name);
            assert_eq!(
                actual.confidence.as_str(),
                expected.confidence,
                "case {}",
                tc.name
            );
            assert_eq!(actual.count, expected.count, "case {}", tc.name);
        }

        let emitted = events.lock().unwrap();
        assert_eq!(
            emitted.len(),
            tc.audit_events.len(),
            "case {}: audit event count mismatch",
            tc.name
        );
        for (actual, expected) in emitted.iter().zip(&tc.audit_events) {
            assert_eq!(actual.detector, expected.detector, "case {}", tc.name);
            assert_eq!(actual.channel, expected.channel, "case {}", tc.name);
            assert_eq!(
                actual.confidence.as_str(),
                expected.confidence,
                "case {}",
                tc.name
            );
            assert_eq!(
                actual.redacted_count, expected.redacted_count,
                "case {}",
                tc.name
            );
            assert_eq!(actual.blocked, expected.blocked, "case {}", tc.name);
            assert_eq!(
                actual.correlation_id.as_deref().unwrap_or(""),
                expected.correlation_id,
                "case {}",
                tc.name
            );
        }
    }
}

#[test]
fn truthy_table_matches_go_oracle() {
    let fix = fixture();
    for tc in fix.truthy_cases {
        assert_eq!(
            is_truthy(&tc.input),
            tc.expected,
            "truthy mismatch for input {:?}",
            tc.input
        );
    }
}

#[test]
fn property_shannon_entropy_mathematical_bounds() {
    assert_eq!(shannon_entropy(""), 0.0);
    // Shannon entropy of uniform distribution over N symbols is log2(N)
    for n in 1..=127 {
        let bytes: Vec<u8> = (1..=n as u8).collect();
        if let Ok(valid_str) = core::str::from_utf8(&bytes) {
            let h = shannon_entropy(valid_str);
            let expected = (valid_str.len() as f64).log2();
            assert!((h - expected).abs() < 1e-6);
        }
    }
}

#[test]
fn property_exact_value_leak_prevention() {
    let secrets = [
        "super-secret-passphrase",
        concat!("gh", "p_1234567890abcdefghijklmnopqrstuvwxyz"),
        "AKIAIOSFODNN7EXAMPLE",
    ];
    let d = ExactValueDetector::new(secrets);

    for sec in secrets {
        let text = format!("header {sec} trailer and {sec} again");
        let (redacted, count) = d.redact(&text).expect("redact");
        assert_eq!(count, 2);
        assert!(!redacted.contains(sec), "leaked secret: {sec}");
        assert_eq!(
            redacted,
            format!("header {MARKER} trailer and {MARKER} again")
        );
    }
}
