#![deny(unsafe_code)]

//! Secret redaction core: detectors, Shannon entropy heuristic, and fail-closed scanner.

use core::{cmp::Reverse, fmt};
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Marker substituted for detected secret values.
pub const MARKER: &str = "[REDACTED]";

/// Marker returned when scanner output is withheld/blocked.
pub const BLOCKED_TEXT: &str = "[REDACTED: output withheld]";

/// Opt-in environment variable name enabling strict blocking mode.
pub const ENV_STRICT_MODE: &str = "SYMVAULT_REDACT_STRICT_MODE";

/// Minimum length for a literal exact-value detector match.
pub const MIN_EXACT_VALUE_LEN: usize = 4;

/// Maximum number of distinct exact values retained by one detector.
pub const MAX_EXACT_VALUE_COUNT: usize = 1024;

/// Maximum number of exact match spans retained by one detector.
pub const MAX_EXACT_MATCH_SPANS: usize = 4096;

/// Maximum number of exact-value byte comparisons per detector invocation.
/// The 64 MiB budget supports normal 16 MiB outputs with a small number of
/// values while bounding CPU for large outputs and many non-matching values.
pub const MAX_EXACT_SCAN_WORK: usize = 64 * 1024 * 1024;

/// Minimum token length for the entropy heuristic detector.
pub const MIN_TOKEN_LEN: usize = 20;

/// Shannon entropy floor in bits per character for the entropy heuristic.
pub const MIN_ENTROPY_BITS_PER_CHAR: f64 = 4.85;

/// Confidence classification of a detector match.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// High-confidence match (exact value, verified credential format).
    High,
    /// Low-confidence heuristic match (entropy-based candidate).
    Low,
}

impl Confidence {
    /// Human-readable label for confidence tier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Low => "low",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Error returned when a detector fails during scanning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactError(String);

impl RedactError {
    /// Creates a new detector error.
    #[must_use]
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for RedactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RedactError {}

/// Detector scans text for secrets and replaces matches with `MARKER`.
pub trait Detector: Send + Sync {
    /// Canonical detector name for audit metadata.
    fn name(&self) -> &str;
    /// Confidence tier of this detector.
    fn confidence(&self) -> Confidence;
    /// Redacts matches in place, returning the redacted text and match count.
    fn redact(&self, text: &str) -> Result<(String, usize), RedactError>;
}

/// Detector matching literal occurrences of known secrets.
pub struct ExactValueDetector {
    values: Vec<String>,
    overflowed: bool,
}

impl ExactValueDetector {
    /// Creates a new `ExactValueDetector`, filtering out secrets shorter than `MIN_EXACT_VALUE_LEN`.
    /// Values are stably deduplicated and processed longest-first so overlapping
    /// secrets cannot expose a suffix of the longer value.
    #[must_use]
    pub fn new<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut seen = HashSet::new();
        let mut filtered = Vec::new();
        let mut overflowed = false;
        for value in values {
            let value = value.as_ref();
            if value.len() < MIN_EXACT_VALUE_LEN {
                continue;
            }
            if seen.contains(value) {
                continue;
            }
            if filtered.len() >= MAX_EXACT_VALUE_COUNT {
                overflowed = true;
                break;
            }
            let owned = value.to_string();
            seen.insert(owned.clone());
            filtered.push(owned);
        }
        // Stable sorting preserves caller order for equal-length values,
        // making the tie-break deterministic.
        filtered.sort_by_key(|value| Reverse(value.len()));
        Self {
            values: filtered,
            overflowed,
        }
    }
}

// Custom Debug implementation to prevent secret values from leaking into logs/snapshots.
impl fmt::Debug for ExactValueDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExactValueDetector")
            .field("pattern_count", &self.values.len())
            .field("min_len", &MIN_EXACT_VALUE_LEN)
            .finish()
    }
}

impl Detector for ExactValueDetector {
    fn name(&self) -> &str {
        "exact_value"
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn redact(&self, text: &str) -> Result<(String, usize), RedactError> {
        if self.overflowed && !text.is_empty() {
            return Ok((MARKER.to_string(), 1));
        }
        match redact_exact_values(text, &self.values, MAX_EXACT_SCAN_WORK) {
            Some(result) => Ok(result),
            None => Ok((MARKER.to_string(), 1)),
        }
    }
}

fn redact_exact_values(
    text: &str,
    values: &[String],
    mut scan_work: usize,
) -> Option<(String, usize)> {
    if text.is_empty() {
        return Some((text.to_string(), 0));
    }

    // Find matches against the original text before replacing anything. Each
    // value uses left-to-right, non-overlapping occurrence discovery. Thus
    // self-overlapping occurrences such as "abab" in "ababab" select the
    // first occurrence and then resume after its end.
    let mut ranges = Vec::new();
    for value in values {
        let Some(max_start) = text.len().checked_sub(value.len()) else {
            continue;
        };
        let mut search_start = 0;
        while search_start <= max_start {
            let mut matched = true;
            for offset in 0..value.len() {
                if scan_work == 0 {
                    return None;
                }
                scan_work -= 1;
                let index = search_start.checked_add(offset)?;
                if text.as_bytes()[index] != value.as_bytes()[offset] {
                    matched = false;
                    break;
                }
            }
            if matched {
                let end = search_start.checked_add(value.len())?;
                if ranges.len() >= MAX_EXACT_MATCH_SPANS {
                    return None;
                }
                ranges.push(ExactMatchRange {
                    start: search_start,
                    end,
                });
                search_start = end;
            } else {
                search_start = search_start.checked_add(1)?;
            }
        }
    }
    if ranges.is_empty() {
        return Some((text.to_string(), 0));
    }

    // Merge overlaps, but keep merely adjacent spans separate. Sorting by
    // byte offsets preserves UTF-8 boundaries because every match came from a
    // valid string search and is therefore aligned to the original text.
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut merged = Vec::with_capacity(ranges.len());
    for candidate in ranges {
        if merged
            .last()
            .is_none_or(|previous: &ExactMatchRange| candidate.start >= previous.end)
        {
            merged.push(candidate);
        } else if let Some(previous) = merged.last_mut() {
            previous.end = previous.end.max(candidate.end);
        }
    }

    // Do not calculate an expanded capacity: marker replacement can overflow
    // that arithmetic for attacker-controlled sizes. String grows safely.
    let mut out = String::with_capacity(text.len());
    let mut last_end = 0;
    for span in &merged {
        out.push_str(&text[last_end..span.start]);
        out.push_str(MARKER);
        last_end = span.end;
    }
    out.push_str(&text[last_end..]);
    Some((out, merged.len()))
}

#[derive(Clone, Copy)]
struct ExactMatchRange {
    start: usize,
    end: usize,
}

/// Conservative Shannon entropy heuristic detector for random secret tokens.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EntropyDetector;

impl EntropyDetector {
    /// Creates a new `EntropyDetector`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Detector for EntropyDetector {
    fn name(&self) -> &str {
        "entropy_heuristic"
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn redact(&self, text: &str) -> Result<(String, usize), RedactError> {
        let spans = tokenize(text);
        if spans.is_empty() {
            return Ok((text.to_string(), 0));
        }

        let mut out = String::with_capacity(text.len());
        let mut last_end = 0;
        let mut count = 0;

        for (start, end) in spans {
            if end - start < MIN_TOKEN_LEN {
                continue;
            }
            if shannon_entropy(&text[start..end]) < MIN_ENTROPY_BITS_PER_CHAR {
                continue;
            }
            out.push_str(&text[last_end..start]);
            out.push_str(MARKER);
            last_end = end;
            count += 1;
        }
        out.push_str(&text[last_end..]);

        if count == 0 {
            Ok((text.to_string(), 0))
        } else {
            Ok((out, count))
        }
    }
}

/// Checks whether a character belongs to candidate entropy tokens.
#[must_use]
pub fn is_entropy_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "+=_.~!@#$%^&*".contains(c)
}

fn tokenize(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = None;

    for (idx, c) in text.char_indices() {
        if is_entropy_token_char(c) {
            if start.is_none() {
                start = Some(idx);
            }
        } else if let Some(s) = start.take() {
            spans.push((s, idx));
        }
    }
    if let Some(s) = start {
        spans.push((s, text.len()));
    }
    spans
}

/// Computes empirical Shannon entropy in bits per character.
#[must_use]
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let total = s.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Options configuring a scan invocation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Strict mode blocks output when high-confidence secrets match.
    pub strict: bool,
    /// Correlation ID tied to audit events.
    pub correlation_id: Option<String>,
}

/// Finding metadata produced by a detector during scanning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Detector that reported the match.
    pub detector: String,
    /// Confidence tier.
    pub confidence: Confidence,
    /// Number of matches.
    pub count: usize,
}

/// Safe metadata-only audit event emitted on detection or block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Detector that triggered the event.
    pub detector: String,
    /// Originating channel label (e.g. `stdout`).
    pub channel: String,
    /// Match confidence.
    pub confidence: Confidence,
    /// Number of redacted occurrences.
    pub redacted_count: usize,
    /// Whether output delivery was blocked.
    pub blocked: bool,
    /// Request correlation ID.
    pub correlation_id: Option<String>,
}

/// Outcome of a scan invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    /// Safe output text (original text, redacted text, or blocked marker).
    pub text: String,
    /// Findings reported during scanning.
    pub findings: Vec<Finding>,
    /// Whether output delivery was blocked.
    pub blocked: bool,
}

/// Error returned on detector failure during scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanError {
    /// Safe result that must be surfaced to avoid leaking partial secrets.
    pub safe_result: ScanResult,
    /// Failure message.
    pub message: String,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ScanError {}

/// Callback invoked for each emitted audit event.
pub type AuditCallback = Box<dyn FnMut(&AuditEvent) + Send + Sync>;

/// Scanner running a sequence of detectors over text with fail-closed semantics.
pub struct Scanner {
    detectors: Vec<Box<dyn Detector>>,
    channel: String,
    audit: Option<AuditCallback>,
}

impl Scanner {
    /// Creates a new `Scanner` with the given detector sequence.
    #[must_use]
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self {
            detectors,
            channel: String::new(),
            audit: None,
        }
    }

    /// Sets the channel label (e.g. `stdout`) for emitted audit events.
    #[must_use]
    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = channel.into();
        self
    }

    /// Sets the audit callback for emitted audit events.
    pub fn set_audit<F>(&mut self, audit: F)
    where
        F: FnMut(&AuditEvent) + Send + Sync + 'static,
    {
        self.audit = Some(Box::new(audit));
    }

    /// Scans text through all configured detectors in sequence.
    ///
    /// # Errors
    ///
    /// Returns `ScanError` if any detector fails. The error carries a safe
    /// `safe_result` with blocked text to guarantee fail-closed security.
    pub fn scan(&mut self, text: &str, opts: &ScanOptions) -> Result<ScanResult, ScanError> {
        if self.detectors.is_empty() {
            return Ok(ScanResult {
                text: text.to_string(),
                findings: Vec::new(),
                blocked: false,
            });
        }

        let mut current = text.to_string();
        let mut findings = Vec::new();
        let mut high_confidence_hit = false;

        for d in &self.detectors {
            match d.redact(&current) {
                Ok((redacted, count)) => {
                    if count > 0 {
                        findings.push(Finding {
                            detector: d.name().to_string(),
                            confidence: d.confidence(),
                            count,
                        });
                        if d.confidence() == Confidence::High {
                            high_confidence_hit = true;
                        }
                    }
                    current = redacted;
                }
                Err(err) => {
                    let event = AuditEvent {
                        detector: d.name().to_string(),
                        channel: self.channel.clone(),
                        confidence: d.confidence(),
                        redacted_count: 0,
                        blocked: true,
                        correlation_id: opts.correlation_id.clone(),
                    };
                    if let Some(ref mut audit_fn) = self.audit {
                        audit_fn(&event);
                    }
                    return Err(ScanError {
                        safe_result: ScanResult {
                            text: BLOCKED_TEXT.to_string(),
                            findings: Vec::new(),
                            blocked: true,
                        },
                        message: format!("redact: detector {:?} failed: {}", d.name(), err),
                    });
                }
            }
        }

        let blocked = opts.strict && high_confidence_hit;
        for f in &findings {
            let event = AuditEvent {
                detector: f.detector.clone(),
                channel: self.channel.clone(),
                confidence: f.confidence,
                redacted_count: f.count,
                blocked,
                correlation_id: opts.correlation_id.clone(),
            };
            if let Some(ref mut audit_fn) = self.audit {
                audit_fn(&event);
            }
        }

        if blocked {
            Ok(ScanResult {
                text: BLOCKED_TEXT.to_string(),
                findings,
                blocked: true,
            })
        } else {
            Ok(ScanResult {
                text: current,
                findings,
                blocked: false,
            })
        }
    }
}

/// Evaluates if an environment variable string represents a truthy opt-in value.
#[must_use]
pub fn is_truthy(v: &str) -> bool {
    matches!(
        v,
        "1" | "t" | "T" | "true" | "TRUE" | "True" | "yes" | "YES" | "Yes" | "on" | "ON" | "On"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_value_detector_masks_debug() {
        let d = ExactValueDetector::new(["mysecretpass"]);
        let debug_str = format!("{d:?}");
        assert!(!debug_str.contains("mysecretpass"));
        assert!(debug_str.contains("pattern_count: 1"));
    }

    #[test]
    fn exact_value_detector_replaces_and_counts() {
        let d = ExactValueDetector::new(["super-secret"]);
        let (out, count) = d.redact("pass is super-secret!").expect("redact");
        assert_eq!(count, 1);
        assert_eq!(out, "pass is [REDACTED]!");
    }

    #[test]
    fn exact_value_ignores_short_values() {
        let d = ExactValueDetector::new(["abc", "a", ""]);
        let (out, count) = d.redact("abc is short").expect("redact");
        assert_eq!(count, 0);
        assert_eq!(out, "abc is short");
    }

    #[test]
    fn exact_value_detector_prefers_longest_overlap_independent_of_order() {
        let short = "short";
        let long = "short-with-sensitive-suffix";
        let input = format!("overlap={long} standalone={short}");
        let want = format!("overlap={MARKER} standalone={MARKER}");

        for values in [[short, long], [long, short]] {
            let d = ExactValueDetector::new(values);
            let (out, count) = d.redact(&input).expect("redact");
            assert_eq!(count, 2);
            assert_eq!(out, want);
        }
    }

    #[test]
    fn exact_value_detector_deduplicates_replacement_counts() {
        let d = ExactValueDetector::new(["short", "short", "short-with-sensitive-suffix"]);
        let (out, count) = d
            .redact("short-with-sensitive-suffix short")
            .expect("redact");
        assert_eq!(count, 2);
        assert_eq!(out, format!("{MARKER} {MARKER}"));
    }

    #[test]
    fn exact_value_detector_overlap_semantics() {
        let cases = [
            (
                "equal_partial_short_first",
                ["abcd", "bcde"],
                "abcde",
                MARKER,
                1,
            ),
            (
                "equal_partial_long_first",
                ["bcde", "abcd"],
                "abcde",
                MARKER,
                1,
            ),
            (
                "unequal_partial",
                ["abcdef", "defgh"],
                "abcdefgh",
                MARKER,
                1,
            ),
            (
                "containment",
                ["secret-value", "cret-val"],
                "prefix secret-value suffix",
                "prefix [REDACTED] suffix",
                1,
            ),
            (
                "adjacent_nonoverlap",
                ["abcd", "efgh"],
                "abcdefgh",
                "[REDACTED][REDACTED]",
                2,
            ),
            (
                "repeated_occurrences",
                ["abcd", "efgh"],
                "abcd--abcd",
                "[REDACTED]--[REDACTED]",
                2,
            ),
            (
                "duplicates",
                ["abcd", "abcd"],
                "abcd abcd",
                "[REDACTED] [REDACTED]",
                2,
            ),
            (
                "utf8_surrounding_text",
                ["sëcret", "ëcret"],
                "🔐sëcret🚀",
                "🔐[REDACTED]🚀",
                1,
            ),
            (
                "self_overlap",
                ["abab", "zzzz"],
                "ababab",
                "[REDACTED]ab",
                1,
            ),
        ];

        for (name, values, input, expected, expected_count) in cases {
            let (out, count) = ExactValueDetector::new(values)
                .redact(input)
                .expect("redact");
            assert_eq!(out, expected, "case {name}");
            assert_eq!(count, expected_count, "case {name}");
        }
    }

    #[test]
    fn exact_value_detector_value_overflow_fails_closed() {
        let values: Vec<String> = (0..=MAX_EXACT_VALUE_COUNT)
            .map(|i| format!("secret-{i:04}"))
            .collect();
        let (out, count) = ExactValueDetector::new(values)
            .redact("ordinary output")
            .expect("redact");
        assert_eq!(out, MARKER);
        assert_eq!(count, 1);
    }

    #[test]
    fn exact_value_detector_span_overflow_fails_closed() {
        let input = "abcd ".repeat(MAX_EXACT_MATCH_SPANS + 1);
        let (out, count) = ExactValueDetector::new(["abcd"])
            .redact(&input)
            .expect("redact");
        assert_eq!(out, MARKER);
        assert_eq!(count, 1);
        assert!(!out.contains("abcd"));
    }

    #[test]
    fn exact_value_scan_work_boundary_is_deterministic() {
        let values = vec!["z".to_string()];
        let (out, count) = redact_exact_values("aaaa", &values, 4).expect("near-bound scan");
        assert_eq!(out, "aaaa");
        assert_eq!(count, 0);
        assert!(redact_exact_values("aaaa", &values, 3).is_none());
    }

    #[cfg_attr(
        miri,
        ignore = "64 MiB CPU-bound stress scan exceeds the Miri execution budget"
    )]
    #[test]
    fn exact_value_scan_work_huge_text_many_values_fails_closed() {
        let input = "x".repeat(1 << 20);
        let values: Vec<String> = (0..MAX_EXACT_VALUE_COUNT)
            .map(|i| format!("not-present-{i:04}"))
            .collect();
        let (out, count) = ExactValueDetector::new(values)
            .redact(&input)
            .expect("redact");
        assert_eq!(out, MARKER);
        assert_eq!(count, 1);
    }

    #[test]
    fn exact_value_scan_work_arithmetic_is_safe() {
        let values = vec!["z".to_string()];
        let (out, count) = redact_exact_values("aaaa", &values, usize::MAX).expect("max budget");
        assert_eq!(out, "aaaa");
        assert_eq!(count, 0);
        let long_value = vec!["zzzzz".to_string()];
        let (out, count) =
            redact_exact_values("aaaa", &long_value, usize::MAX).expect("long value");
        assert_eq!(out, "aaaa");
        assert_eq!(count, 0);
    }

    #[test]
    fn entropy_bounds_and_properties() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaaaaa"), 0.0);
        let e = shannon_entropy("0123456789abcdef");
        assert!((e - 4.0).abs() < 1e-9);
    }

    #[test]
    fn scanner_no_detectors_is_passthrough() {
        let mut s = Scanner::new(vec![]);
        let res = s
            .scan("hello world", &ScanOptions::default())
            .expect("scan");
        assert_eq!(res.text, "hello world");
        assert!(!res.blocked);
        assert!(res.findings.is_empty());
    }

    #[test]
    fn scanner_strict_mode_blocks_high_confidence() {
        let mut s = Scanner::new(vec![Box::new(ExactValueDetector::new(["secretvalue"]))]);
        let res = s
            .scan(
                "output secretvalue",
                &ScanOptions {
                    strict: true,
                    correlation_id: Some("corr-test".into()),
                },
            )
            .expect("scan");
        assert!(res.blocked);
        assert_eq!(res.text, BLOCKED_TEXT);
        assert_eq!(res.findings.len(), 1);
    }

    #[test]
    fn scanner_strict_mode_does_not_block_low_confidence() {
        let mut s = Scanner::new(vec![Box::new(EntropyDetector::new())]);
        let res = s
            .scan(
                "token: kQ7#zM2$pL9@rT4!vX8&wY6^bN3*cJ1~ end",
                &ScanOptions {
                    strict: true,
                    correlation_id: None,
                },
            )
            .expect("scan");
        assert!(!res.blocked);
        assert!(res.text.contains(MARKER));
    }

    struct FailingDetector;
    impl Detector for FailingDetector {
        fn name(&self) -> &str {
            "failing"
        }
        fn confidence(&self) -> Confidence {
            Confidence::High
        }
        fn redact(&self, _text: &str) -> Result<(String, usize), RedactError> {
            Err(RedactError::new("boom"))
        }
    }

    #[test]
    fn scanner_fails_closed_on_detector_error() {
        let mut s = Scanner::new(vec![Box::new(FailingDetector)]);
        let err = s
            .scan("unredacted secret", &ScanOptions::default())
            .expect_err("should fail");
        assert!(err.safe_result.blocked);
        assert_eq!(err.safe_result.text, BLOCKED_TEXT);
    }

    #[test]
    fn truthy_opt_in_table() {
        for v in [
            "1", "t", "T", "true", "TRUE", "True", "yes", "YES", "Yes", "on", "ON", "On",
        ] {
            assert!(is_truthy(v), "should be truthy: {v}");
        }
        for v in ["", "0", "false", "no", "off", "random", "TRUE "] {
            assert!(!is_truthy(v), "should not be truthy: {v}");
        }
    }
}
