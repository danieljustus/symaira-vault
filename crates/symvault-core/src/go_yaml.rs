//! Renders libyaml-level YAML failures the way `gopkg.in/yaml.v3` does.
//!
//! The Go oracle (`internal/config`, `yaml.Unmarshal`) and `serde_yaml_ng`
//! share one lineage: both scan and parse with a port of libyaml, so the
//! *problem* strings and the *marks* they report agree. They differ only in how
//! a failure is worded:
//!
//! - Go (`decode.go`, `parser.fail`) prints `yaml: line N: <problem>`, where
//!   `N` is derived from the context mark when it is not on the first line,
//!   otherwise from the problem mark, and scanner failures are shifted by one
//!   line. Marks on the first line print no `line N:` part at all, and reader
//!   failures (invalid UTF-8, control characters) never carry a line.
//! - `serde_yaml_ng` prints `<problem> at line L column C[, <context> [at …]]`.
//!
//! [`syntax_error_text`] converts the second form to the first for exactly the
//! libyaml reader/scanner/parser failures. Everything else (serde type errors,
//! recursion limits, unknown anchors) is deliberately left to the caller: the
//! Go wording for those comes from a different layer of yaml.v3 and is not
//! reproduced here.
//!
//! The one spelling difference between the two ports is yaml.v3's typo
//! `hexdecimal` (libyaml: `hexadecimal`). It is mapped explicitly; every other
//! problem string is identical, which the Go-recorded corpus
//! (`testdata/port/cli/config-yaml-syntax.json`) pins.

use serde::de::{Deserialize, IgnoredAny};

/// Which libyaml stage reported the failure. Go shifts the reported line only
/// for scanner failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Reader,
    Scanner,
    Parser,
}

/// Returns yaml.v3's wording of `error` when it is a libyaml reader, scanner
/// or parser failure, and `None` for every other kind of `serde_yaml_ng` error.
#[must_use]
pub fn syntax_error_text(error: &serde_yaml_ng::Error) -> Option<String> {
    render(&format!("{error:?}"))
}

/// Reads the first YAML document of `bytes` the way Go's
/// `yaml.Unmarshal(data, &yaml.Node{})` does and returns yaml.v3's wording of
/// its syntax failure, if any.
///
/// Only the first document is read: Go stops after it, so a syntax error in a
/// later document of the stream is not an error of this call.
#[must_use]
pub fn first_document_syntax_error(bytes: &[u8]) -> Option<String> {
    let mut documents = serde_yaml_ng::Deserializer::from_slice(bytes);
    let first = documents.next()?;
    IgnoredAny::deserialize(first)
        .err()
        .as_ref()
        .and_then(syntax_error_text)
}

fn render(debug: &str) -> Option<String> {
    let rest = debug.strip_prefix("Error { kind: ")?;
    let (stage, rest) = if let Some(rest) = rest.strip_prefix("READER, ") {
        (Stage::Reader, rest)
    } else if let Some(rest) = rest.strip_prefix("SCANNER, ") {
        (Stage::Scanner, rest)
    } else {
        (Stage::Parser, rest.strip_prefix("PARSER, ")?)
    };
    let rest = rest.strip_prefix("problem: ")?;
    let (problem, rest) = quoted(rest)?;
    let problem_line = mark_line(rest, "problem_mark: Mark { line: ");
    // The debug form prints marks one-based and omits an all-zero mark; a
    // scanner failure without a context string reports the scanner mark as its
    // context mark (all three such calls in libyaml pass `parser->mark`).
    let context_line = match rest.find("context: ") {
        Some(position) => mark_line(&rest[position..], "context_mark: Mark { line: "),
        None if stage == Stage::Scanner => problem_line,
        None => 0,
    };
    let line = if context_line != 0 {
        context_line
    } else {
        problem_line
    };
    let line = if line != 0 && stage == Stage::Scanner {
        line + 1
    } else {
        line
    };
    let problem = go_problem(&problem);
    Some(if line == 0 {
        format!("yaml: {problem}")
    } else {
        format!("yaml: line {line}: {problem}")
    })
}

/// Returns the zero-based line of the mark introduced by `marker`, or 0 when
/// the debug form carries no such mark.
fn mark_line(text: &str, marker: &str) -> u64 {
    let Some(position) = text.find(marker) else {
        return 0;
    };
    let digits: String = text[position + marker.len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits
        .parse::<u64>()
        .map_or(0, |one_based| one_based.saturating_sub(1))
}

/// Reads one `Debug`-quoted string from the start of `text`.
fn quoted(text: &str) -> Option<(String, &str)> {
    let mut chars = text.strip_prefix('"')?.char_indices();
    let mut value = String::new();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '"' => return Some((value, &text[index + 2..])),
            '\\' => match chars.next()?.1 {
                'n' => value.push('\n'),
                't' => value.push('\t'),
                'r' => value.push('\r'),
                other => value.push(other),
            },
            other => value.push(other),
        }
    }
    None
}

fn go_problem(problem: &str) -> String {
    match problem {
        "did not find expected hexadecimal number" => {
            "did not find expected hexdecimal number".to_owned()
        }
        other => other.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(source: &str) -> Option<String> {
        first_document_syntax_error(source.as_bytes())
    }

    #[test]
    fn scanner_failures_shift_the_line_and_hide_the_first_line() {
        assert_eq!(
            text("a: b: c\n").as_deref(),
            Some("yaml: mapping values are not allowed in this context")
        );
        assert_eq!(
            text("vaultDir: /x\nagents:\n  a: b: c\n").as_deref(),
            Some("yaml: line 3: mapping values are not allowed in this context")
        );
    }

    #[test]
    fn parser_failures_use_the_unshifted_line() {
        assert_eq!(
            text("vaultDir: [\n").as_deref(),
            Some("yaml: line 1: did not find expected node content")
        );
        assert_eq!(
            text("a:\n  b: 1\n c: 2\n").as_deref(),
            Some("yaml: line 2: did not find expected key")
        );
    }

    #[test]
    fn the_context_mark_wins_when_it_is_past_the_first_line() {
        // problem on line 3, context ("simple key") on line 2 → Go reports 2.
        assert_eq!(
            text("a: 1\nb\n").as_deref(),
            Some("yaml: line 2: could not find expected ':'")
        );
    }

    #[test]
    fn reader_failures_carry_no_line() {
        assert_eq!(
            first_document_syntax_error(b"a: \x01\n").as_deref(),
            Some("yaml: control characters are not allowed")
        );
        assert_eq!(
            first_document_syntax_error(b"a: \xff\n").as_deref(),
            Some("yaml: invalid leading UTF-8 octet")
        );
    }

    #[test]
    fn yaml_v3_spelling_of_hexadecimal_is_reproduced() {
        assert_eq!(
            text("vaultDir: \"a\\xZZ\"\n").as_deref(),
            Some("yaml: did not find expected hexdecimal number")
        );
    }

    #[test]
    fn valid_documents_and_non_libyaml_errors_are_not_syntax_errors() {
        assert_eq!(text("a: 1\n"), None);
        assert_eq!(text(""), None);
        // A failure in a later document is not reached, as in Go.
        assert_eq!(text("a: 1\n---\n[\n"), None);
        let error = serde_yaml_ng::from_str::<std::collections::BTreeMap<String, u8>>("a: x\n")
            .expect_err("type error");
        assert_eq!(syntax_error_text(&error), None);
    }
}
