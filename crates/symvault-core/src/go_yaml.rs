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
//!
//! # Known gap: scanner look-ahead
//!
//! The two scanners are not step-for-step identical. libyaml fetches a token
//! only when the parser asks for it (plus whatever a pending simple key needs).
//! yaml.v3 (`yaml_parser_fetch_more_tokens`) keeps a look-ahead of two tokens
//! behind the one the parser is looking at, so that comments can be attached to
//! the right node. When the parser rejects token *T* and a scanner failure sits
//! in the next two tokens, Go reports the scanner failure (for example
//! `mapping values are not allowed in this context` for `a: "x" b: 1`) while
//! libyaml reports the parser failure at *T* (`did not find expected key`).
//! Reproducing that needs the scanner state after *T*, which `serde_yaml_ng`
//! does not expose, so the class is recorded as open divergences in the
//! Go-recorded corpus instead of being approximated here.
//!
//! # Dependency pin
//!
//! [`syntax_error_text`] reads the `Debug` form of `serde_yaml_ng::Error`
//! because the crate exposes no accessor for the libyaml stage, problem or
//! context. The dependency is therefore pinned to an exact version
//! (`=0.10.0`), and `debug_shapes_are_the_ones_the_renderer_parses` fails
//! loudly the moment an upgrade changes that form.

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
    let error = IgnoredAny::deserialize(first).err()?;
    syntax_error_text(&error).or_else(|| unknown_anchor_text(&error, bytes))
}

/// Whether Go's `Decoder.Decode(&yaml.Node{})` accepts `document`, a document
/// that follows the first one in the stream.
///
/// `hasTrailingDocuments` in Go's loader counts a later document only when it
/// decodes without an error, so a libyaml reader, scanner or parser failure in
/// it means "no trailing document". Any other failure is not a syntax
/// failure; it is treated as a document, which is what the loader did before.
/// (yaml.v3 shares anchors across the documents of a stream while
/// `serde_yaml_ng` scopes them to one document, so an alias to an anchor of an
/// earlier document cannot be told apart from an undefined one here; that
/// input stays recorded as an open divergence.)
#[must_use]
pub fn decodes_as_go_node(document: serde_yaml_ng::Deserializer<'_>) -> bool {
    match IgnoredAny::deserialize(document) {
        Ok(_) => true,
        Err(error) => syntax_error_text(&error).is_none(),
    }
}

/// yaml.v3 builds its node tree event by event and rejects an alias to an
/// anchor that was not defined earlier with `yaml: unknown anchor 'x'
/// referenced` (no line). `serde_yaml_ng` rejects the same alias at the same
/// point but words it `unknown anchor at line L column C`, without the name,
/// so the name is read back from the alias token at the reported position.
fn unknown_anchor_text(error: &serde_yaml_ng::Error, bytes: &[u8]) -> Option<String> {
    if !format!("{error:?}").starts_with("Error(\"unknown anchor\", ") {
        return None;
    }
    // The mark's index is a byte offset into the stream (the port adds the
    // width of every character it skips), so the lookup is byte based.
    let rest = bytes.get(error.location()?.index()..)?.strip_prefix(b"*")?;
    let name: String = rest
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        .map(|&byte| char::from(byte))
        .collect();
    (!name.is_empty()).then(|| format!("yaml: unknown anchor '{name}' referenced"))
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

    #[test]
    fn unknown_anchors_are_worded_like_yaml_v3() {
        assert_eq!(
            text("a: *nope\n").as_deref(),
            Some("yaml: unknown anchor 'nope' referenced")
        );
        // The mark is a byte offset, so non-ASCII text before the alias must
        // not shift the lookup.
        assert_eq!(
            text("ключ: значение\nb: *nope-1_x\n").as_deref(),
            Some("yaml: unknown anchor 'nope-1_x' referenced")
        );
        assert_eq!(
            text("a: [1, *later]\nb: &later 2\n").as_deref(),
            Some("yaml: unknown anchor 'later' referenced")
        );
        // The first failure in event order wins, as in Go's node builder.
        assert_eq!(
            text("a: *nope\nb: [\n").as_deref(),
            Some("yaml: unknown anchor 'nope' referenced")
        );
        assert_eq!(text("a: &x 1\nb: *x\n"), None);
    }

    #[test]
    fn later_documents_count_unless_libyaml_rejects_them() {
        fn later(source: &str) -> bool {
            let mut documents = serde_yaml_ng::Deserializer::from_str(source);
            documents.next().expect("first document");
            decodes_as_go_node(documents.next().expect("second document"))
        }
        assert!(later("a: 1\n---\nb: 2\n"));
        assert!(later("a: 1\n---\n"));
        // Go's `Decode(&second)` fails on a syntax error, so the stream has no
        // trailing document.
        assert!(!later("a: 1\n---\n[\n"));
        assert!(!later("a: 1\n...\nb: [\n"));
        assert!(!later("a: 1\n---\nb: c: d\n"));
    }

    #[test]
    fn debug_shapes_are_the_ones_the_renderer_parses() {
        fn debug_of(source: &str) -> String {
            let mut documents = serde_yaml_ng::Deserializer::from_str(source);
            let first = documents.next().expect("first document");
            let error = IgnoredAny::deserialize(first).expect_err("malformed document");
            format!("{error:?}")
        }
        const HINT: &str =
            "serde_yaml_ng's Debug output changed (pinned =0.10.0): update go_yaml::render";

        let scanner = debug_of("a: b: c\n");
        assert!(
            scanner.starts_with(
                "Error { kind: SCANNER, problem: \"mapping values are not allowed in this context\""
            ),
            "{HINT}: {scanner}"
        );
        assert_eq!(
            render(&scanner).as_deref(),
            Some("yaml: mapping values are not allowed in this context"),
            "{HINT}"
        );

        let parser = debug_of("a:\n  b: 1\n c: 2\n");
        assert!(
            parser.starts_with("Error { kind: PARSER, problem: \"did not find expected key\""),
            "{HINT}: {parser}"
        );
        assert!(
            parser.contains("problem_mark: Mark { line: 3"),
            "{HINT}: {parser}"
        );
        assert_eq!(
            render(&parser).as_deref(),
            Some("yaml: line 2: did not find expected key"),
            "{HINT}"
        );

        let reader = debug_of("a: \u{1}\n");
        assert!(
            reader.starts_with(
                "Error { kind: READER, problem: \"control characters are not allowed\""
            ),
            "{HINT}: {reader}"
        );
        assert_eq!(
            render(&reader).as_deref(),
            Some("yaml: control characters are not allowed"),
            "{HINT}"
        );

        // Not a libyaml stage: left to the caller.
        let anchor = debug_of("a: *nope\n");
        assert_eq!(
            anchor, "Error(\"unknown anchor\", line: 1, column: 4)",
            "{HINT}"
        );
        assert_eq!(render(&anchor), None, "{HINT}");
    }
}
