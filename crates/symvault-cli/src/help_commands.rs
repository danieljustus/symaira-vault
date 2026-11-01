use crate::cli_artifacts as artifact;
use std::io::{self, Write};

pub fn flag_help_topic(args: &[std::ffi::OsString]) -> Option<&'static str> {
    artifact::flag_help(args)
}

pub fn write_nested<W: Write>(topic: &str, output: &mut W) -> io::Result<()> {
    let path = if topic.is_empty() {
        "symvault".to_owned()
    } else {
        format!("symvault {topic}")
    };
    let help = artifact::DATA
        .help
        .get(&path)
        .ok_or_else(|| io::Error::other("unknown frozen help topic"))?;
    output.write_all(artifact::render(help).as_bytes())
}

pub fn write<W: Write>(_root: clap::Command, path: &[String], output: &mut W) -> io::Result<()> {
    let mut selected = artifact::root();
    let mut matched = false;
    for part in path {
        let Some(next) = artifact::child(selected, part) else {
            if !matched {
                return write_unknown_topic(path, &mut io::stderr().lock());
            }
            break;
        };
        matched = true;
        selected = next;
    }
    let page = artifact::DATA
        .help
        .get(&selected.path)
        .ok_or_else(|| io::Error::other("missing frozen help page"))?;
    output.write_all(artifact::render(page).as_bytes())
}

fn write_unknown_topic<W: Write>(path: &[String], output: &mut W) -> io::Result<()> {
    let root = &artifact::DATA.help["symvault"];
    let (_, usage) = root
        .split_once("Usage:\n")
        .ok_or_else(|| io::Error::other("root help lacks Usage"))?;
    // Go prints the argument slice with `%#q`: every word is backquoted when it
    // can be, otherwise double-quoted like strconv.Quote.
    let words: Vec<String> = path.iter().map(|word| go_alt_quote(word)).collect();
    writeln!(output, "Unknown help topic [{}]", words.join(" "))?;
    writeln!(output, "Usage:")?;
    for line in usage
        .split_inclusive('\n')
        .filter(|line| !line.contains("-h, --help"))
    {
        output.write_all(line.as_bytes())?;
    }
    Ok(())
}

/// `fmt`'s `%#q` for a string: a raw string when `strconv.CanBackquote` allows
/// it, a `strconv.Quote` literal otherwise.
fn go_alt_quote(word: &str) -> String {
    let can_backquote = word
        .chars()
        .all(|ch| (ch == '\t' || !ch.is_control()) && ch != '`' && ch != '\u{feff}');
    if can_backquote {
        format!("`{word}`")
    } else {
        artifact::quote_go_string(word)
    }
}

#[cfg(test)]
mod tests {
    use super::go_alt_quote;

    #[test]
    fn unknown_topic_words_are_quoted_like_go_percent_hash_q() {
        assert_eq!(go_alt_quote("x"), "`x`");
        assert_eq!(go_alt_quote(""), "``");
        // A backquote cannot sit in a raw string, so Go falls back to strconv.Quote.
        assert_eq!(go_alt_quote("a`b"), "\"a`b\"");
        assert_eq!(go_alt_quote("a\nb"), "\"a\\nb\"");
        assert_eq!(go_alt_quote("tab\there"), "`tab\there`");
    }
}
