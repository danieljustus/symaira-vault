use std::io::{self, Write};

// Captured byte-for-byte from target/port/symvault-go on 2026-09-23
// (oracle binary SHA-256 cbdbe86a80276032208a3ea6fa2f43ea17918646fc3989aad1183f352045c5a3).
const ROOT_HELP: &str = include_str!("help-root.txt");
const ROOT_HELP_FLAG: &str = "  -h, --help              help for symvault\n";

/// Write root help with the Go command's layout; nested topics use their
/// current clap command definition when no frozen Go page is available.
pub fn write<W: Write>(mut root: clap::Command, path: &[String], output: &mut W) -> io::Result<()> {
    if path.is_empty() {
        return output.write_all(ROOT_HELP.as_bytes());
    }

    root.build();
    let mut selected = &mut root;
    for topic in path {
        let Some(command) = selected.find_subcommand_mut(topic) else {
            return write_unknown_topic(path, output);
        };
        selected = command;
    }

    selected.write_long_help(output)
}

fn write_unknown_topic<W: Write>(path: &[String], output: &mut W) -> io::Result<()> {
    let Some((_, root_usage)) = ROOT_HELP.split_once("Usage:\n") else {
        return Err(io::Error::other(
            "frozen root help is missing its Usage section",
        ));
    };
    let root_usage = root_usage.replace(ROOT_HELP_FLAG, "");
    writeln!(output, "Unknown help topic [`{}`]", path.join(" "))?;
    writeln!(output, "Usage:")?;
    output.write_all(root_usage.as_bytes())
}
