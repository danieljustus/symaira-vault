use std::io::{self, Write};

// Captured byte-for-byte from target/port/symvault-go on 2026-09-23
// (oracle binary SHA-256 cbdbe86a80276032208a3ea6fa2f43ea17918646fc3989aad1183f352045c5a3).
const ROOT_HELP: &str = include_str!("help-root.txt");
const GET_HELP: &str = include_str!("help-get.txt");
const LIST_HELP: &str = include_str!("help-list.txt");
const ROOT_HELP_FLAG: &str = "  -h, --help              help for symvault\n";

/// Find direct `get --help` / `list --help` requests before clap renders its
/// help. The Go CLI's nested pages are frozen byte-for-byte from the oracle.
pub fn flag_help_topic(args: &[std::ffi::OsString]) -> Option<&'static str> {
    let mut index = 1;
    while index < args.len() {
        let word = args[index].to_str()?;
        match word {
            "--vault" | "--profile" | "--output" | "--color" | "--theme" => {
                index += 2;
                continue;
            }
            "get" | "show" | "cat" => {
                return args[index + 1..]
                    .iter()
                    .any(|arg| arg == "--help" || arg == "-h")
                    .then_some("get");
            }
            "list" | "ls" => {
                return args[index + 1..]
                    .iter()
                    .any(|arg| arg == "--help" || arg == "-h")
                    .then_some("list");
            }
            _ if word.starts_with('-') => index += 1,
            _ => return None,
        }
    }
    None
}

pub fn write_nested<W: Write>(topic: &str, output: &mut W) -> io::Result<()> {
    let help = match topic {
        "get" => GET_HELP,
        "list" => LIST_HELP,
        _ => return Err(io::Error::other("unknown frozen help topic")),
    };
    output.write_all(help.as_bytes())
}

/// Write root help with the Go command's layout; nested topics use their
/// current clap command definition when no frozen Go page is available.
pub fn write<W: Write>(mut root: clap::Command, path: &[String], output: &mut W) -> io::Result<()> {
    if path.is_empty() {
        return output.write_all(ROOT_HELP.as_bytes());
    }

    if path.len() == 1 {
        match path[0].as_str() {
            "get" | "show" | "cat" => return write_nested("get", output),
            "list" | "ls" => return write_nested("list", output),
            _ => {}
        }
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
