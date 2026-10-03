use std::io::{self, Write};

// Captured byte-for-byte from target/port/symvault-go on 2026-09-23
// (oracle binary SHA-256 cbdbe86a80276032208a3ea6fa2f43ea17918646fc3989aad1183f352045c5a3).
const ROOT_HELP: &str = include_str!("help-root.txt");
const GET_HELP: &str = include_str!("help-get.txt");
const LIST_HELP: &str = include_str!("help-list.txt");
// Captured from the pinned fca3f894 Go binary (SHA-256 7023771750c3915d0e7144598a12aac3dfbd242847a587eedd335466aecd1e31).
const DYNAMIC_HELP: &str = include_str!("help-dynamic.txt");
const DYNAMIC_GENERATE_HELP: &str = include_str!("help-dynamic-generate.txt");
const SETUP_HELP: &str = include_str!("help-setup.txt");
// Actual Go help captured at bd020d11dc9fa4611075117b4ab3a587fd010ddd
// in a disposable HOME/XDG root; live freshness is checked by cli-help-differential.
const UPDATE_HELP: &str = include_str!("help-update.txt");
const UPDATE_CHECK_HELP: &str = include_str!("help-update-check.txt");
const UPDATE_APPLY_HELP: &str = include_str!("help-update-apply.txt");
const UPDATE_INFO_HELP: &str = include_str!("help-update-info.txt");
const ROOT_HELP_FLAG: &str = "  -h, --help              help for symvault\n";

/// Find direct nested `--help` requests before clap renders its
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
            "update" => return update_flag_help_topic(&args[index + 1..]),
            "get" | "show" | "cat" => {
                return args[index + 1..]
                    .iter()
                    .take_while(|arg| *arg != "--")
                    .any(|arg| arg == "--help" || arg == "-h")
                    .then_some("get");
            }
            "list" | "ls" => {
                return args[index + 1..]
                    .iter()
                    .take_while(|arg| *arg != "--")
                    .any(|arg| arg == "--help" || arg == "-h")
                    .then_some("list");
            }
            "dynamic" => {
                return args[index + 1..]
                    .iter()
                    .take_while(|arg| *arg != "--")
                    .any(|arg| arg == "--help" || arg == "-h")
                    .then_some(
                        if args.get(index + 1).is_some_and(|arg| arg == "generate") {
                            "dynamic generate"
                        } else {
                            "dynamic"
                        },
                    );
            }
            "setup" => {
                return args[index + 1..]
                    .iter()
                    .take_while(|arg| *arg != "--")
                    .any(|arg| arg == "--help" || arg == "-h")
                    .then_some("setup");
            }
            _ if word.starts_with('-') => index += 1,
            _ => return None,
        }
    }
    None
}

// The update runner captures hyphenated values. Recognize help before it can
// check releases or install anything, while respecting flag values and `--`.
// Unknown flags stay in the ordinary error path instead of being hidden by help.
fn update_flag_help_topic(args: &[std::ffi::OsString]) -> Option<&'static str> {
    let mut topic = "update";
    let mut selected = false;
    let mut help = false;
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        let argument = argument.to_str()?;
        if argument == "--" {
            break;
        }
        let (name, value) = argument
            .split_once('=')
            .map_or((argument, None), |(name, value)| (name, Some(value)));
        match name {
            "--vault" | "--profile" | "--output" | "--color" | "--theme" => {
                if value.is_none() {
                    args.get(index + 1)?;
                    index += 1;
                }
            }
            "--help" | "-h" | "--quiet" | "--no-pipe-warning" | "--json" | "--force"
            | "--dry-run" => {
                if (name == "--force" && !matches!(topic, "update check" | "update apply"))
                    || (name == "--dry-run" && topic != "update apply")
                {
                    return None;
                }
                let enabled = match value {
                    None | Some("1" | "t" | "T" | "true" | "TRUE" | "True") => true,
                    Some("0" | "f" | "F" | "false" | "FALSE" | "False") => false,
                    _ => return None,
                };
                if matches!(name, "--help" | "-h") {
                    help = enabled;
                }
            }
            _ if argument.starts_with('-') => return None,
            _ if !selected => {
                topic = match argument {
                    "check" => "update check",
                    "apply" => "update apply",
                    "info" => "update info",
                    _ => "update",
                };
                selected = true;
            }
            _ => {}
        }
        index += 1;
    }
    help.then_some(topic)
}

pub fn write_nested<W: Write>(topic: &str, output: &mut W) -> io::Result<()> {
    let help = match topic {
        "get" => GET_HELP,
        "list" => LIST_HELP,
        "dynamic" => DYNAMIC_HELP,
        "dynamic generate" => DYNAMIC_GENERATE_HELP,
        "setup" => SETUP_HELP,
        "update" => UPDATE_HELP,
        "update check" => UPDATE_CHECK_HELP,
        "update apply" => UPDATE_APPLY_HELP,
        "update info" => UPDATE_INFO_HELP,
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
    let topic = path.iter().map(String::as_str).collect::<Vec<_>>();
    for length in (1..=topic.len()).rev() {
        if let Some(help) = frozen_help(&topic[..length]) {
            return output.write_all(help.as_bytes());
        }
    }

    root.build();
    let mut selected = &mut root;
    let mut matched = Vec::new();
    for part in path {
        if selected.find_subcommand(part).is_none() {
            if matched.is_empty() {
                return write_unknown_topic(path, &mut io::stderr().lock());
            }
            return selected.write_long_help(output);
        }
        matched.push(part.as_str());
        selected = selected.find_subcommand_mut(part).expect("checked child");
    }

    selected.write_long_help(output)
}

fn frozen_help(path: &[&str]) -> Option<&'static str> {
    match path {
        ["get" | "show" | "cat"] => Some(GET_HELP),
        ["list" | "ls"] => Some(LIST_HELP),
        ["dynamic"] => Some(DYNAMIC_HELP),
        ["dynamic", "generate"] => Some(DYNAMIC_GENERATE_HELP),
        ["setup"] => Some(SETUP_HELP),
        ["update"] => Some(UPDATE_HELP),
        ["update", "check"] => Some(UPDATE_CHECK_HELP),
        ["update", "apply"] => Some(UPDATE_APPLY_HELP),
        ["update", "info"] => Some(UPDATE_INFO_HELP),
        _ => None,
    }
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
