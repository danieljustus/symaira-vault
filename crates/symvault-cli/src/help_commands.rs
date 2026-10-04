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
    writeln!(output, "Unknown help topic [`{}`]", path.join(" "))?;
    writeln!(output, "Usage:")?;
    for line in usage
        .split_inclusive('\n')
        .filter(|line| !line.contains("-h, --help"))
    {
        output.write_all(line.as_bytes())?;
    }
    Ok(())
}
