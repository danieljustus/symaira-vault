#[path = "config_fix.rs"]
mod fix;

use std::{
    env, fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

/// Why `config get` / `config set` failed.
pub enum ConfigFailure {
    /// A message printed once, as before.
    Plain(String),
    /// A Go `ExitConfigError` that carries its cause in its text: the root
    /// handler prints `Error: …` twice and appends the doctor hint.
    GoConfigError(String),
    /// The same, for a cause that is not valid UTF-8 (yaml.v3 cuts a value at
    /// seven BYTES, which can split a character).
    GoConfigBytes(Vec<u8>),
}

impl From<String> for ConfigFailure {
    fn from(message: String) -> Self {
        Self::Plain(message)
    }
}

impl From<&str> for ConfigFailure {
    fn from(message: &str) -> Self {
        Self::Plain(message.to_owned())
    }
}

/// Go's `LoadConfigNode` parses the whole first document with yaml.v3 before
/// `config get` / `config set` look at a key. Its failure reaches the user as
/// `cannot load config: cannot parse config file: <yaml error>` plus the same
/// cause again (`CLIError.Error` appends it).
fn go_syntax_gate(bytes: &[u8]) -> Result<(), ConfigFailure> {
    match symvault_core::go_yaml::first_document_syntax_error(bytes) {
        Some(message) => Err(ConfigFailure::GoConfigError(format!(
            "cannot load config: cannot parse config file: {message}: cannot parse config file: {message}"
        ))),
        None => Ok(()),
    }
}

/// The `syscall.Errno` text Go prints for the failures of opening a file; other
/// causes keep Rust's generic wording until they are probed against the oracle.
pub(crate) fn go_errno_text(error: &io::Error) -> Option<&'static str> {
    match error.kind() {
        io::ErrorKind::NotFound => return Some("no such file or directory"),
        io::ErrorKind::PermissionDenied => return Some("permission denied"),
        io::ErrorKind::IsADirectory => return Some("is a directory"),
        _ => {}
    }
    #[cfg(unix)]
    match error.raw_os_error()? {
        libc::ENOTDIR => Some("not a directory"),
        libc::ELOOP => Some("too many levels of symbolic links"),
        libc::ENAMETOOLONG => Some("file name too long"),
        _ => None,
    }
    #[cfg(not(unix))]
    None
}

/// Go's `*fs.PathError` text, `open <path>: <cause>`. `os.ReadFile` of a
/// directory opens it fine and fails on the read, so `read` names that verb.
pub(crate) fn go_path_error(path: &Path, error: &io::Error, read: bool) -> Option<String> {
    let reason = go_errno_text(error)?;
    let verb = if read && error.kind() == io::ErrorKind::IsADirectory {
        "read"
    } else {
        "open"
    };
    Some(format!("{verb} {}: {reason}", path.display()))
}

/// `load config: <cause>` as Go's `config.Load` callers word it: a missing or
/// unreadable file is the `open <path>: <errno text>` error of `os.ReadFile`,
/// every other failure keeps the loader's own text.
pub(crate) fn go_load_config_error(
    path: &Path,
    error: &symvault_core::config::ConfigError,
) -> String {
    if let symvault_core::config::ConfigError::Read(io_error) = error
        && let Some(path_error) = go_path_error(
            &crate::agent_list_commands::clean_path(path),
            io_error,
            true,
        )
    {
        return format!("load config: {path_error}");
    }
    format!("load config: {error}")
}

/// Go's wording of a failed read of the config file: `os.ReadFile` fails with
/// `open <path>: <cause>` (or `read <path>: is a directory`). `config get|set`
/// wrap it in `cannot read config file: …`, `config list` does not; the root
/// handler repeats the cause and prints the doctor hint (exit 6).
fn read_config_file(path: &Path, wrapped: bool) -> Result<Vec<u8>, ConfigFailure> {
    let clean = crate::agent_list_commands::clean_path(path);
    fs::read(&clean).map_err(|error| {
        let Some(path_error) = go_path_error(&clean, &error, true) else {
            return ConfigFailure::Plain(format!("cannot load config: {error}"));
        };
        let prefix = if wrapped {
            "cannot read config file: "
        } else {
            ""
        };
        let cause = format!("{prefix}{path_error}");
        ConfigFailure::GoConfigError(format!("cannot load config: {cause}: {cause}"))
    })
}

pub fn list(path: &Path, quiet: bool) -> Result<(), ConfigFailure> {
    let bytes = read_config_file(path, false)?;
    if !quiet {
        let _ = io::stdout().write_all(&bytes);
    }
    Ok(())
}

pub fn get(path: &Path, key: &str, output: &str, quiet: bool) -> Result<(), ConfigFailure> {
    let bytes = read_config_file(path, true)?;
    go_syntax_gate(&bytes)?;
    let source = std::str::from_utf8(&bytes)
        .map_err(|error| format!("cannot load config: invalid UTF-8: {error}"))?;
    let value = lookup_scalar(source, key).map_err(|error| {
        if error.starts_with("key ") && error.ends_with(" not found") {
            // Go wraps the lookup failure in a config error that repeats it.
            ConfigFailure::GoConfigError(format!("key {key:?} not found: {error}"))
        } else {
            ConfigFailure::Plain(error)
        }
    })?;
    if quiet {
        return Ok(());
    }
    if output == "json" {
        let key = json_string(key)?;
        let value = json_string(&value)?;
        let encoded = format!("{{{key}:{value}}}\n");
        io::stdout()
            .write_all(encoded.as_bytes())
            .map_err(|error| format!("cannot write config: {error}"))?;
    } else {
        println!("{value}");
    }
    Ok(())
}

pub fn set(path: &Path, key: &str, value: &str, quiet: bool) -> Result<(), ConfigFailure> {
    use yaml_edit::path::YamlPath;

    let bytes = read_config_file(path, true)?;
    go_syntax_gate(&bytes)?;
    let source = std::str::from_utf8(&bytes)
        .map_err(|error| format!("cannot load config: invalid UTF-8: {error}"))?;
    let file = yaml_edit::YamlFile::from_str(source)
        .map_err(|error| format!("cannot load config: {error}"))?;
    let document = file
        .documents()
        .next()
        .ok_or_else(|| "cannot load config: missing YAML document".to_owned())?;
    let target_line = document.try_get_path(key).ok().and_then(|node| {
        node.as_scalar()
            .map(|scalar| scalar.start_position(source).line)
    });
    ensure_mapping_parents(&document, key)?;
    match parse_set_value(value)? {
        SetValue::Scalar(scalar) => document
            .try_set_path(key, scalar)
            .map_err(|error| format!("cannot set {key:?}: {error}"))?,
        SetValue::Node(node) => document
            .try_set_path(key, node)
            .map_err(|error| format!("cannot set {key:?}: {error}"))?,
    }
    let mut rendered = document.to_string();
    if let Some(line) = target_line {
        rendered = strip_target_inline_comment(rendered, line);
    }
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    // Go re-encodes the whole document with a two-space indent.
    let rendered = symvault_core::config_typed::tag_merge_keys(&reindent_two_spaces(&rendered));
    atomic_write(path, rendered.as_bytes())?;
    // Go rejects traversal on its post-write reload, even when Windows
    // resolves the raw rename destination through a parent component.
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(
            "config is invalid after update: config file path escapes expected directory".into(),
        );
    }
    // Go reloads the file into the typed config; yaml.v3's type errors come
    // before any validation of the decoded values.
    if let Some(cause) = symvault_core::config_typed::unmarshal_errors(&rendered) {
        let mut message = b"config is invalid after update: ".to_vec();
        message.extend_from_slice(&cause);
        message.extend_from_slice(b": ");
        message.extend_from_slice(&cause);
        return Err(ConfigFailure::GoConfigBytes(message));
    }
    if let Err(error) = symvault_core::config::Config::load(path) {
        return Err(format!("config is invalid after update: {error}").into());
    }
    if !quiet {
        println!("Set {key} = {value}");
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct IndentLevel {
    column: usize,
    depth: usize,
    /// A sequence written at its parent key's column (`key:\n- item`).
    compact_sequence: bool,
}

/// Re-indents block YAML to yaml.v3's two-space style: every mapping or
/// sequence level is two columns deeper than its parent, a sequence under a
/// mapping key is indented, and the content of `- key: v` lines lines up two
/// columns after the dash. A document already in this style is unchanged.
/// Block scalar content stays two columns inside its owner.
fn reindent_two_spaces(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut stack: Vec<IndentLevel> = Vec::new();
    let mut key_column: Option<usize> = None;
    let mut comments: Vec<(&str, &str)> = Vec::new();
    // (owner column in the input, owner column in the output, first content column)
    let mut block: Option<(usize, usize, Option<usize>)> = None;
    for line in text.split_inclusive('\n') {
        let newline = if line.ends_with('\n') { "\n" } else { "" };
        let body = line.trim_end_matches('\n');
        let column = body.len() - body.trim_start_matches(' ').len();
        let content = &body[column..];
        if let Some((owner_old, owner_new, first)) = &mut block {
            if content.is_empty() {
                out.push_str(line);
                continue;
            }
            if column > *owner_old {
                let first_column = *first.get_or_insert(column);
                out.push_str(&" ".repeat(*owner_new + 2 + column - first_column));
                out.push_str(content);
                out.push_str(newline);
                continue;
            }
            block = None;
        }
        if content.is_empty() {
            out.push_str(line);
            continue;
        }
        if content.starts_with('#') {
            // A head comment sits at the indent of the node that follows it.
            comments.push((content, newline));
            continue;
        }
        let dash = content == "-" || content.starts_with("- ");
        while let Some(top) = stack.last() {
            if top.column > column || (top.column == column && top.compact_sequence && !dash) {
                stack.pop();
            } else {
                break;
            }
        }
        let mut depth = match stack.last() {
            Some(top) if top.column == column => top.depth,
            Some(top) => {
                let depth = top.depth + 1;
                stack.push(IndentLevel {
                    column,
                    depth,
                    compact_sequence: false,
                });
                depth
            }
            None => {
                stack.push(IndentLevel {
                    column,
                    depth: 0,
                    compact_sequence: false,
                });
                0
            }
        };
        if dash && key_column == Some(column) {
            // `key:\n- item`: the compact sequence is one level inside its key.
            depth += 1;
            stack.push(IndentLevel {
                column,
                depth,
                compact_sequence: true,
            });
        }
        for (comment, comment_newline) in comments.drain(..) {
            out.push_str(&" ".repeat(depth * 2));
            out.push_str(comment);
            out.push_str(comment_newline);
        }
        out.push_str(&" ".repeat(depth * 2));
        out.push_str(content);
        out.push_str(newline);

        let mut owner_column = column;
        let mut tail = content;
        if dash {
            tail = content[1..].trim_start_matches(' ');
            if !tail.is_empty() {
                owner_column = column + (content.len() - tail.len());
                stack.push(IndentLevel {
                    column: owner_column,
                    depth: depth + 1,
                    compact_sequence: false,
                });
            }
        }
        key_column = tail.ends_with(':').then_some(owner_column);
        let header = tail.rsplit(' ').next().unwrap_or("");
        let is_block_header = matches!(header.as_bytes().first(), Some(b'|' | b'>'))
            && header[1..]
                .chars()
                .all(|c| matches!(c, '-' | '+' | '0'..='9'));
        if is_block_header {
            let new_owner = if dash && owner_column != column {
                depth * 2 + 2
            } else {
                depth * 2
            };
            block = Some((owner_column, new_owner, None));
        }
    }
    for (comment, comment_newline) in comments {
        out.push_str(comment);
        out.push_str(comment_newline);
    }
    out
}

fn ensure_mapping_parents(document: &yaml_edit::Document, key: &str) -> Result<(), String> {
    use yaml_edit::path::YamlPath;

    let parts = key.split('.').collect::<Vec<_>>();
    for index in 1..parts.len() {
        let prefix = parts[..index].join(".");
        if let Ok(node) = document.try_get_path(&prefix)
            && !node.is_mapping()
        {
            document
                .try_set_path(
                    &prefix,
                    yaml_edit::YamlNode::Mapping(yaml_edit::Mapping::new()),
                )
                .map_err(|error| format!("cannot set {key:?}: {error}"))?;
        }
    }
    Ok(())
}

enum SetValue {
    Scalar(yaml_edit::ScalarValue),
    Node(yaml_edit::YamlNode),
}

fn parse_set_value(value: &str) -> Result<SetValue, String> {
    if value.is_empty() {
        return Ok(SetValue::Scalar(yaml_edit::ScalarValue::double_quoted("")));
    }
    let file = yaml_edit::YamlFile::from_str(value)
        .map_err(|error| format!("cannot parse config value: {error}"))?;
    let document = file
        .documents()
        .next()
        .ok_or_else(|| "cannot parse config value: missing YAML value".to_owned())?;
    if let Some(mapping) = document.as_mapping() {
        return Ok(SetValue::Node(canonical_mapping(&mapping)?));
    }
    if let Some(sequence) = document.as_sequence() {
        return Ok(SetValue::Node(canonical_sequence(&sequence)?));
    }
    if let Some(scalar) = document.as_scalar() {
        return Ok(SetValue::Node(canonical_scalar_node(&scalar)?));
    }
    Err("cannot parse config value: unsupported YAML node".to_owned())
}

fn canonical_node(node: yaml_edit::YamlNode) -> Result<yaml_edit::YamlNode, String> {
    if let Some(scalar) = node.as_scalar() {
        return canonical_scalar_node(scalar);
    }
    if let Some(mapping) = node.as_mapping() {
        return canonical_mapping(mapping);
    }
    if let Some(sequence) = node.as_sequence() {
        return canonical_sequence(sequence);
    }
    if let Some(alias) = node.as_alias() {
        return Ok(yaml_edit::YamlNode::Alias(yaml_edit::Alias::new(
            alias.name(),
        )));
    }
    Err("cannot parse config value: unsupported YAML node".to_owned())
}

fn canonical_scalar_node(scalar: &yaml_edit::Scalar) -> Result<yaml_edit::YamlNode, String> {
    let parsed = yaml_edit::ScalarValue::from_scalar(scalar);
    let mut value = scalar.as_string();
    if matches!(
        parsed.style(),
        yaml_edit::ScalarStyle::Literal | yaml_edit::ScalarStyle::Folded
    ) && !scalar.value().ends_with('\n')
        && value.ends_with('\n')
    {
        value.pop();
    }
    if parsed.scalar_type() == yaml_edit::ScalarType::String {
        if value.trim_matches('\n').is_empty() {
            return scalar_node_from_value(yaml_edit::ScalarValue::double_quoted(""));
        }
        if value.contains('\n') {
            let trailing_newlines = value.len() - value.trim_end_matches('\n').len();
            let header = match trailing_newlines {
                0 => "|-",
                1 => "|",
                _ => "|+",
            };
            let content = value.trim_end_matches('\n');
            let mut source = format!("{header}\n");
            if content.is_empty() {
                source.push_str("  \n");
            } else {
                for line in content.lines() {
                    source.push_str("  ");
                    source.push_str(line);
                    source.push('\n');
                }
            }
            for _ in 1..trailing_newlines {
                source.push('\n');
            }
            return scalar_node_from_source(&source);
        }
        let plain = yaml_edit::ScalarValue::string(&value);
        let value = if plain.to_yaml_string().starts_with('\'') {
            yaml_edit::ScalarValue::double_quoted(value)
        } else {
            plain
        };
        return scalar_node_from_value(value);
    }
    let scalar = match parsed.scalar_type() {
        yaml_edit::ScalarType::Integer => parsed
            .to_i64()
            .map(yaml_edit::ScalarValue::from)
            .unwrap_or_else(|| yaml_edit::ScalarValue::parse(value)),
        yaml_edit::ScalarType::Float => parsed
            .to_f64()
            .map(yaml_edit::ScalarValue::from)
            .unwrap_or_else(|| yaml_edit::ScalarValue::parse(value)),
        yaml_edit::ScalarType::Boolean => parsed
            .to_bool()
            .map(yaml_edit::ScalarValue::from)
            .unwrap_or_else(|| yaml_edit::ScalarValue::parse(value)),
        yaml_edit::ScalarType::Null => yaml_edit::ScalarValue::null(),
        _ => yaml_edit::ScalarValue::parse(value),
    };
    scalar_node_from_value(scalar)
}

fn scalar_node_from_source(source: &str) -> Result<yaml_edit::YamlNode, String> {
    let file = yaml_edit::YamlFile::from_str(source)
        .map_err(|error| format!("cannot parse config value: {error}"))?;
    file.documents()
        .next()
        .and_then(|document| document.as_scalar())
        .map(yaml_edit::YamlNode::Scalar)
        .ok_or_else(|| "cannot parse config value: unsupported YAML scalar".to_owned())
}

fn scalar_node_from_value(value: yaml_edit::ScalarValue) -> Result<yaml_edit::YamlNode, String> {
    yaml_edit::YamlBuilder::scalar(value)
        .build()
        .documents()
        .next()
        .and_then(|document| document.as_scalar())
        .map(yaml_edit::YamlNode::Scalar)
        .ok_or_else(|| "cannot parse config value: unsupported YAML scalar".to_owned())
}

fn canonical_mapping(mapping: &yaml_edit::Mapping) -> Result<yaml_edit::YamlNode, String> {
    let mut builder = yaml_edit::YamlBuilder::mapping();
    for (key, value) in mapping.iter() {
        let key = key
            .as_scalar()
            .map(|scalar| scalar.as_string())
            .ok_or_else(|| "cannot parse config value: mapping key is not scalar".to_owned())?;
        builder = builder.pair(key, canonical_node(value)?);
    }
    let file = builder.build().build();
    file.documents()
        .next()
        .and_then(|document| document.as_mapping())
        .map(yaml_edit::YamlNode::Mapping)
        .ok_or_else(|| "cannot parse config value: unsupported YAML mapping".to_owned())
}

fn canonical_sequence(sequence: &yaml_edit::Sequence) -> Result<yaml_edit::YamlNode, String> {
    let mut builder = yaml_edit::YamlBuilder::sequence();
    for value in sequence.values() {
        builder = builder.item(canonical_node(value)?);
    }
    let file = builder.build().build();
    file.documents()
        .next()
        .and_then(|document| document.as_sequence())
        .map(yaml_edit::YamlNode::Sequence)
        .ok_or_else(|| "cannot parse config value: unsupported YAML sequence".to_owned())
}

fn strip_target_inline_comment(rendered: String, line_number: usize) -> String {
    let mut lines = rendered
        .split_inclusive('\n')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let Some(line) = lines.get_mut(line_number.saturating_sub(1)) else {
        return lines.concat();
    };
    let newline = line.ends_with('\n');
    let content = line.strip_suffix('\n').unwrap_or(line).to_owned();
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
    let mut comment = None;
    for (index, byte) in content.bytes().enumerate() {
        if double_quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                double_quoted = false;
            }
            continue;
        }
        if single_quoted {
            if byte == b'\'' {
                single_quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => double_quoted = true,
            b'\'' => single_quoted = true,
            b'#' if index > 0 && content.as_bytes()[index - 1].is_ascii_whitespace() => {
                comment = Some(index);
                break;
            }
            _ => {}
        }
    }
    if let Some(index) = comment {
        let mut replacement = content[..index].trim_end().to_owned();
        if newline {
            replacement.push('\n');
        }
        *line = replacement;
    }
    lines.concat()
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "cannot write config: invalid path".to_owned())?;
    // Go stages beside filepath.Clean(path), then renames to the raw target.
    // Keep the target raw so an absent intermediate component cannot redirect
    // a config set into the existing cleaned file.
    let temporary = crate::agent_list_commands::clean_path(path)
        .with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    let mut created = false;
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| format!("cannot write config: {error}"))?;
        created = true;
        file.write_all(bytes)
            .map_err(|error| format!("cannot write config: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("cannot write config: {error}"))?;
        fs::rename(&temporary, path).map_err(|error| format!("cannot write config: {error}"))?;
        Ok(())
    })();
    if created && result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn json_string(value: &str) -> Result<String, String> {
    let encoded = serde_json::to_string(value).map_err(|error| error.to_string())?;
    Ok(encoded
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029"))
}

fn lookup_scalar(source: &str, path: &str) -> Result<String, String> {
    let parts = path.split('.').collect::<Vec<_>>();
    if parts.is_empty() || parts.iter().any(|part| part.is_empty()) {
        return Err(format!("key {path:?} not found"));
    }
    let file = yaml_edit::YamlFile::from_str(source)
        .map_err(|error| format!("cannot load config: {error}"))?;
    let document = file
        .documents()
        .next()
        .ok_or_else(|| "cannot load config: missing YAML document".to_owned())?;
    let Some(mut current) = document.get(parts[0]) else {
        return Err(format!("key {:?} not found", parts[0]));
    };
    for (index, part) in parts.iter().enumerate().skip(1) {
        let Some(value) = current.get(*part) else {
            if current.is_scalar() || current.is_alias() {
                return Err(format!(
                    "cannot access key {:?}: parent is a scalar node, not a mapping",
                    part
                ));
            }
            return Err(format!("key {:?} not found", parts[..=index].join(".")));
        };
        current = value;
    }
    let value = match &current {
        yaml_edit::YamlNode::Scalar(scalar) => scalar.as_string(),
        yaml_edit::YamlNode::Alias(alias) => alias.name(),
        _ => normalize_node_text_for_node(source, &current),
    };
    Ok(value)
}

fn normalize_node_text(text: &str) -> String {
    let lines = text.lines().collect::<Vec<_>>();
    let first_value = lines.iter().position(|line| !line.trim().is_empty());
    let Some(first_value) = first_value else {
        return String::new();
    };
    let base = lines
        .iter()
        .skip(first_value + 1)
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                Some(line.len() - trimmed.len())
            }
        })
        .map(|indent| indent.saturating_sub(2))
        .min()
        .unwrap_or(0);

    normalize_node_lines(&lines, first_value, base)
}

fn normalize_node_lines(lines: &[&str], first_value: usize, base: usize) -> String {
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            if index <= first_value {
                (*line).to_owned()
            } else {
                line.get(base..).unwrap_or("").to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_node_text_for_node(source: &str, node: &yaml_edit::YamlNode) -> String {
    let Some(range) = node_range(node) else {
        return normalize_node_text(&node.to_string());
    };
    let Some(text) = source.get(range.start as usize..range.end as usize) else {
        return normalize_node_text(&node.to_string());
    };
    let line_start = source[..range.start as usize]
        .rfind('\n')
        .map_or(0, |index| index + 1);
    let source_indent = range.start as usize - line_start;
    let lines = text.lines().collect::<Vec<_>>();
    let mut rendered = lines
        .first()
        .map(|_| normalize_node_lines(&lines, 0, source_indent))
        .unwrap_or_default();
    let mut scalar_ranges = Vec::new();
    collect_block_scalar_ranges(node, &mut scalar_ranges);
    normalize_block_scalar_indentation(&mut rendered, source, range.start as usize, &scalar_ranges);
    let source_lines = source[..line_start].lines().collect::<Vec<_>>();
    let mut comments = Vec::new();
    for line in source_lines.iter().rev() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        if !trimmed.starts_with('#') {
            break;
        }
        let indent = line.len() - trimmed.len();
        if indent < source_indent {
            break;
        }
        comments.push(trimmed.to_owned());
    }
    if comments.is_empty() {
        return rendered;
    }
    comments.reverse();
    format!("{}\n{rendered}", comments.join("\n"))
}

fn normalize_block_scalar_indentation(
    rendered: &mut String,
    source: &str,
    node_start: usize,
    scalar_ranges: &[BlockScalarInfo],
) {
    if scalar_ranges.is_empty() {
        return;
    }
    let node_line = source[..node_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    let mut lines = rendered.lines().map(str::to_owned).collect::<Vec<_>>();
    for scalar in scalar_ranges.iter().rev() {
        let header_line = source[..scalar.range.start as usize]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            .saturating_sub(node_line);
        let end = scalar.range.end as usize;
        let end_line = source[..end]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            .saturating_sub(usize::from(end > 0 && source.as_bytes()[end - 1] == b'\n'))
            .saturating_sub(node_line);
        let body_start = header_line + 1;
        if body_start >= lines.len() || end_line < body_start {
            continue;
        }
        let body_end = end_line.min(lines.len().saturating_sub(1));
        let source_lines = source.lines().collect::<Vec<_>>();
        let Some(body_base) = (body_start..=body_end)
            .filter_map(|line| source_lines.get(node_line + line))
            .filter_map(|line| {
                let trimmed = line.trim_start();
                (!trimmed.is_empty()).then_some(line.len() - trimmed.len())
            })
            .min()
        else {
            continue;
        };
        let header_indent = lines[header_line].len() - lines[header_line].trim_start().len();
        let target_indent = header_indent + 2;
        let raw_header = source_lines
            .get(node_line + header_line)
            .copied()
            .unwrap_or_default();
        let raw_indent = raw_header.len() - raw_header.trim_start().len();
        let raw_marker = scalar.range.start as usize
            - source[..scalar.range.start as usize]
                .rfind('\n')
                .map_or(0, |offset| offset + 1);
        let rendered_indent = lines[header_line].len() - lines[header_line].trim_start().len();
        let marker = raw_marker
            .saturating_sub(raw_indent)
            .saturating_add(rendered_indent);
        if matches!(lines[header_line].as_bytes().get(marker), Some(b'|' | b'>')) {
            let token_end = lines[header_line][marker + 1..]
                .char_indices()
                .find(|(_, character)| !matches!(character, '+' | '-' | '0'..='9'))
                .map_or(lines[header_line].len(), |(offset, _)| marker + 1 + offset);
            let header = canonical_block_scalar_header(scalar.style, &scalar.value);
            lines[header_line].replace_range(marker..token_end, &header);
        }
        for (line, output_line) in lines
            .iter_mut()
            .enumerate()
            .take(body_end + 1)
            .skip(body_start)
        {
            let Some(source_line) = source_lines.get(node_line + line) else {
                continue;
            };
            let trimmed = source_line.trim_start();
            if trimmed.is_empty() {
                continue;
            }
            let indent = source_line.len() - trimmed.len();
            let relative = indent.saturating_sub(body_base);
            *output_line = format!("{}{}", " ".repeat(target_indent + relative), trimmed);
        }
        if scalar.style == yaml_edit::ScalarStyle::Folded {
            for line in (body_start..=body_end).rev() {
                let Some(source_line) = source_lines.get(node_line + line) else {
                    continue;
                };
                let trimmed = source_line.trim_start();
                let indent = source_line.len() - trimmed.len();
                if !trimmed.is_empty()
                    && indent > body_base
                    && lines
                        .get(line.saturating_sub(1))
                        .is_some_and(|previous| !previous.is_empty())
                {
                    lines.insert(line, String::new());
                }
            }
        }
    }
    *rendered = lines.join("\n");
}

struct BlockScalarInfo {
    range: yaml_edit::TextPosition,
    style: yaml_edit::ScalarStyle,
    value: String,
}

fn canonical_block_scalar_header(style: yaml_edit::ScalarStyle, value: &str) -> String {
    let marker = match style {
        yaml_edit::ScalarStyle::Literal => '|',
        yaml_edit::ScalarStyle::Folded => '>',
        _ => return String::new(),
    };
    let trailing_newlines = value.len() - value.trim_end_matches('\n').len();
    let chomping = match trailing_newlines {
        0 => "-",
        1 => "",
        _ => "+",
    };
    format!("{marker}{chomping}")
}

fn collect_block_scalar_ranges(node: &yaml_edit::YamlNode, ranges: &mut Vec<BlockScalarInfo>) {
    match node {
        yaml_edit::YamlNode::Scalar(scalar)
            if matches!(
                yaml_edit::ScalarValue::from_scalar(scalar).style(),
                yaml_edit::ScalarStyle::Literal | yaml_edit::ScalarStyle::Folded
            ) =>
        {
            let parsed = yaml_edit::ScalarValue::from_scalar(scalar);
            ranges.push(BlockScalarInfo {
                range: scalar.byte_range(),
                style: parsed.style(),
                value: scalar.as_string(),
            })
        }
        yaml_edit::YamlNode::Mapping(mapping) => {
            for (_, value) in mapping.iter() {
                collect_block_scalar_ranges(&value, ranges);
            }
        }
        yaml_edit::YamlNode::Sequence(sequence) => {
            for value in sequence.values() {
                collect_block_scalar_ranges(&value, ranges);
            }
        }
        _ => {}
    }
}

fn node_range(node: &yaml_edit::YamlNode) -> Option<yaml_edit::TextPosition> {
    match node {
        yaml_edit::YamlNode::Mapping(mapping) => Some(mapping.byte_range()),
        yaml_edit::YamlNode::Sequence(sequence) => Some(sequence.byte_range()),
        yaml_edit::YamlNode::Scalar(scalar) => Some(scalar.byte_range()),
        yaml_edit::YamlNode::Alias(_) | yaml_edit::YamlNode::TaggedNode(_) => None,
    }
}

/// The sink for the loader's deprecation warnings (Go's
/// `config.SetWarnFunc(cliout.Warnf)`).
pub(crate) fn warn_sink(message: &str) {
    self::fix::warnf(message);
}

/// Implements `symvault config validate [path]`.
///
/// Mirrors Go's `config validate`: load, then run
/// [`symvault_core::config::Config::validate`], reporting every violation at
/// once. With `--fix` and an interactive stdin the interactive repair flow
/// (see [`fix`]) runs instead of reporting the failure, exactly as Go's
/// `configValidateCmd` does; a non-terminal stdin validates as usual.
pub(crate) fn format_go_path_error(op: &str, path: &Path, err: &io::Error) -> String {
    #[cfg(windows)]
    if err.kind() == io::ErrorKind::PermissionDenied
        && fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
    {
        // Rust's File::open rejects directories, whereas Go opens them and
        // reports the later Windows ReadFile error.
        return format!("read {}: Incorrect function.", path.display());
    }
    #[cfg(windows)]
    let err_msg = match err.raw_os_error() {
        Some(2) => "The system cannot find the file specified.",
        Some(3) => "The system cannot find the path specified.",
        Some(5) => "Access is denied.",
        _ => {
            if err.kind() == io::ErrorKind::NotFound {
                "The system cannot find the file specified."
            } else {
                "general error"
            }
        }
    };
    #[cfg(not(windows))]
    let err_msg = match err.raw_os_error() {
        Some(2) => "no such file or directory",
        Some(13) => "permission denied",
        Some(21) => "is a directory",
        _ => {
            if err.kind() == io::ErrorKind::NotFound {
                "no such file or directory"
            } else if err.kind() == io::ErrorKind::PermissionDenied {
                "permission denied"
            } else {
                "input/output error"
            }
        }
    };
    #[cfg(not(windows))]
    let op = if err.kind() == io::ErrorKind::IsADirectory {
        "read"
    } else {
        op
    };
    format!("{op} {}: {err_msg}", path.display())
}

pub fn validate(path: &Path, fix: bool, output: &str, quiet: bool) -> Result<(), String> {
    let json = output == "json";
    // The header below prints the RAW argument, exactly like Go's
    // `cannot load config from %s` (cmd/admin/config.go), while config.Load
    // rejects traversal before os.ReadFile(filepath.Clean(path)).
    let path_display = path.display().to_string();

    let first = self::fix::load(path);
    let loaded = if fix && std::io::stdin().is_terminal() {
        self::fix::fix(path, first, quiet)?
    } else {
        match first {
            Ok(loaded) => loaded,
            Err(load_error) => {
                if json {
                    print_json(
                        &serde_json::json!({ "error": load_error, "valid": false }),
                        quiet,
                    )?;
                    return Err(format!("config load failed: {load_error}"));
                }
                return Err(format!(
                    "cannot load config from {path_display}: {load_error}: {load_error}"
                ));
            }
        }
    };

    let errors = self::fix::validate(&loaded);
    if !errors.is_empty() {
        if json {
            print_json(
                &serde_json::json!({ "errors": errors, "valid": false }),
                quiet,
            )?;
        } else if !quiet {
            println!("Configuration is invalid ({path_display}):");
            for line in &errors {
                println!("  ✗ {line}");
            }
        }
        return Err(format!("config validation failed: {}", errors.join("\n")));
    }

    if json {
        print_json(
            &serde_json::json!({ "path": path_display, "valid": true }),
            quiet,
        )?;
    } else if !quiet {
        println!("Configuration is valid ({path_display})");
    }
    Ok(())
}

/// Encodes `value` as one line of JSON, matching Go's `SetEscapeHTML(false)`
/// printer. Suppressed under `--quiet`, matching Go's quiet-aware `PrintJSON`.
fn print_json(value: &serde_json::Value, quiet: bool) -> Result<(), String> {
    if quiet {
        return Ok(());
    }
    let mut rendered = serde_json::to_string(value)
        .map_err(|error| error.to_string())?
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    rendered.push('\n');
    io::stdout()
        .write_all(rendered.as_bytes())
        .map_err(|error| error.to_string())
}

pub fn resolve_path(file: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(path) = file
        && !path.as_os_str().is_empty()
    {
        return Ok(path);
    }
    #[cfg(windows)]
    let home = env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let home = env::var_os("HOME");
    let home = home
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "cannot determine config file path".to_owned())?;
    // Go builds this via filepath.Join(home, subdir, "config.yaml"), whose
    // Clean collapses structural quirks such as a doubled slash in $HOME;
    // a raw PathBuf join keeps them. Reuse the repo's filepath.Clean mirror
    // (agent_list_commands::clean_path) instead of a second implementation.
    Ok(crate::agent_list_commands::clean_path(
        &PathBuf::from(home).join(".symvault").join("config.yaml"),
    ))
}

#[cfg(test)]
mod tests {
    use super::atomic_write;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn atomic_write_keeps_preexisting_tempfile_on_create_collision() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("symvault-config-atomic-{unique}"));
        fs::create_dir_all(&root).expect("create test directory");
        let target = root.join("config.yaml");
        let temporary = root.join(format!(".config.yaml.tmp-{}", std::process::id()));
        fs::write(&temporary, b"owned by another writer").expect("create collision tempfile");

        let result = atomic_write(&target, b"new content");

        assert!(result.is_err());
        assert!(!target.exists());
        assert_eq!(
            fs::read(&temporary).expect("read collision tempfile"),
            b"owned by another writer"
        );
        let _ = fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod reindent_tests {
    use super::reindent_two_spaces;

    #[test]
    fn four_space_documents_become_two_space() {
        let input = "agents:\n    cli:\n        allowedPaths:\n            - '*'\n        canWrite: true\nvault:\n    authMethod: passphrase\n";
        assert_eq!(
            reindent_two_spaces(input),
            "agents:\n  cli:\n    allowedPaths:\n      - '*'\n    canWrite: true\nvault:\n  authMethod: passphrase\n"
        );
    }

    #[test]
    fn two_space_documents_are_unchanged() {
        let input = "a:\n  b:\n    - x\n    - y: 1\n      z: 2\n  c: |\n    text\n    more\nd: 1\n";
        assert_eq!(reindent_two_spaces(input), input);
    }

    #[test]
    fn compact_sequences_and_dash_maps_are_indented() {
        assert_eq!(
            reindent_two_spaces("a:\n- x\n- y\nb: 1\n"),
            "a:\n  - x\n  - y\nb: 1\n"
        );
        assert_eq!(
            reindent_two_spaces("a:\n        - k: 1\n          m: 2\nb: 1\n"),
            "a:\n  - k: 1\n    m: 2\nb: 1\n"
        );
        assert_eq!(
            reindent_two_spaces("a:\n    # note\n    b: 1\n"),
            "a:\n  # note\n  b: 1\n"
        );
    }
}
