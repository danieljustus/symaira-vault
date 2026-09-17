use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

pub fn list(path: &Path, quiet: bool) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot load config: {error}"))?;
    if !quiet {
        let _ = io::stdout().write_all(&bytes);
    }
    Ok(())
}

pub fn get(path: &Path, key: &str, output: &str, quiet: bool) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot load config: {error}"))?;
    let source = std::str::from_utf8(&bytes)
        .map_err(|error| format!("cannot load config: invalid UTF-8: {error}"))?;
    let value = lookup_scalar(source, key)?;
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

pub fn set(path: &Path, key: &str, value: &str, quiet: bool) -> Result<(), String> {
    use yaml_edit::path::YamlPath;

    let bytes = fs::read(path).map_err(|error| format!("cannot load config: {error}"))?;
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
    atomic_write(path, rendered.as_bytes())?;
    if let Err(error) = symvault_core::config::Config::load(path) {
        return Err(format!("config is invalid after update: {error}"));
    }
    if !quiet {
        println!("Set {key} = {value}");
    }
    Ok(())
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
            for line in content.lines() {
                source.push_str("  ");
                source.push_str(line);
                source.push('\n');
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
    let temporary = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
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
        .trim()
        .to_owned()
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
    let rendered = lines
        .first()
        .map(|_| normalize_node_lines(&lines, 0, source_indent))
        .map(normalize_block_scalar_indentation)
        .unwrap_or_default();
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

fn normalize_block_scalar_indentation(text: String) -> String {
    let mut lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
    let mut block_header_indent = None;
    for line in &mut lines {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if let Some(header_indent) = block_header_indent {
            if trimmed.is_empty() || indent > header_indent {
                if indent > header_indent + 2 {
                    *line = format!("{}{}", " ".repeat(header_indent + 2), trimmed);
                }
                continue;
            }
            block_header_indent = None;
        }
        if trimmed.ends_with('|') || trimmed.ends_with('>') {
            block_header_indent = Some(indent);
        }
    }
    lines.join("\n")
}

fn node_range(node: &yaml_edit::YamlNode) -> Option<yaml_edit::TextPosition> {
    match node {
        yaml_edit::YamlNode::Mapping(mapping) => Some(mapping.byte_range()),
        yaml_edit::YamlNode::Sequence(sequence) => Some(sequence.byte_range()),
        yaml_edit::YamlNode::Scalar(scalar) => Some(scalar.byte_range()),
        yaml_edit::YamlNode::Alias(_) | yaml_edit::YamlNode::TaggedNode(_) => None,
    }
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
    Ok(PathBuf::from(home).join(".symvault").join("config.yaml"))
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
