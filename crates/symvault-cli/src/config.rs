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
        let parsed = yaml_edit::ScalarValue::from_scalar(&scalar);
        let value = scalar.as_string();
        if matches!(
            parsed.style(),
            yaml_edit::ScalarStyle::Literal | yaml_edit::ScalarStyle::Folded
        ) {
            return Ok(SetValue::Node(canonical_scalar_node(&scalar)?));
        }
        let scalar = match parsed.scalar_type() {
            yaml_edit::ScalarType::String => {
                let plain = yaml_edit::ScalarValue::string(&value);
                if plain.to_yaml_string().starts_with('\'') {
                    yaml_edit::ScalarValue::double_quoted(value)
                } else {
                    plain
                }
            }
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
        return Ok(SetValue::Scalar(scalar));
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
    let value = scalar.as_string();
    if matches!(
        parsed.style(),
        yaml_edit::ScalarStyle::Literal | yaml_edit::ScalarStyle::Folded
    ) {
        let content = value.strip_suffix('\n').unwrap_or(&value);
        let mut source = String::from("|-\n");
        for line in content.lines() {
            source.push_str("  ");
            source.push_str(line);
            source.push('\n');
        }
        let file = yaml_edit::YamlFile::from_str(&source)
            .map_err(|error| format!("cannot parse config value: {error}"))?;
        return file
            .documents()
            .next()
            .and_then(|document| document.as_scalar())
            .map(yaml_edit::YamlNode::Scalar)
            .ok_or_else(|| "cannot parse config value: unsupported YAML scalar".to_owned());
    }
    let scalar = match parsed.scalar_type() {
        yaml_edit::ScalarType::String => {
            let plain = yaml_edit::ScalarValue::string(&value);
            if plain.to_yaml_string().starts_with('\'') {
                yaml_edit::ScalarValue::double_quoted(value)
            } else {
                plain
            }
        }
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
    yaml_edit::YamlBuilder::scalar(scalar)
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
        file.write_all(bytes)
            .map_err(|error| format!("cannot write config: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("cannot write config: {error}"))?;
        fs::rename(&temporary, path).map_err(|error| format!("cannot write config: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn json_string(value: &str) -> Result<String, String> {
    Ok(serde_json::to_string(value)
        .map_err(|error| error.to_string())?
        .replace("\\u003c", "<")
        .replace("\\u003e", ">")
        .replace("\\u0026", "&"))
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
        _ => normalize_node_text_with_comments(source, &current.to_string()),
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
        .enumerate()
        .skip(first_value + 1)
        .filter_map(|(_, line)| {
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let indent = line.len() - trimmed.len();
            if is_structural_yaml_line(trimmed) {
                Some(indent)
            } else {
                None
            }
        })
        .min()
        .or_else(|| {
            lines
                .iter()
                .skip(first_value + 1)
                .filter_map(|line| {
                    let trimmed = line.trim_start();
                    (!trimmed.is_empty()).then(|| line.len() - trimmed.len())
                })
                .map(|indent| indent.saturating_sub(2))
                .min()
        })
        .unwrap_or(0);

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

fn normalize_node_text_with_comments(source: &str, text: &str) -> String {
    let rendered = normalize_node_text(text);
    let Some(first_line) = rendered.lines().next() else {
        return rendered;
    };
    let source_lines = source.lines().collect::<Vec<_>>();
    let Some(first_index) = source_lines
        .iter()
        .position(|line| line.trim() == first_line.trim())
    else {
        return rendered;
    };
    let source_indent =
        source_lines[first_index].len() - source_lines[first_index].trim_start_matches(' ').len();
    let mut comments = Vec::new();
    for line in source_lines[..first_index].iter().rev() {
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

fn is_structural_yaml_line(line: &str) -> bool {
    line.starts_with('-') || line.find(':').is_some_and(|index| index > 0)
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
