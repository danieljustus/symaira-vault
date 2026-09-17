use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use serde_yaml_ng::Value;

pub fn get(path: &Path, key: &str, output: &str, quiet: bool) -> Result<(), String> {
    let root = load(path)?;
    let value = lookup(&root, key)?;
    if quiet {
        return Ok(());
    }

    let value = value_to_string(value)?;
    match output {
        "text" => println!("{value}"),
        "json" => {
            let mut result = BTreeMap::new();
            result.insert(key, value);
            println!(
                "{}",
                serde_json::to_string(&result).map_err(|error| error.to_string())?
            );
        }
        _ => println!("{value}"),
    }
    Ok(())
}

pub fn list(path: &Path, output: &str, quiet: bool) -> Result<(), String> {
    let _ = output;
    let bytes = fs::read(path).map_err(|error| format!("cannot load config: {error}"))?;
    if !quiet {
        io::stdout()
            .write_all(&bytes)
            .map_err(|error| format!("cannot write config: {error}"))?;
    }
    Ok(())
}

fn load(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot load config: {error}"))?;
    serde_yaml_ng::from_slice(&bytes).map_err(|error| format!("cannot load config: {error}"))
}

fn lookup<'a>(root: &'a Value, key: &str) -> Result<&'a Value, String> {
    let mut current = root;
    for (index, part) in key.split('.').enumerate() {
        let Value::Mapping(mapping) = current else {
            return Err(format!("key {part:?} not found"));
        };
        let path = key.split('.').take(index + 1).collect::<Vec<_>>().join(".");
        current = mapping
            .get(Value::String(part.to_owned()))
            .ok_or_else(|| format!("key {path:?} not found"))?;
    }
    Ok(current)
}

fn value_to_string(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => Ok(value.clone()),
        Value::Sequence(_) | Value::Mapping(_) => serde_yaml_ng::to_string(value)
            .map(|value| value.trim().to_owned())
            .map_err(|error| error.to_string()),
        _ => serde_yaml_ng::to_string(value)
            .map(|value| value.trim().to_owned())
            .map_err(|error| error.to_string()),
    }
}

pub fn resolve_path(file: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(path) = file {
        return Ok(path);
    }
    #[cfg(windows)]
    let home = env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let home = env::var_os("HOME");
    let home = home.ok_or_else(|| "cannot determine config file path".to_owned())?;
    Ok(PathBuf::from(home).join(".symvault").join("config.yaml"))
}
