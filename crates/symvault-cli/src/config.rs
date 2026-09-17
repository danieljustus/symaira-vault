use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

pub fn list(path: &Path, quiet: bool) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot load config: {error}"))?;
    if !quiet {
        let _ = io::stdout().write_all(&bytes);
    }
    Ok(())
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
