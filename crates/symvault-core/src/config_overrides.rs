//! Root vault/profile precedence, distinct from YAML field merging.
//!
//! Go does not bind arbitrary `SYMVAULT_*` keys to Config fields and has no
//! root `--config` flag. Expansion is supplied by the CLI's filepath.Clean
//! adapter so platform path semantics remain at that boundary.
use crate::config::{Config, PathResolver};
use std::path::{Path, PathBuf};

/// Presence is significant: `Some("")` is an explicitly changed flag.
#[derive(Debug, Default)]
pub struct VaultOverrides<'a> {
    pub vault_flag: Option<&'a Path>,
    pub profile_flag: Option<&'a str>,
    pub vault_env: Option<&'a str>,
    pub profile_env: Option<&'a str>,
}

impl VaultOverrides<'_> {
    /// Mirrors internal/cli.VaultPath. An explicitly requested invalid profile
    /// fails; an invalid default profile falls back to the discovered data dir.
    pub fn resolve(
        &self,
        resolver: &PathResolver,
        load: impl FnOnce() -> Result<Config, String>,
        expand: impl Fn(&Path) -> Result<PathBuf, String>,
    ) -> Result<PathBuf, String> {
        if let Some(path) = self.vault_flag {
            return expand(path);
        }
        if let Some(value) = self.vault_env.map(str::trim).filter(|v| !v.is_empty()) {
            return expand(Path::new(value));
        }
        let requested = self
            .profile_flag
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .or_else(|| self.profile_env.map(str::trim).filter(|v| !v.is_empty()));
        let config = load();
        let resolve_profile = |config: &Config, name: &str| {
            let profile = config
                .profile_for_name(name)
                .ok_or_else(|| format!("profile {name:?} not found"))?;
            if profile.vault_path.is_empty() {
                return Err(format!("profile {name:?} has no vault path configured"));
            }
            expand(Path::new(&profile.vault_path))
        };
        if let Some(name) = requested {
            return resolve_profile(
                config
                    .as_ref()
                    .map_err(|e| format!("cannot load config: {e}"))?,
                name,
            );
        }
        if let Ok(config) = config
            && !config.default_profile.is_empty()
            && let Ok(path) = resolve_profile(&config, &config.default_profile)
        {
            return Ok(path);
        }
        if !resolver.data_dir.as_os_str().is_empty() {
            return Ok(resolver.data_dir.clone());
        }
        expand(Path::new("~/.symvault"))
    }
}
