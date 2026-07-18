#![allow(
    clippy::result_large_err,
    reason = "Task 1 requires BridgeResult<T> = Result<T, BridgeError> with inline ErrorDetails"
)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::error::{BridgeError, BridgeResult};
use crate::path::RemotePath;
use crate::{MAX_FRAME_BYTES, MAX_OUTPUT_BYTES, MAX_READ_BYTES, MAX_WRITE_BYTES};

const MAX_CONNECT_TIMEOUT_MS: u64 = 120_000;
const MAX_COMMAND_TIMEOUT_MS: u64 = 3_600_000;
const MAX_READ_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_PREVIEW_BYTES: usize = 1024 * 1024;
const MAX_GLOBAL_CONCURRENCY: usize = 32;
const MAX_PER_HOST_CONCURRENCY: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub limits: Limits,
    pub hosts: BTreeMap<String, HostProfile>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            limits: Limits::default(),
            hosts: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub connect_timeout_ms: u64,
    pub command_timeout_ms: u64,
    pub max_frame_bytes: usize,
    pub read_chunk_bytes: usize,
    pub max_read_bytes: usize,
    pub max_write_bytes: usize,
    pub preview_bytes: usize,
    pub max_output_bytes: u64,
    pub global_concurrency: usize,
    pub per_host_concurrency: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 10_000,
            command_timeout_ms: 300_000,
            max_frame_bytes: MAX_FRAME_BYTES,
            read_chunk_bytes: 256 * 1024,
            max_read_bytes: MAX_READ_BYTES,
            max_write_bytes: MAX_WRITE_BYTES,
            preview_bytes: 256 * 1024,
            max_output_bytes: MAX_OUTPUT_BYTES,
            global_concurrency: 8,
            per_host_concurrency: 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProfile {
    pub root: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub limits: HostLimitOverrides,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostLimitOverrides {
    pub connect_timeout_ms: Option<u64>,
    pub command_timeout_ms: Option<u64>,
    pub max_read_bytes: Option<usize>,
    pub max_write_bytes: Option<usize>,
    pub preview_bytes: Option<usize>,
    pub max_output_bytes: Option<u64>,
    pub per_host_concurrency: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveLimits {
    pub connect_timeout_ms: u64,
    pub command_timeout_ms: u64,
    pub max_frame_bytes: usize,
    pub read_chunk_bytes: usize,
    pub max_read_bytes: usize,
    pub max_write_bytes: usize,
    pub preview_bytes: usize,
    pub max_output_bytes: u64,
    pub global_concurrency: usize,
    pub per_host_concurrency: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConfig {
    pub config: Config,
    pub source: ConfigSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSource {
    pub path: PathBuf,
    pub from_environment: bool,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedHost<'a> {
    pub alias: &'a str,
    pub profile: &'a HostProfile,
    pub limits: EffectiveLimits,
}

impl Config {
    pub fn load(path: &Path) -> BridgeResult<Self> {
        let mut file = open_config(path)?;
        validate_file_security(&file)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(BridgeError::io)?;
        let config: Self = toml::from_str(&contents).map_err(|error| {
            BridgeError::invalid_config(format!("invalid configuration: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_default() -> BridgeResult<LoadedConfig> {
        let (path, from_environment, warning) = match std::env::var_os("CODEX_SSH_BRIDGE_CONFIG") {
            Some(path) => (
                PathBuf::from(path),
                true,
                Some(
                    "CODEX_SSH_BRIDGE_CONFIG is trusted execution-authority input; verify its source and permissions"
                        .to_owned(),
                ),
            ),
            None => (default_config_path()?, false, None),
        };
        let config = Self::load(&path)?;
        Ok(LoadedConfig {
            config,
            source: ConfigSource {
                path,
                from_environment,
                warning,
            },
        })
    }

    pub fn save_atomic(&self, path: &Path) -> BridgeResult<()> {
        self.validate()?;
        let serialized = toml::to_string_pretty(self).map_err(|error| {
            BridgeError::invalid_config(format!("cannot serialize configuration: {error}"))
        })?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = NamedTempFile::new_in(parent).map_err(BridgeError::io)?;
        set_private_permissions(temporary.as_file())?;
        temporary
            .write_all(serialized.as_bytes())
            .map_err(BridgeError::io)?;
        temporary.flush().map_err(BridgeError::io)?;
        temporary.as_file().sync_all().map_err(BridgeError::io)?;
        temporary
            .persist(path)
            .map_err(|error| BridgeError::io(error.error))?;
        Ok(())
    }

    pub fn host<'a>(&'a self, alias: &'a str) -> BridgeResult<ResolvedHost<'a>> {
        if !valid_alias(alias) {
            return Err(BridgeError::invalid_argument("invalid host alias"));
        }
        self.validate()?;
        let profile = self
            .hosts
            .get(alias)
            .ok_or_else(|| BridgeError::invalid_config("unknown host alias"))?;
        Ok(ResolvedHost {
            alias,
            profile,
            limits: effective_limits(&self.limits, &profile.limits),
        })
    }

    fn validate(&self) -> BridgeResult<()> {
        validate_limits(&self.limits)?;
        for (alias, profile) in &self.hosts {
            if !valid_alias(alias) {
                return Err(BridgeError::invalid_config(format!(
                    "invalid host alias: {alias}"
                )));
            }
            RemotePath::resolve(&profile.root, ".").map_err(|_| {
                BridgeError::invalid_config(format!("host {alias} has an invalid root"))
            })?;
            validate_host_limits(alias, &profile.limits, &self.limits)?;
        }
        Ok(())
    }
}

fn validate_limits(limits: &Limits) -> BridgeResult<()> {
    validate_u64(
        "connect_timeout_ms",
        limits.connect_timeout_ms,
        MAX_CONNECT_TIMEOUT_MS,
    )?;
    validate_u64(
        "command_timeout_ms",
        limits.command_timeout_ms,
        MAX_COMMAND_TIMEOUT_MS,
    )?;
    validate_usize("max_frame_bytes", limits.max_frame_bytes, MAX_FRAME_BYTES)?;
    validate_usize(
        "read_chunk_bytes",
        limits.read_chunk_bytes,
        MAX_READ_CHUNK_BYTES,
    )?;
    validate_usize("max_read_bytes", limits.max_read_bytes, MAX_READ_BYTES)?;
    validate_usize("max_write_bytes", limits.max_write_bytes, MAX_WRITE_BYTES)?;
    validate_usize("preview_bytes", limits.preview_bytes, MAX_PREVIEW_BYTES)?;
    validate_u64(
        "max_output_bytes",
        limits.max_output_bytes,
        MAX_OUTPUT_BYTES,
    )?;
    validate_usize(
        "global_concurrency",
        limits.global_concurrency,
        MAX_GLOBAL_CONCURRENCY,
    )?;
    validate_usize(
        "per_host_concurrency",
        limits.per_host_concurrency,
        MAX_PER_HOST_CONCURRENCY,
    )?;
    if limits.per_host_concurrency > limits.global_concurrency {
        return Err(BridgeError::invalid_config(
            "per_host_concurrency cannot exceed global_concurrency",
        ));
    }
    Ok(())
}

fn validate_host_limits(
    alias: &str,
    overrides: &HostLimitOverrides,
    global: &Limits,
) -> BridgeResult<()> {
    if let Some(value) = overrides.connect_timeout_ms {
        validate_u64("connect_timeout_ms", value, MAX_CONNECT_TIMEOUT_MS)?;
    }
    if let Some(value) = overrides.command_timeout_ms {
        validate_u64("command_timeout_ms", value, MAX_COMMAND_TIMEOUT_MS)?;
    }
    if let Some(value) = overrides.max_read_bytes {
        validate_usize("max_read_bytes", value, MAX_READ_BYTES)?;
    }
    if let Some(value) = overrides.max_write_bytes {
        validate_usize("max_write_bytes", value, MAX_WRITE_BYTES)?;
    }
    if let Some(value) = overrides.preview_bytes {
        validate_usize("preview_bytes", value, MAX_PREVIEW_BYTES)?;
    }
    if let Some(value) = overrides.max_output_bytes {
        validate_u64("max_output_bytes", value, MAX_OUTPUT_BYTES)?;
    }
    if let Some(value) = overrides.per_host_concurrency {
        validate_usize("per_host_concurrency", value, MAX_PER_HOST_CONCURRENCY)?;
        if value > global.global_concurrency {
            return Err(BridgeError::invalid_config(format!(
                "host {alias} per_host_concurrency cannot exceed global_concurrency"
            )));
        }
    }
    Ok(())
}

fn validate_u64(name: &str, value: u64, maximum: u64) -> BridgeResult<()> {
    if value == 0 || value > maximum {
        return Err(BridgeError::invalid_config(format!(
            "{name} must be between 1 and {maximum}"
        )));
    }
    Ok(())
}

fn validate_usize(name: &str, value: usize, maximum: usize) -> BridgeResult<()> {
    if value == 0 || value > maximum {
        return Err(BridgeError::invalid_config(format!(
            "{name} must be between 1 and {maximum}"
        )));
    }
    Ok(())
}

fn effective_limits(global: &Limits, host: &HostLimitOverrides) -> EffectiveLimits {
    EffectiveLimits {
        connect_timeout_ms: host.connect_timeout_ms.unwrap_or(global.connect_timeout_ms),
        command_timeout_ms: host.command_timeout_ms.unwrap_or(global.command_timeout_ms),
        max_frame_bytes: global.max_frame_bytes,
        read_chunk_bytes: global.read_chunk_bytes,
        max_read_bytes: host.max_read_bytes.unwrap_or(global.max_read_bytes),
        max_write_bytes: host.max_write_bytes.unwrap_or(global.max_write_bytes),
        preview_bytes: host.preview_bytes.unwrap_or(global.preview_bytes),
        max_output_bytes: host.max_output_bytes.unwrap_or(global.max_output_bytes),
        global_concurrency: global.global_concurrency,
        per_host_concurrency: host
            .per_host_concurrency
            .unwrap_or(global.per_host_concurrency),
    }
}

fn valid_alias(alias: &str) -> bool {
    let bytes = alias.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn default_config_path() -> BridgeResult<PathBuf> {
    let base = nonempty_environment("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| nonempty_environment("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| {
            BridgeError::invalid_config(
                "cannot determine config path: XDG_CONFIG_HOME and HOME are unset",
            )
        })?;
    Ok(base.join("codex-ssh-bridge").join("config.toml"))
}

fn nonempty_environment(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}

fn open_config(path: &Path) -> BridgeResult<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    options.open(path).map_err(|error| {
        #[cfg(unix)]
        if error.raw_os_error() == Some(libc::ELOOP) {
            return BridgeError::invalid_config("configuration must not be a symlink");
        }
        BridgeError::io(error)
    })
}

fn validate_file_security(file: &fs::File) -> BridgeResult<()> {
    let metadata = file.metadata().map_err(BridgeError::io)?;
    if !metadata.is_file() {
        return Err(BridgeError::invalid_config(
            "configuration must be a regular file",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // SAFETY: geteuid has no preconditions and does not dereference pointers.
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid {
            return Err(BridgeError::invalid_config(
                "configuration must be owned by the current user",
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(BridgeError::invalid_config(
                "configuration must not be writable by group or others",
            ));
        }
    }
    Ok(())
}

fn set_private_permissions(file: &fs::File) -> BridgeResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(BridgeError::io)?;
    }
    Ok(())
}
