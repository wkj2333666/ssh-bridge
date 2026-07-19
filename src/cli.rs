#![allow(
    clippy::result_large_err,
    reason = "the shared BridgeResult intentionally stores BridgeError inline"
)]

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::json;

use crate::config::{Config, HostLimitOverrides, HostProfile};
use crate::error::{BridgeError, BridgeResult};

#[derive(Debug, Parser)]
#[command(
    name = "codex-ssh-bridge",
    about = "Operate allowlisted SSH servers from the local machine",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the local stdio MCP server.
    Mcp,
    /// Manage exact allowlisted OpenSSH aliases.
    Hosts(HostsArgs),
    /// Diagnose configuration, SSH resolution, and remote capabilities.
    Doctor(DoctorArgs),
    /// Run an argv-style command on an allowlisted remote host.
    Run(RunArgs),
    /// Mount a remote path explicitly with SSHFS (human use only).
    Mount(MountArgs),
    /// Unmount an explicit local SSHFS mountpoint.
    Unmount(MountpointArgs),
    /// Report whether a local path is an SSHFS mountpoint.
    MountStatus(MountpointArgs),
    /// Install the local MCP entry and Skill; dry-run unless --apply is supplied.
    Install(InstallArgs),
    /// Uninstall only an identity-matching local installation; dry-run unless --apply is supplied.
    Uninstall(InstallArgs),
}

#[derive(Debug, Args)]
pub struct HostsArgs {
    #[command(subcommand)]
    pub command: HostsCommand,
}

#[derive(Debug, Subcommand)]
pub enum HostsCommand {
    List,
    Show(HostName),
    Add(AddHostArgs),
    Remove(HostName),
}

#[derive(Debug, Args)]
pub struct HostName {
    #[arg(allow_hyphen_values = true)]
    pub alias: String,
}

#[derive(Debug, Args)]
pub struct AddHostArgs {
    #[arg(allow_hyphen_values = true)]
    pub alias: String,
    #[arg(long)]
    pub root: String,
    #[arg(long)]
    pub description: Option<String>,
    #[arg(long)]
    pub read_only: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    pub host: Option<String>,
    #[arg(long)]
    pub verbose_ssh: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ShellArg {
    Auto,
    Bash,
    Sh,
    Login,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    pub host: String,
    #[arg(long, default_value = ".")]
    pub cwd: String,
    #[arg(long, value_enum, default_value = "auto")]
    pub shell: ShellArg,
    #[arg(long)]
    pub timeout_ms: Option<u64>,
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub argv: Vec<String>,
}

#[derive(Debug, Args)]
pub struct MountArgs {
    pub host: String,
    pub mountpoint: PathBuf,
    #[arg(long, default_value = ".")]
    pub remote_path: String,
    #[arg(long)]
    pub allow_nonempty: bool,
}

#[derive(Debug, Args)]
pub struct MountpointArgs {
    pub mountpoint: PathBuf,
}

#[derive(Debug, Args)]
pub struct InstallArgs {
    #[arg(long, required = true)]
    pub user: bool,
    #[arg(long)]
    pub apply: bool,
}

pub fn known_human_mode(value: &std::ffi::OsStr) -> bool {
    matches!(
        value.to_str(),
        Some(
            "--help"
                | "-h"
                | "hosts"
                | "doctor"
                | "run"
                | "mount"
                | "unmount"
                | "mount-status"
                | "install"
                | "uninstall"
        )
    )
}

pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(std::iter::once(OsString::from("codex-ssh-bridge")).chain(arguments))
}

pub async fn run(cli: Cli) -> BridgeResult<()> {
    match cli.command {
        Command::Hosts(arguments) => run_hosts(config_path()?, arguments),
        Command::Mcp => Err(BridgeError::invalid_argument(
            "mcp mode is dispatched by the binary entry point",
        )),
        Command::Doctor(_)
        | Command::Run(_)
        | Command::Mount(_)
        | Command::Unmount(_)
        | Command::MountStatus(_)
        | Command::Install(_)
        | Command::Uninstall(_) => Err(BridgeError::invalid_argument(
            "this human command is not implemented yet",
        )),
    }
}

fn config_path() -> BridgeResult<PathBuf> {
    if let Some(path) = std::env::var_os("CODEX_SSH_BRIDGE_CONFIG") {
        if path.is_empty() {
            return Err(BridgeError::invalid_config(
                "CODEX_SSH_BRIDGE_CONFIG cannot be empty",
            ));
        }
        return Ok(PathBuf::from(path));
    }
    Config::default_path()
}

fn run_hosts(path: PathBuf, arguments: HostsArgs) -> BridgeResult<()> {
    match arguments.command {
        HostsCommand::Add(arguments) => add_host(&path, arguments),
        HostsCommand::Remove(arguments) => remove_host(&path, &arguments.alias),
        HostsCommand::List => {
            let config = Config::load(&path)?;
            let hosts: Vec<_> = config
                .hosts
                .iter()
                .map(|(alias, profile)| host_json(alias, profile))
                .collect();
            print_json(&json!({ "hosts": hosts }))
        }
        HostsCommand::Show(arguments) => {
            let config = Config::load(&path)?;
            let host = config.host(&arguments.alias)?;
            print_json(&host_json(host.alias, host.profile))
        }
    }
}

fn add_host(path: &Path, arguments: AddHostArgs) -> BridgeResult<()> {
    let mut config = load_for_add(path)?;
    if config.hosts.contains_key(&arguments.alias) {
        return Err(BridgeError::invalid_argument("host alias already exists"));
    }
    config.hosts.insert(
        arguments.alias.clone(),
        HostProfile {
            root: arguments.root,
            description: arguments.description,
            read_only: arguments.read_only,
            limits: HostLimitOverrides::default(),
        },
    );
    ensure_config_parent(path)?;
    config.save_atomic(path)?;
    let profile = config
        .hosts
        .get(&arguments.alias)
        .expect("inserted host profile");
    print_json(&host_json(&arguments.alias, profile))
}

fn remove_host(path: &Path, alias: &str) -> BridgeResult<()> {
    let mut config = Config::load(path)?;
    let profile = config
        .hosts
        .remove(alias)
        .ok_or_else(|| BridgeError::invalid_argument("host alias is not configured"))?;
    config.save_atomic(path)?;
    print_json(&json!({ "removed": host_json(alias, &profile) }))
}

fn load_for_add(path: &Path) -> BridgeResult<Config> {
    match fs::symlink_metadata(path) {
        Ok(_) => Config::load(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(error) => Err(BridgeError::io(error)),
    }
}

fn ensure_config_parent(path: &Path) -> BridgeResult<()> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    if !parent.is_absolute() {
        return Err(BridgeError::invalid_config(
            "configuration parent must be an absolute local path",
        ));
    }
    #[cfg(unix)]
    ensure_secure_absolute_directory(parent)?;
    #[cfg(not(unix))]
    fs::create_dir_all(parent).map_err(BridgeError::io)?;
    Ok(())
}

#[cfg(unix)]
fn ensure_secure_absolute_directory(path: &Path) -> BridgeResult<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::path::Component;

    // SAFETY: credential getters have no preconditions and retain no pointers.
    let current_uid = unsafe { libc::geteuid() };
    let root_uid = fs::symlink_metadata("/").map_err(BridgeError::io)?.uid();
    let mut resolved = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::CurDir => continue,
            Component::Normal(name) => resolved.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(BridgeError::invalid_config(
                    "configuration parent must be a normalized absolute path",
                ));
            }
        }
        let metadata = match fs::symlink_metadata(&resolved) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                if let Err(create_error) = builder.create(&resolved)
                    && create_error.kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(BridgeError::io(create_error));
                }
                fs::symlink_metadata(&resolved).map_err(BridgeError::io)?
            }
            Err(error) => return Err(BridgeError::io(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BridgeError::invalid_config(
                "configuration path ancestors must be real directories",
            ));
        }
        if metadata.uid() != root_uid && metadata.uid() != current_uid {
            return Err(BridgeError::invalid_config(
                "configuration path ancestors must be owned by root or the current user",
            ));
        }
        let writable = metadata.mode() & 0o022 != 0;
        let trusted_tmp = resolved == Path::new("/tmp")
            && metadata.uid() == root_uid
            && metadata.mode() & 0o1000 != 0;
        if writable && !trusted_tmp {
            return Err(BridgeError::invalid_config(
                "configuration path ancestors must not be writable by group or other users",
            ));
        }
    }
    Ok(())
}

fn host_json(alias: &str, profile: &HostProfile) -> serde_json::Value {
    json!({
        "remote": true,
        "host": alias,
        "configured_root": profile.root,
        "description": profile.description,
        "read_only": profile.read_only,
        "limits": profile.limits,
    })
}

fn print_json(value: &serde_json::Value) -> BridgeResult<()> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|error| BridgeError::io(format!("cannot render CLI output: {error}")))?;
    println!("{rendered}");
    Ok(())
}
