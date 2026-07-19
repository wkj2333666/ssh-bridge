use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use crate::config::ResolvedHost;
use crate::error::{BridgeError, BridgeResult};

use super::SshPolicy;

pub fn build_ssh_argv(policy: &SshPolicy, host: &str, remote_command: &str) -> Vec<OsString> {
    let mut argv = policy.options.clone();
    argv.push(OsString::from("--"));
    argv.push(OsString::from(host));
    if !remote_command.is_empty() {
        argv.push(OsString::from(remote_command));
    }
    debug_assert!(argv.iter().any(|argument| argument == OsStr::new("--")));
    argv
}

pub fn build_sshfs_argv(
    policy: &SshPolicy,
    host: ResolvedHost<'_>,
    remote_path: &str,
    mountpoint: &Path,
    allow_nonempty: bool,
) -> BridgeResult<Vec<OsString>> {
    if !remote_path.starts_with('/') || remote_path.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "SSHFS remote path must be absolute and contain no NUL",
        ));
    }
    if !mountpoint.is_absolute() || mountpoint.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "SSHFS mountpoint must be an absolute local path",
        ));
    }

    let mut argv = Vec::with_capacity(policy.options.len() + 24);
    argv.push(OsString::from(format!("{}:{remote_path}", host.alias)));
    argv.push(mountpoint.as_os_str().to_owned());
    push_option(&mut argv, "ssh_command=/usr/bin/ssh");
    argv.extend(policy.options.iter().cloned());
    let connect_seconds = host.limits.connect_timeout_ms.div_ceil(1_000).max(1);
    push_option(&mut argv, format!("ConnectTimeout={connect_seconds}"));
    push_option(&mut argv, "ServerAliveInterval=15");
    push_option(&mut argv, "ServerAliveCountMax=3");
    push_option(&mut argv, "reconnect");
    if host.profile.read_only {
        push_option(&mut argv, "ro");
    }
    if allow_nonempty {
        push_option(&mut argv, "nonempty");
    }
    Ok(argv)
}

pub fn validate_sshfs_mountpoint(path: &Path, allow_nonempty: bool) -> BridgeResult<PathBuf> {
    if !path.is_absolute() {
        return Err(BridgeError::invalid_argument(
            "SSHFS mountpoint must be an absolute local path",
        ));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(BridgeError::io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BridgeError::invalid_argument(
            "SSHFS mountpoint must be a real local directory, not a symlink",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        // Opening with O_NOFOLLOW closes the final-component symlink race before
        // trusting ownership. The retained descriptor is intentionally kept
        // alive through the emptiness check below.
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(BridgeError::io)?;
        let opened = directory.metadata().map_err(BridgeError::io)?;
        // SAFETY: geteuid has no preconditions and reads process credentials.
        let uid = unsafe { libc::geteuid() };
        if opened.uid() != uid || opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err(BridgeError::invalid_argument(
                "SSHFS mountpoint must remain a directory owned by the current user",
            ));
        }
        if !allow_nonempty
            && std::fs::read_dir(path)
                .map_err(BridgeError::io)?
                .next()
                .transpose()
                .map_err(BridgeError::io)?
                .is_some()
        {
            return Err(BridgeError::invalid_argument(
                "SSHFS mountpoint is not empty; pass --allow-nonempty only after inspection",
            ));
        }
        drop(directory);
    }
    #[cfg(not(unix))]
    if !allow_nonempty
        && std::fs::read_dir(path)
            .map_err(BridgeError::io)?
            .next()
            .transpose()
            .map_err(BridgeError::io)?
            .is_some()
    {
        return Err(BridgeError::invalid_argument(
            "SSHFS mountpoint is not empty; pass --allow-nonempty only after inspection",
        ));
    }
    Ok(path.to_owned())
}

fn push_option(argv: &mut Vec<OsString>, value: impl Into<OsString>) {
    argv.push(OsString::from("-o"));
    argv.push(value.into());
}
