#![allow(
    clippy::result_large_err,
    reason = "Task 1 fixes BridgeResult<T> to an inline BridgeError representation"
)]

mod argv;

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::config::{Config, ResolvedHost};
use crate::error::{BridgeError, BridgeResult};

pub use argv::build_ssh_argv;

const RUNTIME_DIRECTORY: &str = "codex-ssh-bridge";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePaths {
    directory: PathBuf,
}

impl RuntimePaths {
    pub fn discover() -> BridgeResult<Self> {
        match std::env::var_os("XDG_RUNTIME_DIR").filter(|value| !value.is_empty()) {
            Some(base) => Self::ensure_from_base(Path::new(&base)),
            None => {
                // SAFETY: geteuid has no preconditions and only reads process credentials.
                let uid = unsafe { libc::geteuid() };
                Self::ensure_directory(PathBuf::from(format!("/tmp/{RUNTIME_DIRECTORY}-{uid}")))
            }
        }
    }

    pub fn ensure_from_base(base: &Path) -> BridgeResult<Self> {
        Self::ensure_directory(base.join(RUNTIME_DIRECTORY))
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn ensure_directory(directory: PathBuf) -> BridgeResult<Self> {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(BridgeError::io(error)),
        }

        let metadata = fs::symlink_metadata(&directory).map_err(BridgeError::io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(unsafe_runtime_directory(
                "runtime path must be a real directory",
            ));
        }
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid {
            return Err(unsafe_runtime_directory(
                "runtime directory must be owned by the current user",
            ));
        }
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(unsafe_runtime_directory(
                "runtime directory permissions must be 0700",
            ));
        }

        Ok(Self { directory })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPolicy {
    options: Vec<OsString>,
}

impl SshPolicy {
    pub fn for_host(
        config: &Config,
        host: ResolvedHost<'_>,
        runtime_paths: &RuntimePaths,
        resolved_connection_identity: &str,
    ) -> BridgeResult<Self> {
        let configured = config.host(host.alias)?;
        if configured.profile != host.profile || configured.limits != host.limits {
            return Err(BridgeError::invalid_config(
                "resolved host does not belong to this configuration",
            ));
        }

        let control_path = runtime_paths
            .directory
            .join(control_filename(host.alias, resolved_connection_identity));
        let mut control_option = OsString::from("ControlPath=");
        control_option.push(control_path);

        let mut options = Vec::new();
        for option in [
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "ForwardAgent=no",
            "ForwardX11=no",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
            "RequestTTY=no",
            "ControlMaster=auto",
            "ControlPersist=300",
        ] {
            options.push(OsString::from("-o"));
            options.push(OsString::from(option));
        }
        options.push(OsString::from("-o"));
        options.push(control_option);

        Ok(Self { options })
    }
}

fn control_filename(alias: &str, resolved_connection_identity: &str) -> String {
    let mut digest = Sha256::new();
    digest.update((alias.len() as u64).to_be_bytes());
    digest.update(alias.as_bytes());
    digest.update((resolved_connection_identity.len() as u64).to_be_bytes());
    digest.update(resolved_connection_identity.as_bytes());
    let digest = digest.finalize();
    let mut filename = String::from("cm-");
    for byte in &digest[..16] {
        write!(&mut filename, "{byte:02x}").expect("writing to a String cannot fail");
    }
    filename
}

fn unsafe_runtime_directory(message: &str) -> BridgeError {
    BridgeError::invalid_config(message)
}
