use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::capability::Capability;
use crate::error::{BridgeError, BridgeResult};
use crate::quote::shell_word;

const HELPER_DIRECTORY_ENV: &str = "CODEX_SSH_BRIDGE_HELPERS_DIR";
const HELPER_DIRECTORY_NAME: &str = "remote-helpers";
const HELPER_BOOTSTRAP_TAG: &str = "codex-ssh-helper-bootstrap-1";
const MAX_HELPER_BYTES: u64 = 256 * 1024 * 1024;

const HELPER_BOOTSTRAP_SCRIPT: &str = r#"set -u
umask 077
bootstrap_tag=${1-}
helper_length=${2-}
max_frame=${3-}
[ "$bootstrap_tag" = codex-ssh-helper-bootstrap-1 ] || exit 64
case "$helper_length:$max_frame" in
    ''|*[!0-9:]*|*:*:) exit 64 ;;
esac
[ "$helper_length" -gt 0 ] || exit 64
[ "$max_frame" -gt 0 ] || exit 64
base=${TMPDIR:-/tmp}/codex-ssh-bridge-helper.$$
suffix=0
while ! (umask 077 && mkdir "$base" 2>/dev/null); do
    suffix=$((suffix + 1))
    [ "$suffix" -le 100 ] || exit 73
    base=${TMPDIR:-/tmp}/codex-ssh-bridge-helper.$$.$suffix
done
helper=$base/helper
cleanup() { rm -rf -- "$base"; }
trap cleanup EXIT HUP INT TERM
: >"$helper" || exit 74
read_bytes=0
while [ "$read_bytes" -lt "$helper_length" ]; do
    chunk=$((helper_length - read_bytes))
    [ "$chunk" -le 65536 ] || chunk=65536
    dd bs="$chunk" count=1 >>"$helper" 2>/dev/null || exit 74
    now=$(wc -c <"$helper" | tr -d '[:space:]') || exit 74
    case "$now" in ''|*[!0-9]*) exit 74 ;; esac
    [ "$now" -gt "$read_bytes" ] || exit 74
    [ "$now" -le "$helper_length" ] || exit 74
    read_bytes=$now
done
[ "$read_bytes" -eq "$helper_length" ] || exit 74
chmod 700 "$helper" || exit 74
CODEX_SSH_HELPER_PATH="$helper" exec "$helper" --max-frame "$max_frame"
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelperArtifact {
    pub(crate) path: PathBuf,
    pub(crate) target: &'static str,
    pub(crate) arch: &'static str,
}

pub(crate) fn helper_artifact(capability: &Capability) -> Option<HelperArtifact> {
    if capability.kernel_name.as_deref() != Some("Linux") {
        return None;
    }
    let (target, arch) = helper_target_for_arch(capability.machine_arch.as_deref()?)?;
    let directory = helper_directory().ok()?;
    let path = directory.join(target);
    validate_artifact_path(&directory, &path).ok()?;
    Some(HelperArtifact { path, target, arch })
}

fn helper_target_for_arch(machine_arch: &str) -> Option<(&'static str, &'static str)> {
    match machine_arch {
        "x86_64" => Some(("x86_64-unknown-linux-musl", "x86_64")),
        "aarch64" => Some(("aarch64-unknown-linux-musl", "aarch64")),
        "armv7l" | "armv7" => Some(("armv7-unknown-linux-musleabihf", "armv7l")),
        "riscv64" => Some(("riscv64gc-unknown-linux-gnu", "riscv64")),
        "ppc64le" => Some(("powerpc64le-unknown-linux-gnu", "ppc64le")),
        "s390x" => Some(("s390x-unknown-linux-gnu", "s390x")),
        _ => None,
    }
}

pub(crate) fn helper_bytes(artifact: &HelperArtifact) -> BridgeResult<Vec<u8>> {
    let directory = artifact
        .path
        .parent()
        .ok_or_else(|| BridgeError::invalid_config("remote helper artifact has no parent"))?;
    validate_artifact_path(directory, &artifact.path)?;
    let metadata = fs::symlink_metadata(&artifact.path).map_err(BridgeError::io)?;
    if metadata.len() == 0 || metadata.len() > MAX_HELPER_BYTES {
        return Err(BridgeError::invalid_config(
            "remote helper artifact size is outside the safe bound",
        ));
    }
    fs::read(&artifact.path).map_err(BridgeError::io)
}

pub(crate) fn helper_command(max_frame_bytes: usize, helper_length: usize) -> BridgeResult<String> {
    if max_frame_bytes == 0 || helper_length == 0 {
        return Err(BridgeError::invalid_argument(
            "remote helper bootstrap lengths must be positive",
        ));
    }
    let script = shell_word(HELPER_BOOTSTRAP_SCRIPT)?;
    let tag = shell_word(HELPER_BOOTSTRAP_TAG)?;
    let length = shell_word(&helper_length.to_string())?;
    let max_frame = shell_word(&max_frame_bytes.to_string())?;
    Ok(format!("sh -c {script} -- {tag} {length} {max_frame}"))
}

pub(crate) fn helper_directory() -> BridgeResult<PathBuf> {
    let directory = match std::env::var_os(HELPER_DIRECTORY_ENV) {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => std::env::current_exe()
            .map_err(BridgeError::io)?
            .parent()
            .map(|parent| parent.join(HELPER_DIRECTORY_NAME))
            .ok_or_else(|| {
                BridgeError::invalid_config("bridge executable has no parent directory")
            })?,
    };
    Ok(directory)
}

fn validate_artifact_path(directory: &Path, path: &Path) -> BridgeResult<()> {
    let directory_metadata = fs::symlink_metadata(directory).map_err(BridgeError::io)?;
    let file_metadata = fs::symlink_metadata(path).map_err(BridgeError::io)?;
    let uid = unsafe { libc::geteuid() };
    if !directory_metadata.is_dir()
        || directory_metadata.file_type().is_symlink()
        || directory_metadata.permissions().mode() & 0o022 != 0
        || (directory_metadata.uid() != uid && directory_metadata.uid() != 0)
        || !file_metadata.is_file()
        || file_metadata.file_type().is_symlink()
        || file_metadata.permissions().mode() & 0o111 == 0
        || file_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(BridgeError::invalid_config(
            "remote helper artifact path is not a private executable",
        ));
    }
    if file_metadata.uid() != uid && file_metadata.uid() != 0 {
        return Err(BridgeError::invalid_config(
            "remote helper artifact has an unexpected owner",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{helper_artifact, helper_command, helper_target_for_arch};
    use crate::capability::{Capability, ShellKind};
    use std::collections::BTreeMap;

    fn capability(kernel_name: Option<&str>, machine_arch: Option<&str>) -> Capability {
        Capability {
            physical_root: "/".to_owned(),
            root_device: 1,
            root_inode: 1,
            kernel_name: kernel_name.map(str::to_owned),
            machine_arch: machine_arch.map(str::to_owned),
            shell: ShellKind::PosixSh,
            bash_version: None,
            login_shell: Some("/bin/sh".to_owned()),
            tools: BTreeMap::new(),
        }
    }

    #[test]
    fn supported_architectures_map_to_helper_targets() {
        for (arch, target) in [
            ("x86_64", "x86_64-unknown-linux-musl"),
            ("aarch64", "aarch64-unknown-linux-musl"),
            ("armv7l", "armv7-unknown-linux-musleabihf"),
            ("armv7", "armv7-unknown-linux-musleabihf"),
            ("riscv64", "riscv64gc-unknown-linux-gnu"),
            ("ppc64le", "powerpc64le-unknown-linux-gnu"),
            ("s390x", "s390x-unknown-linux-gnu"),
        ] {
            assert_eq!(
                helper_target_for_arch(arch).map(|(target, _)| target),
                Some(target)
            );
            let capability = capability(Some("Linux"), Some(arch));
            let artifact = helper_artifact(&capability);
            if std::env::var_os("CODEX_SSH_BRIDGE_HELPERS_DIR").is_some() {
                assert_eq!(artifact.map(|artifact| artifact.target), Some(target));
            } else {
                assert!(artifact.is_none());
            }
        }
        assert!(helper_artifact(&capability(Some("Darwin"), Some("x86_64"))).is_none());
        assert!(helper_artifact(&capability(Some("Linux"), Some("mips64"))).is_none());
    }

    #[test]
    fn bootstrap_is_shell_quoted_and_carries_exact_lengths() {
        let command = helper_command(8 * 1024 * 1024, 1234).unwrap();
        assert!(command.starts_with("sh -c "));
        assert!(command.contains("codex-ssh-helper-bootstrap-1"));
        assert!(command.contains("1234"));
        assert!(command.contains("8388608"));
        assert!(!command.as_bytes().contains(&0));
    }

    #[test]
    fn bootstrap_uploads_and_executes_the_helper_without_interpreting_bytes() {
        use std::io::{BufReader, Write};
        use std::process::{Command, Stdio};

        let helper_path = std::env::var("CARGO_BIN_EXE_codex-ssh-bridge-helper")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_codex_ssh_bridge_helper"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("target/debug/codex-ssh-bridge-helper")
            });
        if !helper_path.is_file() {
            return;
        }
        let bytes = std::fs::read(helper_path).unwrap();
        let command = helper_command(64 * 1024, bytes.len()).unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", &command])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        input.write_all(&bytes).unwrap();
        input.flush().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let hello = crate::remote_helper_protocol::read_frame(&mut output, 64 * 1024)
            .unwrap()
            .unwrap();
        assert_eq!(
            hello.kind,
            crate::remote_helper_protocol::FrameKind::HelloAck
        );
        crate::remote_helper_protocol::write_frame(
            &mut input,
            &crate::remote_helper_protocol::Frame {
                kind: crate::remote_helper_protocol::FrameKind::Close,
                request_id: 0,
                payload: Vec::new(),
            },
            64 * 1024,
        )
        .unwrap();
        input.flush().unwrap();
        drop(input);
        assert!(child.wait().unwrap().success());
    }
}
