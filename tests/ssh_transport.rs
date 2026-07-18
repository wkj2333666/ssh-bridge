#![deny(unsafe_code)]

mod support;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use codex_ssh_bridge::capability::{
    CAPABILITY_PROBE_SCRIPT, Capability, CapabilityCache, ShellKind, ShellRequest,
    parse_probe_output, select_shell,
};
use codex_ssh_bridge::config::{Config, HostProfile, Limits};
use codex_ssh_bridge::error::{BridgeError, ErrorCode};
use codex_ssh_bridge::output::{CaptureLimits, OutputReference, OutputStore, StreamKind};
use codex_ssh_bridge::path::RemotePath;
use codex_ssh_bridge::remote::{RemoteBridge, StatRequest};
use codex_ssh_bridge::ssh::{RunRequest, RuntimePaths, SshPolicy, SshRunner, build_ssh_argv};
use codex_ssh_bridge::{MAX_OUTPUT_BYTES, MAX_READ_BYTES, MAX_WRITE_BYTES};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

use support::{config_with_host, fake_ssh_path};

const HARDENED_OPTIONS: &[&str] = &[
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    "ForwardAgent=no",
    "ForwardX11=no",
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
    "RequestTTY=no",
    "ControlMaster=auto",
    "ControlPersist=300",
];
const LONG_XDG_CHILD_SENTINEL: &str = "CODEX_SSH_BRIDGE_LONG_XDG_CHILD_EXPECTED";
const RESTRICTIVE_UMASK_CHILD_SENTINEL: &str = "CODEX_SSH_BRIDGE_RESTRICTIVE_UMASK_BASE";

fn option_is_distinct(argv: &[OsString], expected: &str) -> bool {
    argv.windows(2)
        .any(|pair| pair[0] == OsStr::new("-o") && pair[1] == OsStr::new(expected))
}

fn policy(
    config: &codex_ssh_bridge::config::Config,
    paths: &RuntimePaths,
    identity: &str,
) -> SshPolicy {
    SshPolicy::for_host(config, config.host("dev-box").unwrap(), paths, identity).unwrap()
}

fn bash_probe(requested: &str, physical: &str) -> Vec<u8> {
    format!(
        "CODEX_SSH_PROBE=1\0REQUESTED_ROOT={requested}\0ROOT={physical}\0SHELL_KIND=bash\0BASH_VERSION=5.2.15\0TOOL_rg=1\0TOOL_dd_nofollow=1\0TOOL_timeout=0\0"
    )
    .into_bytes()
}

fn bash_probe_with_version(requested: &str, physical: &str, version: &str) -> Vec<u8> {
    format!(
        "CODEX_SSH_PROBE=1\0REQUESTED_ROOT={requested}\0ROOT={physical}\0SHELL_KIND=bash\0BASH_VERSION={version}\0TOOL_rg=1\0TOOL_dd_nofollow=1\0TOOL_timeout=0\0"
    )
    .into_bytes()
}

fn sh_probe(requested: &str, physical: &str) -> Vec<u8> {
    format!(
        "CODEX_SSH_PROBE=1\0REQUESTED_ROOT={requested}\0ROOT={physical}\0SHELL_KIND=sh\0BASH_VERSION=\0TOOL_rg=0\0"
    )
    .into_bytes()
}

fn capability(shell: ShellKind) -> Capability {
    let bash_version = match &shell {
        ShellKind::Bash { version } => Some(version.clone()),
        ShellKind::PosixSh | ShellKind::Login => None,
    };
    Capability {
        physical_root: "/srv/project".to_owned(),
        shell,
        bash_version,
        tools: BTreeMap::new(),
    }
}

fn base_for_control_path_bytes(container: &TempDir, target: usize) -> std::path::PathBuf {
    const CONTROL_FILENAME_BYTES: usize = 3 + 32;
    let suffix = 1 + "codex-ssh-bridge".len() + 1 + CONTROL_FILENAME_BYTES;
    let desired_base_bytes = target.checked_sub(suffix).unwrap();
    let container_bytes = container.path().as_os_str().as_bytes().len();
    let component_bytes = desired_base_bytes.checked_sub(container_bytes + 1).unwrap();
    let base = container.path().join("x".repeat(component_bytes));
    fs::create_dir(&base).unwrap();
    assert_eq!(base.as_os_str().as_bytes().len(), desired_base_bytes);
    base
}

#[test]
fn argv_uses_hardened_distinct_options_and_a_private_hashed_control_path() {
    let base = TempDir::new().unwrap();
    let paths = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let runtime_metadata = fs::symlink_metadata(paths.directory()).unwrap();
    assert!(runtime_metadata.is_dir());
    assert_eq!(runtime_metadata.permissions().mode() & 0o777, 0o700);
    assert_eq!(
        runtime_metadata.uid(),
        fs::metadata(base.path()).unwrap().uid()
    );

    let config = config_with_host("dev-box", "/srv/project");
    let identity = "hostname=server.internal;user=deploy;port=22";
    let ssh_policy = policy(&config, &paths, identity);
    let argv = build_ssh_argv(&ssh_policy, "dev-box", "printf safe");

    for expected in HARDENED_OPTIONS {
        assert!(
            option_is_distinct(&argv, expected),
            "missing distinct option {expected:?} in {argv:?}"
        );
    }
    let control_option = argv
        .iter()
        .find_map(|argument| {
            argument
                .to_str()
                .and_then(|value| value.strip_prefix("ControlPath="))
        })
        .expect("ControlPath option");
    assert!(ssh_policy.control_path().starts_with(paths.directory()));
    assert!(control_option.starts_with('"'));
    assert!(control_option.ends_with('"'));
    assert!(!control_option.contains("dev-box"));
    assert!(!control_option.contains(identity));

    let same = build_ssh_argv(&policy(&config, &paths, identity), "dev-box", "printf safe");
    assert_eq!(argv, same);
    let changed = build_ssh_argv(
        &policy(&config, &paths, "hostname=other;user=deploy;port=22"),
        "dev-box",
        "printf safe",
    );
    assert_ne!(
        control_option,
        changed
            .iter()
            .find_map(|argument| argument
                .to_str()
                .and_then(|value| value.strip_prefix("ControlPath=")))
            .unwrap()
    );
}

#[test]
fn hostile_host_text_is_only_an_operand_after_the_option_separator() {
    let base = TempDir::new().unwrap();
    let paths = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let config = config_with_host("dev-box", "/srv/project");
    let policy = policy(&config, &paths, "stable identity");
    let hostile = "-oProxyCommand=touch /tmp/owned";
    let argv = build_ssh_argv(&policy, hostile, "true");
    let separator = argv
        .iter()
        .position(|argument| argument == OsStr::new("--"))
        .expect("option separator");
    assert!(!argv[..separator].iter().any(|argument| argument == hostile));
    assert_eq!(argv.get(separator + 1), Some(&OsString::from(hostile)));

    let output = Command::new(fake_ssh_path()).args(&argv).output().unwrap();
    assert!(output.status.success());
    let recorded: Vec<&[u8]> = output
        .stdout
        .strip_suffix(&[0])
        .unwrap()
        .split(|byte| *byte == 0)
        .collect();
    let expected: Vec<&[u8]> = argv
        .iter()
        .map(|argument| argument.as_os_str().as_bytes())
        .collect();
    assert_eq!(recorded, expected);
}

#[test]
fn openssh_config_encoder_round_trips_every_control_path_metacharacter() {
    let container = TempDir::new().unwrap();
    let base = container.path().join("s \t%h%r%p\"\\");
    fs::create_dir(&base).unwrap();
    let paths = RuntimePaths::ensure_from_base(&base).unwrap();
    let config = config_with_host("dev-box", "/srv/project");
    let policy = policy(&config, &paths, "stable identity");
    let literal = policy.control_path().to_str().unwrap().to_owned();
    let argv = build_ssh_argv(&policy, "example.invalid", "");
    let control_argument = argv
        .iter()
        .find_map(|argument| {
            argument
                .to_str()
                .filter(|value| value.starts_with("ControlPath="))
        })
        .unwrap();

    let output = Command::new("/usr/bin/ssh")
        .args(["-F", "/dev/null", "-G"])
        .args(&argv)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ssh -G failed\nargv: {argv:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).unwrap();
    let actual = rendered
        .lines()
        .find_map(|line| line.strip_prefix("controlpath "))
        .expect("ssh -G controlpath");
    assert!(control_argument.starts_with("ControlPath=\""));
    assert!(control_argument.ends_with('"'));
    assert!(control_argument.contains("%%h"));
    assert!(control_argument.contains("%%r"));
    assert!(control_argument.contains("%%p"));
    assert!(control_argument.contains("\\\""));
    assert!(control_argument.contains("\\\\"));
    assert_eq!(actual, literal, "argv: {argv:?}");
}

#[test]
fn control_path_accepts_107_bytes_and_rejects_108_bytes() {
    let config = config_with_host("dev-box", "/srv/project");

    let accepted_container = TempDir::new().unwrap();
    let accepted_base = base_for_control_path_bytes(&accepted_container, 107);
    let accepted_paths = RuntimePaths::ensure_from_base(&accepted_base).unwrap();
    let accepted = policy(&config, &accepted_paths, "stable identity");
    assert_eq!(accepted.control_path().as_os_str().as_bytes().len(), 107);

    let rejected_container = TempDir::new().unwrap();
    let rejected_base = base_for_control_path_bytes(&rejected_container, 108);
    let rejected_paths = RuntimePaths::ensure_from_base(&rejected_base).unwrap();
    let error = SshPolicy::for_host(
        &config,
        config.host("dev-box").unwrap(),
        &rejected_paths,
        "stable identity",
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidConfig);
}

#[test]
fn discover_long_xdg_fallback_child() {
    let Some(expected) = std::env::var_os(LONG_XDG_CHILD_SENTINEL) else {
        return;
    };
    let paths = RuntimePaths::discover().unwrap();
    assert_eq!(paths.directory(), std::path::Path::new(&expected));
}

#[test]
fn discover_falls_back_to_short_tmp_runtime_when_xdg_exceeds_control_path_budget() {
    let container = TempDir::new().unwrap();
    let long_base = base_for_control_path_bytes(&container, 108);
    let uid = fs::metadata("/proc/self").unwrap().uid();
    let expected = format!("/tmp/codex-ssh-bridge-{uid}");
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "discover_long_xdg_fallback_child", "--nocapture"])
        .env(LONG_XDG_CHILD_SENTINEL, &expected)
        .env("XDG_RUNTIME_DIR", &long_base)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !long_base.join("codex-ssh-bridge").exists(),
        "discover must preflight before creating an unusable XDG leaf"
    );
}

#[test]
fn explicit_runtime_base_rejects_unrepresentable_control_paths_before_creating_a_leaf() {
    let container = TempDir::new().unwrap();
    let names = [
        OsString::from("line\nbreak"),
        OsString::from("carriage\rreturn"),
        OsString::from_vec(b"non-utf8-\xff".to_vec()),
    ];

    for name in names {
        let base = container.path().join(name);
        fs::create_dir(&base).unwrap();
        let error = RuntimePaths::ensure_from_base(&base).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidConfig, "base: {base:?}");
        assert!(
            !base.join("codex-ssh-bridge").exists(),
            "invalid base created a runtime leaf: {base:?}"
        );
    }
}

#[test]
fn discover_falls_back_before_creating_an_unrepresentable_xdg_leaf() {
    let container = TempDir::new().unwrap();
    let bases = [
        container.path().join("line\nbreak"),
        container.path().join("carriage\rreturn"),
        container
            .path()
            .join(OsString::from_vec(b"non-utf8-\xff".to_vec())),
    ];

    for base in bases {
        fs::create_dir(&base).unwrap();
        let uid = fs::metadata("/proc/self").unwrap().uid();
        let expected = format!("/tmp/codex-ssh-bridge-{uid}");
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "discover_long_xdg_fallback_child", "--nocapture"])
            .env(LONG_XDG_CHILD_SENTINEL, &expected)
            .env("XDG_RUNTIME_DIR", &base)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed for {base:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !base.join("codex-ssh-bridge").exists(),
            "discover created an unusable XDG leaf: {base:?}"
        );
    }
}

#[test]
fn runtime_paths_refuse_insecure_modes_and_symlinks() {
    let insecure_base = TempDir::new().unwrap();
    let insecure = insecure_base.path().join("codex-ssh-bridge");
    fs::create_dir(&insecure).unwrap();
    fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755)).unwrap();
    let mode_error = RuntimePaths::ensure_from_base(insecure_base.path()).unwrap_err();
    assert_eq!(mode_error.code, ErrorCode::InvalidConfig);

    let symlink_base = TempDir::new().unwrap();
    let target = symlink_base.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&target, symlink_base.path().join("codex-ssh-bridge")).unwrap();
    let symlink_error = RuntimePaths::ensure_from_base(symlink_base.path()).unwrap_err();
    assert_eq!(symlink_error.code, ErrorCode::InvalidConfig);

    let special_mode_base = TempDir::new().unwrap();
    let special_mode = special_mode_base.path().join("codex-ssh-bridge");
    fs::create_dir(&special_mode).unwrap();
    fs::set_permissions(&special_mode, fs::Permissions::from_mode(0o1700)).unwrap();
    let special_mode_error = RuntimePaths::ensure_from_base(special_mode_base.path()).unwrap_err();
    assert_eq!(special_mode_error.code, ErrorCode::InvalidConfig);

    let real_base_container = TempDir::new().unwrap();
    let real_base = real_base_container.path().join("real-base");
    fs::create_dir(&real_base).unwrap();
    let linked_base = real_base_container.path().join("linked-base");
    symlink(&real_base, &linked_base).unwrap();
    let linked_base_error = RuntimePaths::ensure_from_base(&linked_base).unwrap_err();
    assert_eq!(linked_base_error.code, ErrorCode::InvalidConfig);

    let writable_base = TempDir::new().unwrap();
    fs::set_permissions(writable_base.path(), fs::Permissions::from_mode(0o770)).unwrap();
    let writable_base_error = RuntimePaths::ensure_from_base(writable_base.path()).unwrap_err();
    assert_eq!(writable_base_error.code, ErrorCode::InvalidConfig);
}

#[test]
fn runtime_paths_reject_relative_bases() {
    let error =
        RuntimePaths::ensure_from_base(std::path::Path::new("relative/runtime")).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidConfig);
}

#[test]
fn runtime_paths_reject_a_symlink_in_the_base_ancestor_chain() {
    let container = TempDir::new().unwrap();
    let real_ancestor = container.path().join("real-ancestor");
    let base = real_ancestor.join("base");
    fs::create_dir_all(&base).unwrap();
    let linked_ancestor = container.path().join("linked-ancestor");
    symlink(&real_ancestor, &linked_ancestor).unwrap();

    let error = RuntimePaths::ensure_from_base(&linked_ancestor.join("base")).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidConfig);
    assert_eq!(
        error.details.path.as_deref(),
        linked_ancestor.to_str(),
        "must reject the symlink component itself"
    );
}

#[test]
fn runtime_paths_reject_a_world_writable_intermediate_ancestor() {
    let container = TempDir::new().unwrap();
    let writable_ancestor = container.path().join("writable-ancestor");
    let base = writable_ancestor.join("base");
    fs::create_dir_all(&base).unwrap();
    fs::set_permissions(&writable_ancestor, fs::Permissions::from_mode(0o777)).unwrap();

    let error = RuntimePaths::ensure_from_base(&base).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidConfig);
    assert_eq!(
        error.details.path.as_deref(),
        writable_ancestor.to_str(),
        "must reject the writable intermediate itself"
    );
}

#[test]
fn parser_accepts_bash_sh_and_newlines_without_conflating_requested_and_physical_roots() {
    let expected_bash = RemotePath::resolve("/srv/requested\nroot", ".").unwrap();
    let bash = parse_probe_output(
        &bash_probe(expected_bash.absolute(), "/srv/physical\nroot"),
        &expected_bash,
    )
    .unwrap();
    assert_eq!(bash.physical_root, "/srv/physical\nroot");
    assert_eq!(
        bash.shell,
        ShellKind::Bash {
            version: "5.2.15".to_owned()
        }
    );
    assert_eq!(bash.bash_version.as_deref(), Some("5.2.15"));
    assert_eq!(bash.tools.get("rg"), Some(&true));
    assert_eq!(bash.tools.get("dd_nofollow"), Some(&true));
    assert_eq!(bash.tools.get("timeout"), Some(&false));

    let expected_sh = RemotePath::resolve("/srv/link", ".").unwrap();
    let sh = parse_probe_output(&sh_probe("/srv/link", "/srv/physical"), &expected_sh).unwrap();
    assert_eq!(sh.physical_root, "/srv/physical");
    assert_eq!(sh.shell, ShellKind::PosixSh);
    assert_eq!(sh.bash_version, None);
}

#[test]
fn parser_fails_closed_for_malformed_duplicate_unknown_and_mismatched_records() {
    let expected = RemotePath::resolve("/srv/project", ".").unwrap();
    let cases: Vec<Vec<u8>> = vec![
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0SHELL_KIND=sh\0BASH_VERSION=".to_vec(),
        b"CODEX_SSH_PROBE=1\0BROKEN\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0SHELL_KIND=sh\0BASH_VERSION=\0".to_vec(),
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0ROOT=/srv/other\0SHELL_KIND=sh\0BASH_VERSION=\0".to_vec(),
        b"CODEX_SSH_PROBE=2\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0SHELL_KIND=sh\0BASH_VERSION=\0".to_vec(),
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/other\0ROOT=/srv/project\0SHELL_KIND=sh\0BASH_VERSION=\0".to_vec(),
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=relative\0SHELL_KIND=sh\0BASH_VERSION=\0".to_vec(),
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/./project\0SHELL_KIND=sh\0BASH_VERSION=\0".to_vec(),
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0SHELL_KIND=sh\0BASH_VERSION=\0UNKNOWN=value\0".to_vec(),
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0SHELL_KIND=sh\0BASH_VERSION=\0TOOL_curl=1\0".to_vec(),
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0SHELL_KIND=sh\0BASH_VERSION=\0TOOL_rg=2\0".to_vec(),
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0SHELL_KIND=bash\0BASH_VERSION=\0".to_vec(),
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0SHELL_KIND=sh\0BASH_VERSION=5.2\0".to_vec(),
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0SHELL_KIND=unknown\0BASH_VERSION=\0".to_vec(),
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0SHELL_KIND=sh\0BASH_VERSION=\0\xff\0".to_vec(),
        b"CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0SHELL_KIND=sh\0".to_vec(),
    ];

    for output in cases {
        let error = parse_probe_output(&output, &expected).unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError, "{output:?}");
    }
}

#[test]
fn shell_selection_records_profile_free_bash_posix_fallback_and_login_semantics() {
    let bash = capability(ShellKind::Bash {
        version: "5.2.15".to_owned(),
    });
    let automatic_bash = select_shell(&bash, ShellRequest::Auto).unwrap();
    assert_eq!(automatic_bash.shell, bash.shell);
    assert!(!automatic_bash.fallback);

    let sh = capability(ShellKind::PosixSh);
    let automatic_sh = select_shell(&sh, ShellRequest::Auto).unwrap();
    assert_eq!(automatic_sh.shell, ShellKind::PosixSh);
    assert!(automatic_sh.fallback);

    let explicit_sh = select_shell(&bash, ShellRequest::Sh).unwrap();
    assert_eq!(explicit_sh.shell, ShellKind::PosixSh);
    assert!(!explicit_sh.fallback);

    let explicit_sh_without_bash = select_shell(&sh, ShellRequest::Sh).unwrap();
    assert_eq!(explicit_sh_without_bash.shell, ShellKind::PosixSh);
    assert!(!explicit_sh_without_bash.fallback);

    let missing = select_shell(&sh, ShellRequest::Bash).unwrap_err();
    assert_eq!(missing.code, ErrorCode::RemoteCapabilityMissing);

    let login = select_shell(&sh, ShellRequest::Login).unwrap();
    assert_eq!(login.shell, ShellKind::Login);
    assert!(!login.fallback);

    let reported_login = capability(ShellKind::Login);
    let automatic_login = select_shell(&reported_login, ShellRequest::Auto).unwrap();
    assert_eq!(automatic_login.shell, ShellKind::PosixSh);
    assert!(automatic_login.fallback);
}

#[test]
fn task78_physical_root_byte_bound_ascii_and_utf8_are_enforced_before_context() {
    let expected = RemotePath::resolve("/srv/project", ".").unwrap();
    for exact in [
        format!("/{}", "a".repeat(65_535)),
        format!("/{}a", "é".repeat(32_767)),
    ] {
        assert_eq!(exact.len(), 65_536);
        let capability =
            parse_probe_output(&sh_probe(expected.absolute(), &exact), &expected).unwrap();
        assert_eq!(capability.physical_root, exact);

        let over = format!("{exact}a");
        assert_eq!(over.len(), 65_537);
        let error =
            parse_probe_output(&sh_probe(expected.absolute(), &over), &expected).unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.details.physical_root, None);
    }
}

#[test]
fn task78_physical_root_byte_bound_bash_version_and_spoofed_values_are_enforced() {
    let expected = RemotePath::resolve("/srv/project", ".").unwrap();
    for exact in ["v".repeat(256), format!("{}aa", "é".repeat(127))] {
        assert_eq!(exact.len(), 256);
        let capability = parse_probe_output(
            &bash_probe_with_version(expected.absolute(), "/srv/project", &exact),
            &expected,
        )
        .unwrap();
        assert_eq!(capability.bash_version.as_deref(), Some(exact.as_str()));
        assert_eq!(
            capability.shell,
            ShellKind::Bash {
                version: exact.clone()
            }
        );

        let over = format!("{exact}a");
        assert_eq!(over.len(), 257);
        let error = parse_probe_output(
            &bash_probe_with_version(expected.absolute(), "/srv/project", &over),
            &expected,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.details.shell, None);
    }

    let spoofed = "$(touch /tmp/codex-ssh-bridge-must-not-run)";
    let capability = parse_probe_output(
        &bash_probe_with_version(expected.absolute(), "/srv/project", spoofed),
        &expected,
    )
    .unwrap();
    assert_eq!(capability.bash_version.as_deref(), Some(spoofed));
}

#[tokio::test]
async fn task78_exact_root_and_bash_version_survive_the_real_capability_cache() {
    let root = format!("/{}a", "é".repeat(32_767));
    let version = format!("{}aa", "é".repeat(127));
    assert_eq!(root.len(), 65_536);
    assert_eq!(version.len(), 256);

    let base = TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let log = base.path().join("cache.log");
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("echo-command"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from(&root)),
        (OsString::from("FAKE_SSH_SHELL"), OsString::from("bash")),
        (
            OsString::from("FAKE_SSH_BASH_VERSION"),
            OsString::from(&version),
        ),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
    ]);
    let runner = SshRunner::with_executable(
        Arc::new(config_with_host("dev", &root)),
        runtime,
        store,
        fake_ssh_path(),
        environment,
    )
    .unwrap();

    for _ in 0..2 {
        let result = runner
            .execute(
                request("dev", ShellRequest::Auto, Duration::from_secs(2)),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.physical_root, root);
        assert_eq!(
            result.shell.shell,
            ShellKind::Bash {
                version: version.clone()
            }
        );
    }
    assert_eq!(
        fs::read_to_string(log)
            .unwrap()
            .lines()
            .filter(|line| *line == "P")
            .count(),
        1
    );
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_cache_callers_share_one_probe_and_one_capability() {
    let cache = Arc::new(CapabilityCache::default());
    let probes = Arc::new(AtomicUsize::new(0));
    let expected = capability(ShellKind::PosixSh);

    let first = {
        let cache = Arc::clone(&cache);
        let probes = Arc::clone(&probes);
        let expected = expected.clone();
        tokio::spawn(async move {
            cache
                .get_or_probe("dev", || async move {
                    probes.fetch_add(1, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    Ok(expected)
                })
                .await
        })
    };
    let second = {
        let cache = Arc::clone(&cache);
        let probes = Arc::clone(&probes);
        let expected = expected.clone();
        tokio::spawn(async move {
            cache
                .get_or_probe("dev", || async move {
                    probes.fetch_add(1, Ordering::SeqCst);
                    Ok(expected)
                })
                .await
        })
    };

    let first = first.await.unwrap().unwrap();
    let second = second.await.unwrap().unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(probes.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_probe_is_not_cached_or_allowed_to_invalidate_another_host() {
    let cache = CapabilityCache::default();
    let healthy_probes = AtomicUsize::new(0);
    let failed_probes = AtomicUsize::new(0);
    let expected = capability(ShellKind::PosixSh);

    cache
        .get_or_probe("healthy", || async {
            healthy_probes.fetch_add(1, Ordering::SeqCst);
            Ok(expected.clone())
        })
        .await
        .unwrap();

    let error = cache
        .get_or_probe("broken", || async {
            failed_probes.fetch_add(1, Ordering::SeqCst);
            Err(BridgeError::new(
                ErrorCode::RemoteCapabilityMissing,
                "probe failed",
                false,
            ))
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteCapabilityMissing);

    cache
        .get_or_probe("broken", || async {
            failed_probes.fetch_add(1, Ordering::SeqCst);
            Ok(expected.clone())
        })
        .await
        .unwrap();
    cache
        .get_or_probe("healthy", || async {
            healthy_probes.fetch_add(1, Ordering::SeqCst);
            Ok(expected.clone())
        })
        .await
        .unwrap();

    assert_eq!(failed_probes.load(Ordering::SeqCst), 2);
    assert_eq!(healthy_probes.load(Ordering::SeqCst), 1);
    assert!(!cache.invalidate("missing").await);
    assert!(cache.invalidate("healthy").await);
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_failed_callers_share_one_outcome_then_a_new_call_retries() {
    let cache = Arc::new(CapabilityCache::default());
    let probes = Arc::new(AtomicUsize::new(0));
    let first_started = Arc::new(Notify::new());
    let release_first = Arc::new(Notify::new());

    let first = {
        let cache = Arc::clone(&cache);
        let probes = Arc::clone(&probes);
        let first_started = Arc::clone(&first_started);
        let release_first = Arc::clone(&release_first);
        tokio::spawn(async move {
            cache
                .get_or_probe("dev", || async move {
                    probes.fetch_add(1, Ordering::SeqCst);
                    first_started.notify_one();
                    release_first.notified().await;
                    Err(BridgeError::new(ErrorCode::Io, "first failure", false))
                })
                .await
        })
    };
    first_started.notified().await;

    let second_entered = Arc::new(Notify::new());
    let second = {
        let cache = Arc::clone(&cache);
        let probes = Arc::clone(&probes);
        let second_entered = Arc::clone(&second_entered);
        tokio::spawn(async move {
            second_entered.notify_one();
            cache
                .get_or_probe("dev", || async move {
                    probes.fetch_add(1, Ordering::SeqCst);
                    Err(BridgeError::new(ErrorCode::Io, "second failure", false))
                })
                .await
        })
    };
    second_entered.notified().await;
    tokio::task::yield_now().await;
    release_first.notify_waiters();

    let first_error = first.await.unwrap().unwrap_err();
    let second_error = second.await.unwrap().unwrap_err();
    assert_eq!(first_error.message, "first failure");
    assert_eq!(second_error.message, "first failure");
    assert_eq!(probes.load(Ordering::SeqCst), 1);

    cache
        .get_or_probe("dev", || async {
            probes.fetch_add(1, Ordering::SeqCst);
            Ok(capability(ShellKind::PosixSh))
        })
        .await
        .unwrap();
    assert_eq!(probes.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_old_generation_cannot_remove_a_new_successful_generation() {
    let cache = Arc::new(CapabilityCache::default());
    let old_started = Arc::new(Notify::new());
    let release_old = Arc::new(Notify::new());

    let old = {
        let cache = Arc::clone(&cache);
        let old_started = Arc::clone(&old_started);
        let release_old = Arc::clone(&release_old);
        tokio::spawn(async move {
            cache
                .get_or_probe("dev", || async move {
                    old_started.notify_one();
                    release_old.notified().await;
                    Err(BridgeError::new(ErrorCode::Io, "old failure", false))
                })
                .await
        })
    };
    old_started.notified().await;
    assert!(cache.invalidate("dev").await);

    cache
        .get_or_probe("dev", || async {
            Ok(capability(ShellKind::Bash {
                version: "5.2.15".to_owned(),
            }))
        })
        .await
        .unwrap();
    release_old.notify_waiters();
    assert_eq!(old.await.unwrap().unwrap_err().message, "old failure");

    let unexpected_probe = AtomicUsize::new(0);
    let cached = cache
        .get_or_probe("dev", || async {
            unexpected_probe.fetch_add(1, Ordering::SeqCst);
            Ok(capability(ShellKind::PosixSh))
        })
        .await
        .unwrap();
    assert!(matches!(cached.shell, ShellKind::Bash { .. }));
    assert_eq!(unexpected_probe.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_probe_leader_does_not_leave_the_host_permanently_in_flight() {
    let cache = Arc::new(CapabilityCache::default());
    let old_started = Arc::new(Notify::new());
    let leader = {
        let cache = Arc::clone(&cache);
        let old_started = Arc::clone(&old_started);
        tokio::spawn(async move {
            cache
                .get_or_probe("dev", || async move {
                    old_started.notify_one();
                    std::future::pending::<codex_ssh_bridge::BridgeResult<Capability>>().await
                })
                .await
        })
    };
    old_started.notified().await;
    leader.abort();
    assert!(leader.await.unwrap_err().is_cancelled());

    let retry = cache.get_or_probe("dev", || async { Ok(capability(ShellKind::PosixSh)) });
    tokio::pin!(retry);
    tokio::select! {
        result = &mut retry => {
            assert_eq!(result.unwrap().shell, ShellKind::PosixSh);
        }
        () = async {
            for _ in 0..100 {
                tokio::task::yield_now().await;
            }
        } => panic!("cancelled probe left the cache permanently in flight"),
    }
}

#[test]
fn fixed_probe_script_emits_parseable_nul_records_and_cleans_its_private_directory() {
    let filesystem = TempDir::new().unwrap();
    let physical = filesystem.path().join("physical root\n\n");
    fs::create_dir(&physical).unwrap();
    let requested = filesystem.path().join("requested root\n");
    symlink(&physical, &requested).unwrap();
    let scratch = TempDir::new().unwrap();
    let requested_text = requested.to_str().unwrap();
    let expected = RemotePath::resolve(requested_text, ".").unwrap();

    let output = Command::new("/bin/sh")
        .args(["-c", CAPABILITY_PROBE_SCRIPT, "probe", requested_text])
        .env("TMPDIR", scratch.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let capability = parse_probe_output(&output.stdout, &expected).unwrap();
    assert_eq!(
        capability.physical_root,
        physical.canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(
        capability.tools.keys().collect::<Vec<_>>(),
        [
            "dd_nofollow",
            "find",
            "find_nul",
            "grep",
            "grep_nul",
            "guarded_delete",
            "ln",
            "mktemp",
            "mv",
            "read_slice",
            "rg",
            "rg_json",
            "safe_write",
            "search_bound",
            "sha256sum",
            "stat",
            "stat_printf",
            "timeout",
            "xargs_nul",
        ]
    );
    for key in [
        "read_slice",
        "find_nul",
        "stat_printf",
        "rg_json",
        "grep_nul",
        "xargs_nul",
        "search_bound",
        "safe_write",
        "guarded_delete",
    ] {
        assert_eq!(
            capability.tools.get(key),
            Some(&true),
            "functional probe {key}"
        );
    }
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn task5_full_probe_reports_functional_mutation_flags() {
    let root = TempDir::new().unwrap();
    let scratch = TempDir::new().unwrap();
    let requested = RemotePath::resolve(root.path().to_str().unwrap(), ".").unwrap();
    let output = Command::new("/bin/sh")
        .args([
            "-c",
            CAPABILITY_PROBE_SCRIPT,
            "probe",
            root.path().to_str().unwrap(),
        ])
        .env("TMPDIR", scratch.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "probe stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let capability = parse_probe_output(&output.stdout, &requested).unwrap();
    assert_eq!(capability.tools.get("safe_write"), Some(&true));
    assert_eq!(capability.tools.get("guarded_delete"), Some(&true));
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn capability_probe_rejects_each_incompatible_exact_behavior() {
    let root = TempDir::new().unwrap();
    let scratch = TempDir::new().unwrap();
    let system_path = "/usr/local/bin:/usr/bin:/bin";
    let cases = [
        (
            "read_slice",
            "tail",
            "case \" $* \" in *codex-probe-read*) exit 64;; esac\nexec /usr/bin/tail \"$@\"\n",
        ),
        (
            "find_nul",
            "find",
            "case \" $* \" in *codex-probe-find*) exit 64;; esac\nexec /usr/bin/find \"$@\"\n",
        ),
        (
            "find_nul",
            "find",
            "case \" $* \" in *codex-probe-find-link*) /usr/bin/find \"$@\" | /usr/bin/sed 's/visible/changed/g'; exit 0;; esac\nexec /usr/bin/find \"$@\"\n",
        ),
        (
            "stat_printf",
            "stat",
            "case \" $* \" in *codex-probe-stat*) exit 64;; esac\nexec /usr/bin/stat \"$@\"\n",
        ),
        ("rg_json", "rg", "exit 64\n"),
        (
            "rg_json",
            "rg",
            "case \" $* \" in *codex-probe-rg-error*) exit 1;; *needle*codex-probe-rg*) shim_out=${TMPDIR:-/tmp}/codex-rg-shim.$$; /usr/bin/rg \"$@\" >\"$shim_out\"; shim_status=$?; /usr/bin/sed 's/\"line_number\":1/\"line_number\":9/g' \"$shim_out\"; rm -f \"$shim_out\"; exit \"$shim_status\";; esac\nexec /usr/bin/rg \"$@\"\n",
        ),
        (
            "grep_nul",
            "grep",
            "case \" $* \" in *-IHnZ*) exit 64;; esac\nexec /usr/bin/grep \"$@\"\n",
        ),
        (
            "xargs_nul",
            "xargs",
            "case \" $* \" in *codex-ssh-probe-xargs*) exit 64;; esac\nexec /usr/bin/xargs \"$@\"\n",
        ),
        (
            "search_bound",
            "head",
            "case \" $* \" in *\" -c 3 \"*) exit 64;; esac\nexec /usr/bin/head \"$@\"\n",
        ),
        (
            "search_bound",
            "mktemp",
            "case \" $* \" in *codex-probe-bound*) exit 64;; esac\nexec /usr/bin/mktemp \"$@\"\n",
        ),
        (
            "search_bound",
            "mkfifo",
            "case \" $* \" in *codex-probe-bound*) exit 64;; esac\nexec /usr/bin/mkfifo \"$@\"\n",
        ),
        (
            "search_bound",
            "xargs",
            "case \" $* \" in *codex-ssh-probe-bound-xargs*) exit 0;; esac\nexec /usr/bin/xargs \"$@\"\n",
        ),
        (
            "search_bound",
            "rm",
            "case \" $* \" in *codex-probe-bound.*) exit 0;; esac\nexec /usr/bin/rm \"$@\"\n",
        ),
        (
            "safe_write",
            "stat",
            "case \" $* \" in *\" -L \"*codex-probe-safe-write/followed-parent-link*) exit 64;; esac\nexec /usr/bin/stat \"$@\"\n",
        ),
        (
            "safe_write",
            "mktemp",
            "case \" $* \" in *--tmpdir=*codex-probe-safe-write*.codex-ssh-bridge.*) exit 64;; esac\nexec /usr/bin/mktemp \"$@\"\n",
        ),
        (
            "safe_write",
            "dd",
            "case \" $* \" in *codex-probe-safe-write*bs=262144*oflag=nofollow*) exit 64;; esac\nexec /usr/bin/dd \"$@\"\n",
        ),
        (
            "safe_write",
            "dd",
            "case \" $* \" in *codex-probe-safe-write*bs=262144*iflag=nofollow*) /usr/bin/dd \"$@\"; exit 7;; esac\nexec /usr/bin/dd \"$@\"\n",
        ),
        (
            "safe_write",
            "stat",
            "case \" $* \" in *codex-probe-safe-write/.codex-ssh-bridge.*) printf '81a4:0:600:7:1:2:1:extra\\n'; exit 0;; esac\nexec /usr/bin/stat \"$@\"\n",
        ),
        (
            "safe_write",
            "stat",
            "case \" $* \" in *codex-probe-safe-write/.codex-ssh-bridge.*) printf '81a4:0:600:7:1:*:1\\n'; exit 0;; esac\nexec /usr/bin/stat \"$@\"\n",
        ),
        (
            "safe_write",
            "stat",
            "case \" $* \" in *\" --printf=%f:%u:%a:%s:%d:%i:%h\\n -- \"*codex-probe-safe-write*) line=$(/usr/bin/stat \"$@\") || exit $?; old_ifs=$IFS; IFS=:; set -- $line; IFS=$old_ifs; printf '%s:%s:%s:%s:123456789012345678901:123456789012345678901:%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$7\"; exit 0;; esac\nexec /usr/bin/stat \"$@\"\n",
        ),
        (
            "safe_write",
            "stat",
            "case \" $* \" in *\" --printf=%f:%u:%a:%s:%d:%i:%h\\n -- \"*codex-probe-safe-write*) line=$(/usr/bin/stat \"$@\") || exit $?; old_ifs=$IFS; IFS=:; set -- $line; IFS=$old_ifs; printf '%s:%s:%s:%s:18446744073709551616:18446744073709551616:%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$7\"; exit 0;; esac\nexec /usr/bin/stat \"$@\"\n",
        ),
        (
            "safe_write",
            "stat",
            "case \" $* \" in *\" --printf=%f:%u:%a:%s:%d:%i:%h\\n -- \"*codex-probe-safe-write/dd-link*) printf '8180:0:600:7:1:2:1\\n'; exit 0;; esac\nexec /usr/bin/stat \"$@\"\n",
        ),
        (
            "safe_write",
            "id",
            "case \" $* \" in *\" -u \"*) exit 64;; esac\nexec /usr/bin/id \"$@\"\n",
        ),
        (
            "safe_write",
            "chmod",
            "case \" $* \" in *codex-probe-safe-write*chmod-link*) exit 64;; esac\nexec /usr/bin/chmod \"$@\"\n",
        ),
        (
            "guarded_delete",
            "stat",
            "case \" $* \" in *\" -L \"*codex-probe-guarded-delete*) exit 64;; esac\nexec /usr/bin/stat \"$@\"\n",
        ),
        (
            "guarded_delete",
            "stat",
            "case \" $* \" in *codex-probe-guarded-delete*target:*) marker=${TMPDIR:-/tmp}/task5-delete-stat-count; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); if [ \"$count\" -eq 2 ]; then /usr/bin/rm -f \"$marker\"; printf 'a1ff:0:777:7:1:2:1\\n'; exit 0; fi; printf %s \"$count\" >\"$marker\";; esac\nexec /usr/bin/stat \"$@\"\n",
        ),
        (
            "guarded_delete",
            "dd",
            "case \" $* \" in *codex-probe-guarded-delete*bs=262144*iflag=nofollow*) marker=${TMPDIR:-/tmp}/task5-guarded-hash-count; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); if [ \"$count\" -eq 2 ]; then /usr/bin/rm -f \"$marker\"; exit 64; fi; printf %s \"$count\" >\"$marker\";; esac\nexec /usr/bin/dd \"$@\"\n",
        ),
        (
            "safe_write",
            "ln",
            "case \" $* \" in *codex-probe-safe-write*created*) exit 0;; esac\nexec /usr/bin/ln \"$@\"\n",
        ),
        (
            "safe_write",
            "ln",
            "case \" $* \" in *\" -T -- \"*codex-probe-safe-write*directory-link*) shift 2; exec /usr/bin/ln -- \"$@\";; esac\nexec /usr/bin/ln \"$@\"\n",
        ),
        (
            "safe_write",
            "mv",
            "case \" $* \" in *codex-probe-safe-write*replaced*) exit 0;; esac\nexec /usr/bin/mv \"$@\"\n",
        ),
        (
            "safe_write",
            "rm",
            "case \" $* \" in *\" -f -- \"*codex-probe-safe-write*created*) exit 0;; esac\nexec /usr/bin/rm \"$@\"\n",
        ),
        (
            "guarded_delete",
            "rm",
            "case \" $* \" in *codex-probe-guarded-delete*target:*) exit 0;; esac\nexec /usr/bin/rm \"$@\"\n",
        ),
    ];

    for (expected_false, tool, body) in cases {
        let shim = TempDir::new().unwrap();
        let executable = shim.path().join(tool);
        fs::write(&executable, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let output = Command::new("/bin/sh")
            .args([
                "-c",
                CAPABILITY_PROBE_SCRIPT,
                "probe",
                root.path().to_str().unwrap(),
            ])
            .env("PATH", format!("{}:{system_path}", shim.path().display()))
            .env("TMPDIR", scratch.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{expected_false}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected_root = RemotePath::resolve(root.path().to_str().unwrap(), ".").unwrap();
        let capability = parse_probe_output(&output.stdout, &expected_root).unwrap();
        for key in [
            "read_slice",
            "find_nul",
            "stat_printf",
            "rg_json",
            "grep_nul",
            "xargs_nul",
            "search_bound",
            "safe_write",
            "guarded_delete",
        ] {
            assert_eq!(
                capability.tools.get(key),
                Some(&(key != expected_false)),
                "shim={tool}, key={key}"
            );
        }
        assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
    }
}

#[test]
fn task5_mutation_hash_probe_is_closed_and_restores_shell_state() {
    let root = TempDir::new().unwrap();
    let scratch = TempDir::new().unwrap();
    let shim = TempDir::new().unwrap();
    let count_path = shim.path().join("sha-count");
    let executable = shim.path().join("sha256sum");
    fs::write(
        &executable,
        format!(
            "#!/bin/sh\nmarker={}\ncount=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0)\ncount=$((count + 1))\nprintf %s \"$count\" >\"$marker\"\nif [ \"$count\" -eq 2 ]; then printf 'CODEX_DD_STATUS=0\\nMALFORMED\\n'; fi\nexec /usr/bin/sha256sum \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(count_path.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new("/bin/sh")
        .args([
            "-c",
            CAPABILITY_PROBE_SCRIPT,
            "probe",
            root.path().to_str().unwrap(),
        ])
        .env(
            "PATH",
            format!("{}:/usr/local/bin:/usr/bin:/bin", shim.path().display()),
        )
        .env("TMPDIR", scratch.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "probe stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected_root = RemotePath::resolve(root.path().to_str().unwrap(), ".").unwrap();
    let capability = parse_probe_output(&output.stdout, &expected_root).unwrap();
    assert_eq!(capability.tools.get("safe_write"), Some(&true));
    assert_eq!(capability.tools.get("guarded_delete"), Some(&true));
    assert_eq!(fs::read_to_string(count_path).unwrap(), "5");
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn task5_shared_hash_failure_closes_only_mutation_capabilities() {
    let root = TempDir::new().unwrap();
    let scratch = TempDir::new().unwrap();
    let shim = TempDir::new().unwrap();
    let executable = shim.path().join("sha256sum");
    fs::write(&executable, "#!/bin/sh\nexit 64\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new("/bin/sh")
        .args([
            "-c",
            CAPABILITY_PROBE_SCRIPT,
            "probe",
            root.path().to_str().unwrap(),
        ])
        .env(
            "PATH",
            format!("{}:/usr/local/bin:/usr/bin:/bin", shim.path().display()),
        )
        .env("TMPDIR", scratch.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let expected_root = RemotePath::resolve(root.path().to_str().unwrap(), ".").unwrap();
    let capability = parse_probe_output(&output.stdout, &expected_root).unwrap();
    assert_eq!(capability.tools.get("safe_write"), Some(&false));
    assert_eq!(capability.tools.get("guarded_delete"), Some(&false));
    for key in [
        "read_slice",
        "find_nul",
        "stat_printf",
        "rg_json",
        "grep_nul",
        "xargs_nul",
        "search_bound",
    ] {
        assert_eq!(capability.tools.get(key), Some(&true), "key={key}");
    }
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn local_fixed_executes_the_real_capability_probe() {
    let root = TempDir::new().unwrap();
    let scratch = TempDir::new().unwrap();
    let command = format!(
        "exec sh -c {} codex-ssh-probe {}",
        codex_ssh_bridge::quote::shell_word(CAPABILITY_PROBE_SCRIPT).unwrap(),
        codex_ssh_bridge::quote::shell_word(root.path().to_str().unwrap()).unwrap()
    );
    let output = Command::new(fake_ssh_path())
        .args(["dev", &command])
        .env("FAKE_SSH_MODE", "local-fixed")
        .env("FAKE_SSH_ROOT", root.path())
        .env("FAKE_SSH_HAS_READ_SLICE", "0")
        .env("TMPDIR", scratch.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let expected = RemotePath::resolve(root.path().to_str().unwrap(), ".").unwrap();
    let capability = parse_probe_output(&output.stdout, &expected).unwrap();
    assert_eq!(capability.tools.get("read_slice"), Some(&true));
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

struct RunnerFixture {
    _base: TempDir,
    runtime: RuntimePaths,
    store: Arc<OutputStore>,
    runner: Arc<SshRunner>,
}

fn task3_config(hosts: &[&str], limits: Limits) -> Arc<Config> {
    let hosts = hosts
        .iter()
        .map(|alias| {
            (
                (*alias).to_owned(),
                HostProfile {
                    root: "/srv/project".to_owned(),
                    description: None,
                    read_only: false,
                    limits: Default::default(),
                },
            )
        })
        .collect();
    Arc::new(Config {
        limits,
        hosts,
        ..Config::default()
    })
}

fn task3_runner(
    hosts: &[&str],
    limits: Limits,
    ttl: Duration,
    environment: &[(&str, String)],
) -> RunnerFixture {
    let base = TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let store = Arc::new(OutputStore::with_ttl(&runtime, ttl).unwrap());
    let environment = environment
        .iter()
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect();
    let runner = Arc::new(
        SshRunner::with_executable(
            task3_config(hosts, limits),
            runtime.clone(),
            Arc::clone(&store),
            fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    RunnerFixture {
        _base: base,
        runtime,
        store,
        runner,
    }
}

fn request(host: &str, shell: ShellRequest, timeout: Duration) -> RunRequest {
    RunRequest {
        host: host.to_owned(),
        command: "printf safe".to_owned(),
        cwd: "/srv/project".to_owned(),
        shell,
        stdin: None,
        timeout,
    }
}

#[tokio::test]
async fn task78_run_cwd_is_encoded_as_data_and_never_executed() {
    let filesystem = TempDir::new().unwrap();
    let sentinel = filesystem.path().join("cwd-injection");
    let hostile_cwd = format!("'; touch {}; '", sentinel.display());
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[("FAKE_SSH_MODE", "echo-command".to_owned())],
    );
    let mut run = request("dev", ShellRequest::Sh, Duration::from_secs(2));
    run.cwd = hostile_cwd;
    let result = fixture
        .runner
        .execute(run, CancellationToken::new())
        .await
        .unwrap();
    let rendered = String::from_utf8(preview_bytes(&result.output.stdout)).unwrap();
    assert!(rendered.contains("codex-ssh-bridge-run"), "{rendered}");
    assert!(!sentinel.exists());
}

#[tokio::test]
async fn task78_run_rejects_quote_expansion_over_frame_before_command_child() {
    let log_dir = TempDir::new().unwrap();
    let log = log_dir.path().join("calls.log");
    let limits = Limits {
        max_frame_bytes: 512,
        ..Limits::default()
    };
    let fixture = task3_runner(
        &["dev"],
        limits,
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "echo-command".to_owned()),
            ("FAKE_SSH_LOG", log.display().to_string()),
        ],
    );
    let mut run = request("dev", ShellRequest::Sh, Duration::from_secs(2));
    run.command = "'".repeat(200);
    assert!(run.command.len() < 512);
    let error = fixture
        .runner
        .execute(run, CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge);
    assert_eq!(
        fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|line| *line == "C")
            .count(),
        0
    );
}

fn preview_bytes(preview: &codex_ssh_bridge::output::OutputPreview) -> Vec<u8> {
    let mut bytes = preview.head.clone();
    bytes.extend_from_slice(&preview.tail);
    bytes
}

async fn wait_for_log_marker(path: &std::path::Path, marker: &str) {
    timeout(Duration::from_secs(2), async {
        loop {
            if fs::read_to_string(path)
                .unwrap_or_default()
                .lines()
                .any(|line| line == marker)
            {
                return;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("fake SSH marker");
}

async fn wait_for_file(path: &std::path::Path) {
    timeout(Duration::from_secs(2), async {
        while !path.exists() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("fake SSH file");
}

async fn wait_for_process_exit(pid: u32) {
    let process = std::path::PathBuf::from(format!("/proc/{pid}"));
    timeout(Duration::from_millis(200), async {
        while process.exists() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("fake SSH child survived process-group cancellation");
}

fn force_kill_process(pid: u32) {
    let _ = Command::new("/bin/kill")
        .args(["-KILL", &pid.to_string()])
        .status();
}

#[tokio::test]
async fn runner_resolves_once_probes_once_and_uses_hardened_ssh_g() {
    let log_dir = TempDir::new().unwrap();
    let log = log_dir.path().join("calls.log");
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "echo-command".to_owned()),
            ("FAKE_SSH_LOG", log.display().to_string()),
        ],
    );

    for _ in 0..2 {
        fixture
            .runner
            .execute(
                request("dev", ShellRequest::Auto, Duration::from_secs(2)),
                CancellationToken::new(),
            )
            .await
            .unwrap();
    }

    let calls = fs::read_to_string(log).unwrap();
    assert_eq!(calls.lines().filter(|line| *line == "G").count(), 1);
    assert_eq!(calls.lines().filter(|line| *line == "P").count(), 1);
    assert_eq!(calls.lines().filter(|line| *line == "C").count(), 2);
    for option in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "RequestTTY=no",
        "ControlPersist=300",
    ] {
        assert!(calls.contains(&format!("arg={option}")), "{calls}");
    }
    let config_call = calls.split("END\n").next().unwrap();
    assert!(!config_call.contains("ControlMaster="));
    assert!(!config_call.contains("ControlPath="));
    assert!(config_call.contains("arg=--\narg=dev\n"));
}

#[tokio::test]
async fn ssh_g_identity_accepts_non_utf8_bytes_without_exposing_raw_config() {
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "echo-command".to_owned()),
            ("FAKE_SSH_G_NON_UTF8", "1".to_owned()),
        ],
    );
    let result = fixture
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_secs(2)),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.status, 0);
    assert!(!preview_bytes(&result.output.stdout).contains(&0xff));
}

#[tokio::test]
async fn ssh_g_enforces_independent_stdout_and_stderr_bounds() {
    for (name, environment) in [
        (
            "stdout",
            vec![("FAKE_SSH_G_STDOUT_BYTES", (1024 * 1024 + 1).to_string())],
        ),
        (
            "stderr",
            vec![("FAKE_SSH_G_STDERR_BYTES", (64 * 1024 + 1).to_string())],
        ),
    ] {
        let fixture = task3_runner(
            &["dev"],
            Limits::default(),
            Duration::from_secs(600),
            &environment,
        );
        let error = fixture
            .runner
            .execute(
                request("dev", ShellRequest::Auto, Duration::from_secs(2)),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError, "{name}");
        assert!(!error.message.contains("fake.internal"));
        assert!(private_spool_files(&fixture.runtime).is_empty());
    }
}

#[tokio::test]
async fn command_stdin_is_streamed_and_oversized_input_is_rejected_before_ssh() {
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[("FAKE_SSH_MODE", "stdin".to_owned())],
    );
    let mut run = request("dev", ShellRequest::Auto, Duration::from_secs(2));
    run.stdin = Some(b"stdin\0bytes\n".to_vec());
    let result = fixture
        .runner
        .execute(run, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(preview_bytes(&result.output.stdout), b"stdin\0bytes\n");

    let mut oversized = request("dev", ShellRequest::Auto, Duration::from_secs(2));
    oversized.stdin = Some(vec![0; codex_ssh_bridge::MAX_WRITE_BYTES + 1]);
    let error = fixture
        .runner
        .execute(oversized, CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge);
}

#[tokio::test]
async fn selected_shell_and_remote_gnu_timeout_are_reported_and_rendered_exactly() {
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "echo-command".to_owned()),
            ("FAKE_SSH_HAS_TIMEOUT", "1".to_owned()),
        ],
    );
    let result = fixture
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_millis(123)),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(result.status, 0);
    assert_eq!(result.shell.shell, ShellKind::PosixSh);
    assert!(result.shell.fallback);
    assert!(!result.remote_process_may_continue);
    let rendered = String::from_utf8(preview_bytes(&result.output.stdout)).unwrap();
    assert_eq!(
        rendered,
        concat!(
            "exec sh -c 'set -u\n",
            "[ \"$#\" -eq 3 ] || exit 2\n",
            "cd -- \"$1\" || exit 126\n",
            "if [ -n \"$3\" ]; then\n",
            "    exec timeout --signal=TERM --kill-after=1s \"$3\" sh -c \"$2\"\n",
            "fi\n",
            "exec sh -c \"$2\"' codex-ssh-bridge-run '/srv/project' 'printf safe' '0.123s'"
        )
    );
}

#[test]
fn capability_probe_functionally_rejects_an_incompatible_timeout() {
    let filesystem = TempDir::new().unwrap();
    let root = filesystem.path().join("root");
    fs::create_dir(&root).unwrap();
    let fake_bin = filesystem.path().join("bin");
    fs::create_dir(&fake_bin).unwrap();
    let fake_timeout = fake_bin.join("timeout");
    fs::write(&fake_timeout, "#!/bin/sh\nexit 125\n").unwrap();
    fs::set_permissions(&fake_timeout, fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths(std::iter::once(fake_bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    let expected = RemotePath::resolve(root.to_str().unwrap(), ".").unwrap();
    let output = Command::new("/bin/sh")
        .args([
            "-c",
            CAPABILITY_PROBE_SCRIPT,
            "probe",
            root.to_str().unwrap(),
        ])
        .env("PATH", path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let capability = parse_probe_output(&output.stdout, &expected).unwrap();
    assert_eq!(capability.tools.get("timeout"), Some(&false));
}

#[tokio::test]
async fn login_shell_is_raw_and_never_remote_timeout_wrapped() {
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "echo-command".to_owned()),
            ("FAKE_SSH_HAS_TIMEOUT", "1".to_owned()),
        ],
    );
    let result = fixture
        .runner
        .execute(
            request("dev", ShellRequest::Login, Duration::from_millis(123)),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.shell.shell, ShellKind::Login);
    assert_eq!(
        preview_bytes(&result.output.stdout),
        b"cd -- '/srv/project' || exit 126\nprintf safe"
    );
}

#[tokio::test]
async fn transport_and_remote_failures_have_stable_codes_without_diagnostics() {
    let bootstrap_cases = [
        ("host-key", ErrorCode::HostKeyUnknown, false),
        ("host-key-ed25519", ErrorCode::HostKeyUnknown, false),
        ("host-key-rsa", ErrorCode::HostKeyUnknown, false),
        ("host-key-ecdsa", ErrorCode::HostKeyUnknown, false),
        ("auth", ErrorCode::AuthRequired, false),
        ("connect-timeout", ErrorCode::ConnectTimeout, true),
    ];
    for (kind, code, retryable) in bootstrap_cases {
        let fixture = task3_runner(
            &["dev"],
            Limits::default(),
            Duration::from_secs(600),
            &[("FAKE_SSH_PROBE_ERROR", kind.to_owned())],
        );
        let error = fixture
            .runner
            .execute(
                request("dev", ShellRequest::Auto, Duration::from_secs(2)),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, code, "{kind}");
        assert_eq!(error.retryable, retryable, "{kind}");
        assert!(!error.message.contains("VERY_SECRET"), "{error:?}");
    }

    let resolve = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[("FAKE_SSH_G_ERROR", "host-key".to_owned())],
    );
    let error = resolve
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_secs(2)),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::HostKeyUnknown);

    let resolve_non_255 = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_G_ERROR", "host-key".to_owned()),
            ("FAKE_SSH_ERROR_STATUS", "7".to_owned()),
        ],
    );
    let error = resolve_non_255
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_secs(2)),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteExit);
    assert!(!error.retryable);
    assert_eq!(error.details.exit_status, Some(7));

    let remote = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "error".to_owned()),
            ("FAKE_SSH_ERROR", "remote".to_owned()),
        ],
    );
    let error = remote
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_secs(2)),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteExit);
    assert!(!error.retryable);
    assert_eq!(error.details.exit_status, Some(7));
    assert!(!error.message.contains("VERY_SECRET"));
}

#[tokio::test]
async fn command_phase_exit_255_canonical_lines_are_nonretryable_remote_exit() {
    let shells = [
        ("sh", ShellRequest::Auto),
        ("bash", ShellRequest::Bash),
        ("sh", ShellRequest::Login),
    ];
    for (reported_shell, request_shell) in shells {
        for diagnostic in ["host-key", "auth", "connect-timeout"] {
            let fixture = task3_runner(
                &["dev"],
                Limits::default(),
                Duration::from_secs(600),
                &[
                    ("FAKE_SSH_MODE", "error".to_owned()),
                    ("FAKE_SSH_ERROR", diagnostic.to_owned()),
                    ("FAKE_SSH_SHELL", reported_shell.to_owned()),
                ],
            );
            let error = fixture
                .runner
                .execute(
                    request("dev", request_shell, Duration::from_secs(2)),
                    CancellationToken::new(),
                )
                .await
                .unwrap_err();
            assert_eq!(
                error.code,
                ErrorCode::RemoteExit,
                "shell={request_shell:?} diagnostic={diagnostic}"
            );
            assert!(!error.retryable);
            assert_eq!(error.details.exit_status, Some(255));
            assert_eq!(error.details.remote_process_may_continue, Some(true));
            assert_eq!(error.message, "remote command exited unsuccessfully");
            assert!(!error.message.contains("VERY_SECRET"));
        }
    }
}

#[tokio::test]
async fn fuzzy_or_remote_spoofed_exit_255_diagnostics_are_not_transport_failures() {
    let diagnostics = [
        "Host key verification failed. trailing text",
        "remote: Host key verification failed.",
        "fixture@fake.internal: Permission denied (publickey). trailing text",
        "Permission denied (publickey).",
        "ssh: connect to host fake.internal port 22: Connection timed out trailing text",
        "remote: ssh: connect to host fake.internal port 22: Connection timed out",
        "connection timed out",
    ];
    for diagnostic in diagnostics {
        let fixture = task3_runner(
            &["dev"],
            Limits::default(),
            Duration::from_secs(600),
            &[
                ("FAKE_SSH_MODE", "error".to_owned()),
                ("FAKE_SSH_ERROR", "diagnostic".to_owned()),
                ("FAKE_SSH_DIAGNOSTIC", diagnostic.to_owned()),
            ],
        );
        let error = fixture
            .runner
            .execute(
                request("dev", ShellRequest::Auto, Duration::from_secs(2)),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::RemoteExit, "{diagnostic:?}");
        assert!(!error.retryable, "{diagnostic:?}");
        assert_eq!(error.details.exit_status, Some(255), "{diagnostic:?}");
    }
}

#[tokio::test]
async fn missing_requested_shell_is_a_capability_error() {
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[("FAKE_SSH_MODE", "echo-command".to_owned())],
    );
    let error = fixture
        .runner
        .execute(
            request("dev", ShellRequest::Bash, Duration::from_secs(2)),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteCapabilityMissing);
}

#[tokio::test]
async fn local_deadline_and_gnu_timeout_status_are_command_timeouts() {
    let local = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "sleep".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "2".to_owned()),
        ],
    );
    let error = local
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_millis(80)),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::CommandTimeout);
    assert_eq!(error.details.remote_process_may_continue, Some(true));

    let remote = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "error".to_owned()),
            ("FAKE_SSH_ERROR", "remote".to_owned()),
            ("FAKE_SSH_EXIT_STATUS", "124".to_owned()),
            ("FAKE_SSH_HAS_TIMEOUT", "1".to_owned()),
        ],
    );
    let error = remote
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_secs(1)),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::CommandTimeout);
}

fn assert_task78_selected_context(error: &BridgeError, expected_code: ErrorCode) {
    assert_eq!(error.code, expected_code, "{error:?}");
    assert_eq!(error.details.host.as_deref(), Some("dev"));
    assert_eq!(error.details.physical_root.as_deref(), Some("/srv/project"));
    let shell = error
        .details
        .shell
        .as_ref()
        .expect("selected shell metadata");
    assert_eq!(shell.kind, "sh");
    assert_eq!(shell.version, None);
    assert!(shell.fallback);
}

#[tokio::test]
async fn task78_selected_remote_context_is_attached_to_exit_timeout_cancel_and_output_limit() {
    let exited = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "error".to_owned()),
            ("FAKE_SSH_ERROR", "remote".to_owned()),
        ],
    );
    let error = exited
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_secs(2)),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_task78_selected_context(&error, ErrorCode::RemoteExit);

    let timed_out = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "sleep".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "2".to_owned()),
        ],
    );
    let error = timed_out
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_millis(50)),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_task78_selected_context(&error, ErrorCode::CommandTimeout);

    let cancel_log_dir = TempDir::new().unwrap();
    let cancel_log = cancel_log_dir.path().join("calls.log");
    let cancelled = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "sleep".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "2".to_owned()),
            ("FAKE_SSH_LOG", cancel_log.display().to_string()),
        ],
    );
    let token = CancellationToken::new();
    let operation = {
        let runner = Arc::clone(&cancelled.runner);
        let token = token.clone();
        tokio::spawn(async move {
            runner
                .execute(
                    request("dev", ShellRequest::Auto, Duration::from_secs(2)),
                    token,
                )
                .await
        })
    };
    wait_for_log_marker(&cancel_log, "C").await;
    token.cancel();
    let error = operation.await.unwrap().unwrap_err();
    assert_task78_selected_context(&error, ErrorCode::Cancelled);

    let output_limits = Limits {
        max_output_bytes: 1_024,
        preview_bytes: 512,
        ..Limits::default()
    };
    let limited = task3_runner(
        &["dev"],
        output_limits,
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "bytes".to_owned()),
            ("FAKE_SSH_STDOUT_BYTES", "2048".to_owned()),
        ],
    );
    let error = limited
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_secs(2)),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_task78_selected_context(&error, ErrorCode::OutputLimit);
}

#[tokio::test]
async fn five_commands_are_not_head_of_line_blocked() {
    let hosts = ["one", "two", "three", "four", "five"];
    let fixture = task3_runner(
        &hosts,
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "sleep".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "1".to_owned()),
        ],
    );
    let started = Instant::now();
    let mut tasks = JoinSet::new();
    for host in hosts {
        let runner = Arc::clone(&fixture.runner);
        tasks.spawn(async move {
            runner
                .execute(
                    request(host, ShellRequest::Auto, Duration::from_secs(3)),
                    CancellationToken::new(),
                )
                .await
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap().unwrap();
    }
    assert!(started.elapsed() < Duration::from_millis(1_500));
}

#[tokio::test]
async fn cancellation_kills_the_child_group_quickly() {
    let log_dir = TempDir::new().unwrap();
    let log = log_dir.path().join("calls.log");
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "sleep".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "10".to_owned()),
            ("FAKE_SSH_IGNORE_TERM", "1".to_owned()),
            ("FAKE_SSH_LOG", log.display().to_string()),
        ],
    );
    let cancel = CancellationToken::new();
    let task = {
        let runner = Arc::clone(&fixture.runner);
        let cancel = cancel.clone();
        tokio::spawn(async move {
            runner
                .execute(
                    request("dev", ShellRequest::Auto, Duration::from_secs(20)),
                    cancel,
                )
                .await
        })
    };
    wait_for_log_marker(&log, "C").await;
    let started = Instant::now();
    cancel.cancel();
    let error = timeout(Duration::from_millis(250), task)
        .await
        .expect("cancellation exceeded 250 ms")
        .unwrap()
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_millis(250));
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(error.details.remote_process_may_continue, Some(true));
}

#[tokio::test]
async fn cancellation_during_ssh_g_kills_its_group_without_remote_detach_warning() {
    let files = TempDir::new().unwrap();
    let log = files.path().join("calls.log");
    let pid_file = files.path().join("child.pid");
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "echo-command".to_owned()),
            ("FAKE_SSH_G_SLEEP_SECONDS", "10".to_owned()),
            ("FAKE_SSH_IGNORE_TERM", "1".to_owned()),
            ("FAKE_SSH_LOG", log.display().to_string()),
            ("FAKE_SSH_CHILD_PID_FILE", pid_file.display().to_string()),
        ],
    );
    let cancel = CancellationToken::new();
    let task = {
        let runner = Arc::clone(&fixture.runner);
        let token = cancel.clone();
        tokio::spawn(async move {
            runner
                .execute(
                    request("dev", ShellRequest::Auto, Duration::from_secs(20)),
                    token,
                )
                .await
        })
    };
    wait_for_log_marker(&log, "G").await;
    wait_for_file(&pid_file).await;
    let pid = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    cancel.cancel();
    let error = timeout(Duration::from_millis(250), task)
        .await
        .expect("ssh -G cancellation exceeded 250 ms")
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(error.details.remote_process_may_continue, Some(false));
    wait_for_process_exit(pid).await;
}

#[tokio::test]
async fn cancellation_interrupts_a_follower_waiting_for_first_host_initialization() {
    let files = TempDir::new().unwrap();
    let log = files.path().join("calls.log");
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "echo-command".to_owned()),
            ("FAKE_SSH_G_SLEEP_SECONDS", "10".to_owned()),
            ("FAKE_SSH_LOG", log.display().to_string()),
        ],
    );
    let first_cancel = CancellationToken::new();
    let first = {
        let runner = Arc::clone(&fixture.runner);
        let token = first_cancel.clone();
        tokio::spawn(async move {
            runner
                .execute(
                    request("dev", ShellRequest::Auto, Duration::from_secs(20)),
                    token,
                )
                .await
        })
    };
    wait_for_log_marker(&log, "G").await;

    let follower_cancel = CancellationToken::new();
    let mut follower = {
        let runner = Arc::clone(&fixture.runner);
        let token = follower_cancel.clone();
        tokio::spawn(async move {
            runner
                .execute(
                    request("dev", ShellRequest::Auto, Duration::from_secs(20)),
                    token,
                )
                .await
        })
    };
    sleep(Duration::from_millis(20)).await;
    follower_cancel.cancel();
    let follower_result = timeout(Duration::from_millis(250), &mut follower).await;
    first_cancel.cancel();
    first.await.unwrap().unwrap_err();
    let error = match follower_result {
        Ok(result) => result.unwrap().unwrap_err(),
        Err(_) => {
            follower.abort();
            let _ = follower.await;
            panic!("cancelled identity-cache follower remained blocked")
        }
    };
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(error.details.remote_process_may_continue, Some(false));
}

#[tokio::test]
async fn cancellation_during_capability_probe_is_remote_best_effort_and_kills_the_group() {
    let files = TempDir::new().unwrap();
    let log = files.path().join("calls.log");
    let pid_file = files.path().join("child.pid");
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_PROBE_SLEEP_SECONDS", "10".to_owned()),
            ("FAKE_SSH_IGNORE_TERM", "1".to_owned()),
            ("FAKE_SSH_LOG", log.display().to_string()),
            ("FAKE_SSH_CHILD_PID_FILE", pid_file.display().to_string()),
        ],
    );
    let cancel = CancellationToken::new();
    let task = {
        let runner = Arc::clone(&fixture.runner);
        let token = cancel.clone();
        tokio::spawn(async move {
            runner
                .execute(
                    request("dev", ShellRequest::Auto, Duration::from_secs(20)),
                    token,
                )
                .await
        })
    };
    wait_for_log_marker(&log, "P").await;
    wait_for_file(&pid_file).await;
    let pid = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    cancel.cancel();
    let error = timeout(Duration::from_millis(250), task)
        .await
        .expect("probe cancellation exceeded 250 ms")
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(error.details.remote_process_may_continue, Some(true));
    wait_for_process_exit(pid).await;
}

#[tokio::test]
async fn cancellation_still_kills_pipe_inheriting_descendants_after_ssh_parent_exit() {
    let files = TempDir::new().unwrap();
    let pid_file = files.path().join("child.pid");
    let parent_exit = files.path().join("parent.exit");
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "orphan-streams".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "10".to_owned()),
            ("FAKE_SSH_CHILD_PID_FILE", pid_file.display().to_string()),
            (
                "FAKE_SSH_PARENT_EXIT_FILE",
                parent_exit.display().to_string(),
            ),
        ],
    );
    let cancel = CancellationToken::new();
    let mut task = {
        let runner = Arc::clone(&fixture.runner);
        let token = cancel.clone();
        tokio::spawn(async move {
            runner
                .execute(
                    request("dev", ShellRequest::Auto, Duration::from_secs(20)),
                    token,
                )
                .await
        })
    };
    wait_for_file(&pid_file).await;
    wait_for_file(&parent_exit).await;
    let pid = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    sleep(Duration::from_millis(20)).await;
    cancel.cancel();
    let result = timeout(Duration::from_millis(250), &mut task).await;
    let error = match result {
        Ok(result) => result.unwrap().unwrap_err(),
        Err(_) => {
            force_kill_process(pid);
            let _ = timeout(Duration::from_millis(250), &mut task).await;
            task.abort();
            panic!("cancel was ignored after the SSH parent exited")
        }
    };
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(error.details.remote_process_may_continue, Some(true));
    wait_for_process_exit(pid).await;
}

#[tokio::test]
async fn deadline_still_kills_pipe_inheriting_descendants_after_ssh_parent_exit() {
    let files = TempDir::new().unwrap();
    let pid_file = files.path().join("child.pid");
    let parent_exit = files.path().join("parent.exit");
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "orphan-streams".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "10".to_owned()),
            ("FAKE_SSH_CHILD_PID_FILE", pid_file.display().to_string()),
            (
                "FAKE_SSH_PARENT_EXIT_FILE",
                parent_exit.display().to_string(),
            ),
        ],
    );
    let mut task = {
        let runner = Arc::clone(&fixture.runner);
        tokio::spawn(async move {
            runner
                .execute(
                    request("dev", ShellRequest::Auto, Duration::from_millis(80)),
                    CancellationToken::new(),
                )
                .await
        })
    };
    wait_for_file(&pid_file).await;
    wait_for_file(&parent_exit).await;
    let pid = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let result = timeout(Duration::from_millis(450), &mut task).await;
    let error = match result {
        Ok(result) => result.unwrap().unwrap_err(),
        Err(_) => {
            force_kill_process(pid);
            let _ = timeout(Duration::from_millis(250), &mut task).await;
            task.abort();
            panic!("deadline was ignored after the SSH parent exited")
        }
    };
    assert_eq!(error.code, ErrorCode::CommandTimeout);
    assert_eq!(error.details.remote_process_may_continue, Some(true));
    wait_for_process_exit(pid).await;
}

#[tokio::test]
async fn cancellation_kills_an_orphan_stdin_holder_after_ssh_parent_exit() {
    let files = TempDir::new().unwrap();
    let pid_file = files.path().join("child.pid");
    let ready_file = files.path().join("child.ready");
    let parent_exit = files.path().join("parent.exit");
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "orphan-stdin".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "10".to_owned()),
            ("FAKE_SSH_CHILD_PID_FILE", pid_file.display().to_string()),
            (
                "FAKE_SSH_CHILD_READY_FILE",
                ready_file.display().to_string(),
            ),
            (
                "FAKE_SSH_PARENT_EXIT_FILE",
                parent_exit.display().to_string(),
            ),
        ],
    );
    let cancel = CancellationToken::new();
    let mut run = request("dev", ShellRequest::Auto, Duration::from_secs(20));
    run.stdin = Some(vec![b'x'; MAX_WRITE_BYTES]);
    let mut task = {
        let runner = Arc::clone(&fixture.runner);
        let token = cancel.clone();
        tokio::spawn(async move { runner.execute(run, token).await })
    };
    wait_for_file(&pid_file).await;
    wait_for_file(&ready_file).await;
    wait_for_file(&parent_exit).await;
    let pid = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    sleep(Duration::from_millis(20)).await;
    let cancelled_at = Instant::now();
    cancel.cancel();
    let result = timeout(Duration::from_millis(250), &mut task).await;
    let error = match result {
        Ok(result) => result.unwrap().unwrap_err(),
        Err(_) => {
            force_kill_process(pid);
            let _ = timeout(Duration::from_millis(250), &mut task).await;
            task.abort();
            panic!("cancel was ignored while an orphan retained stdin")
        }
    };
    assert!(cancelled_at.elapsed() < Duration::from_millis(250));
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(error.details.remote_process_may_continue, Some(true));
    wait_for_process_exit(pid).await;
}

#[tokio::test]
async fn deadline_kills_an_orphan_stdin_holder_after_ssh_parent_exit() {
    let files = TempDir::new().unwrap();
    let pid_file = files.path().join("child.pid");
    let ready_file = files.path().join("child.ready");
    let parent_exit = files.path().join("parent.exit");
    let fixture = task3_runner(
        &["dev"],
        Limits::default(),
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "orphan-stdin".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "10".to_owned()),
            ("FAKE_SSH_CHILD_PID_FILE", pid_file.display().to_string()),
            (
                "FAKE_SSH_CHILD_READY_FILE",
                ready_file.display().to_string(),
            ),
            (
                "FAKE_SSH_PARENT_EXIT_FILE",
                parent_exit.display().to_string(),
            ),
        ],
    );
    let mut run = request("dev", ShellRequest::Auto, Duration::from_millis(80));
    run.stdin = Some(vec![b'x'; MAX_WRITE_BYTES]);
    let started = Instant::now();
    let mut task = {
        let runner = Arc::clone(&fixture.runner);
        tokio::spawn(async move { runner.execute(run, CancellationToken::new()).await })
    };
    wait_for_file(&pid_file).await;
    wait_for_file(&ready_file).await;
    wait_for_file(&parent_exit).await;
    let pid = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let result = timeout(Duration::from_millis(350), &mut task).await;
    let error = match result {
        Ok(result) => result.unwrap().unwrap_err(),
        Err(_) => {
            force_kill_process(pid);
            let _ = timeout(Duration::from_millis(250), &mut task).await;
            task.abort();
            panic!("deadline was ignored while an orphan retained stdin")
        }
    };
    assert!(started.elapsed() < Duration::from_millis(330));
    assert_eq!(error.code, ErrorCode::CommandTimeout);
    assert_eq!(error.details.remote_process_may_continue, Some(true));
    wait_for_process_exit(pid).await;
}

#[tokio::test]
async fn output_capture_honors_a_pre_cancelled_token() {
    let base = TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let store = OutputStore::new(&runtime).unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let error = store
        .capture(
            tokio::io::empty(),
            tokio::io::empty(),
            CaptureLimits {
                preview_bytes: 16,
                max_output_bytes: 1024,
            },
            cancel,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(error.details.bytes_seen, Some(0));
}

#[tokio::test]
async fn output_capture_cancellation_aborts_drains_and_cleans_pending_spool() {
    let base = TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let cancel = CancellationToken::new();
    let (mut writer, reader) = tokio::io::duplex(512 * 1024);
    let mut task = {
        let store = Arc::clone(&store);
        let token = cancel.clone();
        tokio::spawn(async move {
            store
                .capture(
                    reader,
                    tokio::io::empty(),
                    CaptureLimits {
                        preview_bytes: 16,
                        max_output_bytes: 1024 * 1024,
                    },
                    token,
                )
                .await
        })
    };
    writer.write_all(&vec![0; 300 * 1024]).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while private_spool_files(&runtime).len() != 2 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("capture never spilled");
    cancel.cancel();
    let result = timeout(Duration::from_millis(250), &mut task).await;
    let error = match result {
        Ok(result) => result.unwrap().unwrap_err(),
        Err(_) => {
            drop(writer);
            let _ = timeout(Duration::from_millis(250), &mut task).await;
            task.abort();
            panic!("standalone output capture ignored cancellation")
        }
    };
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(error.details.bytes_seen, Some(300 * 1024));
    assert!(private_spool_files(&runtime).is_empty());
}

struct ErrorAfterBytes {
    remaining: usize,
}

impl AsyncRead for ErrorAfterBytes {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.remaining == 0 {
            return std::task::Poll::Ready(Err(std::io::Error::other("fixture read failure")));
        }
        let count = self.remaining.min(buffer.remaining());
        buffer.initialize_unfilled_to(count).fill(b'x');
        buffer.advance(count);
        self.remaining -= count;
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn output_capture_read_error_cleans_an_unregistered_spool() {
    let base = TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let store = OutputStore::new(&runtime).unwrap();
    let error = store
        .capture(
            ErrorAfterBytes {
                remaining: 300 * 1024,
            },
            tokio::io::empty(),
            CaptureLimits {
                preview_bytes: 16,
                max_output_bytes: 1024 * 1024,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Io);
    assert!(private_spool_files(&runtime).is_empty());
}

#[tokio::test]
async fn queued_cancellation_never_claims_a_remote_process_may_continue() {
    let limits = Limits {
        per_host_concurrency: 1,
        ..Limits::default()
    };
    let log_dir = TempDir::new().unwrap();
    let log = log_dir.path().join("calls.log");
    let fixture = task3_runner(
        &["dev"],
        limits,
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "sleep".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "10".to_owned()),
            ("FAKE_SSH_LOG", log.display().to_string()),
        ],
    );
    let first_cancel = CancellationToken::new();
    let first = {
        let runner = Arc::clone(&fixture.runner);
        let token = first_cancel.clone();
        tokio::spawn(async move {
            runner
                .execute(
                    request("dev", ShellRequest::Auto, Duration::from_secs(20)),
                    token,
                )
                .await
        })
    };
    wait_for_log_marker(&log, "C").await;

    let queued_cancel = CancellationToken::new();
    let queued = {
        let runner = Arc::clone(&fixture.runner);
        let token = queued_cancel.clone();
        tokio::spawn(async move {
            runner
                .execute(
                    request("dev", ShellRequest::Auto, Duration::from_secs(20)),
                    token,
                )
                .await
        })
    };
    sleep(Duration::from_millis(20)).await;
    queued_cancel.cancel();
    let error = queued.await.unwrap().unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(error.details.remote_process_may_continue, Some(false));

    first_cancel.cancel();
    first.await.unwrap().unwrap_err();
}

#[tokio::test]
async fn stdout_and_stderr_are_drained_concurrently_with_aggregate_previews() {
    let limits = Limits {
        preview_bytes: 16,
        ..Limits::default()
    };
    let fixture = task3_runner(
        &["dev"],
        limits,
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "streams".to_owned()),
            ("FAKE_SSH_STDOUT", "ABCDEFGHIJK".to_owned()),
            ("FAKE_SSH_STDERR", "abcdefghijklmnop".to_owned()),
        ],
    );
    let result = fixture
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_secs(2)),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.output.stdout.head, b"ABCD");
    assert_eq!(result.output.stdout.tail, b"HIJK");
    assert_eq!(result.output.stderr.head, b"abcd");
    assert_eq!(result.output.stderr.tail, b"mnop");
    assert_eq!(result.output.aggregate_bytes, 27);
    assert!(result.output.stdout.truncated);
    assert!(result.output.stderr.truncated);
    assert!(result.output.reference.is_none());
}

fn private_spool_files(runtime: &RuntimePaths) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for directory in fs::read_dir(runtime.directory()).unwrap() {
        let directory = directory.unwrap().path();
        if directory.is_dir() {
            assert_eq!(
                fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for file in fs::read_dir(directory).unwrap() {
                let file = file.unwrap().path();
                assert_eq!(
                    fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                    0o600
                );
                files.push(file);
            }
        }
    }
    files
}

#[test]
fn spool_files_are_mode_0600_under_restrictive_umask() {
    let base = TempDir::new().unwrap();
    let _runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let output = Command::new("/bin/sh")
        .args(["-c", "umask 0777; exec \"$@\"", "umask-child"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "spool_mode_under_restrictive_umask_child",
            "--nocapture",
        ])
        .env(RESTRICTIVE_UMASK_CHILD_SENTINEL, base.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn spool_mode_under_restrictive_umask_child() {
    let Some(base) = std::env::var_os(RESTRICTIVE_UMASK_CHILD_SENTINEL) else {
        return;
    };
    let runtime = RuntimePaths::ensure_from_base(std::path::Path::new(&base)).unwrap();
    let store = OutputStore::new(&runtime).unwrap();
    let (mut writer, reader) = tokio::io::duplex(512 * 1024);
    let writer_task = tokio::spawn(async move {
        writer.write_all(&vec![b'x'; 300 * 1024]).await.unwrap();
        writer.shutdown().await.unwrap();
    });
    let captured = store
        .capture(
            reader,
            tokio::io::empty(),
            CaptureLimits {
                preview_bytes: 16,
                max_output_bytes: 1024 * 1024,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    writer_task.await.unwrap();
    assert_eq!(private_spool_files(&runtime).len(), 2);
    let reference = captured.reference.as_ref().unwrap();
    let page = store
        .read(reference, StreamKind::Stdout, 0, 17)
        .await
        .unwrap();
    assert_eq!(page.bytes, vec![b'x'; 17]);
}

#[tokio::test]
async fn exact_64_mib_spills_privately_pages_both_streams_and_expires() {
    let limits = Limits {
        preview_bytes: 16,
        max_output_bytes: MAX_OUTPUT_BYTES,
        ..Limits::default()
    };
    let half = MAX_OUTPUT_BYTES / 2;
    let fixture = task3_runner(
        &["dev"],
        limits,
        Duration::from_millis(300),
        &[
            ("FAKE_SSH_MODE", "bytes".to_owned()),
            ("FAKE_SSH_STDOUT_BYTES", half.to_string()),
            ("FAKE_SSH_STDERR_BYTES", half.to_string()),
        ],
    );
    let result = fixture
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_secs(30)),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.output.aggregate_bytes, MAX_OUTPUT_BYTES);
    assert_eq!(
        result.output.stdout.head.len() + result.output.stdout.tail.len(),
        8
    );
    assert_eq!(
        result.output.stderr.head.len() + result.output.stderr.tail.len(),
        8
    );
    let reference = result
        .output
        .reference
        .as_ref()
        .expect("spilled output reference");
    assert_eq!(reference.as_str().len(), 32);
    assert!(
        reference
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );
    assert!(!reference.as_str().contains('/'));
    assert_eq!(private_spool_files(&fixture.runtime).len(), 2);

    for stream in [StreamKind::Stdout, StreamKind::Stderr] {
        let page = fixture.store.read(reference, stream, 0, 17).await.unwrap();
        assert_eq!(page.offset, 0);
        assert_eq!(page.next_offset, 17);
        assert_eq!(page.bytes, vec![0; 17]);
        assert!(!page.eof);
        let end = fixture
            .store
            .read(reference, stream, half, 17)
            .await
            .unwrap();
        assert!(end.bytes.is_empty());
        assert!(end.eof);
        let past_end = fixture
            .store
            .read(reference, stream, half + 1, 17)
            .await
            .unwrap_err();
        assert_eq!(past_end.code, ErrorCode::InvalidArgument);
    }
    assert_eq!(
        fixture
            .store
            .read(reference, StreamKind::Stdout, 0, 0)
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        fixture
            .store
            .read(reference, StreamKind::Stdout, 0, MAX_READ_BYTES + 1)
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );

    sleep(Duration::from_millis(350)).await;
    let expired = fixture
        .store
        .read(reference, StreamKind::Stdout, 0, 1)
        .await
        .unwrap_err();
    assert_eq!(expired.code, ErrorCode::InvalidArgument);
    assert_eq!(expired.message, "output reference is unknown or expired");
    assert!(private_spool_files(&fixture.runtime).is_empty());

    let unknown = OutputReference::parse("00000000000000000000000000000000").unwrap();
    let unknown = fixture
        .store
        .read(&unknown, StreamKind::Stdout, 0, 1)
        .await
        .unwrap_err();
    assert_eq!(unknown.message, "output reference is unknown or expired");
}

#[tokio::test]
async fn task8_internal_capture_quota_is_shared_with_a_committed_command_spool() {
    let remote_root = TempDir::new().unwrap();
    fs::write(remote_root.path().join("a"), b"x").unwrap();
    let base = TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let store = Arc::new(
        OutputStore::with_limits(
            &runtime,
            codex_ssh_bridge::config::MIN_GLOBAL_SPOOL_QUOTA_BYTES,
            1,
        )
        .unwrap(),
    );
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (
            OsString::from("FAKE_SSH_ROOT"),
            remote_root.path().as_os_str().to_owned(),
        ),
    ]);
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config_with_host(
                "dev",
                remote_root.path().to_str().unwrap(),
            )),
            runtime,
            Arc::clone(&store),
            fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = RemoteBridge::new(runner);
    let request = StatRequest {
        host: "dev".to_owned(),
        paths: vec!["a".to_owned()],
    };
    bridge
        .stat(request.clone(), CancellationToken::new())
        .await
        .unwrap();

    let captured = store
        .capture(
            tokio::io::repeat(b'x').take(MAX_OUTPUT_BYTES),
            tokio::io::empty(),
            CaptureLimits {
                preview_bytes: 16,
                max_output_bytes: MAX_OUTPUT_BYTES,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(captured.reference.is_some());

    let error = bridge
        .stat(request, CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::OutputLimit);
}

#[tokio::test]
async fn first_byte_over_limit_kills_the_group_and_cleans_spool_files() {
    let limits = Limits {
        preview_bytes: 16,
        max_output_bytes: 300 * 1024,
        ..Limits::default()
    };
    let fixture = task3_runner(
        &["dev"],
        limits,
        Duration::from_secs(600),
        &[
            ("FAKE_SSH_MODE", "bytes".to_owned()),
            ("FAKE_SSH_STDOUT_BYTES", (300 * 1024 + 1).to_string()),
        ],
    );
    let error = fixture
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_secs(5)),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::OutputLimit);
    assert_eq!(error.details.bytes_seen, Some(300 * 1024 + 1));
    assert_eq!(error.details.remote_process_may_continue, Some(true));
    assert!(private_spool_files(&fixture.runtime).is_empty());
}

#[tokio::test]
async fn expired_spool_files_are_removed_without_a_read_trigger() {
    let limits = Limits {
        preview_bytes: 16,
        max_output_bytes: 300 * 1024,
        ..Limits::default()
    };
    let fixture = task3_runner(
        &["dev"],
        limits,
        Duration::from_millis(20),
        &[
            ("FAKE_SSH_MODE", "bytes".to_owned()),
            ("FAKE_SSH_STDOUT_BYTES", (300 * 1024).to_string()),
        ],
    );
    let result = fixture
        .runner
        .execute(
            request("dev", ShellRequest::Auto, Duration::from_secs(5)),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(result.output.reference.is_some());
    assert_eq!(private_spool_files(&fixture.runtime).len(), 2);
    sleep(Duration::from_millis(50)).await;
    assert!(private_spool_files(&fixture.runtime).is_empty());
}

#[tokio::test]
async fn output_store_rejects_a_limit_above_the_compiled_hard_ceiling() {
    let base = TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let store = OutputStore::new(&runtime).unwrap();
    let error = store
        .capture(
            tokio::io::empty(),
            tokio::io::empty(),
            CaptureLimits {
                preview_bytes: 16,
                max_output_bytes: MAX_OUTPUT_BYTES + 1,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn output_store_rejects_a_ttl_above_ten_minutes() {
    let base = TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let ttl_error = OutputStore::with_ttl(&runtime, Duration::from_secs(601)).unwrap_err();
    assert_eq!(ttl_error.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn output_store_rejects_an_unbounded_preview_budget() {
    let base = TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let store = OutputStore::new(&runtime).unwrap();
    let preview_error = store
        .capture(
            tokio::io::empty(),
            tokio::io::empty(),
            CaptureLimits {
                preview_bytes: usize::MAX,
                max_output_bytes: 1,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(preview_error.code, ErrorCode::InvalidArgument);
}
