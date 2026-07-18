#![deny(unsafe_code)]

mod support;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use codex_ssh_bridge::capability::{
    CAPABILITY_PROBE_SCRIPT, Capability, CapabilityCache, ShellKind, ShellRequest,
    parse_probe_output, select_shell,
};
use codex_ssh_bridge::error::{BridgeError, ErrorCode};
use codex_ssh_bridge::path::RemotePath;
use codex_ssh_bridge::ssh::{RuntimePaths, SshPolicy, build_ssh_argv};
use tempfile::TempDir;

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
    let control_path = argv
        .iter()
        .find_map(|argument| {
            argument
                .to_str()
                .and_then(|value| value.strip_prefix("ControlPath="))
        })
        .expect("ControlPath option");
    assert!(std::path::Path::new(control_path).starts_with(paths.directory()));
    assert!(!control_path.contains("dev-box"));
    assert!(!control_path.contains(identity));

    let same = build_ssh_argv(&policy(&config, &paths, identity), "dev-box", "printf safe");
    assert_eq!(argv, same);
    let changed = build_ssh_argv(
        &policy(&config, &paths, "hostname=other;user=deploy;port=22"),
        "dev-box",
        "printf safe",
    );
    assert_ne!(
        control_path,
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

    let missing = select_shell(&sh, ShellRequest::Bash).unwrap_err();
    assert_eq!(missing.code, ErrorCode::RemoteCapabilityMissing);

    let login = select_shell(&sh, ShellRequest::Login).unwrap();
    assert_eq!(login.shell, ShellKind::Login);
    assert!(!login.fallback);
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

#[test]
fn fixed_probe_script_emits_parseable_nul_records_and_cleans_its_private_directory() {
    let filesystem = TempDir::new().unwrap();
    let physical = filesystem.path().join("physical\nroot");
    fs::create_dir(&physical).unwrap();
    let requested = filesystem.path().join("requested\nroot");
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
            "grep",
            "ln",
            "mktemp",
            "mv",
            "rg",
            "sha256sum",
            "stat",
            "timeout",
        ]
    );
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}
