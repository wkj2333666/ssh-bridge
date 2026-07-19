#![deny(unsafe_code)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::sync::Arc;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use codex_ssh_bridge::cli::{
    LocalCommandSpec, RunArgs, ShellArg, doctor_host, mount_sshfs_with_executable,
    parse_sshfs_mount_status, redact_ssh_diagnostics, run_local_command, run_remote_argv,
    unmount_sshfs_with_executable,
};
use codex_ssh_bridge::config::{Config, HostLimitOverrides, HostProfile};
use codex_ssh_bridge::output::OutputStore;
use codex_ssh_bridge::remote::RemoteBridge;
use codex_ssh_bridge::ssh::SshRunner;
use codex_ssh_bridge::ssh::{RuntimePaths, SshPolicy, build_sshfs_argv, validate_sshfs_mountpoint};
use predicates::prelude::*;

fn bridge_command(config: &std::path::Path, runtime: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_codex-ssh-bridge"));
    command
        .env("CODEX_SSH_BRIDGE_CONFIG", config)
        .env("XDG_RUNTIME_DIR", runtime);
    command
}

#[test]
fn task9_help_lists_human_commands_while_mcp_remains_an_entry_mode() {
    Command::new(env!("CARGO_BIN_EXE_codex-ssh-bridge"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("mcp"))
        .stdout(predicate::str::contains("hosts"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("mount"))
        .stdout(predicate::str::contains("unmount"))
        .stdout(predicate::str::contains("mount-status"))
        .stdout(predicate::str::contains("install"));
}

#[test]
fn task9_hosts_add_show_list_remove_round_trip_and_save_mode_0600() {
    let private = tempfile::TempDir::new().unwrap();
    let config = private.path().join("config.toml");

    bridge_command(&config, private.path())
        .args([
            "hosts",
            "add",
            "future-7",
            "--root",
            "/srv/future project",
            "--description",
            "future host",
            "--read-only",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("future-7"));

    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let loaded = codex_ssh_bridge::config::Config::load(&config).unwrap();
    let host = loaded.host("future-7").unwrap();
    assert_eq!(host.profile.root, "/srv/future project");
    assert_eq!(host.profile.description.as_deref(), Some("future host"));
    assert!(host.profile.read_only);

    for subcommand in ["show", "list"] {
        let mut command = bridge_command(&config, private.path());
        command.args(["hosts", subcommand]);
        if subcommand == "show" {
            command.arg("future-7");
        }
        command
            .assert()
            .success()
            .stdout(predicate::str::contains("future-7"))
            .stdout(predicate::str::contains("/srv/future project"));
    }

    bridge_command(&config, private.path())
        .args(["hosts", "remove", "future-7"])
        .assert()
        .success();
    assert!(
        codex_ssh_bridge::config::Config::load(&config)
            .unwrap()
            .hosts
            .is_empty()
    );
}

#[test]
fn task9_hosts_add_rejects_invalid_alias_and_relative_root_without_creating_config() {
    for (alias, root) in [("-oProxyCommand=bad", "/srv/x"), ("valid", "relative/root")] {
        let private = tempfile::TempDir::new().unwrap();
        let config = private.path().join("config.toml");
        bridge_command(&config, private.path())
            .args(["hosts", "add", alias, "--root", root])
            .assert()
            .failure()
            .stderr(predicate::str::contains("INVALID_"));
        assert!(!config.exists());
    }
}

#[test]
fn task9_hosts_add_never_imposes_a_five_host_ceiling() {
    let private = tempfile::TempDir::new().unwrap();
    let config = private.path().join("config.toml");
    for index in 0..7 {
        bridge_command(&config, private.path())
            .args([
                "hosts",
                "add",
                &format!("server-{index}"),
                "--root",
                &format!("/srv/server-{index}"),
            ])
            .assert()
            .success();
    }
    assert_eq!(
        codex_ssh_bridge::config::Config::load(&config)
            .unwrap()
            .hosts
            .len(),
        7
    );
}

#[test]
fn task9_hosts_add_refuses_symlinked_or_group_writable_config_ancestors() {
    let private = tempfile::TempDir::new().unwrap();
    let outside = tempfile::TempDir::new().unwrap();
    let linked = private.path().join("linked");
    symlink(outside.path(), &linked).unwrap();
    let through_link = linked.join("bridge/config.toml");
    bridge_command(&through_link, private.path())
        .args(["hosts", "add", "dev", "--root", "/srv/dev"])
        .assert()
        .failure();
    assert!(!outside.path().join("bridge").exists());

    let writable = private.path().join("writable");
    fs::create_dir(&writable).unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
    let unsafe_config = writable.join("bridge/config.toml");
    bridge_command(&unsafe_config, private.path())
        .args(["hosts", "add", "dev", "--root", "/srv/dev"])
        .assert()
        .failure();
    assert!(!writable.join("bridge").exists());
}

#[test]
fn task9_fresh_config_creates_each_missing_parent_privately_without_global_config_flag() {
    let private = tempfile::TempDir::new().unwrap();
    let first = private.path().join("one");
    let second = first.join("two");
    let config = second.join("config.toml");
    bridge_command(&config, private.path())
        .args(["hosts", "add", "dev", "--root", "/srv/dev"])
        .assert()
        .success();
    for directory in [&first, &second] {
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    Command::new(env!("CARGO_BIN_EXE_codex-ssh-bridge"))
        .args(["--config", config.to_str().unwrap(), "hosts", "list"])
        .assert()
        .code(2)
        .stderr("usage: codex-ssh-bridge mcp\n");
}

#[test]
fn task9_mcp_source_tree_contains_no_sshfs_or_mount_tool() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for file in [
        "src/mcp/mod.rs",
        "src/mcp/protocol.rs",
        "src/mcp/render.rs",
        "src/mcp/stdio.rs",
        "src/mcp/tools.rs",
    ] {
        let source = fs::read_to_string(manifest.join(file)).unwrap();
        let lowered = source.to_ascii_lowercase();
        assert!(!lowered.contains("sshfs"), "{file}");
        assert!(!lowered.contains("remote_mount"), "{file}");
    }
}

fn sshfs_policy(private: &tempfile::TempDir, read_only: bool) -> (Config, RuntimePaths) {
    let mut config = Config::default();
    config.hosts.insert(
        "future-box".to_owned(),
        HostProfile {
            root: "/srv/project".to_owned(),
            description: None,
            read_only,
            limits: HostLimitOverrides::default(),
        },
    );
    let runtime = RuntimePaths::ensure_from_base(private.path()).unwrap();
    (config, runtime)
}

fn option_is_distinct(argv: &[std::ffi::OsString], expected: &str) -> bool {
    argv.windows(2)
        .any(|pair| pair[0] == "-o" && pair[1] == expected)
}

#[test]
fn task9_sshfs_argv_has_exact_hardening_reconnect_and_forced_read_only() {
    let private = tempfile::TempDir::new().unwrap();
    let (config, runtime) = sshfs_policy(&private, true);
    let host = config.host("future-box").unwrap();
    let policy = SshPolicy::for_host(&config, host, &runtime, "resolved identity").unwrap();
    let argv = build_sshfs_argv(
        &policy,
        host,
        "/srv/project/path with spaces",
        std::path::Path::new("/mnt/remote project"),
        true,
    )
    .unwrap();

    for option in [
        "ssh_command=/usr/bin/ssh",
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "RequestTTY=no",
        "ConnectTimeout=10",
        "ServerAliveInterval=15",
        "ServerAliveCountMax=3",
        "ControlMaster=auto",
        "ControlPersist=300",
        "reconnect",
        "ro",
        "nonempty",
    ] {
        assert!(
            option_is_distinct(&argv, option),
            "missing {option:?}: {argv:?}"
        );
    }
    assert!(!argv.iter().any(|argument| argument == "allow_other"));
    assert!(
        argv.iter()
            .any(|argument| argument == "future-box:/srv/project/path with spaces")
    );
    assert!(
        argv.iter()
            .any(|argument| argument == "/mnt/remote project")
    );
}

#[test]
fn task9_sshfs_argv_does_not_add_ro_or_nonempty_for_normal_read_write_mount() {
    let private = tempfile::TempDir::new().unwrap();
    let (config, runtime) = sshfs_policy(&private, false);
    let host = config.host("future-box").unwrap();
    let policy = SshPolicy::for_host(&config, host, &runtime, "resolved identity").unwrap();
    let argv = build_sshfs_argv(
        &policy,
        host,
        "/srv/project",
        std::path::Path::new("/mnt/project"),
        false,
    )
    .unwrap();
    assert!(!option_is_distinct(&argv, "ro"));
    assert!(!option_is_distinct(&argv, "nonempty"));
}

#[test]
fn task9_mountpoint_must_be_absolute_real_owned_directory_and_empty_by_default() {
    let private = tempfile::TempDir::new().unwrap();
    let empty = private.path().join("empty");
    let nonempty = private.path().join("nonempty");
    let target = private.path().join("target");
    let link = private.path().join("link");
    fs::create_dir(&empty).unwrap();
    fs::create_dir(&nonempty).unwrap();
    fs::create_dir(&target).unwrap();
    fs::write(nonempty.join("sentinel"), b"keep").unwrap();
    symlink(&target, &link).unwrap();

    assert_eq!(validate_sshfs_mountpoint(&empty, false).unwrap(), empty);
    assert!(validate_sshfs_mountpoint(std::path::Path::new("relative"), false).is_err());
    assert!(validate_sshfs_mountpoint(&nonempty, false).is_err());
    assert!(validate_sshfs_mountpoint(&link, true).is_err());
    assert_eq!(
        validate_sshfs_mountpoint(&nonempty, true).unwrap(),
        nonempty
    );
}

fn executable_script(directory: &std::path::Path, name: &str, source: &str) -> std::path::PathBuf {
    let path = directory.join(name);
    fs::write(&path, source).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn remote_bridge(root: &std::path::Path, private: &tempfile::TempDir) -> Arc<RemoteBridge> {
    let mut config = Config::default();
    config.hosts.insert(
        "dev".to_owned(),
        HostProfile {
            root: root.to_str().unwrap().to_owned(),
            description: None,
            read_only: false,
            limits: HostLimitOverrides::default(),
        },
    );
    let runtime = RuntimePaths::ensure_from_base(private.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-ssh.sh"),
            [
                (
                    OsString::from("FAKE_SSH_MODE"),
                    OsString::from("local-fixed"),
                ),
                (OsString::from("FAKE_SSH_SHELL"), OsString::from("bash")),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap(),
    );
    Arc::new(RemoteBridge::new(runner))
}

fn remote_runner(
    root: &std::path::Path,
    private: &tempfile::TempDir,
    read_only: bool,
) -> Arc<SshRunner> {
    let mut config = Config::default();
    config.hosts.insert(
        "dev".to_owned(),
        HostProfile {
            root: root.to_str().unwrap().to_owned(),
            description: None,
            read_only,
            limits: HostLimitOverrides::default(),
        },
    );
    let runtime = RuntimePaths::ensure_from_base(private.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-ssh.sh"),
            [(
                OsString::from("FAKE_SSH_MODE"),
                OsString::from("local-fixed"),
            )]
            .into_iter()
            .collect(),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn task9_doctor_uses_shared_probe_and_reports_remote_root_and_actual_shell() {
    let private = tempfile::TempDir::new().unwrap();
    let remote = tempfile::TempDir::new().unwrap();
    let bridge = remote_bridge(remote.path(), &private);
    let result = doctor_host(&bridge, "dev").await.unwrap();
    assert_eq!(result["remote"], true);
    assert_eq!(result["host"], "dev");
    assert_eq!(result["physical_root"], remote.path().to_str().unwrap());
    assert_eq!(result["shell"]["kind"], "sh");
    assert_eq!(result["shell"]["version"], serde_json::Value::Null);
    assert_eq!(result["shell"]["fallback"], false);
}

#[tokio::test]
async fn task9_direct_run_quotes_each_argv_word_and_reports_shell() {
    let private = tempfile::TempDir::new().unwrap();
    let remote = tempfile::TempDir::new().unwrap();
    let bridge = remote_bridge(remote.path(), &private);
    let hostile = "space '$HOME' $(touch should-not-exist) * newline\nend";
    let result = run_remote_argv(
        &bridge,
        RunArgs {
            host: "dev".to_owned(),
            cwd: ".".to_owned(),
            shell: ShellArg::Auto,
            timeout_ms: Some(5_000),
            argv: vec!["printf".to_owned(), "%s".to_owned(), hostile.to_owned()],
        },
    )
    .await
    .unwrap();
    let value = serde_json::to_value(result).unwrap();
    assert_eq!(value["shell"]["kind"], "bash");
    assert_eq!(value["shell"]["fallback"], false);
    assert_eq!(value["warnings"], serde_json::json!([]));
    assert_eq!(value["stdout"]["head"]["encoding"], "utf8");
    assert_eq!(value["stdout"]["head"]["value"], hostile);
    assert!(!remote.path().join("should-not-exist").exists());
}

#[tokio::test]
async fn task9_local_executor_preserves_argv_and_bounded_output_without_a_shell() {
    let private = tempfile::TempDir::new().unwrap();
    let executable = executable_script(
        private.path(),
        "fixture",
        "#!/bin/sh\nprintf '%s' \"$1\"\nprintf '%s' \"$2\" >&2\nexit 7\n",
    );
    let output = run_local_command(LocalCommandSpec {
        executable,
        arguments: vec![
            OsString::from("literal;$(false)"),
            OsString::from("diagnostic"),
        ],
        timeout: Duration::from_secs(2),
        max_output_bytes: 1024,
    })
    .await
    .unwrap();
    assert_eq!(output.status, 7);
    assert_eq!(output.stdout, b"literal;$(false)");
    assert_eq!(output.stderr, b"diagnostic");
}

#[tokio::test]
async fn task9_local_executor_timeout_kills_the_process_group_promptly() {
    let private = tempfile::TempDir::new().unwrap();
    let pid_file = private.path().join("child.pid");
    let executable = executable_script(
        private.path(),
        "hang",
        "#!/bin/sh\ntrap '' TERM\nsleep 30 &\nprintf '%s\\n' \"$!\" >\"$1\"\nwait\n",
    );
    let started = Instant::now();
    let error = run_local_command(LocalCommandSpec {
        executable,
        arguments: vec![pid_file.as_os_str().to_owned()],
        timeout: Duration::from_millis(100),
        max_output_bytes: 1024,
    })
    .await
    .unwrap_err();
    assert_eq!(error.code, codex_ssh_bridge::ErrorCode::CommandTimeout);
    assert!(started.elapsed() < Duration::from_secs(1));
    let child: i32 = fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let child_proc = std::path::PathBuf::from(format!("/proc/{child}"));
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if !child_proc.exists() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "local grandchild survived timeout"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn task9_local_executor_output_limit_wins_and_kills_a_term_ignoring_group() {
    let private = tempfile::TempDir::new().unwrap();
    let executable = executable_script(
        private.path(),
        "overflow",
        "#!/bin/sh\ntrap '' TERM\ndd if=/dev/zero bs=2048 count=1 2>/dev/null\nsleep 30\n",
    );
    let started = Instant::now();
    let error = run_local_command(LocalCommandSpec {
        executable,
        arguments: Vec::new(),
        timeout: Duration::from_secs(2),
        max_output_bytes: 1024,
    })
    .await
    .unwrap_err();
    assert_eq!(error.code, codex_ssh_bridge::ErrorCode::OutputLimit);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn task9_verbose_doctor_redacts_paths_commands_credentials_and_controls() {
    let diagnostic = b"debug1: safe negotiated algorithm ssh-ed25519\n\
debug1: identity file /home/alice/.ssh/id_ed25519 type 3\n\
debug1: identity agent /run/user/1000/ssh-agent.socket\n\
debug1: Sending command: deploy --token=DOCTOR_TOKEN_SECRET\n\
Authorization: Bearer DOCTOR_BEARER_SECRET\n\
password=DOCTOR_PASSWORD_SECRET\n\
safe-control:\x1b[31m\n";
    let rendered = redact_ssh_diagnostics(diagnostic);
    assert!(rendered.contains("safe negotiated algorithm ssh-ed25519"));
    assert!(rendered.contains("[REDACTED]"));
    for secret in [
        "/home/alice/.ssh/id_ed25519",
        "/run/user/1000/ssh-agent.socket",
        "deploy --token",
        "DOCTOR_TOKEN_SECRET",
        "DOCTOR_BEARER_SECRET",
        "DOCTOR_PASSWORD_SECRET",
        "\u{1b}",
    ] {
        assert!(
            !rendered.contains(secret),
            "leaked {secret:?}: {rendered:?}"
        );
    }
}

#[test]
fn task9_mount_status_parser_decodes_mountinfo_and_distinguishes_other_fuse() {
    let sshfs = b"36 25 0:32 / /mnt/remote\\040project rw,nosuid - fuse.sshfs dev:/srv rw\n";
    let status =
        parse_sshfs_mount_status(sshfs, std::path::Path::new("/mnt/remote project")).unwrap();
    assert!(status.mounted);
    assert!(status.sshfs);
    assert_eq!(status.filesystem_type.as_deref(), Some("fuse.sshfs"));

    let other = b"36 25 0:32 / /mnt/remote\\040project rw,nosuid - fuse.other x rw\n";
    let status =
        parse_sshfs_mount_status(other, std::path::Path::new("/mnt/remote project")).unwrap();
    assert!(status.mounted);
    assert!(!status.sshfs);
}

#[tokio::test]
async fn task9_mount_executes_hardened_sshfs_and_forces_profile_read_only() {
    let private = tempfile::TempDir::new().unwrap();
    let remote = tempfile::TempDir::new().unwrap();
    let mountpoint = private.path().join("mountpoint");
    let log = private.path().join("sshfs.log");
    fs::create_dir(&mountpoint).unwrap();
    let source = format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >'{}'\n", log.display());
    let sshfs = executable_script(private.path(), "sshfs", &source);
    let runner = remote_runner(remote.path(), &private, true);
    let result = mount_sshfs_with_executable(
        &runner,
        sshfs,
        codex_ssh_bridge::cli::MountArgs {
            host: "dev".to_owned(),
            mountpoint: mountpoint.clone(),
            remote_path: ".".to_owned(),
            allow_nonempty: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(result["remote"], true);
    assert_eq!(result["host"], "dev");
    assert!(
        result["warning"]
            .as_str()
            .unwrap()
            .contains("not an Agent workspace")
    );
    let logged = fs::read_to_string(log).unwrap();
    for option in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "ForwardAgent=no",
        "ClearAllForwardings=yes",
        "reconnect",
        "ro",
    ] {
        assert!(logged.lines().any(|line| line == option), "{logged}");
    }
    assert!(logged.contains(mountpoint.to_str().unwrap()));
}

#[tokio::test]
async fn task9_unmount_executes_only_for_identity_checked_sshfs_mount() {
    let private = tempfile::TempDir::new().unwrap();
    let mountpoint = private.path().join("mountpoint");
    let log = private.path().join("unmount.log");
    fs::create_dir(&mountpoint).unwrap();
    let source = format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >'{}'\n", log.display());
    let helper = executable_script(private.path(), "fusermount3", &source);
    let mountinfo = format!(
        "36 25 0:32 / {} rw,nosuid - fuse.sshfs dev:/srv rw\n",
        mountpoint.display()
    );
    let result = unmount_sshfs_with_executable(helper.clone(), &mountpoint, mountinfo.as_bytes())
        .await
        .unwrap();
    assert_eq!(result["unmounted"], mountpoint.to_str().unwrap());
    let logged = fs::read_to_string(&log).unwrap();
    assert_eq!(
        logged.lines().collect::<Vec<_>>(),
        ["-u", mountpoint.to_str().unwrap()]
    );

    fs::remove_file(&log).unwrap();
    let other = mountinfo.replace("fuse.sshfs", "fuse.other");
    assert!(
        unmount_sshfs_with_executable(helper, &mountpoint, other.as_bytes())
            .await
            .is_err()
    );
    assert!(!log.exists());
}
