#![deny(unsafe_code)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::sync::Arc;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use codex_ssh_bridge::cli::{
    InstallLayout, LocalCommandSpec, RunArgs, ShellArg, doctor_host, install_user,
    mount_sshfs_with_executable, parse_sshfs_mount_status, redact_ssh_diagnostics,
    run_local_command, run_remote_argv, uninstall_user,
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

fn option_count(argv: &[std::ffi::OsString], expected: &str) -> usize {
    argv.windows(2)
        .filter(|pair| pair[0] == "-o" && pair[1] == expected)
        .count()
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
    for option in ["ServerAliveInterval=15", "ServerAliveCountMax=3"] {
        assert_eq!(
            option_count(&argv, option),
            1,
            "option={option:?}, argv={argv:?}"
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
async fn task9_auto_run_reports_sh_fallback_and_warning_when_bash_is_unavailable() {
    let private = tempfile::TempDir::new().unwrap();
    let remote = tempfile::TempDir::new().unwrap();
    let mut config = Config::default();
    config.hosts.insert(
        "dev".to_owned(),
        HostProfile {
            root: remote.path().to_str().unwrap().to_owned(),
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
                    OsString::from("echo-command"),
                ),
                (OsString::from("FAKE_SSH_SHELL"), OsString::from("sh")),
                (
                    OsString::from("FAKE_SSH_ROOT"),
                    remote.path().as_os_str().to_owned(),
                ),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap(),
    );
    let bridge = RemoteBridge::new(runner);
    let result = run_remote_argv(
        &bridge,
        RunArgs {
            host: "dev".to_owned(),
            cwd: ".".to_owned(),
            shell: ShellArg::Auto,
            timeout_ms: Some(5_000),
            argv: vec!["printf".to_owned(), "%s".to_owned(), "ok".to_owned()],
        },
    )
    .await
    .unwrap();
    let value = serde_json::to_value(result).unwrap();
    assert_eq!(value["shell"]["kind"], "sh");
    assert_eq!(value["shell"]["fallback"], true);
    assert!(value["warnings"].as_array().unwrap().iter().any(|warning| {
        warning
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .contains("bash")
    }));
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
    assert_eq!(status.mount_id, Some(36));
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
    assert_eq!(logged.lines().nth(1), mountpoint.to_str());
}

struct InstallFixture {
    _private: tempfile::TempDir,
    layout: InstallLayout,
    codex_state: std::path::PathBuf,
    log: std::path::PathBuf,
}

#[derive(Default)]
struct InstallFixtureOptions {
    add_skill_conflict: bool,
    drift_mcp_after_add: bool,
    fail_after_add: bool,
    get_failure: Option<&'static str>,
    known_warning_before_missing: bool,
    remove_failure_after_delete: bool,
    slow_add: bool,
    hang_get: bool,
}

fn install_fixture(options: InstallFixtureOptions) -> InstallFixture {
    let private = tempfile::TempDir::new().unwrap();
    let bundle = private.path().join("bundle");
    let binary = bundle.join("bin/codex-ssh-bridge");
    let plugin_manifest = bundle.join(".codex-plugin/plugin.json");
    let mcp_manifest = bundle.join(".mcp.json");
    let skill_source = bundle.join("skills/remote-ssh-ops");
    let skill_target = private.path().join("user/.agents/skills/remote-ssh-ops");
    let identity_file = private
        .path()
        .join("user/state/codex-ssh-bridge/install.toml");
    let codex = private.path().join("bin/codex");
    let codex_state = private.path().join("codex-state.json");
    let mcp_value = private.path().join("matching-mcp.json");
    let log = private.path().join("codex.log");
    for directory in [
        private.path().join("user"),
        binary.parent().unwrap().to_owned(),
        plugin_manifest.parent().unwrap().to_owned(),
        skill_source.join("agents"),
        skill_source.join("references"),
        codex.parent().unwrap().to_owned(),
    ] {
        fs::create_dir_all(directory).unwrap();
    }
    fs::write(&binary, b"RUST-BINARY-FIXTURE").unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        &plugin_manifest,
        br#"{"name":"codex-ssh-bridge","skills":"./skills/","mcpServers":"./.mcp.json"}"#,
    )
    .unwrap();
    fs::write(
        &mcp_manifest,
        br#"{"mcpServers":{"ssh-bridge":{"command":"./bin/codex-ssh-bridge","args":["mcp"]}}}"#,
    )
    .unwrap();
    fs::write(
        skill_source.join("SKILL.md"),
        b"---\nname: remote-ssh-ops\ndescription: safe remote operations\n---\n\n# Remote SSH Ops\n",
    )
    .unwrap();
    fs::write(
        skill_source.join("agents/openai.yaml"),
        b"interface: {}\ndependencies:\n  tools:\n    - type: \"mcp\"\n      value: \"ssh-bridge\"\n      transport: \"stdio\"\n",
    )
    .unwrap();
    fs::write(
        skill_source.join("references/operations.md"),
        b"# operations\n",
    )
    .unwrap();
    fs::write(
        &mcp_value,
        serde_json::to_vec(&serde_json::json!({
            "transport": {
                "type": "stdio",
                "command": binary,
                "args": ["mcp"],
                "env": null,
                "cwd": null
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let quote = |path: &std::path::Path| {
        codex_ssh_bridge::quote::shell_word(path.to_str().unwrap()).unwrap()
    };
    let get_body = if options.hang_get {
        "sleep 30".to_owned()
    } else {
        match options.get_failure {
            Some(message) => format!(
                "printf '%s\\n' {} >&2; exit 1",
                codex_ssh_bridge::quote::shell_word(message).unwrap()
            ),
            None => {
                let warning = if options.known_warning_before_missing {
                    "printf '%s\\n' \"WARNING: proceeding, even though we could not create PATH aliases: Read-only file system (os error 30)\" >&2;"
                } else {
                    ""
                };
                format!(
                    "if [ -f {state} ]; then cat {state}; else {warning} printf '%s\\n' \"Error: No MCP server named 'ssh-bridge' found.\" >&2; exit 1; fi",
                    state = quote(&codex_state)
                )
            }
        }
    };
    let mut add_actions = vec![format!(
        "cp {source} {state}",
        source = quote(&mcp_value),
        state = quote(&codex_state)
    )];
    if options.add_skill_conflict {
        add_actions.push(format!(
            "mkdir -p {parent}; printf conflict >{target}",
            parent = quote(skill_target.parent().unwrap()),
            target = quote(&skill_target)
        ));
    }
    if options.drift_mcp_after_add {
        add_actions.push(format!(
            "printf '%s' '{{\"transport\":{{\"type\":\"stdio\",\"command\":\"/bin/false\",\"args\":[\"mcp\"]}}}}' >{state}",
            state = quote(&codex_state)
        ));
    }
    if options.fail_after_add {
        add_actions.push("exit 7".to_owned());
    }
    if options.slow_add {
        add_actions.push("sleep 0.2".to_owned());
    }
    let add_body = add_actions.join("; ");
    let remove_body = if options.remove_failure_after_delete {
        format!("rm -f {}; exit 9", quote(&codex_state))
    } else {
        format!("rm -f {}", quote(&codex_state))
    };
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >>{log}\ncase \"$1:$2\" in\n  mcp:get) {get_body};;\n  mcp:add) {add_body};;\n  mcp:remove) {remove_body};;\n  *) exit 64;;\nesac\n",
        log = quote(&log),
    );
    fs::write(&codex, script).unwrap();
    fs::set_permissions(&codex, fs::Permissions::from_mode(0o700)).unwrap();
    InstallFixture {
        _private: private,
        layout: InstallLayout {
            binary,
            plugin_manifest,
            mcp_manifest,
            skill_source,
            skill_target,
            identity_file,
            codex_executable: codex,
            quarantine_delete_failure: None,
        },
        codex_state,
        log,
    }
}

#[tokio::test]
async fn task9_installer_is_dry_run_by_default_then_applies_idempotently() {
    let fixture = install_fixture(InstallFixtureOptions::default());
    let dry = install_user(fixture.layout.clone(), false).await.unwrap();
    assert!(!dry.applied);
    assert!(!fixture.codex_state.exists());
    assert!(!fixture.layout.skill_target.exists());
    assert!(!fixture.layout.identity_file.exists());

    let applied = install_user(fixture.layout.clone(), true).await.unwrap();
    assert!(applied.applied);
    assert!(fixture.codex_state.exists());
    assert_eq!(
        fs::canonicalize(&fixture.layout.skill_target).unwrap(),
        fs::canonicalize(&fixture.layout.skill_source).unwrap()
    );
    assert_eq!(
        fs::metadata(&fixture.layout.identity_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let before = fs::read_to_string(&fixture.log).unwrap();
    install_user(fixture.layout.clone(), true).await.unwrap();
    let after = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(
        before.matches("mcp add").count(),
        after.matches("mcp add").count()
    );
}

#[tokio::test]
async fn task9_installer_refuses_unrelated_mcp_and_differentiates_get_failure() {
    let fixture = install_fixture(InstallFixtureOptions::default());
    fs::write(
        &fixture.codex_state,
        br#"{"transport":{"type":"stdio","command":"/bin/false","args":["mcp"]}}"#,
    )
    .unwrap();
    assert!(install_user(fixture.layout.clone(), true).await.is_err());
    assert!(!fixture.layout.skill_target.exists());
    assert!(!fixture.layout.identity_file.exists());

    let failed = install_fixture(InstallFixtureOptions {
        get_failure: Some("permission denied reading Codex config"),
        ..InstallFixtureOptions::default()
    });
    assert!(install_user(failed.layout.clone(), true).await.is_err());
    assert!(!failed.layout.skill_target.exists());
    assert!(!failed.layout.identity_file.exists());
}

#[tokio::test]
async fn task9_installer_accepts_only_exact_missing_stderr_plus_known_codex_warning() {
    let warning = install_fixture(InstallFixtureOptions {
        known_warning_before_missing: true,
        ..InstallFixtureOptions::default()
    });
    assert!(install_user(warning.layout.clone(), false).await.is_ok());

    let mixed = install_fixture(InstallFixtureOptions {
        get_failure: Some("Error: No MCP server named 'ssh-bridge' found.\nunexpected diagnostic"),
        ..InstallFixtureOptions::default()
    });
    assert!(install_user(mixed.layout.clone(), false).await.is_err());
}

#[tokio::test]
async fn task9_installer_bounds_a_hung_codex_cli_call() {
    let fixture = install_fixture(InstallFixtureOptions {
        hang_get: true,
        ..InstallFixtureOptions::default()
    });
    let started = Instant::now();
    let error = install_user(fixture.layout.clone(), false)
        .await
        .unwrap_err();
    assert_eq!(error.code, codex_ssh_bridge::ErrorCode::CommandTimeout);
    assert!(started.elapsed() < Duration::from_secs(12));
    assert!(!fixture.codex_state.exists());
    assert!(!fixture.layout.skill_target.exists());
}

#[tokio::test]
async fn task9_installer_accepts_trusted_root_owned_codex_executable() {
    let mut fixture = install_fixture(InstallFixtureOptions::default());
    fixture.layout.codex_executable = fs::canonicalize("/bin/true").unwrap();
    let metadata = fs::metadata(&fixture.layout.codex_executable).unwrap();
    assert_eq!(
        std::os::unix::fs::MetadataExt::uid(&metadata),
        std::os::unix::fs::MetadataExt::uid(&fs::symlink_metadata("/").unwrap())
    );
    let error = install_user(fixture.layout.clone(), false)
        .await
        .unwrap_err();
    assert_eq!(
        error.message,
        "`codex mcp get --json` returned invalid JSON"
    );
}

#[tokio::test]
async fn task9_installer_accepts_group_writable_user_source_below_private_user_ancestor() {
    let fixture = install_fixture(InstallFixtureOptions::default());
    assert_eq!(
        fs::metadata(fixture._private.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    fs::set_permissions(
        fixture.layout.codex_executable.parent().unwrap(),
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();

    install_user(fixture.layout.clone(), false).await.unwrap();
}

#[tokio::test]
async fn task9_installer_rejects_group_writable_user_source_without_private_user_ancestor() {
    let fixture = install_fixture(InstallFixtureOptions::default());
    fs::set_permissions(fixture._private.path(), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(
        fixture.layout.codex_executable.parent().unwrap(),
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();

    assert!(install_user(fixture.layout.clone(), false).await.is_err());
    assert!(!fixture.log.exists());
}

#[tokio::test]
async fn task9_installer_accepts_codex_path_symlink_to_a_trusted_executable() {
    let mut fixture = install_fixture(InstallFixtureOptions::default());
    let linked_codex = fixture._private.path().join("linked-codex");
    symlink(&fixture.layout.codex_executable, &linked_codex).unwrap();
    fixture.layout.codex_executable = linked_codex;

    install_user(fixture.layout.clone(), false).await.unwrap();
    assert!(fixture.log.exists());
}

#[tokio::test]
async fn task9_installer_rejects_codex_path_symlink_to_an_unsealed_writable_target() {
    let mut fixture = install_fixture(InstallFixtureOptions::default());
    fs::set_permissions(fixture._private.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let unsafe_directory = fixture._private.path().join("unsafe-bin");
    fs::create_dir(&unsafe_directory).unwrap();
    fs::set_permissions(&unsafe_directory, fs::Permissions::from_mode(0o775)).unwrap();
    let unsafe_codex = unsafe_directory.join("codex");
    fs::copy(&fixture.layout.codex_executable, &unsafe_codex).unwrap();
    fs::set_permissions(&unsafe_codex, fs::Permissions::from_mode(0o700)).unwrap();
    let linked_codex = fixture._private.path().join("linked-codex");
    symlink(&unsafe_codex, &linked_codex).unwrap();
    fixture.layout.codex_executable = linked_codex;

    assert!(install_user(fixture.layout.clone(), false).await.is_err());
    assert!(!fixture.log.exists());
}

#[tokio::test]
async fn task9_installer_rejects_symlinked_package_binary() {
    let fixture = install_fixture(InstallFixtureOptions::default());
    let real_binary = fixture.layout.binary.with_file_name("real-binary");
    fs::rename(&fixture.layout.binary, &real_binary).unwrap();
    symlink(&real_binary, &fixture.layout.binary).unwrap();

    assert!(install_user(fixture.layout.clone(), false).await.is_err());
    assert!(!fixture.log.exists());
}

#[tokio::test]
async fn task9_installer_validates_the_rust_package_chain_before_codex_mutation() {
    let plugin = install_fixture(InstallFixtureOptions::default());
    fs::write(
        &plugin.layout.plugin_manifest,
        br#"{"name":"some-other-plugin","skills":"./skills/","mcpServers":"./.mcp.json"}"#,
    )
    .unwrap();
    assert!(install_user(plugin.layout.clone(), true).await.is_err());
    assert!(!plugin.log.exists());

    let mcp = install_fixture(InstallFixtureOptions::default());
    fs::write(
        &mcp.layout.mcp_manifest,
        br#"{"mcpServers":{"ssh-bridge":{"command":"/bin/false","args":["wrong-mode"]}}}"#,
    )
    .unwrap();
    assert!(install_user(mcp.layout.clone(), true).await.is_err());
    assert!(!mcp.log.exists());

    let skill = install_fixture(InstallFixtureOptions::default());
    fs::write(
        skill.layout.skill_source.join("SKILL.md"),
        b"---\nname: unrelated-skill\ndescription: wrong\n---\n",
    )
    .unwrap();
    assert!(install_user(skill.layout.clone(), true).await.is_err());
    assert!(!skill.log.exists());
}

#[tokio::test]
async fn task9_installer_rolls_back_only_its_mcp_when_skill_creation_races() {
    let fixture = install_fixture(InstallFixtureOptions {
        add_skill_conflict: true,
        ..InstallFixtureOptions::default()
    });
    assert!(install_user(fixture.layout.clone(), true).await.is_err());
    assert!(!fixture.codex_state.exists());
    assert!(
        fixture.layout.skill_target.exists(),
        "race target missing; codex log: {}",
        fs::read_to_string(&fixture.log).unwrap_or_default()
    );
    assert_eq!(fs::read(&fixture.layout.skill_target).unwrap(), b"conflict");
    assert!(!fixture.layout.identity_file.exists());
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("mcp add"));
    assert!(log.contains("mcp remove"));
}

#[tokio::test]
async fn task9_installer_rollback_never_removes_concurrently_replaced_mcp() {
    let fixture = install_fixture(InstallFixtureOptions {
        add_skill_conflict: true,
        drift_mcp_after_add: true,
        ..InstallFixtureOptions::default()
    });
    assert!(install_user(fixture.layout.clone(), true).await.is_err());
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.codex_state).unwrap()).unwrap();
    assert_eq!(state["transport"]["command"], "/bin/false");
    assert!(
        !fs::read_to_string(&fixture.log)
            .unwrap()
            .contains("mcp remove")
    );
}

#[tokio::test]
async fn task9_installer_rolls_back_matching_mcp_left_by_failed_codex_add() {
    let fixture = install_fixture(InstallFixtureOptions {
        fail_after_add: true,
        ..InstallFixtureOptions::default()
    });
    assert!(install_user(fixture.layout.clone(), true).await.is_err());
    assert!(!fixture.codex_state.exists());
    assert!(
        fs::read_to_string(&fixture.log)
            .unwrap()
            .contains("mcp remove")
    );
}

#[tokio::test]
async fn task9_uninstall_requires_recorded_identity_and_exact_skill_target() {
    let fixture = install_fixture(InstallFixtureOptions::default());
    install_user(fixture.layout.clone(), true).await.unwrap();
    let other = fixture._private.path().join("other-skill");
    fs::create_dir(&other).unwrap();
    fs::remove_file(&fixture.layout.skill_target).unwrap();
    symlink(&other, &fixture.layout.skill_target).unwrap();
    assert!(uninstall_user(fixture.layout.clone(), true).await.is_err());
    assert!(fixture.codex_state.exists());
    assert!(fixture.layout.identity_file.exists());

    fs::remove_file(&fixture.layout.skill_target).unwrap();
    symlink(&fixture.layout.skill_source, &fixture.layout.skill_target).unwrap();
    let dry = uninstall_user(fixture.layout.clone(), false).await.unwrap();
    assert!(!dry.applied);
    assert!(fixture.codex_state.exists());
    let applied = uninstall_user(fixture.layout.clone(), true).await.unwrap();
    assert!(applied.applied);
    assert!(!fixture.codex_state.exists());
    assert!(!fixture.layout.skill_target.exists());
    assert!(!fixture.layout.identity_file.exists());
}

#[tokio::test]
async fn task9_uninstall_cleanup_failure_restores_local_objects_and_mcp() {
    let mut fixture = install_fixture(InstallFixtureOptions::default());
    install_user(fixture.layout.clone(), true).await.unwrap();
    fixture.layout.quarantine_delete_failure = Some(2);

    let error = uninstall_user(fixture.layout.clone(), true)
        .await
        .unwrap_err();
    assert!(!error.message.contains("rollback was incomplete"));
    assert!(fixture.codex_state.exists());
    assert_eq!(
        fs::canonicalize(&fixture.layout.skill_target).unwrap(),
        fs::canonicalize(&fixture.layout.skill_source).unwrap()
    );
    assert!(fixture.layout.identity_file.exists());
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.matches("mcp add").count() >= 2, "{log}");
    assert!(
        fs::read_dir(fixture.layout.skill_target.parent().unwrap())
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("quarantine"))
    );
}

#[tokio::test]
async fn task9_apply_uses_one_private_cross_bundle_lock_and_rechecks_after_locking() {
    let fixture = install_fixture(InstallFixtureOptions {
        slow_add: true,
        ..InstallFixtureOptions::default()
    });
    let lock = fixture
        .layout
        .skill_target
        .ancestors()
        .nth(3)
        .unwrap()
        .join(".codex-ssh-bridge.install.lock");

    install_user(fixture.layout.clone(), false).await.unwrap();
    assert!(
        !lock.exists(),
        "dry-run must not create the transaction lock"
    );

    let first = install_user(fixture.layout.clone(), true);
    let second = install_user(fixture.layout.clone(), true);
    let (first, second) = tokio::join!(first, second);
    first.unwrap();
    second.unwrap();
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(log.matches("mcp add").count(), 1, "{log}");
    let metadata = fs::symlink_metadata(&lock).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        std::os::unix::fs::MetadataExt::uid(&metadata),
        std::os::unix::fs::MetadataExt::uid(
            &fs::metadata(fixture._private.path().join("user")).unwrap()
        )
    );
}

#[tokio::test]
async fn task9_apply_refuses_a_symlink_transaction_lock_before_codex_mutation() {
    let fixture = install_fixture(InstallFixtureOptions::default());
    let lock = fixture
        .layout
        .skill_target
        .ancestors()
        .nth(3)
        .unwrap()
        .join(".codex-ssh-bridge.install.lock");
    symlink("/dev/null", &lock).unwrap();
    assert!(install_user(fixture.layout.clone(), true).await.is_err());
    assert!(
        !fs::read_to_string(&fixture.log)
            .unwrap_or_default()
            .contains("mcp add")
    );
    assert!(!fixture.layout.skill_target.exists());
}

#[tokio::test]
async fn task9_failed_codex_remove_that_did_remove_is_compensated() {
    let fixture = install_fixture(InstallFixtureOptions {
        remove_failure_after_delete: true,
        ..InstallFixtureOptions::default()
    });
    install_user(fixture.layout.clone(), true).await.unwrap();

    let error = uninstall_user(fixture.layout.clone(), true)
        .await
        .unwrap_err();
    assert!(
        error.message.contains("remove") || error.message.contains("uninstall"),
        "{}",
        error.message
    );
    assert!(
        fixture.codex_state.exists(),
        "failed remove must be compensated"
    );
    assert!(fixture.layout.skill_target.exists());
    assert!(fixture.layout.identity_file.exists());
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.matches("mcp get").count() >= 3, "{log}");
    assert!(log.contains("mcp add"), "{log}");
}

#[tokio::test]
async fn task9_package_requires_trusted_ancestors_and_hashes_the_complete_skill_tree() {
    let writable = install_fixture(InstallFixtureOptions::default());
    fs::set_permissions(writable._private.path(), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(
        writable.layout.binary.ancestors().nth(2).unwrap(),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(install_user(writable.layout.clone(), false).await.is_err());
    assert!(!writable.log.exists());

    let linked = install_fixture(InstallFixtureOptions::default());
    symlink(
        "/dev/null",
        linked.layout.skill_source.join("untracked-link"),
    )
    .unwrap();
    assert!(install_user(linked.layout.clone(), false).await.is_err());
    assert!(!linked.log.exists());

    let extra = install_fixture(InstallFixtureOptions::default());
    fs::write(extra.layout.skill_source.join("EXTRA.md"), b"first").unwrap();
    let first = install_user(extra.layout.clone(), false).await.unwrap();
    fs::write(extra.layout.skill_source.join("EXTRA.md"), b"second").unwrap();
    let second = install_user(extra.layout.clone(), false).await.unwrap();
    assert_ne!(first.installation_id, second.installation_id);
}

#[tokio::test]
async fn task9_skill_yaml_requires_one_typed_stdio_mcp_dependency_object() {
    for yaml in [
        "dependencies:\n  tools:\n    - type: \"mcp\"\n      value: \"ssh-bridge\"\n      transport: \"wrong\"\n",
        "dependencies:\n  tools:\n    - type: \"mcp\"\n      value: \"other\"\n      transport: \"stdio\"\n    - type: \"other\"\n      value: \"ssh-bridge\"\n      transport: \"stdio\"\n",
        "dependencies:\n  tools:\n    - type: \"other\"\n      value: \"ssh-bridge\"\n      transport: \"stdio\"\n",
    ] {
        let fixture = install_fixture(InstallFixtureOptions::default());
        fs::write(fixture.layout.skill_source.join("agents/openai.yaml"), yaml).unwrap();
        assert!(install_user(fixture.layout.clone(), false).await.is_err());
        assert!(!fixture.log.exists());
    }
}

#[tokio::test]
async fn task9_destination_ancestors_are_fully_preflighted_before_codex_add() {
    let fixture = install_fixture(InstallFixtureOptions::default());
    let agents = fixture.layout.skill_target.ancestors().nth(2).unwrap();
    fs::create_dir_all(agents).unwrap();
    fs::set_permissions(agents, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(install_user(fixture.layout.clone(), true).await.is_err());
    let log = fs::read_to_string(&fixture.log).unwrap_or_default();
    assert!(!log.contains("mcp add"), "{log}");
    assert!(!fixture.codex_state.exists());
}

#[tokio::test]
async fn task9_unwritable_existing_destination_is_rejected_before_codex_is_called() {
    let fixture = install_fixture(InstallFixtureOptions::default());
    let skill_parent = fixture.layout.skill_target.parent().unwrap();
    fs::create_dir_all(skill_parent).unwrap();
    fs::set_permissions(skill_parent, fs::Permissions::from_mode(0o500)).unwrap();

    let result = install_user(fixture.layout.clone(), true).await;
    fs::set_permissions(skill_parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
    assert!(
        !fs::read_to_string(&fixture.log)
            .unwrap_or_default()
            .contains("mcp"),
        "destination failure must precede every Codex CLI call"
    );
    assert!(!fixture.codex_state.exists());
}

#[tokio::test]
async fn task9_partial_destination_directory_creation_is_rolled_back() {
    let mut fixture = install_fixture(InstallFixtureOptions::default());
    let state = fixture._private.path().join("user/new-state");
    fixture.layout.identity_file = state.join("x".repeat(300)).join("install.toml");
    assert!(install_user(fixture.layout.clone(), true).await.is_err());
    assert!(
        !fs::read_to_string(&fixture.log)
            .unwrap_or_default()
            .contains("mcp"),
        "predictable ENAMETOOLONG must be detected before Codex CLI"
    );
    assert!(
        !state.exists(),
        "partially created directory must be journaled"
    );
    assert!(!fixture.codex_state.exists());
    assert!(!fixture.layout.skill_target.exists());
}

#[test]
fn task9_existing_config_load_and_save_reject_unsafe_ancestors() {
    let private = tempfile::TempDir::new().unwrap();
    let real = private.path().join("real");
    fs::create_dir(&real).unwrap();
    let path = real.join("config.toml");
    Config::default().save_atomic(&path).unwrap();
    let original = fs::read(&path).unwrap();

    fs::set_permissions(&real, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(Config::load(&path).is_err());
    assert!(Config::default().save_atomic(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);

    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let through = private.path().join("through");
    symlink(&real, &through).unwrap();
    assert!(Config::load(&through.join("config.toml")).is_err());
}
