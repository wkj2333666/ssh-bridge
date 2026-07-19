#![deny(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;

use assert_cmd::Command;
use codex_ssh_bridge::config::{Config, HostLimitOverrides, HostProfile};
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
