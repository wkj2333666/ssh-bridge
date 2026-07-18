mod support;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::sync::Arc;
use std::time::Duration;

use codex_ssh_bridge::capability::ShellRequest;
use codex_ssh_bridge::output::OutputStore;
use codex_ssh_bridge::output::StreamKind;
use codex_ssh_bridge::remote::{
    EncodedValue, EntryError, EntryErrorCode, HostInfo, HostsResult, ListEntry, ListRequest,
    ListResult, OutputReadResult, ReadEntry, ReadRequest, ReadResult, RemoteBridge, RemoteContext,
    RemoteFileKind, RemoteMetadata, SearchEngine, SearchMatch, SearchRequest, SearchResult,
    ShellMetadata, ShellName, StatEntry, StatRequest, StatResult, ValueEncoding,
};
use codex_ssh_bridge::ssh::{RunRequest, RuntimePaths, SshRunner};
use codex_ssh_bridge::{BridgeError, ErrorCode};
use tokio_util::sync::CancellationToken;

fn fixture(root: &std::path::Path, rg: bool) -> (tempfile::TempDir, Arc<SshRunner>, RemoteBridge) {
    fixture_with_options(root, rg, None, &[])
}

fn fixture_with_options(
    root: &std::path::Path,
    rg: bool,
    max_frame: Option<usize>,
    extra: &[(&str, OsString)],
) -> (tempfile::TempDir, Arc<SshRunner>, RemoteBridge) {
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("dev", root.to_str().unwrap());
    if let Some(max_frame) = max_frame {
        config.limits.max_frame_bytes = max_frame;
    }
    let mut environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), root.as_os_str().to_owned()),
        (
            OsString::from("FAKE_SSH_HAS_RG_JSON"),
            OsString::from(if rg { "1" } else { "0" }),
        ),
    ]);
    for (key, value) in extra {
        environment.insert(OsString::from(key), value.clone());
    }
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = RemoteBridge::new(Arc::clone(&runner));
    (runtime_base, runner, bridge)
}

fn context() -> RemoteContext {
    RemoteContext {
        remote: true,
        host: "dev".to_owned(),
        physical_root: "/physical/root".to_owned(),
        shell: ShellMetadata {
            kind: ShellName::Sh,
            version: None,
            fallback: false,
        },
    }
}

fn value(value: &str) -> EncodedValue {
    EncodedValue {
        encoding: ValueEncoding::Utf8,
        value: value.to_owned(),
    }
}

fn metadata() -> RemoteMetadata {
    RemoteMetadata {
        kind: RemoteFileKind::File,
        size: 3,
        mode: 0o644,
        mtime_seconds: -1,
        mtime_nanoseconds: 2,
    }
}

#[test]
fn task4_request_and_result_shapes_are_closed_and_serializable() {
    let read = ReadRequest {
        host: "dev".to_owned(),
        paths: vec!["a".to_owned()],
        start_line: None,
        max_lines: None,
        max_bytes: None,
    };
    assert_eq!(read.start_line, None);
    let _ = ListRequest {
        host: "dev".to_owned(),
        path: None,
        depth: None,
        include_hidden: None,
        max_entries: None,
    };
    let _ = StatRequest {
        host: "dev".to_owned(),
        paths: vec![],
    };
    let _ = SearchRequest {
        host: "dev".to_owned(),
        query: "x".to_owned(),
        path: None,
        globs: vec![],
        max_results: None,
        binary: None,
    };

    let hosts = HostsResult {
        hosts: vec![HostInfo {
            remote: true,
            host: "dev".to_owned(),
            configured_root: "/root".to_owned(),
            description: None,
            read_only: true,
            physical_root: None,
            shell: None,
        }],
    };
    assert_eq!(
        serde_json::to_value(hosts).unwrap(),
        serde_json::json!({"hosts":[{
            "remote":true,"host":"dev","configured_root":"/root","description":null,
            "read_only":true,"physical_root":null,"shell":null
        }]})
    );

    let list = ListResult {
        context: context(),
        actual_path: value("/root"),
        relative_path: value(""),
        entries: vec![ListEntry {
            actual_path: value("/root/a"),
            relative_path: value("a"),
            metadata: metadata(),
        }],
        truncated: false,
    };
    assert_eq!(
        serde_json::to_value(list).unwrap()["shell"]["version"],
        serde_json::Value::Null
    );

    let stat = StatResult {
        context: context(),
        entries: vec![
            StatEntry::Success {
                actual_path: value("/root/a"),
                relative_path: value("a"),
                metadata: metadata(),
            },
            StatEntry::Error {
                actual_path: value("/root/b"),
                relative_path: value("b"),
                error: EntryError {
                    code: EntryErrorCode::NotFound,
                    message: "remote path was not found",
                },
            },
        ],
    };
    let stat_json = serde_json::to_value(stat).unwrap();
    assert_eq!(stat_json["entries"][0]["status"], "success");
    assert_eq!(stat_json["entries"][1]["error"]["code"], "NOT_FOUND");

    let read_result = ReadResult {
        context: context(),
        files: vec![ReadEntry::Success {
            actual_path: value("/root/a"),
            relative_path: value("a"),
            content: value("abc"),
            raw_bytes: 3,
            sha256: "0".repeat(64),
            truncated_before: false,
            truncated_after: false,
            truncated: false,
        }],
        returned_raw_bytes: 3,
    };
    assert_eq!(
        serde_json::to_value(read_result).unwrap()["files"][0]["status"],
        "success"
    );

    let search = SearchResult {
        context: context(),
        engine: SearchEngine::Rg,
        matches: vec![SearchMatch {
            actual_path: value("/root/a"),
            relative_path: value("a"),
            line: 1,
            column: 2,
            content: value("abc"),
        }],
        truncated: false,
    };
    assert_eq!(serde_json::to_value(search).unwrap()["engine"], "rg");

    let page = OutputReadResult {
        context: context(),
        stream: StreamKind::Stdout,
        offset: 0,
        next_offset: 3,
        eof: true,
        data: value("abc"),
    };
    assert_eq!(serde_json::to_value(page).unwrap()["stream"], "stdout");

    let error = BridgeError::new(
        ErrorCode::ReadConflict,
        "remote file changed while being read",
        false,
    );
    assert_eq!(
        serde_json::to_value(error).unwrap()["code"],
        "READ_CONFLICT"
    );
}

#[tokio::test]
async fn metadata_read_and_grep_search_run_through_fixed_spools() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("alpha.txt"), b"one\ntwo needle\nthree").unwrap();
    std::fs::create_dir(remote.path().join("dir")).unwrap();
    std::fs::write(remote.path().join(".hidden"), b"needle").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let cancel = CancellationToken::new();

    let list = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: Some(1),
                include_hidden: Some(false),
                max_entries: None,
            },
            cancel.clone(),
        )
        .await
        .unwrap();
    assert_eq!(list.entries.len(), 2);
    assert!(
        list.entries
            .iter()
            .all(|entry| entry.relative_path.value != ".hidden")
    );

    let stat = bridge
        .stat(
            StatRequest {
                host: "dev".into(),
                paths: vec!["alpha.txt".into(), "missing".into()],
            },
            cancel.clone(),
        )
        .await
        .unwrap();
    assert!(matches!(stat.entries[0], StatEntry::Success { .. }));
    assert!(matches!(stat.entries[1], StatEntry::Error { .. }));

    let read = bridge
        .read(
            ReadRequest {
                host: "dev".into(),
                paths: vec!["alpha.txt".into()],
                start_line: Some(2),
                max_lines: Some(1),
                max_bytes: Some(1024),
            },
            cancel.clone(),
        )
        .await
        .unwrap();
    match &read.files[0] {
        ReadEntry::Success {
            content,
            truncated_before,
            truncated_after,
            ..
        } => {
            assert_eq!(content.value, "two needle\n");
            assert!(*truncated_before);
            assert!(*truncated_after);
        }
        _ => panic!("expected read success"),
    }

    let search = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: None,
                globs: vec!["**/*.txt".into()],
                max_results: None,
                binary: Some(false),
            },
            cancel,
        )
        .await
        .unwrap();
    assert_eq!(search.engine, SearchEngine::Grep);
    assert_eq!(search.matches.len(), 1, "{search:?}");
    assert_eq!(search.matches[0].column, 5);
}

#[tokio::test]
async fn output_read_requires_and_uses_command_provenance() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, runner, bridge) = fixture(remote.path(), false);
    let result = runner
        .execute(
            RunRequest {
                host: "dev".into(),
                command: "head -c 300000 /dev/zero".into(),
                shell: ShellRequest::Auto,
                stdin: None,
                timeout: Duration::from_secs(5),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let reference = result.output.reference.unwrap();
    let page = bridge
        .output_read(
            codex_ssh_bridge::remote::OutputReadRequest {
                output_ref: reference.as_str().into(),
                stream: StreamKind::Stdout,
                offset: 0,
                max_bytes: 16,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(page.context.host, "dev");
    assert_eq!(page.data.encoding, ValueEncoding::Base64);
    assert_eq!(page.next_offset, 16);
}

#[tokio::test]
async fn capability_retry_is_exactly_once_for_a_required_key() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let marker = runtime_base.path().join("mismatch-once");
    let log = runtime_base.path().join("ssh.log");
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (
            OsString::from("FAKE_SSH_ROOT"),
            remote.path().as_os_str().to_owned(),
        ),
        (
            OsString::from("FAKE_SSH_MISMATCH_FILE"),
            marker.as_os_str().to_owned(),
        ),
        (
            OsString::from("FAKE_SSH_MISMATCH_KEY"),
            OsString::from("find_nul"),
        ),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
    ]);
    let config = Arc::new(support::config_with_host(
        "dev",
        remote.path().to_str().unwrap(),
    ));
    let runner = Arc::new(
        SshRunner::with_executable(
            config,
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = RemoteBridge::new(runner);
    let result = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.entries.len(), 1);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "P").count(), 2);
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 2);
}

#[tokio::test]
async fn capability_mismatch_unknown_key_is_protocol_error_without_retry() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let marker = remote.path().join("mismatch-marker");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_MISMATCH_FILE", marker.as_os_str().to_owned()),
            ("FAKE_SSH_MISMATCH_KEY", OsString::from("unexpected_key")),
        ],
    );
    let error = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
}

#[tokio::test]
async fn non_utf8_paths_and_binary_content_are_lossless() {
    let remote = tempfile::TempDir::new().unwrap();
    let raw_name = OsString::from_vec(b"raw-\xff".to_vec());
    std::fs::write(remote.path().join(&raw_name), b"needle\n").unwrap();
    std::fs::write(remote.path().join("binary"), b"a\0needle\xff\n").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), true);
    let list = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: Some(true),
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        list.entries
            .iter()
            .any(|entry| entry.relative_path.encoding == ValueEncoding::Base64)
    );
    let search = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: None,
                globs: vec![],
                max_results: None,
                binary: Some(true),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(search.engine, SearchEngine::Rg);
    assert!(
        search
            .matches
            .iter()
            .any(|entry| entry.actual_path.encoding == ValueEncoding::Base64)
    );
    assert!(
        search
            .matches
            .iter()
            .any(|entry| entry.content.encoding == ValueEncoding::Base64)
    );
    let read = bridge
        .read(
            ReadRequest {
                host: "dev".into(),
                paths: vec!["binary".into()],
                start_line: None,
                max_lines: None,
                max_bytes: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        matches!(&read.files[0], ReadEntry::Success { content, .. } if content.encoding == ValueEncoding::Base64)
    );
}

#[tokio::test]
async fn hosts_are_local_and_list_and_read_bounds_are_exact() {
    let remote = tempfile::TempDir::new().unwrap();
    for name in ["a", "b", "c"] {
        std::fs::write(remote.path().join(name), b"1234").unwrap();
    }
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let hosts = bridge.hosts().await.unwrap();
    assert_eq!(hosts.hosts[0].physical_root, None);
    let list = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: None,
                max_entries: Some(1),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(list.entries.len(), 1);
    assert!(list.truncated);
    let read = bridge
        .read(
            ReadRequest {
                host: "dev".into(),
                paths: vec!["a".into(), "b".into()],
                start_line: None,
                max_lines: None,
                max_bytes: Some(5),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(read.returned_raw_bytes, 5);
    assert!(matches!(&read.files[1], ReadEntry::Success { truncated, .. } if *truncated));
}

#[tokio::test]
async fn aborting_a_fixed_facade_unlinks_internal_spools_without_ttl() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let runtime_directory = runtime.directory().to_owned();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (
            OsString::from("FAKE_SSH_ROOT"),
            remote.path().as_os_str().to_owned(),
        ),
        (
            OsString::from("FAKE_SSH_FIXED_SLEEP_SECONDS"),
            OsString::from("0.5"),
        ),
    ]);
    let config = Arc::new(support::config_with_host(
        "dev",
        remote.path().to_str().unwrap(),
    ));
    let runner = Arc::new(
        SshRunner::with_executable(
            config,
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = RemoteBridge::new(runner);
    let task = tokio::spawn(async move {
        bridge
            .list(
                ListRequest {
                    host: "dev".into(),
                    path: None,
                    depth: None,
                    include_hidden: None,
                    max_entries: None,
                },
                CancellationToken::new(),
            )
            .await
    });
    for _ in 0..100 {
        if spool_file_count(&runtime_directory) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(spool_file_count(&runtime_directory) >= 2);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    for _ in 0..100 {
        if spool_file_count(&runtime_directory) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(spool_file_count(&runtime_directory), 0);
}

fn spool_file_count(runtime: &std::path::Path) -> usize {
    std::fs::read_dir(runtime)
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            if entry.file_type().ok()?.is_dir()
                && entry.file_name().to_string_lossy().starts_with("output-")
            {
                Some(entry.path())
            } else {
                None
            }
        })
        .map(|directory| std::fs::read_dir(directory).unwrap().count())
        .sum()
}

fn spool_files(runtime: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(runtime)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_dir())
                && entry.file_name().to_string_lossy().starts_with("output-")
        })
        .flat_map(|entry| {
            std::fs::read_dir(entry.path())
                .unwrap()
                .filter_map(Result::ok)
                .map(|file| file.path())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn resident_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
        .unwrap()
}

#[tokio::test]
async fn five_hosts_overlap_with_forty_mib_spooled_and_bounded_rss() {
    use codex_ssh_bridge::config::HostProfile;
    use std::os::unix::fs::PermissionsExt;
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let runtime_directory = runtime.directory().to_owned();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("h0", remote.path().to_str().unwrap());
    let profile: HostProfile = config.hosts["h0"].clone();
    for index in 1..5 {
        config.hosts.insert(format!("h{index}"), profile.clone());
    }
    config.limits.global_concurrency = 5;
    config.limits.per_host_concurrency = 1;
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (
            OsString::from("FAKE_SSH_ROOT"),
            remote.path().as_os_str().to_owned(),
        ),
        (
            OsString::from("FAKE_SSH_FIXED_STDOUT_BYTES"),
            OsString::from((8 * 1024 * 1024).to_string()),
        ),
        (
            OsString::from("FAKE_SSH_FIXED_SLEEP_SECONDS"),
            OsString::from("0.3"),
        ),
    ]);
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = Arc::new(RemoteBridge::new(runner));
    let baseline_rss = resident_kib();
    let started = std::time::Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..5 {
        let bridge = Arc::clone(&bridge);
        tasks.spawn(async move {
            bridge
                .list(
                    ListRequest {
                        host: format!("h{index}"),
                        path: None,
                        depth: None,
                        include_hidden: None,
                        max_entries: None,
                    },
                    CancellationToken::new(),
                )
                .await
        });
    }
    let mut peak_files = Vec::new();
    for _ in 0..300 {
        let files = spool_files(&runtime_directory);
        if files
            .iter()
            .filter(|path| {
                path.extension().is_some_and(|value| value == "stdout")
                    && path
                        .metadata()
                        .is_ok_and(|metadata| metadata.len() >= 8 * 1024 * 1024)
            })
            .count()
            == 5
        {
            peak_files = files;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(peak_files.len(), 10);
    assert!(
        peak_files
            .iter()
            .all(|path| path.metadata().unwrap().permissions().mode() & 0o777 == 0o600)
    );
    let peak_rss = resident_kib();
    assert!(
        peak_rss.saturating_sub(baseline_rss) < 32 * 1024,
        "RSS grew {} KiB",
        peak_rss.saturating_sub(baseline_rss)
    );
    let mut completed = 0;
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap().unwrap_err().code, ErrorCode::OutputLimit);
        completed += 1;
    }
    assert_eq!(completed, 5);
    assert!(started.elapsed() < Duration::from_millis(1_200));
    assert_eq!(spool_file_count(&runtime_directory), 0);
}

#[tokio::test]
async fn metadata_list_stat_preserve_order_kinds_and_hidden_depth() {
    use std::os::unix::fs::symlink;
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(remote.path().join("dir/.nested")).unwrap();
    std::fs::write(remote.path().join("file"), b"abc").unwrap();
    symlink("file", remote.path().join("link")).unwrap();
    std::fs::write(remote.path().join("dir/.nested/secret"), b"x").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let list = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: Some(3),
                include_hidden: Some(false),
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        list.entries
            .iter()
            .all(|entry| !entry.relative_path.value.contains(".nested"))
    );
    let stat = bridge
        .stat(
            StatRequest {
                host: "dev".into(),
                paths: vec!["link".into(), "file".into()],
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        matches!(&stat.entries[0], StatEntry::Success { metadata, .. } if metadata.kind == RemoteFileKind::Symlink)
    );
    assert!(
        matches!(&stat.entries[1], StatEntry::Success { metadata, .. } if metadata.kind == RemoteFileKind::File && metadata.size == 3)
    );
}

#[tokio::test]
async fn metadata_ten_thousand_lookahead_permission_fifo_socket_and_pre_epoch() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    let remote = tempfile::TempDir::new().unwrap();
    let many = remote.path().join("many");
    std::fs::create_dir(&many).unwrap();
    for index in 0..10_001 {
        std::fs::write(many.join(format!("f{index:05}")), b"").unwrap();
    }
    let fifo = remote.path().join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let socket_path = remote.path().join("socket");
    let socket_listener = UnixListener::bind(&socket_path).ok();
    let socket_available = socket_listener.is_some()
        || find_existing_socket()
            .is_some_and(|source| std::fs::hard_link(source, &socket_path).is_ok());
    let old = remote.path().join("old");
    std::fs::write(&old, b"x").unwrap();
    let pre_epoch_supported = std::process::Command::new("touch")
        .args(["-d", "@-1", "--"])
        .arg(&old)
        .status()
        .unwrap()
        .success();
    let denied = remote.path().join("denied");
    std::fs::create_dir(&denied).unwrap();
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let list = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: Some("many".into()),
                depth: Some(1),
                include_hidden: Some(true),
                max_entries: Some(10_000),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(list.entries.len(), 10_000);
    assert!(list.truncated);
    let mut stat_paths = vec!["fifo".into()];
    if socket_available {
        stat_paths.push("socket".into());
    }
    stat_paths.push("old".into());
    let stat = bridge
        .stat(
            StatRequest {
                host: "dev".into(),
                paths: stat_paths,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        matches!(&stat.entries[0], StatEntry::Success { metadata, .. } if metadata.kind == RemoteFileKind::Fifo)
    );
    let old_index = if socket_available {
        assert!(
            matches!(&stat.entries[1], StatEntry::Success { metadata, .. } if metadata.kind == RemoteFileKind::Socket)
        );
        2
    } else {
        eprintln!(
            "platform skip: sandbox denied AF_UNIX bind and exposed no linkable existing socket"
        );
        1
    };
    if pre_epoch_supported {
        assert!(
            matches!(&stat.entries[old_index], StatEntry::Success { metadata, .. } if metadata.mtime_seconds == -1)
        );
    } else {
        eprintln!("platform skip: filesystem/touch does not support pre-epoch timestamp");
    }
    let effective_uid = std::process::Command::new("id").arg("-u").output().unwrap();
    if effective_uid.stdout != b"0\n" {
        let error = bridge
            .list(
                ListRequest {
                    host: "dev".into(),
                    path: Some("denied".into()),
                    depth: None,
                    include_hidden: None,
                    max_entries: None,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    } else {
        eprintln!("platform skip: permission denial cannot be asserted as effective uid 0");
    }
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn find_existing_socket() -> Option<std::path::PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    std::fs::read_dir("/tmp")
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("tmux-"))
        .find_map(|entry| {
            let candidate = entry.path().join("default");
            candidate
                .symlink_metadata()
                .ok()
                .filter(|metadata| metadata.file_type().is_socket())
                .map(|_| candidate)
        })
}

#[tokio::test]
async fn read_full_hash_missing_symlink_and_aggregate_truncation() {
    use std::os::unix::fs::symlink;
    let remote = tempfile::TempDir::new().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), b"outside").unwrap();
    symlink(outside.path(), remote.path().join("outside-link")).unwrap();
    std::fs::write(remote.path().join("a"), b"abc").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let result = bridge
        .read(
            ReadRequest {
                host: "dev".into(),
                paths: vec!["a".into(), "missing".into(), "outside-link".into()],
                start_line: None,
                max_lines: None,
                max_bytes: Some(8),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        matches!(&result.files[0], ReadEntry::Success { sha256, truncated, .. } if sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" && !truncated)
    );
    assert!(
        matches!(&result.files[1], ReadEntry::Error { error, .. } if error.code == EntryErrorCode::NotFound)
    );
    assert!(matches!(&result.files[2], ReadEntry::Success { truncated, .. } if *truncated));
    assert_eq!(result.returned_raw_bytes, 8);
}

#[tokio::test]
async fn read_hash_before_after_race_is_a_contentless_read_conflict() {
    use std::io::Write as _;
    let remote = tempfile::TempDir::new().unwrap();
    let path = remote.path().join("racing");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(128 * 1024 * 1024)
        .unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let log = runtime_base.path().join("ssh.log");
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (
            OsString::from("FAKE_SSH_ROOT"),
            remote.path().as_os_str().to_owned(),
        ),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
    ]);
    let config = Arc::new(support::config_with_host(
        "dev",
        remote.path().to_str().unwrap(),
    ));
    let runner = Arc::new(
        SshRunner::with_executable(
            config,
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = RemoteBridge::new(runner);
    let task = tokio::spawn(async move {
        bridge
            .read(
                ReadRequest {
                    host: "dev".into(),
                    paths: vec!["racing".into()],
                    start_line: None,
                    max_lines: Some(1),
                    max_bytes: Some(1),
                },
                CancellationToken::new(),
            )
            .await
    });
    for _ in 0..200 {
        if std::fs::read_to_string(&log).is_ok_and(|value| value.lines().any(|line| line == "C")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    for _ in 0..200 {
        if task.is_finished() {
            break;
        }
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let result = task.await.unwrap().unwrap();
    assert!(
        matches!(&result.files[0], ReadEntry::Error { error, .. } if error.code == EntryErrorCode::ReadConflict)
    );
    let json = serde_json::to_value(&result.files[0]).unwrap();
    assert!(json.get("content").is_none());
}

#[tokio::test]
async fn search_rg_and_grep_share_literal_glob_and_byte_column_semantics() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a.txt"), b"xx a.b yy\n").unwrap();
    std::fs::write(remote.path().join("skip.log"), b"a.b\n").unwrap();
    for rg in [false, true] {
        let (_runtime, _runner, bridge) = fixture(remote.path(), rg);
        let result = bridge
            .search(
                SearchRequest {
                    host: "dev".into(),
                    query: "a.b".into(),
                    path: None,
                    globs: vec!["*.txt".into()],
                    max_results: Some(10),
                    binary: Some(false),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.matches.len(), 1, "engine={:?}", result.engine);
        assert_eq!((result.matches[0].line, result.matches[0].column), (1, 4));
        assert_eq!(result.matches[0].relative_path.value, "a.txt");
    }
}

#[tokio::test]
async fn search_planned_cap_accepts_complete_prefix_and_rejects_oversized_first_event() {
    let remote = tempfile::TempDir::new().unwrap();
    let mut many = Vec::new();
    for _ in 0..2_000 {
        many.extend_from_slice(b"needle\n");
    }
    std::fs::write(remote.path().join("many"), many).unwrap();
    let (_runtime, _runner, bridge) =
        fixture_with_options(remote.path(), false, Some(4 * 1024), &[]);
    let result = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: None,
                globs: vec![],
                max_results: Some(10_000),
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(result.truncated);
    assert!(!result.matches.is_empty(), "{result:?}");

    let oversized = tempfile::TempDir::new().unwrap();
    let mut line = vec![b'x'; 5 * 1024];
    line.extend_from_slice(b"needle\n");
    std::fs::write(oversized.path().join("one"), line).unwrap();
    let (_runtime, _runner, bridge) =
        fixture_with_options(oversized.path(), false, Some(4 * 1024), &[]);
    let error = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: None,
                globs: vec![],
                max_results: None,
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
}

#[tokio::test]
async fn search_real_engine_failure_is_fixed_and_redacted() {
    use std::os::unix::fs::PermissionsExt;
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("secret-name"), b"needle\n").unwrap();
    let bin = tempfile::TempDir::new().unwrap();
    let grep = bin.path().join("grep");
    std::fs::write(
        &grep,
        b"#!/bin/sh\nprintf 'VERY_SECRET_ENGINE_DIAGNOSTIC\\n' >&2\nexit 2\n",
    )
    .unwrap();
    std::fs::set_permissions(&grep, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!("{}:/usr/bin:/bin", bin.path().display()));
    let (_runtime, _runner, bridge) =
        fixture_with_options(remote.path(), false, None, &[("PATH", path)]);
    let error = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: None,
                globs: vec![],
                max_results: None,
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteExit);
    assert!(!error.message.contains("VERY_SECRET"));
    assert!(!error.message.contains("secret-name"));
}
