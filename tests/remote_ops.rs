mod support;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use codex_ssh_bridge::capability::ShellRequest;
use codex_ssh_bridge::output::OutputStore;
use codex_ssh_bridge::output::StreamKind;
use codex_ssh_bridge::remote::{
    EncodedValue, EntryError, EntryErrorCode, HostInfo, HostsResult, ListEntry, ListRequest,
    ListResult, OutputReadResult, ReadEntry, ReadRequest, ReadResult, RemoteBridge, RemoteContext,
    RemoteFileKind, RemoteMetadata, SearchEngine, SearchMatch, SearchRequest, SearchResult,
    ShellMetadata, ShellName, StatEntry, StatRequest, StatResult, ValueEncoding, WriteEncoding,
    WriteMode, WriteOperation, WriteRequest, WriteResult,
};
use codex_ssh_bridge::ssh::{RunRequest, RuntimePaths, SshRunner};
use codex_ssh_bridge::{BridgeError, ErrorCode};
use sha2::{Digest, Sha256};
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
    ]);
    for (key, value) in extra {
        environment.insert(OsString::from(key), value.clone());
    }
    if !rg {
        let bin = runtime_base.path().join("no-rg-bin");
        std::fs::create_dir(&bin).unwrap();
        let rg = bin.join("rg");
        std::fs::write(&rg, b"#!/bin/sh\nexit 64\n").unwrap();
        std::fs::set_permissions(&rg, std::fs::Permissions::from_mode(0o755)).unwrap();
        let inherited = environment
            .get(&OsString::from("PATH"))
            .cloned()
            .unwrap_or_else(|| OsString::from("/usr/local/bin:/usr/bin:/bin"));
        environment.insert(
            OsString::from("PATH"),
            OsString::from(format!("{}:{}", bin.display(), inherited.to_string_lossy())),
        );
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

fn ssh_call_count(log: &std::path::Path, marker: &str) -> usize {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == marker)
        .count()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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

#[test]
fn task5_write_result_shape_and_unknown_error_are_closed() {
    let create = WriteRequest {
        host: "dev".to_owned(),
        path: "a".to_owned(),
        content: "abc".to_owned(),
        encoding: WriteEncoding::Utf8,
        mode: WriteMode::Create,
    };
    assert_eq!(create.path, "a");
    let replace = WriteRequest {
        host: "dev".to_owned(),
        path: "a".to_owned(),
        content: "YWJj".to_owned(),
        encoding: WriteEncoding::Base64,
        mode: WriteMode::Replace {
            expected_sha256: Some("0".repeat(64)),
        },
    };
    assert!(matches!(replace.mode, WriteMode::Replace { .. }));

    let result = WriteResult {
        context: context(),
        actual_path: value("/root/a"),
        relative_path: value("a"),
        operation: WriteOperation::Replace,
        raw_bytes: 3,
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned(),
        mode: 0o640,
        temporary_cleanup_confirmed: true,
    };
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        serde_json::json!({
            "remote": true,
            "host": "dev",
            "physical_root": "/physical/root",
            "shell": {"kind": "sh", "version": null, "fallback": false},
            "actual_path": {"encoding": "utf8", "value": "/root/a"},
            "relative_path": {"encoding": "utf8", "value": "a"},
            "operation": "replace",
            "raw_bytes": 3,
            "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "mode": 416,
            "temporary_cleanup_confirmed": true
        })
    );

    let mut error = BridgeError::new(
        ErrorCode::MutationOutcomeUnknown,
        "remote mutation outcome could not be confirmed",
        false,
    );
    error.details.mutation_may_have_applied = Some(true);
    assert_eq!(
        serde_json::to_value(error).unwrap(),
        serde_json::json!({
            "code": "MUTATION_OUTCOME_UNKNOWN",
            "message": "remote mutation outcome could not be confirmed",
            "retryable": false,
            "details": {"mutation_may_have_applied": true}
        })
    );
}

#[tokio::test]
async fn task5_create_writes_exact_bytes_and_closed_result() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let result = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "created.bin".to_owned(),
                content: "a\0b".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(
        std::fs::read(remote.path().join("created.bin")).unwrap(),
        b"a\0b"
    );
    assert_eq!(result.operation, WriteOperation::Create);
    assert_eq!(result.raw_bytes, 3);
    assert_eq!(
        result.sha256,
        "59b271ae1bbcb1d31d41929817f4b16fb439eb4f31520b5ad1d5ce98920a7138"
    );
    assert_eq!(result.mode, 0o600);
    assert!(result.temporary_cleanup_confirmed);
    assert_eq!(result.context.shell.kind, ShellName::Sh);
}

#[tokio::test]
async fn task5_base64_is_strict_and_oversize_preflight_launches_nothing() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    for (index, invalid) in ["Y Q==", "_w==", "YQ", "YR=="].into_iter().enumerate() {
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: format!("invalid-{index}"),
                    content: invalid.to_owned(),
                    encoding: WriteEncoding::Base64,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument, "input={invalid:?}");
    }
    assert_eq!(ssh_call_count(&log, "G"), 0);
    assert_eq!(ssh_call_count(&log, "P"), 0);
    assert_eq!(ssh_call_count(&log, "C"), 0);

    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("dev", remote.path().to_str().unwrap());
    config.limits.max_write_bytes = 4;
    let oversize_log = runtime_base.path().join("oversize.log");
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
            OsString::from("FAKE_SSH_LOG"),
            oversize_log.as_os_str().to_owned(),
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
    let bridge = RemoteBridge::new(runner);
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "oversize".to_owned(),
                content: "QUFBQUE=".to_owned(),
                encoding: WriteEncoding::Base64,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge);
    assert_eq!(ssh_call_count(&oversize_log, "G"), 0);
}

#[tokio::test]
async fn task5_pre_stdin_closed_records_survive_large_input_early_close() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("exists"), b"old").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let collision_log = controls.path().join("collision.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_LOG", collision_log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "exists".to_owned(),
                content: "x".repeat(4 * 1024 * 1024),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::WriteConflict);
    assert_eq!(std::fs::read(remote.path().join("exists")).unwrap(), b"old");
    assert_eq!(ssh_call_count(&collision_log, "C"), 1);
    assert_eq!(ssh_call_count(&collision_log, "P"), 1);

    let mismatch_log = controls.path().join("mismatch.log");
    let shim = tempfile::TempDir::new().unwrap();
    let stat = shim.path().join("stat");
    std::fs::write(
        &stat,
        "#!/bin/sh\ncase \" $* \" in *codex-sentinel-safe-write*parent-link*) printf '41c0:0:700:0:1:2:1:extra\\n'; exit 0;; esac\nexec /usr/bin/stat \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_LOG", mismatch_log.as_os_str().to_owned()),
        ],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "missing-parent/target".to_owned(),
                content: "y".repeat(4 * 1024 * 1024),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteCapabilityMissing);
    assert_eq!(ssh_call_count(&mismatch_log, "C"), 1);
    assert_eq!(ssh_call_count(&mismatch_log, "P"), 1);
}

#[tokio::test]
async fn task5_stale_write_sentinel_invalidates_only_a_future_request() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let marker = controls.path().join("mismatch-used");
    let shim = tempfile::TempDir::new().unwrap();
    let stat = shim.path().join("stat");
    std::fs::write(
        &stat,
        format!(
            "#!/bin/sh\ncase \" $* \" in *codex-sentinel-safe-write*parent-link*) marker={}; if [ ! -e \"$marker\" ]; then : >\"$marker\"; printf '41c0:0:700:0:1:2:1:extra\\n'; exit 0; fi;; esac\nexec /usr/bin/stat \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let first = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "first".to_owned(),
                content: "first".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(first.code, ErrorCode::RemoteCapabilityMissing);
    assert!(!remote.path().join("first").exists());
    assert_eq!(ssh_call_count(&log, "P"), 1);
    assert_eq!(ssh_call_count(&log, "C"), 1);

    let second = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "second".to_owned(),
                content: "second".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(second.operation, WriteOperation::Create);
    assert_eq!(
        std::fs::read(remote.path().join("second")).unwrap(),
        b"second"
    );
    assert_eq!(ssh_call_count(&log, "P"), 2);
    assert_eq!(ssh_call_count(&log, "C"), 2);
}

#[tokio::test]
async fn task5_write_exact_form_sentinel_matrix_is_semantic_and_future_only() {
    struct Case {
        form: &'static str,
        tool: &'static str,
        rule: &'static str,
    }

    let cases = [
        Case {
            form: "parent-follow",
            tool: "stat",
            rule: r#"case " $* " in
  *" -L --printf=%f:%u:%a:%s:%d:%i:%h\n -- "*codex-sentinel-safe-write*/work/parent-link*)
    if [ ! -e "$marker" ]; then : >"$marker"; printf '41ed:0:700:0:0:0:2\n'; exit 0; fi;;
esac"#,
        },
        Case {
            form: "lstat",
            tool: "stat",
            rule: r#"case " $* " in
  *" --printf=%f:%u:%a:%s:%d:%i:%h\n -- "*codex-sentinel-safe-write*/work/.codex-ssh-bridge.*)
    if [ ! -e "$marker" ]; then : >"$marker"; printf '8180:0:600:8:0:0:1\n'; exit 0; fi;;
esac"#,
        },
        Case {
            form: "dd-output",
            tool: "dd",
            rule: r#"case " $* " in
  *codex-sentinel-safe-write*/work/.codex-ssh-bridge.*bs=262144*status=none*conv=notrunc*oflag=nofollow*)
    if [ ! -e "$marker" ]; then : >"$marker"; exec /usr/bin/dd of=/dev/null bs=262144 status=none; fi;;
esac"#,
        },
        Case {
            form: "dd-input-hash",
            tool: "dd",
            rule: r#"case " $* " in
  *codex-sentinel-safe-write*/work/.codex-ssh-bridge.*bs=262144*status=none*iflag=nofollow*)
    if [ ! -e "$marker" ]; then : >"$marker"; printf corrupt; exit 0; fi;;
esac"#,
        },
        Case {
            form: "sha256sum-hash",
            tool: "sha256sum",
            rule: r#"if [ -e "$armed" ] && [ ! -e "$marker" ]; then
  : >"$marker"
  /usr/bin/rm -f -- "$armed"
  /usr/bin/dd of=/dev/null status=none
  printf '0000000000000000000000000000000000000000000000000000000000000000  -\n'
  exit 0
fi"#,
        },
        Case {
            form: "ln",
            tool: "ln",
            rule: r#"case " $* " in
  *" -- "*codex-sentinel-safe-write*/work/.codex-ssh-bridge.*codex-sentinel-safe-write*/work/created*)
    destination=; for destination do :; done
    if [ -e "$destination" ] && [ ! -e "$marker" ]; then : >"$marker"; exit 0; fi;;
esac"#,
        },
        Case {
            form: "mv",
            tool: "mv",
            rule: r#"case " $* " in
  *" -T -- "*codex-sentinel-safe-write*/work/.codex-ssh-bridge.*codex-sentinel-safe-write*/work/replaced*)
    if [ ! -e "$marker" ]; then : >"$marker"; exit 0; fi;;
esac"#,
        },
        Case {
            form: "chmod",
            tool: "chmod",
            rule: r#"case " $* " in
  *" -h 0640 -- "*codex-sentinel-safe-write*/work/replaced*)
    if [ ! -e "$marker" ]; then : >"$marker"; exit 0; fi;;
esac"#,
        },
        Case {
            form: "rm",
            tool: "rm",
            rule: r#"case " $* " in
  *" -f -- "*codex-sentinel-safe-write*/work/created*)
    if [ ! -e "$marker" ]; then : >"$marker"; exit 0; fi;;
esac"#,
        },
    ];

    for case in cases {
        let remote = tempfile::TempDir::new().unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let log = controls.path().join("ssh.log");
        let marker = controls.path().join("semantic-drift-used");
        let armed = controls.path().join("sentinel-hash-armed");
        let scratch = controls.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let shim = tempfile::TempDir::new().unwrap();
        let executable = shim.path().join(case.tool);
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\nmarker={}\narmed={}\n{}\nexec /usr/bin/{} \"$@\"\n",
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                codex_ssh_bridge::quote::shell_word(armed.to_str().unwrap()).unwrap(),
                case.rule,
                case.tool,
            ),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        if case.tool == "sha256sum" {
            let stat = shim.path().join("stat");
            std::fs::write(
                &stat,
                format!(
                    "#!/bin/sh\ncase \" $* \" in *\" --printf=%f:%u:%a:%s:%d:%i:%h\\n -- \"*codex-sentinel-safe-write*/work/.codex-ssh-bridge.*) : >{};; esac\nexec /usr/bin/stat \"$@\"\n",
                    codex_ssh_bridge::quote::shell_word(armed.to_str().unwrap()).unwrap(),
                ),
            )
            .unwrap();
            std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            shim.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[
                ("PATH", path),
                ("TMPDIR", scratch.as_os_str().to_owned()),
                ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
            ],
        );

        let first = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: "first".to_owned(),
                    content: "first payload".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            first.code,
            ErrorCode::RemoteCapabilityMissing,
            "form={}",
            case.form
        );
        assert!(marker.exists(), "form={}", case.form);
        assert!(!remote.path().join("first").exists(), "form={}", case.form);
        assert_eq!(
            std::fs::read_dir(remote.path()).unwrap().count(),
            0,
            "form={}",
            case.form
        );
        assert_eq!(ssh_call_count(&log, "P"), 1, "form={}", case.form);
        assert_eq!(ssh_call_count(&log, "C"), 1, "form={}", case.form);
        assert_eq!(
            std::fs::read_dir(&scratch).unwrap().count(),
            0,
            "form={}",
            case.form
        );

        let second = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: "second".to_owned(),
                    content: "second payload".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            second.operation,
            WriteOperation::Create,
            "form={}",
            case.form
        );
        assert_eq!(
            std::fs::read(remote.path().join("second")).unwrap(),
            b"second payload",
            "form={}",
            case.form
        );
        assert_eq!(ssh_call_count(&log, "P"), 2, "form={}", case.form);
        assert_eq!(ssh_call_count(&log, "C"), 2, "form={}", case.form);
    }
}

#[tokio::test]
async fn task5_malformed_post_child_success_is_unknown_and_never_retried() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let ln = shim.path().join("ln");
    std::fs::write(
        &ln,
        "#!/bin/sh\ncase \" $* \" in *\" ./malformed\"*) /usr/bin/ln \"$@\"; status=$?; printf GARBAGE; exit \"$status\";; esac\nexec /usr/bin/ln \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&ln, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "malformed".to_owned(),
                content: "payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
    assert_eq!(error.details.mutation_may_have_applied, Some(true));
    assert_eq!(ssh_call_count(&log, "C"), 1);
    assert_eq!(ssh_call_count(&log, "P"), 1);
}

#[tokio::test]
async fn task5_unknown_postcommit_transport_and_protocol_outcomes_never_retry() {
    for post in ["disconnect", "malformed", "trailing", "stderr"] {
        let remote = tempfile::TempDir::new().unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let log = controls.path().join("ssh.log");
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[
                ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
                ("FAKE_SSH_LOCAL_FIXED_POST", OsString::from(post)),
            ],
        );
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: post.to_owned(),
                    content: "payload".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown, "post={post}");
        assert!(!error.retryable, "post={post}");
        assert_eq!(
            error.details.mutation_may_have_applied,
            Some(true),
            "post={post}"
        );
        assert_eq!(std::fs::read(remote.path().join(post)).unwrap(), b"payload");
        assert_eq!(ssh_call_count(&log, "C"), 1, "post={post}");
    }
}

#[tokio::test]
async fn task5_hash_command_failure_without_digest_is_unknown_not_mismatch() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let count = controls.path().join("sha-count");
    let shim = tempfile::TempDir::new().unwrap();
    let sha = shim.path().join("sha256sum");
    std::fs::write(
        &sha,
        format!(
            "#!/bin/sh\nmarker={}\ncount=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0)\ncount=$((count + 1))\nprintf %s \"$count\" >\"$marker\"\nif [ \"$count\" -eq 6 ]; then exit 64; fi\nexec /usr/bin/sha256sum \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(count.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&sha, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "target".to_owned(),
                content: "payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
    assert_eq!(error.details.mutation_may_have_applied, Some(true));
    assert_eq!(std::fs::read_to_string(count).unwrap(), "6");
    assert_eq!(ssh_call_count(&log, "P"), 1);
    assert_eq!(ssh_call_count(&log, "C"), 1);
}

#[tokio::test]
async fn task5_write_local_validation_and_final_render_bound_launch_zero_processes() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("validation.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let root = remote.path().to_str().unwrap().to_owned();
    let cases = [
        ("", ErrorCode::InvalidArgument),
        (".", ErrorCode::InvalidArgument),
        (root.as_str(), ErrorCode::InvalidArgument),
        ("../escape", ErrorCode::PathOutsideRoot),
        ("nul\0path", ErrorCode::InvalidArgument),
    ];
    for (path, expected) in cases {
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: path.to_owned(),
                    content: String::new(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, expected, "path={path:?}");
    }
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "x".repeat(64 * 1024 + 1),
                content: String::new(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge);
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "replace".to_owned(),
                content: "not base64".to_owned(),
                encoding: WriteEncoding::Base64,
                mode: WriteMode::Replace {
                    expected_sha256: Some("A".repeat(64)),
                },
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(ssh_call_count(&log, "G"), 0);

    let quote_log = controls.path().join("quote-frame.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        Some(32 * 1024),
        &[("FAKE_SSH_LOG", quote_log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "'".repeat(12 * 1024),
                content: String::new(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge);
    assert_eq!(ssh_call_count(&quote_log, "G"), 0);

    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("dev", remote.path().to_str().unwrap());
    config.hosts.get_mut("dev").unwrap().read_only = true;
    let readonly_log = runtime_base.path().join("readonly.log");
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
            OsString::from("FAKE_SSH_LOG"),
            readonly_log.as_os_str().to_owned(),
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
    let bridge = RemoteBridge::new(runner);
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "readonly".to_owned(),
                content: "not base64".to_owned(),
                encoding: WriteEncoding::Base64,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ReadOnlyHost);
    assert_eq!(ssh_call_count(&readonly_log, "G"), 0);
}

#[tokio::test]
async fn task5_create_collisions_hostile_names_empty_content_and_parent_symlink() {
    use std::os::unix::fs::symlink;

    let remote = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(remote.path().join("directory")).unwrap();
    std::fs::write(remote.path().join("referent"), b"keep").unwrap();
    symlink("referent", remote.path().join("live-link")).unwrap();
    symlink("missing", remote.path().join("dangling-link")).unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    for path in ["directory", "live-link", "dangling-link"] {
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: path.to_owned(),
                    content: "new".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::WriteConflict, "path={path}");
    }
    assert_eq!(
        std::fs::read(remote.path().join("referent")).unwrap(),
        b"keep"
    );

    let hostile = " -quote' line\n*?[$]`$(touch SHOULD_NOT_EXIST)`-雪 ";
    let result = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: hostile.to_owned(),
                content: "a\0b".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.mode, 0o600);
    assert_eq!(std::fs::read(remote.path().join(hostile)).unwrap(), b"a\0b");
    assert!(!remote.path().join("SHOULD_NOT_EXIST").exists());

    bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "empty".to_owned(),
                content: String::new(),
                encoding: WriteEncoding::Base64,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(remote.path().join("empty")).unwrap(), b"");

    let actual_parent = remote.path().join("actual-parent");
    std::fs::create_dir(&actual_parent).unwrap();
    symlink(&actual_parent, remote.path().join("parent-link")).unwrap();
    bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "parent-link/through-link".to_owned(),
                content: "linked".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(actual_parent.join("through-link")).unwrap(),
        b"linked"
    );

    for directory in [remote.path(), actual_parent.as_path()] {
        assert!(std::fs::read_dir(directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".codex-ssh-bridge.")
        }));
    }
}

#[tokio::test]
async fn task5_parent_identity_race_fails_before_staging() {
    use std::os::unix::fs::symlink;

    let remote = tempfile::TempDir::new().unwrap();
    let old_parent = remote.path().join("old-parent");
    let new_parent = remote.path().join("new-parent");
    let parent_link = remote.path().join("parent-link");
    std::fs::create_dir(&old_parent).unwrap();
    std::fs::create_dir(&new_parent).unwrap();
    symlink(&old_parent, &parent_link).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let stat = shim.path().join("stat");
    std::fs::write(
        &stat,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" -L \"*{}*) /usr/bin/stat \"$@\"; status=$?; /usr/bin/rm -f -- {}; /usr/bin/ln -s -- {} {}; exit \"$status\";; esac\nexec /usr/bin/stat \"$@\"\n",
            parent_link.display(),
            codex_ssh_bridge::quote::shell_word(parent_link.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(new_parent.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(parent_link.to_str().unwrap()).unwrap(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "parent-link/target".to_owned(),
                content: "z".repeat(4 * 1024 * 1024),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
    assert!(!old_parent.join("target").exists());
    assert!(!new_parent.join("target").exists());
    for directory in [&old_parent, &new_parent] {
        assert!(std::fs::read_dir(directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".codex-ssh-bridge.")
        }));
    }
    assert_eq!(ssh_call_count(&log, "C"), 1);
}

#[tokio::test]
async fn task5_staging_symlink_attack_never_modifies_referent() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let outside = controls.path().join("outside-root-sentinel");
    std::fs::write(&outside, b"OUTSIDE-SENTINEL").unwrap();
    let log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let dd = shim.path().join("dd");
    std::fs::write(
        &dd,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*bs=262144*oflag=nofollow*) target=; for argument do case \"$argument\" in of=*) target=${{argument#of=}};; esac; done; /usr/bin/rm -f -- \"$target\"; /usr/bin/ln -s -- {} \"$target\"; exec /usr/bin/dd \"$@\";; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(outside.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "target".to_owned(),
                content: "ATTACK".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
    assert_eq!(std::fs::read(&outside).unwrap(), b"OUTSIDE-SENTINEL");
    assert!(!remote.path().join("target").exists());
    assert!(std::fs::read_dir(remote.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".codex-ssh-bridge.")
    }));
    assert_eq!(ssh_call_count(&log, "C"), 1);
}

#[tokio::test]
async fn task5_cleanup_signal_removes_remote_stage_and_local_spools() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let ready = controls.path().join("stage-ready");
    let ssh_log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let dd = shim.path().join("dd");
    std::fs::write(
        &dd,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*bs=262144*oflag=nofollow*) : >{}; exec sleep 10;; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(ready.to_str().unwrap()).unwrap(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_LOG", ssh_log.as_os_str().to_owned()),
        ],
    );
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            bridge
                .write(
                    WriteRequest {
                        host: "dev".to_owned(),
                        path: "cancelled".to_owned(),
                        content: "x".repeat(4 * 1024 * 1024),
                        encoding: WriteEncoding::Utf8,
                        mode: WriteMode::Create,
                    },
                    cancel,
                )
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("caller staging dd never started");
    cancel.cancel();
    let error = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("cancelled mutation did not terminate")
        .unwrap()
        .unwrap_err();
    let cleanup = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let has_residual = std::fs::read_dir(remote.path()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".codex-ssh-bridge.")
            });
            if !has_residual {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    if cleanup.is_err() {
        let residual = std::fs::read_dir(remote.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".codex-ssh-bridge.")
            })
            .map(|entry| {
                let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
                (
                    entry.file_name(),
                    metadata.file_type().is_file(),
                    metadata.file_type().is_symlink(),
                    metadata.permissions().mode() & 0o7777,
                )
            })
            .collect::<Vec<_>>();
        let processes = std::process::Command::new("ps")
            .args(["-eo", "pid,ppid,pgid,stat,args"])
            .output()
            .unwrap();
        panic!(
            "facade={:?}; residual={residual:?}; process_status={:?}; processes=\n{}",
            error.code,
            processes.status.code(),
            String::from_utf8_lossy(&processes.stdout)
        );
    }
    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
    assert_eq!(error.details.mutation_may_have_applied, Some(true));
    assert!(!remote.path().join("cancelled").exists());
    assert_eq!(ssh_call_count(&ssh_log, "C"), 1);
    assert_eq!(
        spool_file_count(&runtime.path().join("codex-ssh-bridge")),
        0
    );
}

#[tokio::test]
async fn task5_cleanup_aborted_facade_removes_remote_stage_and_local_spools() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let ready = controls.path().join("stage-ready");
    let ssh_log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let dd = shim.path().join("dd");
    std::fs::write(
        &dd,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*bs=262144*oflag=nofollow*) : >{}; exec sleep 10;; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(ready.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_LOG", ssh_log.as_os_str().to_owned()),
        ],
    );
    let runtime_directory = runtime.path().join("codex-ssh-bridge");
    let task = tokio::spawn(async move {
        bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: "aborted".to_owned(),
                    content: "x".repeat(4 * 1024 * 1024),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let has_remote_temp = std::fs::read_dir(remote.path()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".codex-ssh-bridge.")
            });
            if ready.exists() && has_remote_temp && spool_file_count(&runtime_directory) == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("aborted write never reached staged/spooled state");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    let cleanup = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let has_remote_temp = std::fs::read_dir(remote.path()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".codex-ssh-bridge.")
            });
            if !has_remote_temp
                && !remote.path().join("aborted").exists()
                && spool_file_count(&runtime_directory) == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    if cleanup.is_err() {
        let residual = std::fs::read_dir(remote.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        let processes = std::process::Command::new("ps")
            .args(["-eo", "pid,ppid,pgid,stat,args"])
            .output()
            .unwrap();
        panic!(
            "residual={residual:?}; spool_count={}; processes=\n{}",
            spool_file_count(&runtime_directory),
            String::from_utf8_lossy(&processes.stdout)
        );
    }
    assert_eq!(ssh_call_count(&ssh_log, "C"), 1);
}

#[tokio::test]
async fn task5_replace_preserves_modes_including_unreadable_final_modes() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    for (index, mode) in [0o000, 0o200, 0o600, 0o640, 0o777].into_iter().enumerate() {
        let name = format!("mode-{mode:o}");
        let path = remote.path().join(&name);
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let content = format!("new-{index}");
        let result = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: name,
                    content: content.clone(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Replace {
                        expected_sha256: (mode & 0o400 != 0).then(|| sha256(b"old")),
                    },
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.operation, WriteOperation::Replace);
        assert_eq!(result.mode, mode);
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            mode
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), content.as_bytes());
    }
}

#[tokio::test]
async fn task5_parent_domain_errors_are_closed_before_large_stdin() {
    use std::os::unix::fs::symlink;

    let remote = tempfile::TempDir::new().unwrap();
    symlink("missing-target", remote.path().join("dangling-parent")).unwrap();
    std::fs::write(remote.path().join("regular-parent"), b"not a directory").unwrap();
    let denied = remote.path().join("denied-parent");
    std::fs::create_dir(&denied).unwrap();
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    for (path, expected) in [
        ("missing-parent/target", ErrorCode::NotFound),
        ("dangling-parent/target", ErrorCode::NotFound),
        ("regular-parent/target", ErrorCode::NotDirectory),
        ("denied-parent/target", ErrorCode::PermissionDenied),
    ] {
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: path.to_owned(),
                    content: "x".repeat(4 * 1024 * 1024),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, expected, "path={path}");
    }
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(ssh_call_count(&log, "P"), 1);
    assert_eq!(ssh_call_count(&log, "C"), 4);
}

#[tokio::test]
async fn task5_replace_precommit_conflicts_preserve_existing_entries() {
    use std::os::unix::fs::symlink;

    let remote = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(remote.path().join("directory")).unwrap();
    let fifo = remote.path().join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(remote.path().join("referent"), b"outside").unwrap();
    symlink("referent", remote.path().join("live-link")).unwrap();
    symlink("missing", remote.path().join("dangling-link")).unwrap();
    for (name, mode) in [("setuid", 0o4600), ("setgid", 0o2600), ("sticky", 0o1600)] {
        let path = remote.path().join(name);
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    std::fs::write(remote.path().join("hash-mismatch"), b"old").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);

    let missing = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "missing".to_owned(),
                content: "new".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Replace {
                    expected_sha256: None,
                },
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(missing.code, ErrorCode::NotFound);

    for path in [
        "directory",
        "fifo",
        "live-link",
        "dangling-link",
        "setuid",
        "setgid",
        "sticky",
    ] {
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: path.to_owned(),
                    content: "new".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Replace {
                        expected_sha256: None,
                    },
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::WriteConflict, "path={path}");
    }
    let mismatch = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "hash-mismatch".to_owned(),
                content: "new".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Replace {
                    expected_sha256: Some("0".repeat(64)),
                },
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(mismatch.code, ErrorCode::WriteConflict);
    assert_eq!(
        std::fs::read(remote.path().join("hash-mismatch")).unwrap(),
        b"old"
    );
    assert_eq!(
        std::fs::read(remote.path().join("referent")).unwrap(),
        b"outside"
    );
    for path in ["setuid", "setgid", "sticky"] {
        assert_eq!(std::fs::read(remote.path().join(path)).unwrap(), b"old");
    }
}

#[tokio::test]
async fn task5_expected_hash_operational_failures_are_unknown_not_conflicts() {
    for followup_stat_fails in [false, true] {
        let remote = tempfile::TempDir::new().unwrap();
        let name = if followup_stat_fails {
            "stat-op"
        } else {
            "hash-op"
        };
        std::fs::write(remote.path().join(name), b"old").unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let marker = controls.path().join("hash-failed");
        let log = controls.path().join("ssh.log");
        let shim = tempfile::TempDir::new().unwrap();
        let dd = shim.path().join("dd");
        std::fs::write(
            &dd,
            format!(
                "#!/bin/sh\ncase \" $* \" in *\" if=./{} \"*bs=262144*iflag=nofollow*) : >{}; exit 64;; esac\nexec /usr/bin/dd \"$@\"\n",
                name,
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();
        if followup_stat_fails {
            let stat = shim.path().join("stat");
            std::fs::write(
                &stat,
                format!(
                    "#!/bin/sh\nif [ -e {} ]; then case \" $* \" in *\" ./{} \"*) exit 64;; esac; fi\nexec /usr/bin/stat \"$@\"\n",
                    codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                    name,
                ),
            )
            .unwrap();
            std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            shim.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: name.to_owned(),
                    content: "new".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Replace {
                        expected_sha256: Some(sha256(b"old")),
                    },
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(std::fs::read(remote.path().join(name)).unwrap(), b"old");
        assert_eq!(ssh_call_count(&log, "C"), 1);
    }
}

#[tokio::test]
async fn task5_replace_target_stat_operational_failures_are_unknown() {
    for (phase, failing_call, expected_sha256) in [
        ("initial", 1, None),
        ("precommit", 2, None),
        ("post-hash", 3, Some(sha256(b"old"))),
    ] {
        let remote = tempfile::TempDir::new().unwrap();
        let name = format!("stat-{phase}");
        let target = remote.path().join(&name);
        std::fs::write(&target, b"old").unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let marker = controls.path().join("stat-count");
        let log = controls.path().join("ssh.log");
        let shim = tempfile::TempDir::new().unwrap();
        let stat = shim.path().join("stat");
        std::fs::write(
            &stat,
            format!(
                "#!/bin/sh\ncase \" $* \" in *\" ./{} \"*) marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\"; if [ \"$count\" -eq {} ]; then exit 64; fi;; esac\nexec /usr/bin/stat \"$@\"\n",
                name,
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                failing_call,
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            shim.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: name,
                    content: "new".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Replace { expected_sha256 },
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::MutationOutcomeUnknown,
            "phase={phase}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"old", "phase={phase}");
        assert_eq!(ssh_call_count(&log, "C"), 1, "phase={phase}");
        assert!(std::fs::read_dir(remote.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".codex-ssh-bridge.")
        }));
    }
}

#[tokio::test]
async fn task5_replace_identity_mode_and_hash_races_conflict_before_commit() {
    for race in ["identity", "mode", "hash"] {
        let remote = tempfile::TempDir::new().unwrap();
        let name = format!("{race}-race");
        let target = remote.path().join(&name);
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let log = controls.path().join("ssh.log");
        let shim = tempfile::TempDir::new().unwrap();
        let executable = shim.path().join("dd");
        let action = match race {
            "identity" => format!(
                "swap={}; printf raced >\"$swap\"; /usr/bin/mv -T -- \"$swap\" {}",
                codex_ssh_bridge::quote::shell_word(
                    remote.path().join("identity-swap").to_str().unwrap()
                )
                .unwrap(),
                codex_ssh_bridge::quote::shell_word(target.to_str().unwrap()).unwrap(),
            ),
            "mode" => format!(
                "/usr/bin/chmod 0644 -- {}",
                codex_ssh_bridge::quote::shell_word(target.to_str().unwrap()).unwrap()
            ),
            "hash" => format!(
                "printf changed >{}",
                codex_ssh_bridge::quote::shell_word(target.to_str().unwrap()).unwrap()
            ),
            _ => unreachable!(),
        };
        let body = if race == "hash" {
            format!(
                "#!/bin/sh\ncase \" $* \" in *\" if=./{} \"*bs=262144*iflag=nofollow*) {}; exec /usr/bin/dd \"$@\";; esac\nexec /usr/bin/dd \"$@\"\n",
                name, action
            )
        } else {
            format!(
                "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*bs=262144*oflag=nofollow*) /usr/bin/dd \"$@\"; status=$?; {}; exit \"$status\";; esac\nexec /usr/bin/dd \"$@\"\n",
                action
            )
        };
        std::fs::write(&executable, body).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            shim.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: name.clone(),
                    content: "payload".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Replace {
                        expected_sha256: (race == "hash").then(|| sha256(b"old")),
                    },
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::WriteConflict, "race={race}");
        assert_ne!(std::fs::read(&target).unwrap(), b"payload", "race={race}");
        assert_eq!(ssh_call_count(&log, "C"), 1);
    }
}

#[tokio::test]
async fn task5_replace_post_rename_failures_are_unknown_and_never_follow_symlinks() {
    for race in ["chmod-fail", "symlink-race", "verify-fail"] {
        let remote = tempfile::TempDir::new().unwrap();
        let target = remote.path().join(race);
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let outside = controls.path().join("outside");
        std::fs::write(&outside, b"OUTSIDE").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
        let log = controls.path().join("ssh.log");
        let marker = controls.path().join("stat-count");
        let shim = tempfile::TempDir::new().unwrap();
        let (tool, body) = match race {
            "chmod-fail" => (
                "chmod",
                format!(
                    "#!/bin/sh\ncase \" $* \" in *\" ./{} \"*) exit 64;; esac\nexec /usr/bin/chmod \"$@\"\n",
                    race
                ),
            ),
            "symlink-race" => (
                "chmod",
                format!(
                    "#!/bin/sh\ncase \" $* \" in *\" ./{} \"*) /usr/bin/rm -f -- {}; /usr/bin/ln -s -- {} {}; exec /usr/bin/chmod \"$@\";; esac\nexec /usr/bin/chmod \"$@\"\n",
                    race,
                    codex_ssh_bridge::quote::shell_word(target.to_str().unwrap()).unwrap(),
                    codex_ssh_bridge::quote::shell_word(outside.to_str().unwrap()).unwrap(),
                    codex_ssh_bridge::quote::shell_word(target.to_str().unwrap()).unwrap(),
                ),
            ),
            "verify-fail" => (
                "stat",
                format!(
                    "#!/bin/sh\ncase \" $* \" in *\" ./{} \"*) marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\"; if [ \"$count\" -eq 4 ]; then printf '81a0:0:640:7:1:2:1:extra\\n'; exit 0; fi;; esac\nexec /usr/bin/stat \"$@\"\n",
                    race,
                    codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                ),
            ),
            _ => unreachable!(),
        };
        let executable = shim.path().join(tool);
        std::fs::write(&executable, body).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            shim.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: race.to_owned(),
                    content: "payload".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Replace {
                        expected_sha256: None,
                    },
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown, "race={race}");
        assert_eq!(error.details.mutation_may_have_applied, Some(true));
        assert_eq!(std::fs::read(&outside).unwrap(), b"OUTSIDE", "race={race}");
        assert_eq!(
            std::fs::symlink_metadata(&outside)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "race={race}"
        );
        if race == "symlink-race" {
            assert!(
                std::fs::symlink_metadata(&target)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        } else {
            assert_eq!(std::fs::read(&target).unwrap(), b"payload", "race={race}");
        }
        assert_eq!(ssh_call_count(&log, "C"), 1);
    }
}

#[tokio::test]
async fn task5_target_created_during_upload_is_a_closed_conflict() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let raced_target = remote.path().join("raced-target");
    let shim = tempfile::TempDir::new().unwrap();
    let dd = shim.path().join("dd");
    std::fs::write(
        &dd,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*bs=262144*oflag=nofollow*) /usr/bin/dd \"$@\"; status=$?; printf RACE >{}; exit \"$status\";; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(raced_target.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "raced-target".to_owned(),
                content: "payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::WriteConflict);
    assert_eq!(std::fs::read(&raced_target).unwrap(), b"RACE");
    assert!(std::fs::read_dir(remote.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".codex-ssh-bridge.")
    }));
    assert_eq!(ssh_call_count(&log, "C"), 1);
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
async fn readonly_real_mismatch_retries_exactly_once_from_the_list_script() {
    use std::os::unix::fs::PermissionsExt;

    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let marker = runtime_base.path().join("find-stale-once");
    let log = runtime_base.path().join("ssh.log");
    let bin = tempfile::TempDir::new().unwrap();
    let find = bin.path().join("find");
    std::fs::write(
        &find,
        format!(
            "#!/bin/sh\ncase \" $* \" in *codex-probe-find*) exec /usr/bin/find \"$@\";; *codex-sentinel-list-production*) if [ ! -e {} ]; then : >{}; printf 'corrupt\\000'; exit 0; fi;; esac\nexec /usr/bin/find \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&find, std::fs::Permissions::from_mode(0o755)).unwrap();
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
            OsString::from("PATH"),
            OsString::from(format!(
                "{}:/usr/local/bin:/usr/bin:/bin",
                bin.path().display()
            )),
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
async fn readonly_stale_sentinel_retries_each_production_form_exactly_once() {
    struct Case {
        tool: &'static str,
        sentinel: &'static str,
        failure: &'static str,
        operation: &'static str,
        rg: bool,
        expected_commands: usize,
        expected_sentinel_invocations: usize,
    }

    let cases = [
        Case {
            tool: "find",
            sentinel: "codex-sentinel-list-production",
            failure: "printf 'corrupt\\000'; exit 0",
            operation: "list",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 6,
        },
        Case {
            tool: "xargs",
            sentinel: "codex-sentinel-list-xargs",
            failure: "exit 0",
            operation: "list",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 4,
        },
        Case {
            tool: "head",
            sentinel: "bound",
            failure: "printf zzz; exit 0",
            operation: "list",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 2,
        },
        Case {
            tool: "mktemp",
            sentinel: "codex-sentinel-bound",
            failure: "shift; d=${1%XXXXXX}bad; mkdir -m 755 \"$d\"; printf '%s\\n' \"$d\"; exit 0",
            operation: "list",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 2,
        },
        Case {
            tool: "mkfifo",
            sentinel: "codex-sentinel-bound",
            failure: ": >\"$1\"; exit 0",
            operation: "list",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 2,
        },
        Case {
            tool: "stat",
            sentinel: "codex-sentinel-stat",
            failure: "printf corrupt; exit 0",
            operation: "stat",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 8,
        },
        Case {
            tool: "tail",
            sentinel: "codex-sentinel-read",
            failure: "printf z; exit 0",
            operation: "read",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 4,
        },
        Case {
            tool: "find",
            sentinel: "codex-sentinel-search-find",
            failure: "printf 'corrupt\\000'; exit 0",
            operation: "rg-search",
            rg: true,
            expected_commands: 3,
            expected_sentinel_invocations: 2,
        },
        Case {
            tool: "rg",
            sentinel: "codex-sentinel-rg",
            failure: "printf '%s\\n' '{\"type\":\"mystery\"}'; exit 0",
            operation: "rg-search",
            rg: true,
            expected_commands: 3,
            expected_sentinel_invocations: 4,
        },
        Case {
            tool: "grep",
            sentinel: "codex-sentinel-grep",
            failure: "printf corrupt; exit 0",
            operation: "grep-search",
            rg: false,
            expected_commands: 3,
            expected_sentinel_invocations: 4,
        },
    ];

    let started = Instant::now();
    for case in cases {
        let remote = tempfile::TempDir::new().unwrap();
        std::fs::write(remote.path().join("a"), b"needle\n").unwrap();
        let state = tempfile::TempDir::new().unwrap();
        let marker = state.path().join("failed-once");
        let sentinel_log = state.path().join("sentinel.log");
        let log = state.path().join("ssh.log");
        let bin = tempfile::TempDir::new().unwrap();
        let executable = bin.path().join(case.tool);
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\ncase \"${{CODEX_SSH_SENTINEL:-}}: $*\" in *{}*) printf 'S\\n' >>{}; if [ ! -e {} ]; then : >{}; {}; fi;; esac\nexec /usr/bin/{} \"$@\"\n",
                case.sentinel,
                codex_ssh_bridge::quote::shell_word(sentinel_log.to_str().unwrap()).unwrap(),
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                case.failure,
                case.tool,
            ),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            bin.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            case.rg,
            None,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let result = match case.operation {
            "list" => bridge
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
                .map(|_| ()),
            "stat" => bridge
                .stat(
                    StatRequest {
                        host: "dev".into(),
                        paths: vec!["a".into()],
                    },
                    CancellationToken::new(),
                )
                .await
                .map(|_| ()),
            "read" => bridge
                .read(
                    ReadRequest {
                        host: "dev".into(),
                        paths: vec!["a".into()],
                        start_line: None,
                        max_lines: None,
                        max_bytes: None,
                    },
                    CancellationToken::new(),
                )
                .await
                .map(|_| ()),
            "rg-search" | "grep-search" => bridge
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
                .map(|_| ()),
            _ => unreachable!(),
        };
        result.unwrap_or_else(|error| {
            panic!("tool={}, sentinel={}: {error:?}", case.tool, case.sentinel)
        });
        let log = std::fs::read_to_string(log).unwrap();
        assert_eq!(
            log.lines().filter(|line| *line == "P").count(),
            2,
            "tool={}, sentinel={}",
            case.tool,
            case.sentinel
        );
        assert_eq!(
            log.lines().filter(|line| *line == "C").count(),
            case.expected_commands,
            "tool={}, sentinel={}",
            case.tool,
            case.sentinel
        );
        assert_eq!(
            std::fs::read_to_string(&sentinel_log)
                .unwrap()
                .lines()
                .count(),
            case.expected_sentinel_invocations,
            "tool={}, sentinel={}",
            case.tool,
            case.sentinel
        );
    }
    eprintln!(
        "ten stale-sentinel retry cases completed in {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn readonly_stale_list_production_forms_retry_exactly_once() {
    struct Case {
        name: &'static str,
        tool: &'static str,
        detect: &'static str,
        failure: &'static str,
        persistent: bool,
    }

    let cases = [
        Case {
            name: "dynamic-depth",
            tool: "find",
            detect: "p=; for a do [ \"$p\" = -maxdepth ] && [ \"$a\" = 3 ] && hit=1; p=$a; done",
            failure: "printf 'corrupt\\000'; exit 0",
            persistent: false,
        },
        Case {
            name: "hidden-prune",
            tool: "find",
            detect: "a=0; b=0; for v do [ \"$v\" = './.*' ] && a=1; [ \"$v\" = '*/.*' ] && b=1; done; [ \"$a:$b\" = 1:1 ] && hit=1",
            failure: "printf 'corrupt\\000'; exit 0",
            persistent: false,
        },
        Case {
            name: "xargs-n100",
            tool: "xargs",
            detect: "p=; for a do [ \"$p\" = -n ] && [ \"$a\" = 100 ] && hit=1; p=$a; done",
            failure: "exit 64",
            persistent: false,
        },
        Case {
            name: "persistent-dynamic-depth",
            tool: "find",
            detect: "p=; for a do [ \"$p\" = -maxdepth ] && [ \"$a\" = 3 ] && hit=1; p=$a; done",
            failure: "printf 'corrupt\\000'; exit 0",
            persistent: true,
        },
    ];

    for case in cases {
        let remote = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(remote.path().join("visible")).unwrap();
        std::fs::write(remote.path().join("visible/leaf"), b"x").unwrap();
        let state = tempfile::TempDir::new().unwrap();
        let marker = state.path().join("failed-once");
        let log = state.path().join("ssh.log");
        let bin = tempfile::TempDir::new().unwrap();
        let executable = bin.path().join(case.tool);
        let failure_guard = if case.persistent {
            case.failure.to_owned()
        } else {
            format!(
                "if [ ! -e {} ]; then : >{}; {}; fi",
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                case.failure,
            )
        };
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\nhit=0; {}\nif [ \"$hit\" = 1 ]; then {}; fi\nexec /usr/bin/{} \"$@\"\n",
                case.detect, failure_guard, case.tool,
            ),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            bin.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            true,
            None,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let result = bridge
            .list(
                ListRequest {
                    host: "dev".into(),
                    path: None,
                    depth: Some(3),
                    include_hidden: Some(false),
                    max_entries: Some(10),
                },
                CancellationToken::new(),
            )
            .await;
        if case.persistent {
            assert_eq!(
                result.unwrap_err().code,
                ErrorCode::RemoteCapabilityMissing,
                "{}",
                case.name
            );
        } else {
            result.unwrap_or_else(|error| panic!("{}: {error:?}", case.name));
        }
        let log = std::fs::read_to_string(log).unwrap();
        assert_eq!(
            log.lines().filter(|line| *line == "P").count(),
            2,
            "{}",
            case.name
        );
        assert_eq!(
            log.lines().filter(|line| *line == "C").count(),
            2,
            "{}",
            case.name
        );
    }

    let remote = tempfile::TempDir::new().unwrap();
    let state = tempfile::TempDir::new().unwrap();
    let log = state.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        true,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: Some("missing".into()),
                depth: Some(3),
                include_hidden: Some(false),
                max_entries: Some(10),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "P").count(), 1);
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 1);
}

#[tokio::test]
async fn readonly_warm_operation_sentinel_latency_evidence() {
    fn report(name: &str, samples: &mut [Duration]) {
        samples.sort_unstable();
        let milliseconds = |duration: Duration| duration.as_secs_f64() * 1_000.0;
        eprintln!(
            "warm {name}: p50={:.2}ms range={:.2}..{:.2}ms (n={})",
            milliseconds(samples[samples.len() / 2]),
            milliseconds(samples[0]),
            milliseconds(samples[samples.len() - 1]),
            samples.len()
        );
    }

    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"needle\n").unwrap();
    let (_runtime, _runner, rg_bridge) = fixture(remote.path(), true);
    rg_bridge
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

    let mut list = Vec::new();
    let mut stat = Vec::new();
    let mut read = Vec::new();
    let mut rg = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        rg_bridge
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
        list.push(started.elapsed());

        let started = Instant::now();
        rg_bridge
            .stat(
                StatRequest {
                    host: "dev".into(),
                    paths: vec!["a".into()],
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        stat.push(started.elapsed());

        let started = Instant::now();
        rg_bridge
            .read(
                ReadRequest {
                    host: "dev".into(),
                    paths: vec!["a".into()],
                    start_line: None,
                    max_lines: None,
                    max_bytes: None,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        read.push(started.elapsed());

        let started = Instant::now();
        rg_bridge
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
            .unwrap();
        rg.push(started.elapsed());
    }

    let (_runtime, _runner, grep_bridge) = fixture(remote.path(), false);
    grep_bridge
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
    let mut grep = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        grep_bridge
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
            .unwrap();
        grep.push(started.elapsed());
    }

    report("list", &mut list);
    report("stat", &mut stat);
    report("read", &mut read);
    report("rg-search", &mut rg);
    report("grep-search", &mut grep);
}

#[tokio::test]
async fn readonly_stale_sentinel_that_remains_bad_is_capability_missing() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let state = tempfile::TempDir::new().unwrap();
    let log = state.path().join("ssh.log");
    let bin = tempfile::TempDir::new().unwrap();
    let find = bin.path().join("find");
    std::fs::write(
        &find,
        b"#!/bin/sh\ncase \" $* \" in *codex-sentinel-list-production*) printf 'corrupt\\000'; exit 0;; esac\nexec /usr/bin/find \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&find, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        bin.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        true,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
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
    assert_eq!(error.code, ErrorCode::RemoteCapabilityMissing);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "P").count(), 2);
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 2);
}

#[tokio::test]
async fn readonly_sentinel_setup_failure_is_not_retried() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let state = tempfile::TempDir::new().unwrap();
    let log = state.path().join("ssh.log");
    let bin = tempfile::TempDir::new().unwrap();
    let mktemp = bin.path().join("mktemp");
    std::fs::write(
        &mktemp,
        b"#!/bin/sh\ncase \" $* \" in *codex-sentinel-bound*) exit 1;; esac\nexec /usr/bin/mktemp \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&mktemp, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        bin.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        true,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
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
    assert_eq!(error.code, ErrorCode::RemoteExit);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "P").count(), 1);
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 1);
}

#[tokio::test]
async fn readonly_filesystem_error_is_not_retried() {
    let remote = tempfile::TempDir::new().unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let log = runtime_base.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: Some("missing".into()),
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 1);
}

#[tokio::test]
async fn readonly_transport_error_is_not_retried() {
    let remote = tempfile::TempDir::new().unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let log = runtime_base.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_MODE", OsString::from("error")),
            ("FAKE_SSH_PROBE_ERROR", OsString::from("connect-timeout")),
            ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
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
    assert_eq!(error.code, ErrorCode::ConnectTimeout);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "P").count(), 1);
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 0);
}

#[tokio::test]
async fn capability_mismatch_unknown_key_is_protocol_error_without_retry() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let marker = remote.path().join("mismatch-marker");
    let runtime_base = tempfile::TempDir::new().unwrap();
    let log = runtime_base.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_MISMATCH_FILE", marker.as_os_str().to_owned()),
            ("FAKE_SSH_MISMATCH_KEY", OsString::from("unexpected_key")),
            ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
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
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 1);
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
                .ok()
                .into_iter()
                .flatten()
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
async fn task5_five_hosts_write_four_mib_with_bounded_rss_and_complete_cleanup() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use codex_ssh_bridge::config::HostProfile;

    const RAW_BYTES: usize = 4 * 1024 * 1024;
    const EXPECTED_HASH: &str = "baa7a6d36ffa957552df230235c2d51d735f28d49c58a5f3438a3a973a25a37d";
    const RSS_DELTA_CEILING_KIB: u64 = 64 * 1024;

    let remote_base = tempfile::TempDir::new().unwrap();
    let mut roots = Vec::new();
    for index in 0..5 {
        let root = remote_base.path().join(format!("h{index}"));
        std::fs::create_dir(&root).unwrap();
        roots.push(root);
    }
    let controls = tempfile::TempDir::new().unwrap();
    let ready_directory = controls.path().join("ready");
    std::fs::create_dir(&ready_directory).unwrap();
    let release = controls.path().join("release");
    let ssh_log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let dd = shim.path().join("dd");
    std::fs::write(
        &dd,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*bs=262144*oflag=nofollow*) ready={}; release={}; : >\"$ready/${{PWD##*/}}\"; while [ ! -e \"$release\" ]; do sleep 0.005; done;; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(ready_directory.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(release.to_str().unwrap()).unwrap(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();

    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let runtime_directory = runtime.directory().to_owned();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("h0", roots[0].to_str().unwrap());
    let profile: HostProfile = config.hosts["h0"].clone();
    for (index, root) in roots.iter().enumerate().skip(1) {
        let mut host = profile.clone();
        host.root = root.to_str().unwrap().to_owned();
        config.hosts.insert(format!("h{index}"), host);
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
            roots[0].as_os_str().to_owned(),
        ),
        (
            OsString::from("FAKE_SSH_LOG"),
            ssh_log.as_os_str().to_owned(),
        ),
        (
            OsString::from("PATH"),
            OsString::from(format!(
                "{}:/usr/local/bin:/usr/bin:/bin",
                shim.path().display()
            )),
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

    let encoded = STANDARD.encode(vec![b'x'; RAW_BYTES]);
    let mut sources = (0..5).map(|_| encoded.clone()).collect::<Vec<_>>();
    drop(encoded);
    let source_bytes = sources.iter().map(String::len).sum::<usize>();
    let touched = sources
        .iter()
        .flat_map(|source| source.as_bytes().iter().step_by(4096))
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    std::hint::black_box(touched);
    let baseline_rss = resident_kib();

    let monitor_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::new(std::sync::Mutex::new((baseline_rss, 0usize, 0usize, true)));
    let monitor = {
        let stop = Arc::clone(&monitor_stop);
        let observed = Arc::clone(&observed);
        let roots = roots.clone();
        let runtime_directory = runtime_directory.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let stages = roots
                    .iter()
                    .flat_map(|root| std::fs::read_dir(root).unwrap())
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".codex-ssh-bridge.")
                    })
                    .collect::<Vec<_>>();
                let spool_count = spool_file_count(&runtime_directory);
                let rss = resident_kib();
                let mut sample = observed.lock().unwrap();
                sample.0 = sample.0.max(rss);
                sample.1 = sample.1.max(stages.len());
                sample.2 = sample.2.max(spool_count);
                sample.3 &= stages.iter().all(|entry| {
                    entry.metadata().is_ok_and(|metadata| {
                        metadata.is_file() && metadata.permissions().mode() & 0o777 == 0o600
                    })
                });
                drop(sample);
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };

    let mut tasks = tokio::task::JoinSet::new();
    for (index, content) in sources.drain(..).enumerate() {
        let bridge = Arc::clone(&bridge);
        tasks.spawn(async move {
            let result = bridge
                .write(
                    WriteRequest {
                        host: format!("h{index}"),
                        path: "payload".to_owned(),
                        content,
                        encoding: WriteEncoding::Base64,
                        mode: WriteMode::Create,
                    },
                    CancellationToken::new(),
                )
                .await;
            (index, result)
        });
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let ready = std::fs::read_dir(&ready_directory).unwrap().count();
            let sample = *observed.lock().unwrap();
            if ready == 5 && sample.1 == 5 && sample.2 == 10 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("five writes never reached the simultaneous staged state");
    std::fs::write(&release, b"release").unwrap();

    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result.unwrap());
    }
    monitor_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    monitor.join().unwrap();
    results.sort_by_key(|(index, _)| *index);
    for (index, result) in results {
        let result = result.unwrap();
        assert_eq!(result.raw_bytes, RAW_BYTES as u64, "host=h{index}");
        assert_eq!(result.sha256, EXPECTED_HASH, "host=h{index}");
        assert_eq!(result.mode, 0o600, "host=h{index}");
        assert!(result.temporary_cleanup_confirmed, "host=h{index}");
        let path = roots[index].join("payload");
        assert_eq!(path.metadata().unwrap().len(), RAW_BYTES as u64);
        assert_eq!(sha256(&std::fs::read(path).unwrap()), EXPECTED_HASH);
    }

    let (peak_rss, max_stages, max_spools, all_stages_secure) = *observed.lock().unwrap();
    let rss_delta = peak_rss.saturating_sub(baseline_rss);
    eprintln!(
        "task5 write RSS sample: baseline={baseline_rss} KiB peak={peak_rss} KiB delta={rss_delta} KiB source_bytes={source_bytes}"
    );
    assert_eq!(max_stages, 5);
    assert_eq!(max_spools, 10);
    assert!(all_stages_secure);
    assert!(
        rss_delta < RSS_DELTA_CEILING_KIB,
        "baseline={baseline_rss} KiB peak={peak_rss} KiB delta={rss_delta} KiB source_bytes={source_bytes}"
    );
    assert_eq!(ssh_call_count(&ssh_log, "C"), 5);
    assert_eq!(spool_file_count(&runtime_directory), 0);
    for root in &roots {
        assert!(std::fs::read_dir(root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".codex-ssh-bridge.")
        }));
    }
}

#[tokio::test]
async fn five_hosts_successfully_stream_forty_mib_below_rss_bound() {
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
            OsString::from("large-candidates"),
        ),
        (
            OsString::from("FAKE_SSH_ROOT"),
            remote.path().as_os_str().to_owned(),
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
    let monitor_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let monitor_peak = Arc::new(std::sync::Mutex::new((0usize, 0u64, baseline_rss, true)));
    let monitor = {
        let stop = Arc::clone(&monitor_stop);
        let peak = Arc::clone(&monitor_peak);
        let directory = runtime_directory.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let files = spool_files(&directory);
                let stdout_bytes = files
                    .iter()
                    .filter(|path| path.to_string_lossy().ends_with(".stdout"))
                    .filter_map(|path| path.metadata().ok().map(|metadata| metadata.len()))
                    .max()
                    .unwrap_or(0);
                let rss = resident_kib();
                let mut observed = peak.lock().unwrap();
                observed.0 = observed.0.max(files.len());
                observed.1 = observed.1.max(stdout_bytes);
                observed.2 = observed.2.max(rss);
                if files.len() == 10 {
                    observed.3 &= files.iter().all(|path| {
                        path.metadata()
                            .is_ok_and(|metadata| metadata.permissions().mode() & 0o777 == 0o600)
                    });
                }
                drop(observed);
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    let started = std::time::Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..5 {
        let bridge = Arc::clone(&bridge);
        tasks.spawn(async move {
            bridge
                .search(
                    SearchRequest {
                        host: format!("h{index}"),
                        path: None,
                        query: "needle".into(),
                        globs: vec!["accept/**".into()],
                        max_results: None,
                        binary: None,
                    },
                    CancellationToken::new(),
                )
                .await
        });
    }
    let mut completed = 0;
    while let Some(result) = tasks.join_next().await {
        let result = result.unwrap().unwrap();
        assert!(result.matches.is_empty());
        assert!(result.truncated);
        completed += 1;
    }
    monitor_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    monitor.join().unwrap();
    let (observed_files, observed_stdout_bytes, peak_rss, all_secure) =
        *monitor_peak.lock().unwrap();
    assert_eq!(observed_files, 10);
    assert_eq!(observed_stdout_bytes, 8 * 1024 * 1024);
    assert!(all_secure);
    assert!(
        peak_rss.saturating_sub(baseline_rss) < 32 * 1024,
        "RSS grew {} KiB",
        peak_rss.saturating_sub(baseline_rss)
    );
    assert_eq!(completed, 5);
    assert!(started.elapsed() < Duration::from_millis(2_400));
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
async fn list_hidden_flood_does_not_consume_remote_cap() {
    let remote = tempfile::TempDir::new().unwrap();
    let hidden = remote.path().join(".hidden");
    std::fs::create_dir(&hidden).unwrap();
    for index in 0..200 {
        std::fs::write(
            hidden.join(format!("hidden-{index:04}-{}", "x".repeat(64))),
            b"",
        )
        .unwrap();
    }
    let visible_dir = remote.path().join("visible-dir");
    let nested_hidden = visible_dir.join(".nested-hidden");
    std::fs::create_dir_all(&nested_hidden).unwrap();
    for index in 0..200 {
        std::fs::write(
            nested_hidden.join(format!("hidden-{index:04}-{}", "y".repeat(64))),
            b"",
        )
        .unwrap();
    }
    std::fs::write(visible_dir.join("visible-c"), b"").unwrap();
    std::fs::write(remote.path().join("visible-a"), b"").unwrap();
    std::fs::write(remote.path().join("visible-b"), b"").unwrap();
    let (_runtime, _runner, bridge) = fixture_with_options(remote.path(), false, Some(4096), &[]);
    let visible = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: Some(3),
                include_hidden: Some(false),
                max_entries: Some(4),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        visible
            .entries
            .iter()
            .map(|entry| entry.relative_path.value.as_str())
            .collect::<Vec<_>>(),
        [
            "visible-a",
            "visible-b",
            "visible-dir",
            "visible-dir/visible-c"
        ]
    );
    assert!(!visible.truncated);

    let all = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: Some(3),
                include_hidden: Some(true),
                max_entries: Some(4),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(all.entries.len(), 4);
    assert!(all.truncated);
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
async fn read_final_symlink_errors_are_safe_and_follow_the_target() {
    use std::os::unix::fs::symlink;

    let remote = tempfile::TempDir::new().unwrap();
    symlink("missing-target", remote.path().join("dangling")).unwrap();
    let denied_target = remote.path().join("denied-target");
    std::fs::write(&denied_target, b"secret").unwrap();
    symlink("denied-target", remote.path().join("denied-link")).unwrap();
    std::fs::set_permissions(&denied_target, std::fs::Permissions::from_mode(0o000)).unwrap();
    let denied_parent = remote.path().join("denied-parent");
    std::fs::create_dir(&denied_parent).unwrap();
    std::fs::write(denied_parent.join("secret"), b"secret").unwrap();
    std::fs::set_permissions(&denied_parent, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let result = bridge
        .read(
            ReadRequest {
                host: "dev".into(),
                paths: vec![
                    "dangling".into(),
                    "denied-link".into(),
                    "denied-parent/secret".into(),
                ],
                start_line: None,
                max_lines: None,
                max_bytes: Some(64),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        matches!(&result.files[0], ReadEntry::Error { error, .. } if error.code == EntryErrorCode::NotFound)
    );
    let effective_uid = std::process::Command::new("id").arg("-u").output().unwrap();
    if effective_uid.stdout != b"0\n" {
        assert!(
            matches!(&result.files[1], ReadEntry::Error { error, .. } if error.code == EntryErrorCode::PermissionDenied)
        );
        assert!(
            matches!(&result.files[2], ReadEntry::Error { error, .. } if error.code == EntryErrorCode::PermissionDenied)
        );
    } else {
        eprintln!("platform skip: unreadable target cannot be asserted as effective uid 0");
    }
    std::fs::set_permissions(&denied_target, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&denied_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
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
async fn search_globs_are_slash_aware_for_star_question_class_and_double_star() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(remote.path().join("nested")).unwrap();
    for path in [
        "root.txt",
        "nested/a.txt",
        "nested/b.txt",
        "nested/c.txt",
        "nested/ab.txt",
    ] {
        std::fs::write(remote.path().join(path), b"needle\n").unwrap();
    }
    for rg in [false, true] {
        let (_runtime, _runner, bridge) = fixture(remote.path(), rg);
        for (glob, expected) in [
            ("*.txt", vec!["root.txt"]),
            (
                "nested/?.txt",
                vec!["nested/a.txt", "nested/b.txt", "nested/c.txt"],
            ),
            ("nested/[ab].txt", vec!["nested/a.txt", "nested/b.txt"]),
            (
                "**/*.txt",
                vec![
                    "nested/a.txt",
                    "nested/ab.txt",
                    "nested/b.txt",
                    "nested/c.txt",
                    "root.txt",
                ],
            ),
        ] {
            let result = bridge
                .search(
                    SearchRequest {
                        host: "dev".into(),
                        query: "needle".into(),
                        path: None,
                        globs: vec![glob.into()],
                        max_results: Some(20),
                        binary: Some(false),
                    },
                    CancellationToken::new(),
                )
                .await
                .unwrap();
            assert_eq!(
                result
                    .matches
                    .iter()
                    .map(|matched| matched.relative_path.value.as_str())
                    .collect::<Vec<_>>(),
                expected,
                "engine={:?}, glob={glob}",
                result.engine
            );
        }
    }
}

#[tokio::test]
async fn search_byte_cap_accepts_complete_prefix_and_rejects_oversized_first_event() {
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
        b"#!/bin/sh\ncase \" $* \" in *codex-probe-grep*|*codex-sentinel-grep*|*/dev/null*) exec /usr/bin/grep \"$@\";; esac\nprintf 'VERY_SECRET_ENGINE_DIAGNOSTIC\\n' >&2\nexit 2\n",
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

#[tokio::test]
async fn list_from_configured_filesystem_root_uses_single_separator() {
    let (_runtime, _runner, bridge) = fixture(std::path::Path::new("/"), true);
    let result = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: Some(1),
                include_hidden: Some(true),
                max_entries: Some(10_000),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let etc = result
        .entries
        .iter()
        .find(|entry| entry.relative_path.value == "etc")
        .expect("the filesystem root should contain /etc");
    assert_eq!(etc.actual_path, value("/etc"));
    assert!(
        result
            .entries
            .iter()
            .all(|entry| !entry.actual_path.value.starts_with("//"))
    );
}

#[tokio::test]
async fn search_from_configured_filesystem_root_derives_relative_paths() {
    let remote = tempfile::TempDir::new().unwrap();
    let file = remote.path().join("a");
    std::fs::write(&file, b"needle\n").unwrap();
    let (_runtime, _runner, bridge) = fixture(std::path::Path::new("/"), false);
    let result = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: Some(remote.path().to_str().unwrap().into()),
                globs: vec![],
                max_results: None,
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].actual_path.value, file.to_str().unwrap());
    assert_eq!(
        result.matches[0].relative_path.value,
        file.strip_prefix("/").unwrap().to_str().unwrap()
    );
}

#[tokio::test]
async fn search_quote_amplification_over_frame_is_request_too_large() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("candidate"), b"x\n").unwrap();
    let (_runtime, _runner, bridge) = fixture_with_options(remote.path(), false, Some(4096), &[]);
    let error = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "'".repeat(300),
                path: None,
                globs: vec![],
                max_results: None,
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge);
}

#[tokio::test]
async fn search_full_prefix_then_exit_two_is_error() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("candidate"), b"needle\n").unwrap();
    let bin = tempfile::TempDir::new().unwrap();
    let grep = bin.path().join("grep");
    std::fs::write(
        &grep,
        b"#!/bin/sh\ncase \" $* \" in *codex-probe-grep*|*codex-sentinel-grep*|*/dev/null*) exec /usr/bin/grep \"$@\";; esac\nfor value do candidate=$value; done\ni=0\nwhile [ \"$i\" -lt 1000 ]; do printf '%s\\000%d:needle\\n' \"$candidate\" \"$((i + 1))\"; i=$((i + 1)); done\nprintf 'VERY_SECRET_LATE_ENGINE_ERROR\\n' >&2\nexit 2\n",
    )
    .unwrap();
    std::fs::set_permissions(&grep, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        bin.path().display()
    ));
    let (_runtime, _runner, bridge) =
        fixture_with_options(remote.path(), false, Some(4096), &[("PATH", path)]);
    let error = bridge
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
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteExit);
    assert!(!error.message.contains("VERY_SECRET"));
}

#[tokio::test]
async fn search_unknown_rg_event_is_protocol_error() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("candidate"), b"needle\n").unwrap();
    let bin = tempfile::TempDir::new().unwrap();
    let rg = bin.path().join("rg");
    std::fs::write(
        &rg,
        b"#!/bin/sh\ncase \" $* \" in *codex-probe-rg*|*codex-sentinel-rg*|*/dev/null*) exec /usr/bin/rg \"$@\";; esac\nprintf '%s\\n' '{\"type\":\"mystery\",\"data\":{}}'\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&rg, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        bin.path().display()
    ));
    let (_runtime, _runner, bridge) =
        fixture_with_options(remote.path(), true, None, &[("PATH", path)]);
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
