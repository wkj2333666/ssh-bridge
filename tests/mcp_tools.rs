use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader as StdBufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use codex_ssh_bridge::config::{Config, HostLimitOverrides, HostProfile};
use codex_ssh_bridge::mcp::stdio::{exact_tools_list_response_bytes, required_mcp_frame_bytes};
use codex_ssh_bridge::mcp::tools::{RemoteMcpTools, tool_definitions};
use codex_ssh_bridge::mcp::{
    CallToolResult, McpServer, RequestId, ToolCallContext, ToolDefinition, ToolFuture, ToolService,
    WireBudget,
};
use codex_ssh_bridge::output::OutputStore;
use codex_ssh_bridge::remote::RemoteBridge;
use codex_ssh_bridge::ssh::{RuntimePaths, SshRunner};
use serde_json::{Value, json};
use tokio::io::{
    AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader, DuplexStream, ReadHalf, WriteHalf,
};
use tokio_util::sync::CancellationToken;

mod support;

fn remote_tools_fixture() -> (tempfile::TempDir, Arc<RemoteBridge>, RemoteMcpTools) {
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let config = Arc::new(support::config_with_host("dev", "/srv/remote"));
    let runner = Arc::new(SshRunner::new(config, runtime, store).unwrap());
    let bridge = Arc::new(RemoteBridge::new(runner));
    (
        runtime_base,
        Arc::clone(&bridge),
        RemoteMcpTools::new(bridge),
    )
}

fn roomy_context() -> ToolCallContext {
    ToolCallContext {
        cancel: CancellationToken::new(),
        wire_budget: WireBudget {
            result_bytes: 2 * 1024 * 1024,
            compact_fallback_bytes: codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes(),
        },
    }
}

fn fake_remote_tools_fixture(
    root: &std::path::Path,
) -> (tempfile::TempDir, std::path::PathBuf, RemoteMcpTools) {
    fake_remote_tools_with_options(root, false, &[])
}

fn fake_remote_tools_with_options(
    root: &std::path::Path,
    read_only: bool,
    extra: &[(&str, OsString)],
) -> (tempfile::TempDir, std::path::PathBuf, RemoteMcpTools) {
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("dev", root.to_str().unwrap());
    config.hosts.get_mut("dev").unwrap().read_only = read_only;
    if read_only {
        config.hosts.get_mut("dev").unwrap().description = Some("D".repeat(2 * 1024 * 1024));
    }
    let log = runtime_base.path().join("ssh.log");
    let mut environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), root.as_os_str().to_owned()),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
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
    let bridge = Arc::new(RemoteBridge::new(runner));
    (runtime_base, log, RemoteMcpTools::new(bridge))
}

async fn call_json(tools: &RemoteMcpTools, name: &str, arguments: Value) -> Value {
    serde_json::to_value(
        tools
            .call(name.to_owned(), arguments, roomy_context())
            .await,
    )
    .unwrap()
}

fn text_json(result: &Value) -> Value {
    serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
}

fn command_calls(log: &std::path::Path) -> usize {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == "C")
        .count()
}

fn write_binary_config(directory: &std::path::Path, contents: &str) -> std::path::PathBuf {
    let path = directory.join("config.toml");
    std::fs::write(&path, contents).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn binary_command(config: &std::path::Path, runtime: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_codex-ssh-bridge"));
    command
        .env("CODEX_SSH_BRIDGE_CONFIG", config)
        .env("XDG_RUNTIME_DIR", runtime);
    command
}

fn wait_for_child_bounded(
    mut child: std::process::Child,
    timeout: Duration,
) -> (std::process::Output, bool) {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap().is_some() {
            return (child.wait_with_output().unwrap(), false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return (child.wait_with_output().unwrap(), true);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn task8_binary_lifecycle_smoke_exposes_exact_surface_without_leaks() {
    let private = tempfile::TempDir::new().unwrap();
    std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let host_root = "/srv/BINARY_HOST_PATH_SENTINEL";
    let secret = "CONFIG_CONTENT_SENTINEL";
    let config = write_binary_config(
        private.path(),
        &format!(
            "[limits]\nmax_frame_bytes = 8388608\nglobal_concurrency = 3\nglobal_spool_quota_bytes = 67108864\nretention_serialization_jobs = 1\n[hosts.dev]\nroot = {host_root:?}\ndescription = {secret:?}\n"
        ),
    );
    let caller_frame = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"remote_hosts","arguments":{}}}
"#;
    let ssh_log = private.path().join("unexpected-ssh.log");
    std::os::unix::fs::symlink(support::fake_ssh_path(), private.path().join("ssh")).unwrap();
    let mut child = binary_command(&config, private.path())
        .arg("mcp")
        .env("PATH", private.path())
        .env("FAKE_SSH_LOG", &ssh_log)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(caller_frame.as_bytes()).unwrap();
    stdin.flush().unwrap();
    let child_stdout = child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in StdBufReader::new(child_stdout).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let mut response_lines = Vec::new();
    for _ in 0..3 {
        match receiver.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(line)) => response_lines.push(line),
            other => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("timed out or failed reading MCP response: {other:?}");
            }
        }
    }
    drop(stdin);
    let (output, eof_timed_out) = wait_for_child_bounded(child, Duration::from_secs(5));
    reader.join().unwrap();
    for line in receiver.try_iter() {
        response_lines.push(line.unwrap());
    }
    assert!(
        !eof_timed_out,
        "binary did not terminate after stdin EOF; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = response_lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 3, "responses={lines:#?}");
    assert_eq!(
        lines.iter().map(|line| &line["id"]).collect::<Vec<_>>(),
        [&json!(1), &json!(2), &json!(3)]
    );
    assert_eq!(lines[0]["result"]["protocolVersion"], "2025-11-25");
    let names = lines[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|definition| definition["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        tool_definitions()
            .iter()
            .map(|definition| definition.name.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(lines[2]["result"]["isError"], Value::Null);
    assert_eq!(lines[2]["result"]["structuredContent"]["host_count"], 1);
    assert_eq!(std::fs::read(&ssh_log).unwrap_or_default(), b"");
    let stderr = String::from_utf8(output.stderr).unwrap();
    for forbidden in [
        secret,
        host_root,
        config.to_str().unwrap(),
        "ControlPath",
        caller_frame.trim(),
    ] {
        assert!(
            !stderr.contains(forbidden),
            "stderr leaked {forbidden:?}: {stderr}"
        );
    }
}

struct ProtocolSession {
    input: WriteHalf<DuplexStream>,
    output: TokioBufReader<ReadHalf<DuplexStream>>,
    server: tokio::task::JoinHandle<codex_ssh_bridge::BridgeResult<()>>,
    next_id: u64,
}

impl ProtocolSession {
    async fn start(tools: RemoteMcpTools) -> Self {
        Self::start_with_frame(tools, codex_ssh_bridge::MAX_FRAME_BYTES).await
    }

    async fn start_with_frame(tools: RemoteMcpTools, max_frame_bytes: usize) -> Self {
        let (client, server_io) = tokio::io::duplex(16 * 1024 * 1024);
        let (client_output, client_input) = tokio::io::split(client);
        let (server_input, server_output) = tokio::io::split(server_io);
        let server = McpServer::new(Arc::new(tools), max_frame_bytes, 4).unwrap();
        let server = tokio::spawn(server.serve(server_input, server_output));
        let mut session = Self {
            input: client_input,
            output: TokioBufReader::new(client_output),
            server,
            next_id: 1,
        };
        let initialized = session
            .request(json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"initialize",
                "params":{
                    "protocolVersion":"2025-11-25",
                    "capabilities":{},
                    "clientInfo":{"name":"task8","version":"1"}
                }
            }))
            .await;
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        session
            .send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        session
    }

    async fn send(&mut self, frame: Value) {
        self.input
            .write_all(format!("{}\n", serde_json::to_string(&frame).unwrap()).as_bytes())
            .await
            .unwrap();
        self.input.flush().await.unwrap();
    }

    async fn request(&mut self, frame: Value) -> Value {
        self.send(frame).await;
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), self.output.read_line(&mut line))
            .await
            .expect("MCP response timed out")
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }

    async fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let response = self
            .request(json!({
                "jsonrpc":"2.0",
                "id":id,
                "method":"tools/call",
                "params":{"name":name,"arguments":arguments}
            }))
            .await;
        assert_eq!(response["id"], id);
        response["result"].clone()
    }

    async fn close(mut self) {
        self.input.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), self.server)
            .await
            .expect("MCP server close timed out")
            .unwrap()
            .unwrap();
    }
}

fn assert_remote_context(result: &Value, root: &std::path::Path) {
    let structured = &result["structuredContent"];
    assert_eq!(structured["remote"], true);
    assert_eq!(structured["host"], "dev");
    assert_eq!(structured["physical_root"], root.to_str().unwrap());
    assert!(structured["shell"]["kind"].is_string());
}

#[tokio::test]
async fn task8_complete_surface_all_nine_tools_are_real_json_rpc_calls() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(
        remote
            .path()
            .join("hostile $(touch SHOULD_NOT_EXIST)\nname.txt"),
        b"hostile name marker\n",
    )
    .unwrap();
    std::fs::write(
        remote.path().join("utf8.txt"),
        b"literal $(touch SHOULD_NOT_EXIST)\nUTF8_SURFACE\n",
    )
    .unwrap();
    std::fs::write(remote.path().join("binary.bin"), [0xff, 0x00, 0x7f]).unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_fixture(remote.path());
    let mut session = ProtocolSession::start(tools).await;

    let hosts = session.call("remote_hosts", json!({})).await;
    assert_eq!(hosts["structuredContent"]["remote"], true);
    assert_eq!(hosts["structuredContent"]["host_count"], 1);

    let listed = session
        .call(
            "remote_list",
            json!({"host":"dev","path":".","max_entries":32}),
        )
        .await;
    assert_remote_context(&listed, remote.path());
    assert!(
        text_json(&listed)
            .to_string()
            .contains("hostile $(touch SHOULD_NOT_EXIST)\\nname.txt")
    );

    let stated = session
        .call(
            "remote_stat",
            json!({"host":"dev","paths":["binary.bin","missing.txt"]}),
        )
        .await;
    assert_remote_context(&stated, remote.path());
    let stat_text = text_json(&stated);
    assert_eq!(stat_text["entries"].as_array().unwrap().len(), 2);
    assert!(stat_text.to_string().contains("missing.txt"));

    let searched = session
        .call(
            "remote_search",
            json!({"host":"dev","query":"$(touch SHOULD_NOT_EXIST)","path":"."}),
        )
        .await;
    assert_remote_context(&searched, remote.path());
    assert!(
        text_json(&searched)
            .to_string()
            .contains("$(touch SHOULD_NOT_EXIST)")
    );

    let read = session
        .call(
            "remote_read",
            json!({"host":"dev","paths":["utf8.txt","binary.bin"],"max_bytes":4096}),
        )
        .await;
    assert_remote_context(&read, remote.path());
    let read_text = text_json(&read).to_string();
    assert!(read_text.contains("UTF8_SURFACE"), "read={read_text}");
    assert!(read_text.contains("/wB/"));

    let run = session
        .call(
            "remote_run",
            json!({"host":"dev","command":"printf RUN_SURFACE; dd if=/dev/zero bs=1024 count=300 2>/dev/null","shell":"sh"}),
        )
        .await;
    assert_remote_context(&run, remote.path());
    assert_eq!(run["structuredContent"]["exit_status"], 0);
    let output_ref = run["structuredContent"]["output_ref"]
        .as_str()
        .expect("run must publish a pageable output reference")
        .to_owned();

    let output = session
        .call(
            "remote_output_read",
            json!({"output_ref":output_ref,"stream":"stdout","offset":0,"max_bytes":11}),
        )
        .await;
    assert_remote_context(&output, remote.path());
    assert!(text_json(&output).to_string().contains("RUN_SURFACE"));

    let written = session
        .call(
            "remote_write",
            json!({
                "host":"dev","path":"created.txt","content":"WRITE_SURFACE\n",
                "encoding":"utf8","mode":{"kind":"create"}
            }),
        )
        .await;
    assert_remote_context(&written, remote.path());
    assert_eq!(written["structuredContent"]["status"], "applied");

    let patched = session
        .call(
            "remote_apply_patch",
            json!({
                "host":"dev",
                "patch":"--- a/created.txt\n+++ b/created.txt\n@@ -1 +1 @@\n-WRITE_SURFACE\n+PATCH_SURFACE\n"
            }),
        )
        .await;
    assert_remote_context(&patched, remote.path());
    assert_eq!(patched["structuredContent"]["status"], "applied");
    assert_eq!(
        std::fs::read(remote.path().join("created.txt")).unwrap(),
        b"PATCH_SURFACE\n"
    );
    assert!(!remote.path().join("SHOULD_NOT_EXIST").exists());
    assert!(!std::path::Path::new("SHOULD_NOT_EXIST").exists());
    session.close().await;
}

#[tokio::test]
async fn task8_shell_surface_reports_bash_auto_sh_and_fallback_exactly() {
    let cases = [
        (
            "bash-auto",
            vec![
                ("FAKE_SSH_MODE", OsString::from("echo-command")),
                ("FAKE_SSH_SHELL", OsString::from("bash")),
                ("FAKE_SSH_BASH_VERSION", OsString::from("5.2.15")),
            ],
            "auto",
            "bash",
            Some("5.2.15"),
            false,
        ),
        (
            "auto-fallback",
            vec![
                ("FAKE_SSH_MODE", OsString::from("echo-command")),
                ("FAKE_SSH_SHELL", OsString::from("sh")),
            ],
            "auto",
            "sh",
            None,
            true,
        ),
        (
            "explicit-sh",
            vec![
                ("FAKE_SSH_MODE", OsString::from("echo-command")),
                ("FAKE_SSH_SHELL", OsString::from("bash")),
                ("FAKE_SSH_BASH_VERSION", OsString::from("5.2.15")),
            ],
            "sh",
            "sh",
            None,
            false,
        ),
    ];
    for (name, environment, requested, kind, version, fallback) in cases {
        let remote = tempfile::TempDir::new().unwrap();
        let extra = environment
            .iter()
            .map(|(key, value)| (*key, value.clone()))
            .collect::<Vec<_>>();
        let (_runtime, _log, tools) = fake_remote_tools_with_options(remote.path(), false, &extra);
        let mut session = ProtocolSession::start(tools).await;
        let run = session
            .call(
                "remote_run",
                json!({"host":"dev","command":"printf safe","shell":requested}),
            )
            .await;
        assert_eq!(run["isError"], Value::Null, "{name}: {run}");
        assert_eq!(run["structuredContent"]["shell"]["kind"], kind, "{name}");
        assert_eq!(
            run["structuredContent"]["shell"]["version"],
            version.map_or(Value::Null, |version| json!(version)),
            "{name}"
        );
        assert_eq!(
            run["structuredContent"]["shell"]["fallback"], fallback,
            "{name}"
        );
        if kind == "sh" {
            assert!(
                run["structuredContent"]["warnings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|warning| warning.as_str().unwrap().contains("POSIX sh")),
                "{name}: {run}"
            );
        }
        session.close().await;
    }
}

#[tokio::test]
async fn task8_shell_surface_missing_bash_rejects_before_command_child() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, log, tools) = fake_remote_tools_with_options(
        remote.path(),
        false,
        &[
            ("FAKE_SSH_MODE", OsString::from("echo-command")),
            ("FAKE_SSH_SHELL", OsString::from("sh")),
        ],
    );
    let mut session = ProtocolSession::start(tools).await;
    let run = session
        .call(
            "remote_run",
            json!({"host":"dev","command":"printf must-not-run","shell":"bash"}),
        )
        .await;
    assert_eq!(run["isError"], true);
    assert_eq!(
        run["structuredContent"]["error"]["code"],
        "REMOTE_CAPABILITY_MISSING"
    );
    assert_eq!(command_calls(&log), 0);
    session.close().await;
}

#[tokio::test]
async fn task8_shell_surface_login_metadata_and_local_timeout_are_explicit() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_with_options(
        remote.path(),
        false,
        &[("FAKE_SSH_MODE", OsString::from("echo-command"))],
    );
    let mut session = ProtocolSession::start(tools).await;
    let run = session
        .call(
            "remote_run",
            json!({"host":"dev","command":"printf safe","shell":"login"}),
        )
        .await;
    assert_eq!(
        run["structuredContent"]["shell"],
        json!({"kind":"login","fallback":false})
    );
    session.close().await;

    let (_runtime, _log, tools) = fake_remote_tools_with_options(
        remote.path(),
        false,
        &[
            ("FAKE_SSH_MODE", OsString::from("sleep")),
            ("FAKE_SSH_SLEEP_SECONDS", OsString::from("5")),
        ],
    );
    let mut session = ProtocolSession::start(tools).await;
    let timed_out = session
        .call(
            "remote_run",
            json!({"host":"dev","command":"printf never","shell":"login","timeout_ms":50}),
        )
        .await;
    assert_eq!(timed_out["isError"], true);
    assert_eq!(
        timed_out["structuredContent"]["error"]["code"],
        "COMMAND_TIMEOUT"
    );
    assert_eq!(
        timed_out["structuredContent"]["shell"],
        json!({"kind":"login","fallback":false})
    );
    session.close().await;
}

#[tokio::test]
async fn task8_shell_surface_read_only_is_enforced_server_side_for_every_mutation() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("read.txt"), b"READ_ONLY_SENTINEL\n").unwrap();
    let (_runtime, log, tools) = fake_remote_tools_with_options(remote.path(), true, &[]);
    let id = RequestId::synthetic_max_wire();
    let minimum_frame = required_mcp_frame_bytes(
        tool_definitions(),
        codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes(),
        &id,
    )
    .unwrap();
    let mut session = ProtocolSession::start_with_frame(tools, minimum_frame).await;
    let retained = session.call("remote_hosts", json!({})).await;
    assert_eq!(
        retained["structuredContent"]["detail_retained"], true,
        "{retained}"
    );
    let output_ref = retained["structuredContent"]["output_ref"]
        .as_str()
        .expect("read-only list detail must be retained")
        .to_owned();

    for (name, arguments) in [
        (
            "remote_list",
            json!({"host":"dev","path":".","max_entries":1}),
        ),
        ("remote_stat", json!({"host":"dev","paths":["read.txt"]})),
        (
            "remote_search",
            json!({"host":"dev","query":"READ_ONLY_SENTINEL","path":"."}),
        ),
        ("remote_read", json!({"host":"dev","paths":["read.txt"]})),
    ] {
        let result = session.call(name, arguments).await;
        assert_ne!(result["isError"], true, "{name}: {result}");
        assert_remote_context(&result, remote.path());
    }
    let output = session
        .call(
            "remote_output_read",
            json!({"output_ref":output_ref,"stream":"stdout","offset":0,"max_bytes":1024}),
        )
        .await;
    assert_ne!(output["isError"], true, "{output}");
    assert_eq!(output["structuredContent"]["remote"], true);
    assert_eq!(output["structuredContent"]["aggregate"], "hosts");

    std::fs::write(&log, b"").unwrap();
    for (name, arguments) in [
        (
            "remote_write",
            json!({"host":"dev","path":"new.txt","content":"x","encoding":"utf8","mode":{"kind":"create"}}),
        ),
        (
            "remote_apply_patch",
            json!({"host":"dev","patch":"--- a/read.txt\n+++ b/read.txt\n@@ -1 +1 @@\n-READ_ONLY_SENTINEL\n+changed\n"}),
        ),
        (
            "remote_run",
            json!({"host":"dev","command":"printf must-not-run","shell":"sh"}),
        ),
    ] {
        let result = session.call(name, arguments).await;
        assert_eq!(result["isError"], true, "{name}: {result}");
        assert_eq!(
            result["structuredContent"]["error"]["code"], "READ_ONLY_HOST",
            "{name}"
        );
    }
    assert_eq!(
        command_calls(&log),
        0,
        "read-only mutations must launch no command child"
    );
    assert!(!remote.path().join("new.txt").exists());
    assert_eq!(
        std::fs::read(remote.path().join("read.txt")).unwrap(),
        b"READ_ONLY_SENTINEL\n"
    );
    session.close().await;
}

#[test]
fn task8_binary_unknown_and_missing_modes_have_fixed_usage_and_exit_two() {
    let private = tempfile::TempDir::new().unwrap();
    let config = private.path().join("absent-config-is-not-consulted");
    let expected = "usage: codex-ssh-bridge mcp\n";
    for arguments in [Vec::<&str>::new(), vec!["unknown"], vec!["mcp", "extra"]] {
        let output = binary_command(&config, private.path())
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8(output.stderr).unwrap(), expected);
    }
}

#[test]
fn task8_binary_fatal_error_is_only_fixed_prefix_and_stable_code() {
    let private = tempfile::TempDir::new().unwrap();
    let secret = "FATAL_CONFIG_SECRET";
    let config = write_binary_config(private.path(), secret);
    let output = binary_command(&config, private.path())
        .arg("mcp")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "codex-ssh-bridge fatal: INVALID_CONFIG\n"
    );
    assert!(
        !output
            .stderr
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    );
    assert!(
        !output
            .stderr
            .windows(config.as_os_str().len())
            .any(|window| window == config.as_os_str().as_encoded_bytes())
    );
}

#[test]
fn task8_binary_bootstrap_preserves_exact_limits_and_ownership_chain() {
    let source = include_str!("../src/main.rs");
    for required in [
        "Config::load_default()",
        "loaded.config.limits.max_frame_bytes",
        "loaded.config.limits.global_concurrency",
        "loaded.config.limits.global_spool_quota_bytes",
        "loaded.config.limits.retention_serialization_jobs",
        "OutputStore::with_limits(",
        "global_spool_quota_bytes,",
        "retention_serialization_jobs,",
        "Arc::new(loaded.config)",
        "SshRunner::new(Arc::clone(&config), runtime, output_store)",
        "RemoteBridge::new(runner)",
        "RemoteMcpTools::new(bridge)",
        "McpServer::new(tools, max_frame_bytes, max_inflight)",
    ] {
        assert!(
            source.contains(required),
            "bootstrap lost required ownership/limit source: {required}"
        );
    }
    assert!(!source.contains("OutputStore::new("));
    assert!(
        !source
            .lines()
            .any(|line| line.trim_start().starts_with("println!("))
    );

    for quota in [64_u64, 127, 255, 511].map(|mebibytes| mebibytes * 1024 * 1024) {
        for jobs in 1..=4 {
            let runtime_base = tempfile::TempDir::new().unwrap();
            let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
            OutputStore::with_limits(&runtime, quota, jobs).unwrap();
        }
    }
}

#[tokio::test]
async fn task8_binary_remote_tools_constructor_accepts_exact_minimum_only() {
    let (_runtime, _bridge, tools) = remote_tools_fixture();
    let id = RequestId::synthetic_max_wire();
    let exact_tools = exact_tools_list_response_bytes(tool_definitions(), &id).unwrap();
    let fallback = codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes();
    let required = required_mcp_frame_bytes(tool_definitions(), fallback, &id).unwrap();
    assert_eq!(required, 1_048_576.max(exact_tools));
    assert!(McpServer::new(Arc::new(tools.clone()), required - 1, 1).is_err());

    let mut session = ProtocolSession::start_with_frame(tools, required).await;
    let maximum_id = "x".repeat(254);
    let listed = session
        .request(json!({
            "jsonrpc":"2.0",
            "id":maximum_id,
            "method":"tools/list",
            "params":{}
        }))
        .await;
    assert_eq!(listed["id"], maximum_id);
    let names = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|definition| definition["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        tool_definitions()
            .iter()
            .map(|definition| definition.name.as_str())
            .collect::<Vec<_>>()
    );
    session.close().await;
}

fn property<'a>(tool: &'a ToolDefinition, name: &str) -> &'a Value {
    &tool.input_schema["properties"][name]
}

fn tool(name: &str) -> &'static ToolDefinition {
    tool_definitions()
        .iter()
        .find(|tool| tool.name == name)
        .unwrap_or_else(|| panic!("missing tool {name}"))
}

fn assert_closed_objects(value: &Value) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("object".to_owned())) {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "object schema was not closed: {value}"
                );
            }
            for child in object.values() {
                assert_closed_objects(child);
            }
        }
        Value::Array(array) => array.iter().for_each(assert_closed_objects),
        _ => {}
    }
}

#[test]
fn task8_registry_contains_exactly_the_nine_high_level_remote_tools() {
    let tools = tool_definitions();
    let names = tools
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "remote_hosts",
            "remote_list",
            "remote_stat",
            "remote_search",
            "remote_read",
            "remote_output_read",
            "remote_apply_patch",
            "remote_write",
            "remote_run",
        ]
    );
    let serialized = serde_json::to_string(tools).unwrap();
    for forbidden in ["sshfs", "guarded_delete", "probe", "shell_word", "raw_ssh"] {
        assert!(!serialized.contains(forbidden));
    }
    for tool in tools {
        assert_closed_objects(&tool.input_schema);
        assert!(
            serde_json::to_value(tool)
                .unwrap()
                .get("outputSchema")
                .is_none(),
            "{} unexpectedly advertises an output schema",
            tool.name
        );
    }
}

struct RegistryService;

impl ToolService for RegistryService {
    fn definitions(&self) -> &[ToolDefinition] {
        tool_definitions()
    }

    fn call(&self, _: String, _: Value, _: ToolCallContext) -> ToolFuture {
        Box::pin(async { CallToolResult::text("unused") })
    }
}

#[test]
fn task8_registry_full_tools_list_is_an_undegradable_service_minimum() {
    let id = RequestId::synthetic_max_wire();
    let exact = exact_tools_list_response_bytes(tool_definitions(), &id).unwrap();
    let fallback = codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes();
    let required = required_mcp_frame_bytes(tool_definitions(), fallback, &id).unwrap();
    assert_eq!(required, 1_048_576.max(exact));
    assert!(exact <= required);
    assert!(
        exact_tools_list_response_bytes(&tool_definitions()[..8], &id).unwrap() < exact,
        "the test must prove that silently dropping a tool would shrink the frame"
    );
    assert!(McpServer::new(Arc::new(RegistryService), required, 1).is_ok());
    // Construction uses the complete immutable registry. It must reject a
    // smaller frame instead of silently degrading the advertised surface.
    assert!(McpServer::new(Arc::new(RegistryService), required - 1, 1).is_err());
}

fn assert_string_bounds(schema: &Value, maximum: u64) {
    assert_eq!(schema["type"], "string");
    assert_eq!(schema["minLength"], 1);
    assert_eq!(schema["maxLength"], maximum);
}

fn assert_host(schema: &Value) {
    assert_string_bounds(schema, 128);
    assert_eq!(schema["pattern"], "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$");
}

fn assert_integer_range(schema: &Value, minimum: u64, maximum: u64) {
    assert_eq!(schema["type"], "integer");
    assert_eq!(schema["minimum"], minimum);
    assert_eq!(schema["maximum"], maximum);
}

#[test]
fn task8_schema_has_exact_required_fields_and_advisory_bounds() {
    let expected_required = [
        ("remote_hosts", json!([])),
        ("remote_list", json!(["host"])),
        ("remote_stat", json!(["host", "paths"])),
        ("remote_search", json!(["host", "query"])),
        ("remote_read", json!(["host", "paths"])),
        ("remote_output_read", json!(["output_ref", "stream"])),
        ("remote_apply_patch", json!(["host", "patch"])),
        (
            "remote_write",
            json!(["host", "path", "content", "encoding", "mode"]),
        ),
        ("remote_run", json!(["host", "command"])),
    ];
    for (name, required) in expected_required {
        assert_eq!(tool(name).input_schema["required"], required, "{name}");
    }
    assert_eq!(tool("remote_hosts").input_schema["properties"], json!({}));

    for name in [
        "remote_list",
        "remote_stat",
        "remote_search",
        "remote_read",
        "remote_apply_patch",
        "remote_write",
        "remote_run",
    ] {
        assert_host(property(tool(name), "host"));
    }
    for (name, field) in [
        ("remote_list", "path"),
        ("remote_search", "path"),
        ("remote_write", "path"),
        ("remote_run", "cwd"),
    ] {
        assert_string_bounds(property(tool(name), field), 65_536);
    }
    for name in ["remote_stat", "remote_read"] {
        assert_string_bounds(&property(tool(name), "paths")["items"], 65_536);
    }

    assert_integer_range(property(tool("remote_list"), "depth"), 1, 32);
    assert_integer_range(property(tool("remote_list"), "max_entries"), 1, 10_000);
    assert_eq!(property(tool("remote_stat"), "paths")["minItems"], 1);
    assert_eq!(property(tool("remote_stat"), "paths")["maxItems"], 256);

    assert_string_bounds(property(tool("remote_search"), "query"), 65_536);
    assert_eq!(property(tool("remote_search"), "globs")["maxItems"], 128);
    assert_string_bounds(&property(tool("remote_search"), "globs")["items"], 4_096);
    assert_integer_range(property(tool("remote_search"), "max_results"), 1, 10_000);

    assert_eq!(property(tool("remote_read"), "paths")["minItems"], 1);
    assert_eq!(property(tool("remote_read"), "paths")["maxItems"], 32);
    assert_eq!(property(tool("remote_read"), "start_line")["minimum"], 1);
    assert_integer_range(property(tool("remote_read"), "max_lines"), 1, 100_000);
    assert_integer_range(property(tool("remote_read"), "max_bytes"), 1, 1_048_576);

    assert_eq!(
        property(tool("remote_output_read"), "output_ref")["pattern"],
        "^[0-9a-f]{32}$"
    );
    assert_eq!(
        property(tool("remote_output_read"), "stream")["enum"],
        json!(["stdout", "stderr"])
    );
    assert_integer_range(
        property(tool("remote_output_read"), "max_bytes"),
        1,
        1_048_576,
    );

    assert_string_bounds(property(tool("remote_apply_patch"), "patch"), 4_194_304);
    assert_eq!(property(tool("remote_write"), "content")["type"], "string");
    assert_eq!(
        property(tool("remote_write"), "content")["maxLength"],
        5_592_408
    );
    assert_eq!(
        property(tool("remote_write"), "encoding")["enum"],
        json!(["utf8", "base64"])
    );

    assert_string_bounds(property(tool("remote_run"), "command"), 8_388_608);
    assert_eq!(
        property(tool("remote_run"), "shell")["enum"],
        json!(["auto", "bash", "sh", "login"])
    );
    assert_integer_range(property(tool("remote_run"), "timeout_ms"), 1, 3_600_000);
    let stdin = property(tool("remote_run"), "stdin");
    assert_eq!(stdin["required"], json!(["encoding", "value"]));
    assert_eq!(stdin["properties"]["value"]["maxLength"], 5_592_408);
}

#[test]
fn task8_schema_defaults_and_closed_write_mode_are_exact() {
    assert_eq!(property(tool("remote_list"), "path")["default"], ".");
    assert_eq!(property(tool("remote_list"), "depth")["default"], 1);
    assert_eq!(
        property(tool("remote_list"), "include_hidden")["default"],
        false
    );
    assert_eq!(
        property(tool("remote_list"), "max_entries")["default"],
        1_000
    );
    assert_eq!(property(tool("remote_search"), "path")["default"], ".");
    assert_eq!(
        property(tool("remote_search"), "globs")["default"],
        json!([])
    );
    assert_eq!(
        property(tool("remote_search"), "max_results")["default"],
        100
    );
    assert_eq!(property(tool("remote_search"), "binary")["default"], false);
    assert_eq!(property(tool("remote_read"), "start_line")["default"], 1);
    assert_eq!(property(tool("remote_read"), "max_lines")["default"], 2_000);
    assert_eq!(property(tool("remote_output_read"), "offset")["default"], 0);
    assert_eq!(
        property(tool("remote_output_read"), "max_bytes")["default"],
        262_144
    );
    assert_eq!(property(tool("remote_run"), "cwd")["default"], ".");
    assert_eq!(property(tool("remote_run"), "shell")["default"], "auto");

    let alternatives = property(tool("remote_write"), "mode")["oneOf"]
        .as_array()
        .unwrap();
    assert_eq!(alternatives.len(), 2);
    for alternative in alternatives {
        assert_closed_objects(alternative);
    }
    assert_eq!(alternatives[0]["required"], json!(["kind"]));
    assert_eq!(alternatives[0]["properties"]["kind"]["const"], "create");
    assert_eq!(
        alternatives[1]["required"],
        json!(["kind"]),
        "the replace hash is deliberately optional"
    );
    assert_eq!(alternatives[1]["properties"]["kind"]["const"], "replace");
    let hash = &alternatives[1]["properties"]["expected_sha256"];
    assert_eq!(hash["minLength"], 64);
    assert_eq!(hash["maxLength"], 64);
    assert_eq!(hash["pattern"], "^[0-9a-f]{64}$");
}

#[test]
fn task8_schema_annotations_match_remote_side_effects() {
    for name in ["remote_hosts", "remote_output_read"] {
        let annotations = serde_json::to_value(tool(name).annotations).unwrap();
        assert_eq!(
            annotations,
            json!({
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            }),
            "{name}"
        );
    }
    for name in ["remote_list", "remote_stat", "remote_search", "remote_read"] {
        let annotations = serde_json::to_value(tool(name).annotations).unwrap();
        assert_eq!(
            annotations,
            json!({
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": true
            }),
            "{name}"
        );
    }
    for name in ["remote_apply_patch", "remote_write", "remote_run"] {
        let annotations = serde_json::to_value(tool(name).annotations).unwrap();
        assert_eq!(
            annotations,
            json!({
                "readOnlyHint": false,
                "destructiveHint": true,
                "idempotentHint": false,
                "openWorldHint": true
            }),
            "{name}"
        );
    }
}

#[test]
fn task8_dispatch_architecture_is_bridge_only() {
    let source = include_str!("../src/mcp/tools.rs");
    for forbidden in [
        "std::process",
        "tokio::process",
        "Command::new",
        "SshRunner",
        "OutputStore",
        "sshfs",
    ] {
        assert!(
            !source.contains(forbidden),
            "MCP dispatch must use RemoteBridge, found {forbidden}"
        );
    }
    assert!(source.contains("RemoteBridge"));
}

#[tokio::test]
async fn task8_dispatch_rejects_known_tool_arguments_before_bridge_work() {
    let (_runtime, _bridge, tools) = remote_tools_fixture();
    let result = tools
        .call(
            "remote_list".to_owned(),
            json!({"host":"dev", "unknown":true}),
            roomy_context(),
        )
        .await;
    let rendered = serde_json::to_value(result).unwrap();
    assert_eq!(rendered["isError"], true);
    assert_eq!(rendered["content"].as_array().unwrap().len(), 1);
    assert_eq!(
        rendered["structuredContent"]["error"]["code"],
        "INVALID_ARGUMENT"
    );
}

#[tokio::test]
async fn task8_single_copy_hosts_payload_is_only_in_text_content() {
    let (_runtime, _bridge, tools) = remote_tools_fixture();
    let result = tools
        .call("remote_hosts".to_owned(), json!({}), roomy_context())
        .await;
    let rendered = serde_json::to_value(result).unwrap();
    assert_eq!(rendered["content"].as_array().unwrap().len(), 1);
    let text = rendered["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("/srv/remote"));
    assert!(rendered["structuredContent"].get("hosts").is_none());
    assert_eq!(rendered["structuredContent"]["remote"], true);
    assert_eq!(rendered["structuredContent"]["host_count"], 1);
}

#[tokio::test]
async fn task8_dispatch_fake_ssh_maps_read_search_run_write_and_patch_presentations() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("utf8.txt"), b"UTF8_SENTINEL\nsecond\n").unwrap();
    std::fs::write(remote.path().join("binary.bin"), [0xff, 0x00, 0x7f]).unwrap();
    let (_runtime, log, tools) = fake_remote_tools_fixture(remote.path());

    let listed = call_json(
        &tools,
        "remote_list",
        json!({"host":"dev", "path":".", "max_entries":32}),
    )
    .await;
    assert!(text_json(&listed).to_string().contains("utf8.txt"));
    assert!(listed["structuredContent"].get("entries").is_none());

    std::fs::write(&log, b"").unwrap();
    let stated = call_json(
        &tools,
        "remote_stat",
        json!({"host":"dev", "paths":["utf8.txt", "binary.bin"]}),
    )
    .await;
    assert_eq!(text_json(&stated)["entries"].as_array().unwrap().len(), 2);
    assert_eq!(
        command_calls(&log),
        1,
        "cached stat must not implicitly retry"
    );

    let read = call_json(
        &tools,
        "remote_read",
        json!({"host":"dev", "paths":["utf8.txt", "binary.bin"], "max_bytes":4096}),
    )
    .await;
    let read_text = text_json(&read).to_string();
    assert!(read_text.contains("UTF8_SENTINEL"));
    assert!(read_text.contains("/wB/"), "binary content must be base64");
    assert!(
        !read["structuredContent"]
            .to_string()
            .contains("UTF8_SENTINEL")
    );

    let searched = call_json(
        &tools,
        "remote_search",
        json!({"host":"dev", "query":"UTF8_SENTINEL", "path":"."}),
    )
    .await;
    assert!(text_json(&searched).to_string().contains("UTF8_SENTINEL"));

    let run = call_json(
        &tools,
        "remote_run",
        json!({"host":"dev", "command":"printf RUN_SENTINEL", "shell":"sh"}),
    )
    .await;
    let run_text = text_json(&run).to_string();
    assert!(run_text.contains("RUN_SENTINEL"));
    assert!(run_text.contains("POSIX sh"));
    assert_eq!(run["structuredContent"]["mutation_may_have_applied"], false);

    let written = call_json(
        &tools,
        "remote_write",
        json!({
            "host":"dev",
            "path":"created.txt",
            "content":"WRITE_SENTINEL\n",
            "encoding":"utf8",
            "mode":{"kind":"create"}
        }),
    )
    .await;
    assert_eq!(written["structuredContent"]["status"], "applied");
    assert_eq!(
        std::fs::read(remote.path().join("created.txt")).unwrap(),
        b"WRITE_SENTINEL\n"
    );

    let patched = call_json(
        &tools,
        "remote_apply_patch",
        json!({
            "host":"dev",
            "patch":"--- a/created.txt\n+++ b/created.txt\n@@ -1 +1 @@\n-WRITE_SENTINEL\n+PATCH_SENTINEL\n"
        }),
    )
    .await;
    assert_eq!(patched["structuredContent"]["status"], "applied");
    assert_eq!(patched["structuredContent"]["changed_count"], 1);
    assert_eq!(
        std::fs::read(remote.path().join("created.txt")).unwrap(),
        b"PATCH_SENTINEL\n"
    );

    let patch_error = call_json(
        &tools,
        "remote_apply_patch",
        json!({"host":"dev", "patch":"GIT binary patch\n"}),
    )
    .await;
    assert_eq!(patch_error["isError"], true);
    assert_eq!(
        patch_error["structuredContent"]["error"]["code"],
        "INVALID_ARGUMENT"
    );
}

#[tokio::test]
async fn task8_dispatch_pre_cancelled_call_launches_no_ssh_process() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, log, tools) = fake_remote_tools_fixture(remote.path());
    let cancel = CancellationToken::new();
    cancel.cancel();
    let result = tools
        .call(
            "remote_list".to_owned(),
            json!({"host":"dev"}),
            ToolCallContext {
                cancel,
                wire_budget: roomy_context().wire_budget,
            },
        )
        .await;
    let rendered = serde_json::to_value(result).unwrap();
    assert_eq!(rendered["structuredContent"]["error"]["code"], "CANCELLED");
    assert_eq!(command_calls(&log), 0);
}

#[tokio::test]
async fn task8_error_rendering_is_direct_bounded_and_does_not_serialize_bridge_error() {
    let (_runtime, _bridge, tools) = remote_tools_fixture();
    let result = tools
        .call(
            "remote_list".to_owned(),
            json!({"host":"not-configured"}),
            roomy_context(),
        )
        .await;
    let rendered = serde_json::to_value(result).unwrap();
    assert_eq!(rendered["isError"], true);
    assert_eq!(rendered["content"].as_array().unwrap().len(), 1);
    assert_eq!(
        rendered["structuredContent"]["error"]["code"],
        "INVALID_CONFIG"
    );
    assert!(
        rendered["structuredContent"]["error"]["message"]
            .as_str()
            .unwrap()
            .len()
            <= 1_024
    );
    assert!(
        rendered["structuredContent"]["error"]["details"]
            .get("host")
            .is_none(),
        "remote context must not be nested into the error core"
    );
}

#[tokio::test]
async fn task8_retention_hosts_fallback_is_truthful_and_pageable() {
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let hosts = (0..7)
        .map(|index| {
            (
                format!("host-{index}"),
                HostProfile {
                    root: format!("/srv/remote/{index}"),
                    description: Some(format!("DETAIL-{index}-{}", "x".repeat(256 * 1024))),
                    read_only: true,
                    limits: HostLimitOverrides::default(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let runner = Arc::new(
        SshRunner::new(
            Arc::new(Config {
                hosts,
                ..Config::default()
            }),
            runtime,
            store,
        )
        .unwrap(),
    );
    let bridge = Arc::new(RemoteBridge::new(runner));
    let tools = RemoteMcpTools::new(Arc::clone(&bridge));
    let id = RequestId::synthetic_max_wire();
    let minimum_frame = required_mcp_frame_bytes(
        tool_definitions(),
        codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes(),
        &id,
    )
    .unwrap();
    let mut session = ProtocolSession::start_with_frame(tools, minimum_frame).await;
    let rendered = session.call("remote_hosts", json!({})).await;
    assert_eq!(rendered["structuredContent"]["host_count"], 7);
    assert_eq!(rendered["structuredContent"]["truncated"], true);
    assert_eq!(rendered["structuredContent"]["detail_retained"], true);
    let output_ref = rendered["structuredContent"]["output_ref"]
        .as_str()
        .unwrap();
    let paged = session
        .call(
            "remote_output_read",
            json!({
                "output_ref":output_ref,
                "stream":"stdout",
                "offset":0,
                "max_bytes":1024
            }),
        )
        .await;
    let paged_text = text_json(&paged);
    assert_eq!(paged_text["remote"], true);
    assert_eq!(paged_text["aggregate"], "hosts");
    assert_eq!(paged_text["source_count"], 7);
    assert_eq!(paged_text["output_ref"], output_ref);
    assert_eq!(paged_text["offset"], 0);
    assert!(paged_text["next_offset"].as_u64().unwrap() > 0);
    let page = bridge
        .output_read(
            codex_ssh_bridge::remote::OutputReadRequest {
                output_ref: output_ref.to_owned(),
                stream: codex_ssh_bridge::output::StreamKind::Stdout,
                offset: 0,
                max_bytes: 1_024,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(page.data.value.contains("DETAIL-0"));
    session.close().await;
}

#[test]
fn task8_error_rendering_real_compact_fallback_is_nonzero_and_fits_minimum() {
    let fallback = codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes();
    assert!(fallback > 0);
    let id = RequestId::synthetic_max_wire();
    let required = required_mcp_frame_bytes(tool_definitions(), fallback, &id).unwrap();
    assert!(fallback <= required);
    assert!(required <= codex_ssh_bridge::MAX_FRAME_BYTES);
}
