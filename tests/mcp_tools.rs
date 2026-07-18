use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::Arc;

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
            compact_fallback_bytes: 128 * 1024,
        },
    }
}

fn fake_remote_tools_fixture(
    root: &std::path::Path,
) -> (tempfile::TempDir, std::path::PathBuf, RemoteMcpTools) {
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let config = Arc::new(support::config_with_host("dev", root.to_str().unwrap()));
    let log = runtime_base.path().join("ssh.log");
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), root.as_os_str().to_owned()),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
    ]);
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
                    description: Some(format!("DETAIL-{index}-{}", "x".repeat(32 * 1024))),
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
    let result = tools
        .call(
            "remote_hosts".to_owned(),
            json!({}),
            ToolCallContext {
                cancel: CancellationToken::new(),
                wire_budget: WireBudget {
                    result_bytes: 0,
                    compact_fallback_bytes: 16 * 1024,
                },
            },
        )
        .await;
    let rendered = serde_json::to_value(result).unwrap();
    assert_eq!(rendered["structuredContent"]["host_count"], 7);
    assert_eq!(rendered["structuredContent"]["truncated"], true);
    assert_eq!(rendered["structuredContent"]["detail_retained"], true);
    let output_ref = rendered["structuredContent"]["output_ref"]
        .as_str()
        .unwrap();
    let paged = call_json(
        &tools,
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
