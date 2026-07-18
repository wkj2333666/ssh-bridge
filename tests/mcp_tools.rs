use std::sync::Arc;

use codex_ssh_bridge::mcp::stdio::{exact_tools_list_response_bytes, required_mcp_frame_bytes};
use codex_ssh_bridge::mcp::tools::tool_definitions;
use codex_ssh_bridge::mcp::{
    CallToolResult, McpServer, RequestId, ToolCallContext, ToolDefinition, ToolFuture, ToolService,
};
use serde_json::{Value, json};

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
    let required = required_mcp_frame_bytes(tool_definitions(), 0, &id).unwrap();
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
