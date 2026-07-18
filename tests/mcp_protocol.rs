use std::future::Future;
use std::pin::Pin;

use codex_ssh_bridge::error::ErrorShellMetadata;
use codex_ssh_bridge::mcp::stdio::{
    CappedJsonBuffer, FrameEvent, FrameReader, MIN_MCP_FRAME_BYTES, SerializeLineError,
    exact_tools_list_response_bytes, required_mcp_frame_bytes, serialize_json_line,
    write_json_line,
};
use codex_ssh_bridge::mcp::{
    CallToolResult, MAX_INVALID_ARGUMENT_ACTION_BYTES, ProtocolState, RequestId,
    SUPPORTED_PROTOCOL_VERSIONS, StrictJsonError, ToolAnnotations, ToolCallContext, ToolDefinition,
    ToolFuture, ToolService, WireBudget, internal_error_response, invalid_params_response,
    invalid_request_response, method_not_found_response, parse_error_response, parse_strict_json,
    request_too_large_response, result_response, server_busy_response,
    server_not_initialized_response,
};
use codex_ssh_bridge::{BridgeError, ErrorCode, ErrorDetails};
use serde::Serialize;
use serde_json::{Value, json};
use std::io::Write;
use tokio::io::{AsyncReadExt, BufReader};

fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(depth * 2 + 4);
    input.extend(std::iter::repeat_n(b'[', depth));
    input.extend_from_slice(b"null");
    input.extend(std::iter::repeat_n(b']', depth));
    input
}

fn wide_array(nodes: usize) -> Vec<u8> {
    assert!(nodes >= 1);
    let mut input = Vec::with_capacity(nodes.saturating_mul(5));
    input.push(b'[');
    for index in 1..nodes {
        if index != 1 {
            input.push(b',');
        }
        input.extend_from_slice(b"null");
    }
    input.push(b']');
    input
}

fn wide_object(members: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(members.saturating_mul(16));
    input.push(b'{');
    for index in 0..members {
        if index != 0 {
            input.push(b',');
        }
        input.extend_from_slice(format!(r#""{index}":null"#).as_bytes());
    }
    input.push(b'}');
    input
}

fn object_with_key_bytes(bytes: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(bytes + 9);
    input.extend_from_slice(b"{\"");
    input.extend(std::iter::repeat_n(b'k', bytes));
    input.extend_from_slice(b"\":null}");
    input
}

fn nested_objects_with_members(members: usize) -> Vec<u8> {
    assert!(members >= 1);
    let inner = wide_object(members - 1);
    let mut input = Vec::with_capacity(inner.len() + 10);
    input.extend_from_slice(b"{\"outer\":");
    input.extend_from_slice(&inner);
    input.push(b'}');
    input
}

fn nested_objects_with_key_bytes(key_bytes: usize) -> Vec<u8> {
    const OUTER_KEY_BYTES: usize = "outer".len();
    assert!(key_bytes >= OUTER_KEY_BYTES);
    let inner = object_with_key_bytes(key_bytes - OUTER_KEY_BYTES);
    let mut input = Vec::with_capacity(inner.len() + 10);
    input.extend_from_slice(b"{\"outer\":");
    input.extend_from_slice(&inner);
    input.push(b'}');
    input
}

#[test]
fn task7_strict_json_rejects_duplicate_keys_at_every_depth() {
    for input in [
        br#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"ping"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","name":"y"}}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"host":"a","host":"b"}}}"#,
    ] {
        assert_eq!(
            parse_strict_json(input),
            Err(StrictJsonError::DuplicateKey)
        );
    }
}

#[test]
fn task7_strict_json_duplicate_marker_wins_before_malformed_duplicate_value() {
    assert_eq!(
        parse_strict_json(br#"{"a":1,"a":}"#),
        Err(StrictJsonError::DuplicateKey)
    );
}

#[test]
fn task7_strict_json_classifies_syntax_and_trailing_data_without_diagnostics() {
    assert_eq!(
        parse_strict_json(br#"{"x":]"#),
        Err(StrictJsonError::Syntax)
    );
    assert_eq!(parse_strict_json(br#"{} {}"#), Err(StrictJsonError::Syntax));
    assert_eq!(StrictJsonError::Syntax.to_string(), "invalid JSON syntax");
}

#[test]
fn task7_strict_json_enforces_depth_boundary() {
    assert!(parse_strict_json(&nested_arrays(64)).is_ok());
    assert_eq!(
        parse_strict_json(&nested_arrays(65)),
        Err(StrictJsonError::StructuralBudget)
    );
}

#[test]
fn task7_strict_json_enforces_node_boundary_for_wide_arrays() {
    assert!(parse_strict_json(&wide_array(262_144)).is_ok());
    assert_eq!(
        parse_strict_json(&wide_array(262_145)),
        Err(StrictJsonError::StructuralBudget)
    );
}

#[test]
fn task7_strict_json_enforces_aggregate_member_boundary_for_wide_objects() {
    assert!(parse_strict_json(&wide_object(131_072)).is_ok());
    assert_eq!(
        parse_strict_json(&wide_object(131_073)),
        Err(StrictJsonError::StructuralBudget)
    );
}

#[test]
fn task7_strict_json_member_budget_is_aggregate_across_distinct_nested_maps() {
    assert!(parse_strict_json(&nested_objects_with_members(131_072)).is_ok());
    assert_eq!(
        parse_strict_json(&nested_objects_with_members(131_073)),
        Err(StrictJsonError::StructuralBudget)
    );
}

#[test]
fn task7_strict_json_enforces_aggregate_key_byte_boundary() {
    assert!(parse_strict_json(&object_with_key_bytes(1_048_576)).is_ok());
    assert_eq!(
        parse_strict_json(&object_with_key_bytes(1_048_577)),
        Err(StrictJsonError::StructuralBudget)
    );
}

#[test]
fn task7_strict_json_key_byte_budget_is_aggregate_across_distinct_nested_maps() {
    assert!(parse_strict_json(&nested_objects_with_key_bytes(1_048_576)).is_ok());
    assert_eq!(
        parse_strict_json(&nested_objects_with_key_bytes(1_048_577)),
        Err(StrictJsonError::StructuralBudget)
    );
}

#[test]
fn task7_strict_json_builds_all_json_value_kinds() {
    let parsed = parse_strict_json(
        br#"{"null":null,"bool":true,"signed":-1,"unsigned":18446744073709551615,"float":1.5,"string":"ok","array":[]}"#,
    )
    .unwrap();
    assert_eq!(
        parsed,
        json!({
            "null": null,
            "bool": true,
            "signed": -1,
            "unsigned": 18_446_744_073_709_551_615_u64,
            "float": 1.5,
            "string": "ok",
            "array": []
        })
    );
}

#[test]
fn task7_strict_json_duplicate_detection_uses_destination_map_only() {
    let source = include_str!("../src/mcp/protocol.rs");
    assert!(source.contains("contains_key"));
    assert!(source.contains("next_key_seed"));
    assert!(source.contains("StrictKeySeed"));
    assert!(!source.contains("next_key::<String>"));
    assert!(!source.contains("HashSet<String>"));
    assert!(!source.contains("HashSet::<String>"));
}

#[test]
fn task7_request_ids_preserve_exact_string_and_integer_identity() {
    assert_ne!(
        RequestId::try_from(json!(1)).unwrap(),
        RequestId::try_from(json!("1")).unwrap()
    );
    for invalid in [Value::Null, json!(true), json!(1.5), json!({}), json!([])] {
        assert!(RequestId::try_from(invalid).is_err());
    }
}

#[test]
fn task7_request_ids_preserve_wire_type_and_enforce_serialized_size() {
    let numeric = RequestId::try_from(json!(42)).unwrap();
    let string = RequestId::try_from(json!("42")).unwrap();
    assert_eq!(serde_json::to_vec(&numeric).unwrap(), b"42");
    assert_eq!(serde_json::to_vec(&string).unwrap(), br#""42""#);

    let exact = RequestId::try_from(json!("x".repeat(254))).unwrap();
    assert_eq!(serde_json::to_vec(&exact).unwrap().len(), 256);
    assert!(RequestId::try_from(json!("x".repeat(255))).is_err());
    assert_eq!(
        serde_json::to_vec(&RequestId::synthetic_max_wire())
            .unwrap()
            .len(),
        256
    );
}

#[test]
fn task7_request_ids_enforce_escaped_control_wire_boundary() {
    let exact_value = format!("{}\n", "x".repeat(252));
    let oversized_value = format!("{}\n", "x".repeat(253));
    assert_eq!(serde_json::to_vec(&exact_value).unwrap().len(), 256);
    assert_eq!(serde_json::to_vec(&oversized_value).unwrap().len(), 257);
    assert!(RequestId::try_from(json!(exact_value)).is_ok());
    assert!(RequestId::try_from(json!(oversized_value)).is_err());
}

#[test]
fn task7_request_ids_enforce_multibyte_utf8_wire_boundary() {
    let prefix = "界".repeat(84);
    let exact_value = format!("{prefix}ab");
    let oversized_value = format!("{prefix}abc");
    assert_eq!(serde_json::to_vec(&exact_value).unwrap().len(), 256);
    assert_eq!(serde_json::to_vec(&oversized_value).unwrap().len(), 257);
    assert!(RequestId::try_from(json!(exact_value)).is_ok());
    assert!(RequestId::try_from(json!(oversized_value)).is_err());
}

#[test]
fn task7_request_id_wire_counter_uses_its_explicit_bound() {
    let source = include_str!("../src/mcp/protocol.rs");
    assert!(source.contains("fn escaped_json_string_len(value: &str, maximum: usize)"));
    assert!(source.contains("escaped_json_string_len(value, maximum)"));
    assert!(source.contains("if length > maximum"));
    assert!(!source.contains("if length > MAX_REQUEST_ID_WIRE_BYTES"));
}

#[test]
fn task7_protocol_constants_and_state_are_exact() {
    assert_eq!(SUPPORTED_PROTOCOL_VERSIONS, ["2025-11-25", "2025-06-18"]);
    assert_ne!(ProtocolState::AwaitInitialize, ProtocolState::Ready);
    let _ = ProtocolState::AwaitInitialized;
    let _ = ProtocolState::Closing;
}

#[test]
fn task7_protocol_constructors_are_fixed_and_preserve_trusted_ids() {
    assert_eq!(
        parse_error_response(),
        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})
    );
    assert_eq!(
        invalid_request_response(),
        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}})
    );
    assert_eq!(
        invalid_params_response(RequestId::try_from(json!(7)).unwrap()),
        json!({"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"Invalid params"}})
    );
    assert_eq!(
        method_not_found_response(RequestId::try_from(json!(8)).unwrap()),
        json!({"jsonrpc":"2.0","id":8,"error":{"code":-32601,"message":"Method not found"}})
    );
    assert_eq!(
        internal_error_response(RequestId::try_from(json!(9)).unwrap()),
        json!({"jsonrpc":"2.0","id":9,"error":{"code":-32603,"message":"Internal error"}})
    );
    assert_eq!(
        server_not_initialized_response(RequestId::try_from(json!(10)).unwrap()),
        json!({"jsonrpc":"2.0","id":10,"error":{"code":-32002,"message":"Server not initialized"}})
    );
    assert_eq!(
        request_too_large_response(),
        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"Request too large"}})
    );
    assert_eq!(
        server_busy_response(RequestId::try_from(json!(11)).unwrap()),
        json!({"jsonrpc":"2.0","id":11,"error":{"code":-32000,"message":"Server busy"}})
    );
    assert_eq!(
        result_response(
            RequestId::try_from(json!("hostile\nmethod")).unwrap(),
            json!({"ok":true})
        ),
        json!({"jsonrpc":"2.0","id":"hostile\nmethod","result":{"ok":true}})
    );

    for response in [
        parse_error_response(),
        invalid_request_response(),
        invalid_params_response(RequestId::try_from(json!(1)).unwrap()),
    ] {
        let message = response["error"]["message"].as_str().unwrap();
        assert!(!message.contains("hostile"));
        assert!(!message.contains("method"));
    }
}

#[test]
fn task7_tool_protocol_models_serialize_exact_shapes() {
    let annotations = ToolAnnotations {
        read_only_hint: true,
        destructive_hint: false,
        idempotent_hint: true,
        open_world_hint: false,
    };
    let definition = ToolDefinition {
        name: "remote_read".into(),
        title: "Read remote file".into(),
        description: "Read a bounded remote file".into(),
        input_schema: json!({"type":"object"}),
        annotations,
    };
    assert_eq!(
        serde_json::to_value(definition).unwrap(),
        json!({
            "name":"remote_read",
            "title":"Read remote file",
            "description":"Read a bounded remote file",
            "inputSchema":{"type":"object"},
            "annotations":{
                "readOnlyHint":true,
                "destructiveHint":false,
                "idempotentHint":true,
                "openWorldHint":false
            }
        })
    );

    assert_eq!(
        serde_json::to_value(CallToolResult::text("ok")).unwrap(),
        json!({
            "content":[{"type":"text","text":"ok"}],
            "structuredContent":{}
        })
    );
    let invalid = CallToolResult::invalid_argument("provide arguments.host");
    let wire = serde_json::to_value(invalid).unwrap();
    assert_eq!(wire["isError"], true);
    assert_eq!(
        wire["structuredContent"]["error"]["code"],
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        wire["structuredContent"]["action"],
        "provide arguments.host"
    );
    let text: Value = serde_json::from_str(wire["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(text["action"], "provide arguments.host");
}

#[test]
fn task7_invalid_argument_accepts_only_static_bounded_actions() {
    const OVERSIZED_STATIC_ACTION: &str = concat!(
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "x"
    );
    assert_eq!(MAX_INVALID_ARGUMENT_ACTION_BYTES, 1024);
    assert_eq!(OVERSIZED_STATIC_ACTION.len(), 1025);

    let bounded = serde_json::to_value(CallToolResult::invalid_argument(
        "provide arguments.host as a configured alias",
    ))
    .unwrap();
    assert_eq!(
        bounded["structuredContent"]["action"],
        "provide arguments.host as a configured alias"
    );

    let oversized =
        serde_json::to_value(CallToolResult::invalid_argument(OVERSIZED_STATIC_ACTION)).unwrap();
    assert_eq!(
        oversized["structuredContent"]["action"],
        "provide valid tool arguments"
    );
    assert!(
        oversized["structuredContent"]["action"]
            .as_str()
            .unwrap()
            .len()
            <= MAX_INVALID_ARGUMENT_ACTION_BYTES
    );

    let source = include_str!("../src/mcp/protocol.rs");
    assert!(source.contains("pub fn invalid_argument(actionable_safe_text: &'static str) -> Self"));
    assert!(!source.contains("invalid_argument(actionable_safe_text: impl Into<String>)"));
}

struct NullService {
    definitions: Vec<ToolDefinition>,
}

impl ToolService for NullService {
    fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }

    fn call(&self, _name: String, _arguments: Value, _context: ToolCallContext) -> ToolFuture {
        Box::pin(async { CallToolResult::text("ok") })
    }
}

#[test]
fn task7_tool_service_future_and_context_contract_are_sendable() {
    fn require_send<T: Send>(_: T) {}
    fn require_future<T: Future<Output = CallToolResult> + Send>(_: T) {}

    let context = ToolCallContext {
        cancel: tokio_util::sync::CancellationToken::new(),
        wire_budget: WireBudget {
            result_bytes: 1024,
            compact_fallback_bytes: 256,
        },
    };
    assert_eq!(context.wire_budget.result_bytes, 1024);
    require_send(context);
    require_future(async { CallToolResult::text("ok") });

    let service = NullService {
        definitions: Vec::new(),
    };
    assert!(service.definitions().is_empty());
    let future: Pin<Box<dyn Future<Output = CallToolResult> + Send>> = service.call(
        "ignored".into(),
        json!({}),
        ToolCallContext {
            cancel: tokio_util::sync::CancellationToken::new(),
            wire_budget: WireBudget {
                result_bytes: 1,
                compact_fallback_bytes: 1,
            },
        },
    );
    require_send(future);
}

#[tokio::test]
async fn task7_frame_reader_accepts_exact_limit_and_recovers_after_plus_one() {
    let wire = b"12345678\n123456789\n{}\n";
    let mut reader = FrameReader::new(BufReader::with_capacity(3, wire.as_slice()), 8);
    assert_eq!(
        reader.next_frame().await.unwrap(),
        FrameEvent::Frame(b"12345678".to_vec())
    );
    assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::Oversized);
    assert_eq!(
        reader.next_frame().await.unwrap(),
        FrameEvent::Frame(b"{}".to_vec())
    );
    assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::Eof);
}

#[tokio::test]
async fn task7_frame_reader_handles_buffering_crlf_empty_and_partial_eof() {
    let wire = b"{}\n[]\r\n\n{\"raw\":\xff}\npartial";
    let mut reader = FrameReader::new(BufReader::with_capacity(64, wire.as_slice()), 64);
    for expected in [
        b"{}".as_slice(),
        b"[]\r".as_slice(),
        b"".as_slice(),
        b"{\"raw\":\xff}".as_slice(),
    ] {
        let event = reader.next_frame().await.unwrap();
        assert_eq!(event, FrameEvent::Frame(expected.to_vec()));
        if expected.contains(&0xff) {
            let FrameEvent::Frame(raw) = event else {
                unreachable!();
            };
            assert_eq!(parse_strict_json(&raw), Err(StrictJsonError::Syntax));
        }
    }
    assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::PartialEof);
    assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::Eof);
}

#[tokio::test]
async fn task7_frame_reader_reports_empty_eof_and_oversized_partial_eof() {
    let mut empty = FrameReader::new(BufReader::new(&b""[..]), 4);
    assert_eq!(empty.next_frame().await.unwrap(), FrameEvent::Eof);

    let mut partial = FrameReader::new(BufReader::new(&b"12345"[..]), 4);
    assert_eq!(partial.next_frame().await.unwrap(), FrameEvent::PartialEof);
    assert_eq!(partial.next_frame().await.unwrap(), FrameEvent::Eof);
}

#[test]
fn task7_capped_writer_accepts_exact_limit_and_rejects_first_extra_byte() {
    let mut output = CappedJsonBuffer::new(8);
    assert_eq!(output.write(b"12345678").unwrap(), 8);
    assert!(output.write(b"9").is_err());
    assert_eq!(output.into_inner(), b"12345678");
}

#[tokio::test]
async fn task7_capped_writer_emits_one_injection_safe_json_line() {
    let value = json!({"text":"line\n\0界 {\"jsonrpc\":\"2.0\"}"});
    let expected_without_delimiter = serde_json::to_vec(&value).unwrap();
    let line = serialize_json_line(&value, expected_without_delimiter.len()).unwrap();
    assert_eq!(line.last(), Some(&b'\n'));
    assert!(!line[..line.len() - 1].contains(&b'\n'));
    assert_eq!(
        serde_json::from_slice::<Value>(&line[..line.len() - 1]).unwrap(),
        value
    );
    assert!(matches!(
        serialize_json_line(&value, expected_without_delimiter.len() - 1),
        Err(SerializeLineError::CapacityExceeded)
    ));

    let (mut tx, mut rx) = tokio::io::duplex(line.len() + 8);
    write_json_line(&mut tx, &value, expected_without_delimiter.len())
        .await
        .unwrap();
    drop(tx);
    let mut actual = Vec::new();
    rx.read_to_end(&mut actual).await.unwrap();
    assert_eq!(actual, line);
}

struct HostileSerializer;

impl Serialize for HostileSerializer {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(serde::ser::Error::custom(
            "HOSTILE caller-controlled serializer diagnostic",
        ))
    }
}

#[test]
fn task7_capped_writer_errors_are_classified_and_do_not_echo_diagnostics() {
    let error = serialize_json_line(&HostileSerializer, 64).unwrap_err();
    assert!(matches!(error, SerializeLineError::Serialization));
    assert_eq!(error.to_string(), "failed to serialize compact JSON frame");
    assert!(!error.to_string().contains("HOSTILE"));

    let capacity = serialize_json_line(&json!({"value":"too long"}), 1).unwrap_err();
    assert!(matches!(capacity, SerializeLineError::CapacityExceeded));
    assert_eq!(
        capacity.to_string(),
        "compact JSON frame exceeds configured bound"
    );
}

fn stub_definition(description: &str) -> ToolDefinition {
    ToolDefinition {
        name: "remote_read".into(),
        title: "Read remote file".into(),
        description: description.into(),
        input_schema: json!({"type":"object","additionalProperties":false}),
        annotations: ToolAnnotations {
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
        },
    }
}

#[test]
fn task7_min_frame_counts_complete_tools_list_and_definition_growth() {
    let id = RequestId::synthetic_max_wire();
    let short = vec![stub_definition("bounded")];
    let long = vec![stub_definition(&"x".repeat(4096))];
    let short_count = exact_tools_list_response_bytes(&short, &id).unwrap();
    let long_count = exact_tools_list_response_bytes(&long, &id).unwrap();
    assert!(long_count > short_count);
    assert!(short_count < MIN_MCP_FRAME_BYTES);
    let task5_nominal = required_mcp_frame_bytes(&short, 0, &id).unwrap();
    assert_eq!(task5_nominal, MIN_MCP_FRAME_BYTES);
    assert!(WireBudget::for_response(task5_nominal, &id, 0).is_some());

    let fallback_result_bytes = MIN_MCP_FRAME_BYTES + 17;
    let envelope = serde_json::to_vec(&result_response(id.clone(), Value::Null))
        .unwrap()
        .len()
        - b"null".len();
    assert_eq!(
        required_mcp_frame_bytes(&short, fallback_result_bytes, &id).unwrap(),
        (envelope + fallback_result_bytes).max(short_count)
    );
    let required = required_mcp_frame_bytes(&short, fallback_result_bytes, &id).unwrap();
    assert!(WireBudget::for_response(required, &id, fallback_result_bytes).is_some());
    assert_eq!(
        required_mcp_frame_bytes(&long, 0, &id).unwrap(),
        MIN_MCP_FRAME_BYTES.max(long_count)
    );
}

#[derive(Serialize)]
struct ProjectedContext<'a> {
    remote: bool,
    host: &'a str,
    physical_root: &'a str,
    shell: ProjectedShell<'a>,
}

#[derive(Serialize)]
struct ProjectedShell<'a> {
    kind: &'a str,
    version: &'a str,
    fallback: bool,
}

#[derive(Serialize)]
struct ProjectedCore<'a> {
    code: ErrorCode,
    message: &'a str,
    retryable: bool,
    mutation_may_have_applied: bool,
    action: &'a str,
    warnings: Vec<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectedStructured<'a> {
    #[serde(flatten)]
    context: &'a ProjectedContext<'a>,
    error: &'a ProjectedCore<'a>,
}

#[test]
fn task7_min_frame_authoritative_future_renderer_projection_fits_compiled_floor() {
    // Task 7 replaces this shape-only projection with its real RenderedErrorCore
    // assertion. Keeping it test-only avoids inventing renderer semantics early.
    let root = format!(
        "/{}",
        "\u{1}".repeat(codex_ssh_bridge::config::MAX_REMOTE_CONTEXT_ROOT_BYTES - 1)
    );
    assert_eq!(
        root.len(),
        codex_ssh_bridge::config::MAX_REMOTE_CONTEXT_ROOT_BYTES
    );
    let version = "\u{1}".repeat(codex_ssh_bridge::capability::MAX_SHELL_VERSION_BYTES);
    assert_eq!(
        version.len(),
        codex_ssh_bridge::capability::MAX_SHELL_VERSION_BYTES
    );
    assert!(version.chars().all(char::is_control));
    assert!(serde_json::to_vec(&version).unwrap().len() > version.len());
    // Task 7's real safe-string projection must replace every Unicode control
    // character with one ASCII '?' before/during UTF-8-bound truncation. Quotes
    // and backslashes are therefore the largest legal JSON-escaping pattern.
    let message = "\"\\".repeat(512);
    let action = "\\\"".repeat(512);
    let warning = "\"\\".repeat(512);
    let bridge_error = BridgeError {
        code: ErrorCode::MutationOutcomeUnknown,
        message: message.clone(),
        retryable: false,
        details: ErrorDetails {
            host: Some("largest-host".into()),
            physical_root: Some(root.clone()),
            shell: Some(ErrorShellMetadata {
                kind: "bash".into(),
                version: Some(version.clone()),
                fallback: false,
            }),
            mutation_may_have_applied: Some(true),
            suggested_action: Some(action.clone()),
            ..ErrorDetails::default()
        },
    };
    let error_shell = bridge_error.details.shell.as_ref().unwrap();
    let context = ProjectedContext {
        remote: true,
        host: bridge_error.details.host.as_deref().unwrap(),
        physical_root: bridge_error.details.physical_root.as_deref().unwrap(),
        shell: ProjectedShell {
            kind: &error_shell.kind,
            version: error_shell.version.as_deref().unwrap(),
            fallback: error_shell.fallback,
        },
    };
    let core = ProjectedCore {
        code: bridge_error.code,
        message: &bridge_error.message,
        retryable: bridge_error.retryable,
        mutation_may_have_applied: true,
        action: bridge_error.details.suggested_action.as_deref().unwrap(),
        warnings: vec![warning.as_str(); 16],
    };
    let projected = ProjectedStructured {
        context: &context,
        error: &core,
    };
    let core_value = serde_json::to_value(&core).unwrap();
    assert!(core_value.get("host").is_none());
    assert!(core_value.get("physical_root").is_none());
    assert!(core_value.get("shell").is_none());
    let projected_value = serde_json::to_value(&projected).unwrap();
    assert_eq!(projected_value["physical_root"], root);
    assert!(projected_value["error"].get("host").is_none());
    assert!(projected_value["error"].get("physical_root").is_none());
    assert!(projected_value["error"].get("shell").is_none());
    let inner = serde_json::to_string(&projected).unwrap();
    let parsed_inner: Value = serde_json::from_str(&inner).unwrap();
    assert_eq!(count_exact_string(&parsed_inner, &root), 1);
    assert_eq!(count_exact_string(&parsed_inner, &version), 1);
    let result = json!({
        "content":[{"type":"text","text":inner}],
        "structuredContent": projected,
        "isError":true
    });
    assert_eq!(count_exact_string(&result["structuredContent"], &root), 1);
    assert_eq!(
        count_exact_string(&result["structuredContent"], &version),
        1
    );
    let response = result_response(RequestId::synthetic_max_wire(), result);
    let exact = serde_json::to_vec(&response).unwrap().len();
    eprintln!("authoritative worst safe fallback bytes={exact}");
    assert!(serialize_json_line(&response, exact).is_ok());
    assert!(matches!(
        serialize_json_line(&response, exact - 1),
        Err(SerializeLineError::CapacityExceeded)
    ));
    let bytes = serialize_json_line(&response, MIN_MCP_FRAME_BYTES).unwrap();
    assert!(bytes.len() - 1 <= MIN_MCP_FRAME_BYTES);
}

fn count_exact_string(value: &Value, needle: &str) -> usize {
    match value {
        Value::String(value) => usize::from(value == needle),
        Value::Array(values) => values
            .iter()
            .map(|value| count_exact_string(value, needle))
            .sum(),
        Value::Object(values) => values
            .values()
            .map(|value| count_exact_string(value, needle))
            .sum(),
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
    }
}

#[test]
fn task7_min_frame_wire_budget_reserves_envelope_id_and_fallback_only() {
    let id = RequestId::synthetic_max_wire();
    let fallback_bytes = 8192;
    let envelope_bytes = serde_json::to_vec(&result_response(id.clone(), Value::Null))
        .unwrap()
        .len()
        - b"null".len();
    let frame = envelope_bytes + fallback_bytes + 123;
    let budget = WireBudget::for_response(frame, &id, fallback_bytes).unwrap();
    assert_eq!(budget.result_bytes, 123);
    assert_eq!(budget.compact_fallback_bytes, fallback_bytes);
    assert!(
        WireBudget::for_response(envelope_bytes + fallback_bytes - 1, &id, fallback_bytes)
            .is_none()
    );
    assert_eq!(
        serde_json::to_vec(&id).unwrap().len(),
        codex_ssh_bridge::mcp::MAX_REQUEST_ID_WIRE_BYTES
    );

    let manually_constructed_oversized_id = RequestId::String("x".repeat(255));
    assert!(
        serde_json::to_vec(&manually_constructed_oversized_id)
            .unwrap()
            .len()
            > codex_ssh_bridge::mcp::MAX_REQUEST_ID_WIRE_BYTES
    );
    assert!(
        WireBudget::for_response(frame, &manually_constructed_oversized_id, fallback_bytes)
            .is_none()
    );
}
