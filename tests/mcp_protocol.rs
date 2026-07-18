use std::future::Future;
use std::pin::Pin;

use codex_ssh_bridge::mcp::{
    CallToolResult, ProtocolState, RequestId, SUPPORTED_PROTOCOL_VERSIONS, StrictJsonError,
    ToolAnnotations, ToolCallContext, ToolDefinition, ToolFuture, ToolService, WireBudget,
    internal_error_response, invalid_params_response, invalid_request_response,
    method_not_found_response, parse_error_response, parse_strict_json, request_too_large_response,
    result_response, server_busy_response, server_not_initialized_response,
};
use serde_json::{Value, json};

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
fn task7_strict_json_enforces_aggregate_key_byte_boundary() {
    assert!(parse_strict_json(&object_with_key_bytes(1_048_576)).is_ok());
    assert_eq!(
        parse_strict_json(&object_with_key_bytes(1_048_577)),
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
