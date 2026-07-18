use std::future::Future;
use std::pin::Pin;

use codex_ssh_bridge::error::ErrorShellMetadata;
use codex_ssh_bridge::mcp::stdio::{
    CappedJsonBuffer, FrameEvent, FrameReader, MIN_MCP_FRAME_BYTES, SerializeLineError,
    exact_tools_list_response_bytes, required_mcp_frame_bytes, serialize_json_line,
    write_json_line,
};
use codex_ssh_bridge::mcp::{
    CallToolResult, MAX_INVALID_ARGUMENT_ACTION_BYTES, McpServer, ProtocolState, RequestId,
    SUPPORTED_PROTOCOL_VERSIONS, StrictJsonError, ToolAnnotations, ToolCallContext, ToolDefinition,
    ToolFuture, ToolService, WireBudget, internal_error_response, invalid_params_response,
    invalid_request_response, method_not_found_response, parse_error_response, parse_strict_json,
    request_too_large_response, result_response, server_busy_response,
    server_not_initialized_response,
};
use codex_ssh_bridge::{BridgeError, ErrorCode, ErrorDetails};
use serde::Serialize;
use serde_json::{Value, json};
use std::io;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{
    AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream,
};
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::time::{Duration, timeout};

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
fn task7_request_ids_borrow_validate_before_bounded_clone() {
    let exact = json!("x".repeat(254));
    assert_eq!(
        RequestId::try_from_ref(&exact).unwrap(),
        RequestId::try_from(exact).unwrap()
    );
    let oversized = json!("x".repeat(1024 * 1024));
    assert!(RequestId::try_from_ref(&oversized).is_err());
    let source = include_str!("../src/mcp/protocol.rs");
    let method = source
        .split("pub fn try_from_ref")
        .nth(1)
        .unwrap()
        .split("impl Serialize")
        .next()
        .unwrap();
    assert!(method.find("string_wire_len_at_most").unwrap() < method.find("to_owned").unwrap());
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

#[derive(Debug)]
struct NullService {
    definitions: Vec<ToolDefinition>,
}

fn lifecycle_definitions() -> Vec<ToolDefinition> {
    ["block", "echo"]
        .into_iter()
        .map(|name| ToolDefinition {
            name: name.into(),
            title: name.into(),
            description: format!("{name} test tool"),
            input_schema: json!({"type":"object","additionalProperties":false}),
            annotations: ToolAnnotations {
                read_only_hint: true,
                destructive_hint: false,
                idempotent_hint: true,
                open_world_hint: false,
            },
        })
        .collect()
}

#[derive(Clone)]
struct StubTools {
    definitions: Arc<Vec<ToolDefinition>>,
    synchronous_calls: Arc<AtomicUsize>,
    first_polls: Arc<AtomicUsize>,
    bridge_ops: Arc<AtomicUsize>,
    observed_cancel: Arc<AtomicBool>,
    entered: Arc<AtomicBool>,
    entered_notify: Arc<Notify>,
    release: Arc<Semaphore>,
    contexts: Arc<Mutex<Vec<ToolCallContext>>>,
}

impl StubTools {
    fn new() -> Self {
        Self {
            definitions: Arc::new(lifecycle_definitions()),
            synchronous_calls: Arc::new(AtomicUsize::new(0)),
            first_polls: Arc::new(AtomicUsize::new(0)),
            bridge_ops: Arc::new(AtomicUsize::new(0)),
            observed_cancel: Arc::new(AtomicBool::new(false)),
            entered: Arc::new(AtomicBool::new(false)),
            entered_notify: Arc::new(Notify::new()),
            release: Arc::new(Semaphore::new(0)),
            contexts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn wait_for_polls(&self, count: usize) {
        loop {
            let notified = self.entered_notify.notified();
            if self.first_polls.load(Ordering::Acquire) >= count {
                return;
            }
            timeout(Duration::from_secs(1), notified)
                .await
                .expect("tool must be first-polled");
        }
    }
}

impl ToolService for StubTools {
    fn definitions(&self) -> &[ToolDefinition] {
        self.definitions.as_slice()
    }

    fn call(&self, name: String, arguments: Value, context: ToolCallContext) -> ToolFuture {
        self.synchronous_calls.fetch_add(1, Ordering::SeqCst);
        let first_polls = Arc::clone(&self.first_polls);
        let bridge_ops = Arc::clone(&self.bridge_ops);
        let observed_cancel = Arc::clone(&self.observed_cancel);
        let entered = Arc::clone(&self.entered);
        let entered_notify = Arc::clone(&self.entered_notify);
        let release = Arc::clone(&self.release);
        let contexts = Arc::clone(&self.contexts);
        Box::pin(async move {
            first_polls.fetch_add(1, Ordering::SeqCst);
            contexts.lock().await.push(context.clone());
            entered.store(true, Ordering::Release);
            entered_notify.notify_waiters();
            if name == "block" {
                bridge_ops.fetch_add(1, Ordering::SeqCst);
                tokio::select! {
                    () = context.cancel.cancelled() => {
                        observed_cancel.store(true, Ordering::SeqCst);
                        return CallToolResult::text("cancelled internally");
                    }
                    permit = release.acquire() => {
                        permit.expect("test release semaphore remains open").forget();
                        return CallToolResult::text("released");
                    }
                }
            }
            if name == "echo" {
                return match arguments.get("text").and_then(Value::as_str) {
                    Some(text) => {
                        bridge_ops.fetch_add(1, Ordering::SeqCst);
                        CallToolResult::text(text)
                    }
                    None => CallToolResult::invalid_argument("provide arguments.text as a string"),
                };
            }
            unreachable!("the lifecycle owner rejects unknown names")
        })
    }
}

struct Session {
    input: DuplexStream,
    output: BufReader<DuplexStream>,
    serve: tokio::task::JoinHandle<Result<(), BridgeError>>,
}

impl Session {
    async fn start<S: ToolService>(server: McpServer<S>) -> Self {
        Self::start_with_output_capacity(server, 128 * 1024).await
    }

    async fn start_with_output_capacity<S: ToolService>(
        server: McpServer<S>,
        capacity: usize,
    ) -> Self {
        let (input, server_reader) = tokio::io::duplex(128 * 1024);
        let (server_writer, output) = tokio::io::duplex(capacity);
        let serve = tokio::spawn(server.serve(server_reader, server_writer));
        Self {
            input,
            output: BufReader::new(output),
            serve,
        }
    }

    async fn send(&mut self, value: &Value) {
        let mut frame = serde_json::to_vec(value).unwrap();
        frame.push(b'\n');
        timeout(Duration::from_secs(1), self.input.write_all(&frame))
            .await
            .expect("send must finish")
            .unwrap();
    }

    async fn recv(&mut self) -> Value {
        let mut line = String::new();
        timeout(Duration::from_secs(1), self.output.read_line(&mut line))
            .await
            .expect("response must arrive")
            .unwrap();
        assert!(!line.is_empty(), "response stream closed");
        serde_json::from_str(line.trim_end()).unwrap()
    }

    async fn ready(&mut self) {
        self.send(&initialize(json!(100), "2025-11-25")).await;
        assert_eq!(self.recv().await["id"], 100);
        self.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}))
            .await;
    }

    async fn close(mut self) -> Result<(), BridgeError> {
        self.input.shutdown().await.unwrap();
        timeout(Duration::from_secs(1), self.serve)
            .await
            .expect("serve must stop")
            .expect("serve must not panic")
    }
}

#[test]
fn task7_constructor_enforces_exact_frame_and_inflight_bounds() {
    let service = Arc::new(NullService {
        definitions: lifecycle_definitions(),
    });
    let required =
        required_mcp_frame_bytes(service.definitions(), 0, &RequestId::synthetic_max_wire())
            .unwrap();
    assert!(McpServer::new(Arc::clone(&service), required, 2).is_ok());

    let too_small = McpServer::new(Arc::clone(&service), required - 1, 2).unwrap_err();
    assert_eq!(
        too_small,
        BridgeError::invalid_argument("MCP frame bound is invalid")
    );
    let too_large = McpServer::new(
        Arc::clone(&service),
        codex_ssh_bridge::MAX_FRAME_BYTES + 1,
        2,
    )
    .unwrap_err();
    assert_eq!(
        too_large,
        BridgeError::invalid_argument("MCP frame bound is invalid")
    );
    for invalid in [0, 33] {
        let error = McpServer::new(Arc::clone(&service), required, invalid).unwrap_err();
        assert_eq!(
            error,
            BridgeError::invalid_argument("MCP in-flight bound is invalid")
        );
    }
}

async fn serve_frames<S: ToolService>(
    server: McpServer<S>,
    frames: &[Value],
) -> (Vec<Value>, Result<(), BridgeError>) {
    let mut input = Vec::new();
    for frame in frames {
        input.extend(serde_json::to_vec(frame).unwrap());
        input.push(b'\n');
    }
    serve_raw(server, input).await
}

async fn serve_raw<S: ToolService>(
    server: McpServer<S>,
    input: Vec<u8>,
) -> (Vec<Value>, Result<(), BridgeError>) {
    let (writer, mut reader) = tokio::io::duplex(2 * 1024 * 1024);
    let serve = tokio::spawn(server.serve(std::io::Cursor::new(input), writer));
    let mut output = Vec::new();
    timeout(Duration::from_secs(1), reader.read_to_end(&mut output))
        .await
        .expect("writer must close")
        .unwrap();
    let result = timeout(Duration::from_secs(1), serve)
        .await
        .expect("server must stop")
        .expect("server task must not panic");
    let responses = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    (responses, result)
}

fn initialize(id: Value, version: &str) -> Value {
    json!({
        "jsonrpc":"2.0",
        "id":id,
        "method":"initialize",
        "params":{
            "protocolVersion":version,
            "capabilities":{},
            "clientInfo":{"name":"test-client","version":"1"}
        }
    })
}

#[tokio::test]
async fn task7_lifecycle_initialize_ready_ping_and_list() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 2).unwrap();
        let frames = [
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}),
        ];
        let (responses, result) = serve_frames(server, &frames).await;
        assert!(result.is_ok());
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[0]["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(responses[1], json!({"jsonrpc":"2.0","id":2,"result":{}}));
        assert_eq!(responses[2]["id"], 3);
        assert_eq!(responses[2]["result"]["tools"].as_array().unwrap().len(), 2);
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_optional_empty_method_params_may_be_absent() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 2).unwrap();
        let frames = [
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
        ];
        let (responses, result) = serve_frames(server, &frames).await;
        assert!(result.is_ok());
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[1]["result"], json!({}));
        assert!(responses[2]["result"]["tools"].is_array());
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_request_notification_barrier_and_strict_envelope() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 2).unwrap();
        let frames = [
            json!({"jsonrpc":"2.0","method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","id":null,"method":"ping","params":{}}),
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            json!({"jsonrpc":"2.0","id":3,"method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","method":"ping","params":{}}),
            json!({"jsonrpc":"2.0","id":4,"method":"ping","params":{},"extra":true}),
            json!({"jsonrpc":"2.0","id":5,"method":"ping","params":{"_meta":{}}}),
        ];
        let (responses, result) = serve_frames(server, &frames).await;
        assert!(result.is_ok());
        assert_eq!(
            responses
                .iter()
                .map(|v| v["id"].clone())
                .collect::<Vec<_>>(),
            [
                Value::Null,
                json!(1),
                json!(2),
                json!(3),
                json!(4),
                json!(5)
            ]
        );
        assert_eq!(responses[0], invalid_request_response());
        assert_eq!(responses[2]["error"]["code"], -32002);
        assert_eq!(responses[3]["error"]["code"], -32600);
        assert_eq!(responses[4]["error"]["code"], -32600);
        assert_eq!(responses[5]["result"], json!({}));
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_invalid_id_and_nonobject_envelope_matrix() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 32).unwrap();
        let frames = [
            json!(null),
            json!([]),
            json!("scalar"),
            json!({"jsonrpc":"2.0","id":null,"method":"ping"}),
            json!({"jsonrpc":"2.0","id":true,"method":"ping"}),
            json!({"jsonrpc":"2.0","id":1.5,"method":"ping"}),
            json!({"jsonrpc":"2.0","id":{},"method":"ping"}),
            json!({"jsonrpc":"2.0","id":[],"method":"ping"}),
            json!({"jsonrpc":"2.0","id":"x".repeat(255),"method":"ping"}),
            initialize(json!(10), "2025-11-25"),
        ];
        let (responses, result) = serve_frames(server, &frames).await;
        assert!(result.is_ok());
        assert_eq!(responses.len(), 10);
        for response in &responses[..9] {
            assert_eq!(response, &invalid_request_response());
        }
        assert_eq!(responses[9]["id"], 10);
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_june_open_and_november_closed_method_extensions() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService { definitions: lifecycle_definitions() });
        let server = McpServer::new(Arc::clone(&service), MIN_MCP_FRAME_BYTES, 1).unwrap();
        let june = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"},"extension":{"bounded":true}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{"extension":true}}),
            json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{"extension":true}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"extension":true}}),
        ];
        let (responses, result) = serve_frames(server, &june).await;
        assert!(result.is_ok());
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[1]["result"], json!({}));
        assert!(responses[2]["result"]["tools"].is_array());

        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 1).unwrap();
        let november = [
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{"extension":true}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"extension":true}}),
        ];
        let (responses, result) = serve_frames(server, &november).await;
        assert!(result.is_ok());
        assert_eq!(responses[1]["error"]["code"], -32602);
        assert_eq!(responses[2]["error"]["code"], -32602);
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_strict_json_errors_are_fixed_and_side_effect_free() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService { definitions: lifecycle_definitions() });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 2).unwrap();
        let input = br#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"initialize"}
{"jsonrpc":"2.0","id":1,"method":]
{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}
"#.to_vec();
        let (responses, result) = serve_raw(server, input).await;
        assert!(result.is_ok());
        assert_eq!(responses[0], invalid_request_response());
        assert_eq!(responses[1], parse_error_response());
        assert_eq!(responses[2]["id"], 2);
        assert_eq!(responses[2]["result"]["protocolVersion"], "2025-11-25");
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_version_shapes_and_absolute_uri_policy() {
    timeout(Duration::from_secs(5), async {
        let june_with_icons = json!({
            "jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":"x","version":"1","icons":[{"src":"data:,ok"}]}
            }
        });
        let invalid_uri = json!({
            "jsonrpc":"2.0","id":2,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"x","version":"1","icons":[{"src":"https://user@example.com/x"}]}
            }
        });
        let valid_latest = json!({
            "jsonrpc":"2.0","id":3,"method":"initialize","params":{
                "protocolVersion":"unsupported","capabilities":{},
                "clientInfo":{"name":"x","version":"1","title":"t","websiteUrl":"HTTPS://example.com:443/a//b?q=?#f","icons":[{"src":"data:,hello","mimeType":"text/plain","sizes":["16x16"],"theme":"dark"}]}
            }
        });
        let numeric_dns = json!({
            "jsonrpc":"2.0","id":4,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"x","version":"1","websiteUrl":"https://123/x"}
            }
        });
        for (request, accepted) in [(june_with_icons, false), (invalid_uri, false), (valid_latest, true), (numeric_dns, true)] {
            let service = Arc::new(NullService { definitions: lifecycle_definitions() });
            let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 2).unwrap();
            let (responses, result) = serve_frames(server, &[request]).await;
            assert!(result.is_ok());
            assert_eq!(responses.len(), 1);
            if accepted {
                assert_eq!(responses[0]["result"]["protocolVersion"], "2025-11-25");
            } else {
                assert_eq!(responses[0]["error"]["code"], -32602);
            }
        }
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_uri_state_machine_adversarial_matrix() {
    timeout(Duration::from_secs(5), async {
        let cases = [
            ("HTTPS://example.com/x", true),
            ("http://127.0.0.1:65535/a", true),
            ("https://[::1]/a", true),
            ("urn:example:test", true),
            ("data:,hello", true),
            ("x:a//b?q=?#f", true),
            ("", false),
            ("relative/path", false),
            ("http:path", false),
            ("https:///x", false),
            ("https://user@example.com/x", false),
            ("https://example..com/x", false),
            ("https://256.1.1.1/x", false),
            ("https://example.com:/x", false),
            ("https://example.com:65536/x", false),
            ("https://example.com/a[b]", false),
            ("urn:a%2", false),
            ("urn:a%zz", false),
            ("urn:a#b#c", false),
            ("urn:a b", false),
            ("urn:界", false),
        ];
        for (index, (uri, accepted)) in cases.into_iter().enumerate() {
            let request = json!({
                "jsonrpc":"2.0","id":index,"method":"initialize","params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"x","version":"1","websiteUrl":uri}
                }
            });
            let service = Arc::new(NullService {
                definitions: lifecycle_definitions(),
            });
            let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 1).unwrap();
            let (responses, result) = serve_frames(server, &[request]).await;
            assert!(result.is_ok());
            assert_eq!(
                responses[0].get("result").is_some(),
                accepted,
                "URI case {uri:?}"
            );
        }
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_client_info_exact_limits_and_plus_one() {
    timeout(Duration::from_secs(5), async {
        let exact_website = format!("https://e/{}", "a".repeat(2048 - "https://e/".len()));
        let exact_icon = format!("data:,{}", "a".repeat(65_536 - "data:,".len()));
        for (field, value, accepted) in [
            ("name", "x".repeat(256), true),
            ("name", "x".repeat(257), false),
            ("title", "x".repeat(256), true),
            ("title", "x".repeat(257), false),
            ("description", "x".repeat(4096), true),
            ("description", "x".repeat(4097), false),
            ("websiteUrl", exact_website.clone(), true),
            ("websiteUrl", format!("{exact_website}a"), false),
        ] {
            let mut client = json!({"name":"x","version":"1"});
            client.as_object_mut().unwrap().insert(field.into(), Value::String(value));
            let request = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":client}});
            let service = Arc::new(NullService { definitions: lifecycle_definitions() });
            let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 1).unwrap();
            let (responses, _) = serve_frames(server, &[request]).await;
            assert_eq!(responses[0].get("result").is_some(), accepted, "field {field}");
        }
        for (src, accepted) in [(exact_icon.clone(), true), (format!("{exact_icon}a"), false)] {
            let request = json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"1","icons":[{"src":src}]}}});
            let service = Arc::new(NullService { definitions: lifecycle_definitions() });
            let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 1).unwrap();
            let (responses, _) = serve_frames(server, &[request]).await;
            assert_eq!(responses[0].get("result").is_some(), accepted);
        }
    }).await.expect("test must complete");
}

#[derive(Clone, Copy)]
enum PanicMode {
    Construct,
    FirstPoll,
    AfterPoll,
}

struct PanicTools {
    definitions: Vec<ToolDefinition>,
    mode: PanicMode,
}

impl PanicTools {
    fn new(mode: PanicMode) -> Self {
        let mut definitions = lifecycle_definitions();
        definitions[0].name = "panic".into();
        Self { definitions, mode }
    }
}

impl ToolService for PanicTools {
    fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }

    fn call(&self, name: String, arguments: Value, _context: ToolCallContext) -> ToolFuture {
        if name == "echo" {
            let text = arguments
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("ok")
                .to_owned();
            return Box::pin(async move { CallToolResult::text(text) });
        }
        match self.mode {
            PanicMode::Construct => panic!("HOSTILE construction payload"),
            PanicMode::FirstPoll => Box::pin(async { panic!("HOSTILE first-poll payload") }),
            PanicMode::AfterPoll => Box::pin(async {
                tokio::task::yield_now().await;
                panic!("HOSTILE later payload")
            }),
        }
    }
}

#[tokio::test]
async fn task7_panic_is_fixed_per_id_and_owner_continues() {
    timeout(Duration::from_secs(5), async {
        for mode in [PanicMode::Construct, PanicMode::FirstPoll, PanicMode::AfterPoll] {
            let tools = Arc::new(PanicTools::new(mode));
            let mut session = Session::start(McpServer::new(tools, MIN_MCP_FRAME_BYTES, 1).unwrap()).await;
            session.ready().await;
            session.send(&json!({"jsonrpc":"2.0","id":"boom","method":"tools/call","params":{"name":"panic","arguments":{}}})).await;
            let panic_response = session.recv().await;
            assert_eq!(panic_response, json!({"jsonrpc":"2.0","id":"boom","error":{"code":-32603,"message":"Internal error"}}));
            assert!(!serde_json::to_string(&panic_response).unwrap().contains("HOSTILE"));
            session.send(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"still alive"}}})).await;
            assert_eq!(session.recv().await["result"]["content"][0]["text"], "still alive");
            assert!(session.close().await.is_ok());
        }
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_dispatch_completes_out_of_order_and_propagates_exact_context() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 2).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"slow","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        session.send(&json!({"jsonrpc":"2.0","id":"fast","method":"tools/call","params":{"name":"echo","arguments":{"text":"done"}}})).await;
        let fast = session.recv().await;
        assert_eq!(fast["id"], "fast");
        assert_eq!(fast["result"]["content"][0]["text"], "done");
        tools.release.add_permits(1);
        assert_eq!(session.recv().await["id"], "slow");
        let contexts = tools.contexts.lock().await;
        assert_eq!(contexts.len(), 2);
        let expected_slow = WireBudget::for_response(
            MIN_MCP_FRAME_BYTES,
            &RequestId::try_from(json!("slow")).unwrap(),
            0,
        )
        .unwrap();
        let expected_fast = WireBudget::for_response(
            MIN_MCP_FRAME_BYTES,
            &RequestId::try_from(json!("fast")).unwrap(),
            0,
        )
        .unwrap();
        assert_eq!(contexts[0].wire_budget.result_bytes, expected_slow.result_bytes);
        assert_eq!(contexts[0].wire_budget.compact_fallback_bytes, expected_slow.compact_fallback_bytes);
        assert_eq!(contexts[1].wire_budget.result_bytes, expected_fast.result_bytes);
        assert_eq!(contexts[1].wire_budget.compact_fallback_bytes, expected_fast.compact_fallback_bytes);
        drop(contexts);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_inflight_rejects_duplicate_before_shape_and_saturation() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 1).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        session.send(&json!({"jsonrpc":"2.0","id":1,"method":"unknown","params":null})).await;
        assert_eq!(session.recv().await, json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Duplicate request id"}}));
        session.send(&json!({"jsonrpc":"2.0","id":1.0,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        assert_eq!(session.recv().await, invalid_request_response());
        session.send(&json!({"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}})).await;
        let busy = session.recv().await;
        assert_eq!(busy["id"], "1");
        assert_eq!(busy["error"]["code"], -32000);
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 1);
        assert_eq!(tools.first_polls.load(Ordering::SeqCst), 1);
        tools.release.add_permits(1);
        assert_eq!(session.recv().await["id"], 1);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_inflight_id_and_permit_release_before_response_backlog() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start_with_output_capacity(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 1).unwrap(), 1).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"reuse","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        tools.release.add_permits(1);
        // One byte proves the first response passed the writer's suppression
        // check and the owner already removed the registry entry. Capacity one
        // keeps the rest durably backlogged without a sleep/yield heuristic.
        let first_byte = timeout(Duration::from_secs(1), session.output.read_u8()).await.expect("first response must start").unwrap();
        session.send(&json!({"jsonrpc":"2.0","id":"reuse","method":"tools/call","params":{"name":"echo","arguments":{"text":"second"}}})).await;
        let mut rest = String::new();
        timeout(Duration::from_secs(1), session.output.read_line(&mut rest)).await.expect("first response must finish").unwrap();
        let mut first_wire = vec![first_byte];
        first_wire.extend_from_slice(rest.as_bytes());
        let first: Value = serde_json::from_slice(&first_wire).unwrap();
        let second = session.recv().await;
        assert_eq!(first["id"], "reuse");
        assert_eq!(second["id"], "reuse");
        assert_eq!(second["result"]["content"][0]["text"], "second");
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 2);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_inflight_third_unique_known_call_is_busy_at_bound_two() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 2).unwrap()).await;
        session.ready().await;
        for id in [1, 2] {
            session.send(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        }
        tools.wait_for_polls(2).await;
        session.send(&json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"busy"}}})).await;
        assert_eq!(session.recv().await, json!({"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"Server busy"}}));
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 2);
        assert_eq!(tools.first_polls.load(Ordering::SeqCst), 2);
        tools.release.add_permits(2);
        let first = session.recv().await["id"].clone();
        let second = session.recv().await["id"].clone();
        assert!(matches!((first.as_i64(), second.as_i64()), (Some(1), Some(2)) | (Some(2), Some(1))));
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_dispatch_known_invalid_arguments_are_normal_tool_results() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 2).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown","arguments":{}}})).await;
        assert_eq!(session.recv().await["error"]["code"], -32602);
        session.send(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}})).await;
        let invalid = session.recv().await;
        assert_eq!(invalid["id"], 2);
        assert_eq!(invalid["result"]["isError"], true);
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 1);
        assert_eq!(tools.first_polls.load(Ordering::SeqCst), 1);
        assert_eq!(tools.bridge_ops.load(Ordering::SeqCst), 0);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_cancellation_cancels_shared_token_and_suppresses_response() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 1).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"job","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        let token = tools.contexts.lock().await[0].cancel.clone();
        session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"job","reason":"hostile\nreason"}})).await;
        timeout(Duration::from_secs(1), async {
            while !tools.observed_cancel.load(Ordering::Acquire) { tokio::task::yield_now().await; }
        }).await.expect("service must observe cancellation");
        assert!(token.is_cancelled());
        session.send(&json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}})).await;
        assert_eq!(session.recv().await["id"], 2);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_cancellation_fully_validates_before_touching_token() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 1).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        for params in [
            json!({}),
            json!({"requestId":null}),
            json!({"requestId":7.5}),
            json!({"requestId":7,"reason":1}),
            json!({"requestId":7,"reason":"x".repeat(1025)}),
            json!({"requestId":7,"_meta":false}),
            json!({"requestId":7,"task":{}}),
            json!({"requestId":7,"extra":true}),
        ] {
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":params})).await;
        }
        tokio::task::yield_now().await;
        assert!(!tools.observed_cancel.load(Ordering::Acquire));
        assert!(!tools.contexts.lock().await[0].cancel.is_cancelled());
        session.send(&json!({"jsonrpc":"2.0","id":8,"method":"notifications/cancelled","params":{"requestId":7}})).await;
        assert_eq!(session.recv().await["error"]["code"], -32600);
        assert!(!tools.contexts.lock().await[0].cancel.is_cancelled());
        session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"_meta":{}}})).await;
        timeout(Duration::from_secs(1), async {
            while !tools.observed_cancel.load(Ordering::Acquire) { tokio::task::yield_now().await; }
        }).await.expect("valid cancellation must propagate");
        session.send(&json!({"jsonrpc":"2.0","id":9,"method":"ping","params":{}})).await;
        assert_eq!(session.recv().await["id"], 9);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_cancellation_shared_token_works_in_service_to_test_direction() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 1).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"manual","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        tools.contexts.lock().await[0].cancel.cancel();
        assert_eq!(session.recv().await["id"], "manual");
        assert!(tools.observed_cancel.load(Ordering::Acquire));
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[test]
fn task7_cancellation_owner_select_has_required_order_and_empty_guard() {
    let source = include_str!("../src/mcp/mod.rs");
    let helper = source
        .split("async fn next_owner_event")
        .nth(1)
        .unwrap()
        .split("async fn writer_loop")
        .next()
        .unwrap();
    assert!(helper.contains("biased;"));
    let writer = helper.find("writer_result = writer_handle").unwrap();
    let input = helper.find("input = frames.next_frame()").unwrap();
    let completion = helper
        .find("completion = join_set.join_next_with_id()")
        .unwrap();
    assert!(writer < input && input < completion);
    assert!(helper.contains("if !join_set.is_empty()"));
    assert!(!helper.contains("loop {"));
}

#[tokio::test]
async fn task7_cancellation_buffered_frame_wins_over_ready_completion() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 1).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"race","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        // On the current-thread runtime the buffered frame and durable permit
        // are both ready before the owner is scheduled again.
        session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"race"}})).await;
        tools.release.add_permits(1);
        session.send(&json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}})).await;
        assert_eq!(session.recv().await["id"], 2);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_cancellation_versioned_extension_policy_unknown_duplicate_and_late() {
    timeout(Duration::from_secs(5), async {
        for (version, extra_cancels) in [("2025-06-18", true), ("2025-11-25", false)] {
            let tools = Arc::new(StubTools::new());
            let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 1).unwrap()).await;
            session.send(&initialize(json!(100), version)).await;
            session.recv().await;
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})).await;
            session.send(&json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
            tools.wait_for_polls(1).await;
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"unknown","extension":true}})).await;
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":11,"extension":true}})).await;
            tokio::task::yield_now().await;
            assert_eq!(tools.contexts.lock().await[0].cancel.is_cancelled(), extra_cancels);
            if !extra_cancels {
                session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":11}})).await;
            }
            // Duplicate and later cancellation are both harmless no-ops.
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":11}})).await;
            session.send(&json!({"jsonrpc":"2.0","id":12,"method":"ping","params":{}})).await;
            assert_eq!(session.recv().await["id"], 12);
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":11}})).await;
            session.send(&json!({"jsonrpc":"2.0","id":13,"method":"ping","params":{}})).await;
            assert_eq!(session.recv().await["id"], 13);
            assert!(session.close().await.is_ok());
        }
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_cancellation_notification_flood_cannot_starve_ready_completion() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 1).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"done","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        tools.release.add_permits(1);
        let mut flood = Vec::new();
        for _ in 0..64 {
            flood.extend(serde_json::to_vec(&json!({"jsonrpc":"2.0","method":"unknown/notification","params":{}})).unwrap());
            flood.push(b'\n');
        }
        flood.extend(serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"after","method":"ping","params":{}})).unwrap());
        flood.push(b'\n');
        session.input.write_all(&flood).await.unwrap();
        assert_eq!(session.recv().await["id"], "done");
        assert_eq!(session.recv().await["id"], "after");
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

struct TestWriter {
    bytes: Arc<StdMutex<Vec<u8>>>,
    one_byte: bool,
    pending: bool,
    fail_write: bool,
    fail_shutdown: bool,
}

impl AsyncWrite for TestWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending {
            return Poll::Pending;
        }
        if self.fail_write {
            return Poll::Ready(Err(io::Error::other("HOSTILE writer diagnostic")));
        }
        let count = if self.one_byte {
            buffer.len().min(1)
        } else {
            buffer.len()
        };
        self.bytes
            .lock()
            .unwrap()
            .extend_from_slice(&buffer[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.fail_shutdown {
            Poll::Ready(Err(io::Error::other("HOSTILE shutdown diagnostic")))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

fn test_writer(one_byte: bool) -> (TestWriter, Arc<StdMutex<Vec<u8>>>) {
    let bytes = Arc::new(StdMutex::new(Vec::new()));
    (
        TestWriter {
            bytes: Arc::clone(&bytes),
            one_byte,
            pending: false,
            fail_write: false,
            fail_shutdown: false,
        },
        bytes,
    )
}

struct PrefixFailWriter {
    bytes: Arc<StdMutex<Vec<u8>>>,
    fail_at: usize,
}

impl AsyncWrite for PrefixFailWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = self.bytes.lock().unwrap().len();
        if written >= self.fail_at {
            return Poll::Ready(Err(io::Error::other("HOSTILE prefix failure")));
        }
        let count = buffer.len().min(self.fail_at - written);
        self.bytes
            .lock()
            .unwrap()
            .extend_from_slice(&buffer[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct PanicWriter;

impl AsyncWrite for PanicWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        panic!("HOSTILE writer panic payload")
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn task7_writer_one_byte_writes_complete_noninterleaved_lines() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 1).unwrap();
        let mut input = Vec::new();
        for frame in [
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}}),
        ] {
            input.extend(serde_json::to_vec(&frame).unwrap());
            input.push(b'\n');
        }
        let (writer, bytes) = test_writer(true);
        assert!(
            server
                .serve(std::io::Cursor::new(input), writer)
                .await
                .is_ok()
        );
        let bytes = bytes.lock().unwrap().clone();
        let lines: Vec<Value> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["id"], 1);
        assert_eq!(lines[1]["id"], 2);
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_writer_failure_shutdown_and_backpressure_are_fixed() {
    timeout(Duration::from_secs(5), async {
        for writer in [
            TestWriter {
                bytes: Arc::new(StdMutex::new(Vec::new())),
                one_byte: false,
                pending: false,
                fail_write: true,
                fail_shutdown: false,
            },
            TestWriter {
                bytes: Arc::new(StdMutex::new(Vec::new())),
                one_byte: false,
                pending: false,
                fail_write: false,
                fail_shutdown: true,
            },
            TestWriter {
                bytes: Arc::new(StdMutex::new(Vec::new())),
                one_byte: false,
                pending: true,
                fail_write: false,
                fail_shutdown: false,
            },
        ] {
            let service = Arc::new(NullService {
                definitions: lifecycle_definitions(),
            });
            let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 1).unwrap();
            let mut input = Vec::new();
            for frame in std::iter::once(initialize(json!(1), "2025-11-25")).chain(
                (0..20).map(|id| json!({"jsonrpc":"2.0","id":id + 10,"method":"ping","params":{}})),
            ) {
                input.extend(serde_json::to_vec(&frame).unwrap());
                input.push(b'\n');
            }
            let error = server
                .serve(std::io::Cursor::new(input), writer)
                .await
                .unwrap_err();
            assert_eq!(error, BridgeError::io("MCP transport failed"));
            assert!(!error.message.contains("HOSTILE"));
        }
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_writer_prefix_error_and_panic_close_without_replacement() {
    timeout(Duration::from_secs(5), async {
        let request = initialize(json!(1), "2025-11-25");
        let mut input = serde_json::to_vec(&request).unwrap();
        input.push(b'\n');
        let bytes = Arc::new(StdMutex::new(Vec::new()));
        let writer = PrefixFailWriter {
            bytes: Arc::clone(&bytes),
            fail_at: 17,
        };
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let error = McpServer::new(service, MIN_MCP_FRAME_BYTES, 1)
            .unwrap()
            .serve(std::io::Cursor::new(input.clone()), writer)
            .await
            .unwrap_err();
        assert_eq!(error, BridgeError::io("MCP transport failed"));
        assert_eq!(bytes.lock().unwrap().len(), 17);

        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let error = McpServer::new(service, MIN_MCP_FRAME_BYTES, 1)
            .unwrap()
            .serve(std::io::Cursor::new(input), PanicWriter)
            .await
            .unwrap_err();
        assert_eq!(error, BridgeError::io("MCP transport failed"));
        assert!(!error.message.contains("HOSTILE"));
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_writer_failure_is_monitored_while_input_stays_open() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 1).unwrap();
        let (mut input, server_reader) = tokio::io::duplex(4096);
        let writer = TestWriter {
            bytes: Arc::new(StdMutex::new(Vec::new())),
            one_byte: false,
            pending: false,
            fail_write: true,
            fail_shutdown: false,
        };
        let serve = tokio::spawn(server.serve(server_reader, writer));
        let mut request = serde_json::to_vec(&initialize(json!(1), "2025-11-25")).unwrap();
        request.push(b'\n');
        input.write_all(&request).await.unwrap();
        let error = timeout(Duration::from_secs(1), serve)
            .await
            .expect("writer failure must wake owner")
            .expect("owner must not panic")
            .unwrap_err();
        assert_eq!(error, BridgeError::io("MCP transport failed"));
    })
    .await
    .expect("test must complete");
}

struct HugeTools {
    definitions: Vec<ToolDefinition>,
}

impl ToolService for HugeTools {
    fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }
    fn call(&self, _name: String, _arguments: Value, _context: ToolCallContext) -> ToolFuture {
        Box::pin(async { CallToolResult::text("x".repeat(MIN_MCP_FRAME_BYTES + 1)) })
    }
}

#[tokio::test]
async fn task7_writer_capacity_overflow_writes_zero_bytes_of_that_frame() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(HugeTools { definitions: vec![lifecycle_definitions().remove(1)] });
        let server = McpServer::new(tools, MIN_MCP_FRAME_BYTES, 1).unwrap();
        let (mut input, server_reader) = tokio::io::duplex(128 * 1024);
        let (writer, bytes) = test_writer(false);
        let serve = tokio::spawn(server.serve(server_reader, writer));
        for frame in [
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}),
        ] {
            let mut wire = serde_json::to_vec(&frame).unwrap();
            wire.push(b'\n');
            input.write_all(&wire).await.unwrap();
        }
        let error = timeout(Duration::from_secs(1), serve).await.expect("capacity failure must wake owner").expect("owner must not panic").unwrap_err();
        assert_eq!(error, BridgeError::io("MCP transport failed"));
        let bytes = bytes.lock().unwrap().clone();
        let lines: Vec<_> = bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).collect();
        assert_eq!(lines.len(), 1, "overflowing call frame must contribute zero bytes");
        assert_eq!(serde_json::from_slice::<Value>(lines[0]).unwrap()["id"], 1);
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_eof_clean_and_partial_have_exact_precedence() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(Arc::clone(&service), MIN_MCP_FRAME_BYTES, 1).unwrap();
        let (responses, result) = serve_raw(server, Vec::new()).await;
        assert!(responses.is_empty());
        assert!(result.is_ok());

        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES, 1).unwrap();
        let (responses, result) = serve_raw(server, b"{".to_vec()).await;
        assert_eq!(responses, [parse_error_response()]);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.message, "partial MCP frame at EOF");
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_eof_partial_parse_error_yields_to_later_writer_failure() {
    timeout(Duration::from_secs(5), async {
        for writer in [
            TestWriter {
                bytes: Arc::new(StdMutex::new(Vec::new())),
                one_byte: false,
                pending: false,
                fail_write: true,
                fail_shutdown: false,
            },
            TestWriter {
                bytes: Arc::new(StdMutex::new(Vec::new())),
                one_byte: false,
                pending: false,
                fail_write: false,
                fail_shutdown: true,
            },
        ] {
            let service = Arc::new(NullService {
                definitions: lifecycle_definitions(),
            });
            let error = McpServer::new(service, MIN_MCP_FRAME_BYTES, 1)
                .unwrap()
                .serve(std::io::Cursor::new(b"{".to_vec()), writer)
                .await
                .unwrap_err();
            assert_eq!(error, BridgeError::io("MCP transport failed"));
        }
    })
    .await
    .expect("test must complete");
}

struct IgnoringTools {
    definitions: Vec<ToolDefinition>,
    entered: Arc<Notify>,
}

impl ToolService for IgnoringTools {
    fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }
    fn call(&self, _name: String, _arguments: Value, _context: ToolCallContext) -> ToolFuture {
        let entered = Arc::clone(&self.entered);
        Box::pin(async move {
            entered.notify_waiters();
            loop {
                tokio::task::yield_now().await;
            }
        })
    }
}

#[tokio::test]
async fn task7_eof_aborts_token_ignoring_yielding_task_within_bound() {
    timeout(Duration::from_secs(5), async {
        let entered = Arc::new(Notify::new());
        let tools = Arc::new(IgnoringTools { definitions: lifecycle_definitions(), entered: Arc::clone(&entered) });
        let mut session = Session::start(McpServer::new(tools, MIN_MCP_FRAME_BYTES, 1).unwrap()).await;
        session.ready().await;
        let notified = entered.notified();
        session.send(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        timeout(Duration::from_secs(1), notified).await.expect("task must start");
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_eof_cancels_cooperative_and_suppresses_already_ready_completion() {
    timeout(Duration::from_secs(5), async {
        for make_ready in [false, true] {
            let tools = Arc::new(StubTools::new());
            let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 1).unwrap()).await;
            session.ready().await;
            session.send(&json!({"jsonrpc":"2.0","id":"closing","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
            tools.wait_for_polls(1).await;
            if make_ready {
                tools.release.add_permits(1);
            }
            session.input.shutdown().await.unwrap();
            let result = timeout(Duration::from_secs(1), &mut session.serve).await.expect("serve must stop").expect("serve must not panic");
            assert!(result.is_ok());
            let mut trailing = Vec::new();
            timeout(Duration::from_secs(1), session.output.read_to_end(&mut trailing)).await.expect("writer must close").unwrap();
            assert!(trailing.is_empty(), "Closing must suppress tool completion");
            if !make_ready {
                assert!(tools.observed_cancel.load(Ordering::Acquire));
            }
        }
    }).await.expect("test must complete");
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
