use std::io::{self, Write};
use std::sync::{Arc, OnceLock};

use base64::Engine as _;
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, ErrorCode, ErrorDetails, ErrorShellMetadata};
use crate::remote::{
    AggregateKind, ApplyPatchResult, EncodedValue, HostsResult, ListResult, OutputReadResult,
    ReadEntry, ReadResult, RemoteBridge, RemoteContext, RemoteRunResult, RetentionProvenance,
    SearchEngine, SearchResult, ShellMetadata, ShellName, StatResult, ValueEncoding, WriteResult,
};

use super::{CallToolResult, TextContent, WireBudget};

const SAFE_TEXT_BYTES: usize = 1_024;
const MAX_WARNINGS: usize = 16;

pub fn maximum_compact_fallback_result_bytes() -> usize {
    static MAXIMUM: OnceLock<usize> = OnceLock::new();
    *MAXIMUM.get_or_init(|| {
        let hostile = "\\\"".repeat(SAFE_TEXT_BYTES / 2);
        let root = "\\\"".repeat(65_536 / 2);
        let mut error = BridgeError::new(ErrorCode::MutationOutcomeUnknown, &hostile, false);
        error.details = ErrorDetails {
            host: Some("h".repeat(128)),
            shell: Some(ErrorShellMetadata {
                kind: "bash".to_owned(),
                version: Some("?".repeat(256)),
                fallback: true,
            }),
            physical_root: Some(root.clone()),
            operation: Some(hostile.clone()),
            path: Some(hostile.clone()),
            suggested_action: Some(hostile.clone()),
            mutation_may_have_applied: Some(true),
            changed_paths: Some(vec![hostile.clone(); MAX_WARNINGS]),
            not_changed_paths: Some(vec![hostile.clone(); MAX_WARNINGS]),
            outcome_unknown_paths: Some(vec![hostile; MAX_WARNINGS]),
            ..ErrorDetails::default()
        };
        let error_result = render_error(
            error,
            WireBudget {
                result_bytes: usize::MAX / 4,
                compact_fallback_bytes: usize::MAX / 4,
            },
        );
        let warning = "\\\"".repeat(SAFE_TEXT_BYTES / 2);
        let run_result = compact_result(
            json!({
                "remote":true,
                "host":"h".repeat(128),
                "physical_root":root.clone(),
                "shell":{
                    "kind":"bash",
                    "version":"\\\"".repeat(128),
                    "fallback":true,
                },
                "status":"completed",
                "exit_status":i32::MIN,
                "elapsed_ms":u64::MAX,
                "stdout_raw_bytes":u64::MAX,
                "stderr_raw_bytes":u64::MAX,
                "aggregate_bytes":u64::MAX,
                "output_ref":"f".repeat(32),
                "output_stream":"stdout",
                "remote_process_may_continue":true,
                "warnings":vec![warning; MAX_WARNINGS],
                "warnings_truncated":true,
                "truncated":true,
                "detail_retained":true,
                "mutation_may_have_applied":true,
                "changed_count":usize::MAX,
                "not_changed_count":usize::MAX,
                "outcome_unknown_count":usize::MAX,
            }),
            false,
        );
        let list_text = json!({
            "remote":true,
            "host":"h".repeat(128),
            "physical_root":root.clone(),
            "shell":{
                "kind":"bash",
                "version":"\\\"".repeat(128),
                "fallback":true,
            },
            "actual_path":{"encoding":"utf8", "value":root.clone()},
            "relative_path":{"encoding":"utf8", "value":root},
            "entry_count":usize::MAX,
            "source_truncated":true,
            "truncated":true,
            "detail_retained":true,
            "output_ref":"f".repeat(32),
            "output_stream":"stdout",
        });
        let mut list_structured = object(list_text.clone());
        list_structured.remove("actual_path");
        list_structured.remove("relative_path");
        let list_result = compact_split_result(&list_text, Value::Object(list_structured), false);
        let invalid = CallToolResult::invalid_argument("provide valid tool arguments");
        [&error_result, &run_result, &list_result, &invalid]
            .into_iter()
            .map(|result| {
                serde_json::to_vec(result)
                    .expect("the maximum compact MCP fallback is serializable")
                    .len()
            })
            .max()
            .expect("the compact fallback set is nonempty")
    })
}

pub async fn hosts(
    bridge: Arc<RemoteBridge>,
    result: Result<HostsResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let metadata = json!({
                "remote": true,
                "aggregate": "hosts",
                "host_count": result.hosts.len(),
                "cached_physical_root_count": result.hosts.iter().filter(|host| host.physical_root.is_some()).count(),
                "cached_shell_count": result.hosts.iter().filter(|host| host.shell.is_some()).count(),
                "truncated": false,
            });
            let provenance = RetentionProvenance::Aggregate {
                kind: AggregateKind::Hosts,
                source_count: result.hosts.len(),
            };
            let presentation = HostsPresentation {
                remote: true,
                hosts: result.hosts,
            };
            render_retained(
                bridge,
                presentation,
                metadata,
                provenance,
                None,
                budget,
                cancel,
            )
            .await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub async fn list(
    bridge: Arc<RemoteBridge>,
    result: Result<ListResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let metadata = with_context(
                &result.context,
                json!({
                    "actual_path":result.actual_path.clone(),
                    "relative_path":result.relative_path.clone(),
                    "entry_count":result.entries.len(),
                    "truncated":result.truncated,
                }),
            );
            retained_remote(bridge, result, metadata, budget, cancel).await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub async fn stat(
    bridge: Arc<RemoteBridge>,
    result: Result<StatResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let metadata = with_context(
                &result.context,
                json!({"entry_count":result.entries.len(), "truncated":false}),
            );
            retained_remote(bridge, result, metadata, budget, cancel).await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub async fn search(
    bridge: Arc<RemoteBridge>,
    result: Result<SearchResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let engine = match result.engine {
                SearchEngine::Rg => "rg",
                SearchEngine::Grep => "grep",
            };
            let metadata = with_context(
                &result.context,
                json!({
                    "engine":engine,
                    "match_count":result.matches.len(),
                    "truncated":result.truncated,
                }),
            );
            retained_remote(bridge, result, metadata, budget, cancel).await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub async fn read(
    bridge: Arc<RemoteBridge>,
    result: Result<ReadResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let truncated = result.files.iter().any(|entry| {
                matches!(
                    entry,
                    ReadEntry::Success {
                        truncated: true,
                        ..
                    }
                )
            });
            let metadata = with_context(
                &result.context,
                json!({
                    "file_count":result.files.len(),
                    "returned_raw_bytes":result.returned_raw_bytes,
                    "truncated":truncated,
                }),
            );
            retained_remote(bridge, result, metadata, budget, cancel).await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub fn output_read(
    output_ref: &str,
    result: Result<OutputReadResult, BridgeError>,
    budget: WireBudget,
) -> CallToolResult {
    let result = match result {
        Ok(result) => result,
        Err(error) => return render_error(error, budget),
    };
    let raw = match result.data.encoding {
        ValueEncoding::Utf8 => result.data.value.into_bytes(),
        ValueEncoding::Base64 => {
            match base64::engine::general_purpose::STANDARD.decode(result.data.value.as_bytes()) {
                Ok(raw) => raw,
                Err(_) => {
                    return render_error(
                        BridgeError::new(
                            ErrorCode::ProtocolError,
                            "retained output encoding was invalid",
                            false,
                        ),
                        budget,
                    );
                }
            }
        }
    };
    let original_next = result.next_offset;
    let original_eof = result.eof;
    let mut inline = raw.len();
    loop {
        if result.data.encoding == ValueEncoding::Utf8 {
            while inline > 0 && std::str::from_utf8(&raw[..inline]).is_err() {
                inline -= 1;
            }
        }
        let data = encode_bytes(&raw[..inline], result.data.encoding);
        let next_offset = result.offset.saturating_add(inline as u64);
        let eof = original_eof && next_offset == original_next;
        let provenance = present_provenance(&result.provenance);
        let presentation = OutputReadPresentation {
            output_ref,
            provenance,
            output_stream: result.stream,
            offset: result.offset,
            next_offset,
            raw_bytes: inline,
            eof,
            truncated: next_offset != original_next,
            data: &data,
        };
        let metadata = with_provenance(
            &result.provenance,
            json!({
                "output_ref":output_ref,
                "output_stream":result.stream,
                "offset":result.offset,
                "next_offset":next_offset,
                "eof":eof,
                "encoding":data.encoding,
                "raw_bytes":inline,
                "truncated":next_offset != original_next,
                "detail_retained":true,
            }),
        );
        if let Some(rendered) = complete_result(&presentation, metadata, budget) {
            return rendered;
        }
        if inline == 0 {
            let eof = original_eof && result.offset == original_next;
            return budgeted_compact_result(
                with_provenance(
                    &result.provenance,
                    json!({
                        "output_ref":output_ref,
                        "output_stream":result.stream,
                        "offset":result.offset,
                        "next_offset":result.offset,
                        "eof":eof,
                        "raw_bytes":0,
                        "truncated":result.offset != original_next,
                        "detail_retained":true,
                    }),
                ),
                false,
                budget,
            );
        }
        inline /= 2;
    }
}

pub async fn write(
    bridge: Arc<RemoteBridge>,
    result: Result<WriteResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let metadata = with_context(
                &result.context,
                json!({
                    "status":"applied",
                    "operation":result.operation,
                    "raw_bytes":result.raw_bytes,
                    "sha256":result.sha256,
                    "mode":result.mode,
                    "temporary_cleanup_confirmed":result.temporary_cleanup_confirmed,
                    "mutation_may_have_applied":false,
                }),
            );
            retained_remote(bridge, result, metadata, budget, cancel).await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub async fn apply_patch(
    bridge: Arc<RemoteBridge>,
    result: Result<ApplyPatchResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let metadata = with_context(
                &result.context,
                json!({
                    "status":"applied",
                    "changed_count":result.changed_paths.len(),
                    "mutation_may_have_applied":false,
                }),
            );
            retained_remote(bridge, result, metadata, budget, cancel).await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub async fn run(
    bridge: Arc<RemoteBridge>,
    result: Result<RemoteRunResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(mut result) => {
            if result.context.shell.kind == ShellName::Sh
                && !result
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("POSIX sh"))
            {
                result
                    .warnings
                    .push(crate::remote::POSIX_SH_WARNING.to_owned());
            }
            let warnings_truncated = normalize_warnings(&mut result.warnings);
            let status = if result.exit_status == 0 {
                "completed"
            } else {
                "failed"
            };
            let mutation_may_have_applied =
                result.exit_status != 0 || result.remote_process_may_continue;
            let metadata = with_context(
                &result.context,
                json!({
                    "status":status,
                    "exit_status":result.exit_status,
                    "elapsed_ms":result.elapsed_ms,
                    "stdout_raw_bytes":result.stdout.raw_bytes,
                    "stderr_raw_bytes":result.stderr.raw_bytes,
                    "aggregate_bytes":result.aggregate_bytes,
                    "output_ref":result.output_ref,
                    "remote_process_may_continue":result.remote_process_may_continue,
                    "mutation_may_have_applied":mutation_may_have_applied,
                    "warnings":result.warnings,
                    "warnings_truncated":warnings_truncated,
                    "truncated":result.stdout.truncated || result.stderr.truncated,
                }),
            );
            let provenance = RetentionProvenance::Remote(result.context.clone());
            let existing_ref = result.output_ref.clone();
            render_retained(
                bridge,
                result,
                metadata,
                provenance,
                existing_ref,
                budget,
                cancel,
            )
            .await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

async fn retained_remote<T>(
    bridge: Arc<RemoteBridge>,
    result: T,
    metadata: Value,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult
where
    T: Serialize + Send + HasRemoteContext + 'static,
{
    let provenance = RetentionProvenance::Remote(result.remote_context().clone());
    render_retained(bridge, result, metadata, provenance, None, budget, cancel).await
}

async fn render_retained<T: Serialize + Send + 'static>(
    bridge: Arc<RemoteBridge>,
    result: T,
    metadata: Value,
    provenance: RetentionProvenance,
    existing_ref: Option<String>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    if let Some(rendered) = complete_result(&result, metadata.clone(), budget) {
        return rendered;
    }

    let retained = match existing_ref {
        Some(output_ref) => Some(output_ref),
        None => bridge
            .retain_serialized_detail(provenance, result, cancel)
            .await
            .ok()
            .map(|reference| reference.as_str().to_owned()),
    };
    let mut metadata = object(metadata);
    if let Some(source_truncated) = metadata.insert("truncated".to_owned(), Value::Bool(true)) {
        metadata.insert("source_truncated".to_owned(), source_truncated);
    }
    metadata.insert(
        "detail_retained".to_owned(),
        Value::Bool(retained.is_some()),
    );
    if let Some(output_ref) = retained {
        metadata.insert("output_ref".to_owned(), Value::String(output_ref));
        metadata.insert(
            "output_stream".to_owned(),
            Value::String("stdout".to_owned()),
        );
    }
    let text_metadata = Value::Object(metadata.clone());
    metadata.remove("actual_path");
    metadata.remove("relative_path");
    budgeted_compact_split_result(&text_metadata, Value::Object(metadata), false, budget)
}

fn complete_result<T: Serialize>(
    presentation: &T,
    structured_content: Value,
    budget: WireBudget,
) -> Option<CallToolResult> {
    let maximum = total_budget(budget);
    let text = serialize_capped(presentation, maximum)?;
    let result = CallToolResult {
        content: vec![TextContent::new(text)],
        structured_content,
        is_error: false,
    };
    serialized_at_most(&result, maximum).then_some(result)
}

fn compact_result(structured_content: Value, is_error: bool) -> CallToolResult {
    let text = serde_json::to_string(&structured_content)
        .expect("compact MCP presentation metadata is serializable");
    CallToolResult {
        content: vec![TextContent::new(text)],
        structured_content,
        is_error,
    }
}

fn compact_split_result<T: Serialize>(
    text_projection: &T,
    structured_content: Value,
    is_error: bool,
) -> CallToolResult {
    let text = serde_json::to_string(text_projection)
        .expect("compact MCP text projection is serializable");
    CallToolResult {
        content: vec![TextContent::new(text)],
        structured_content,
        is_error,
    }
}

fn budgeted_compact_result(
    structured_content: Value,
    is_error: bool,
    budget: WireBudget,
) -> CallToolResult {
    let result = compact_result(structured_content, is_error);
    debug_assert!(
        serialized_at_most(&result, budget.compact_fallback_bytes),
        "compact MCP result exceeded its reserved fallback budget"
    );
    result
}

fn budgeted_compact_split_result<T: Serialize>(
    text_projection: &T,
    structured_content: Value,
    is_error: bool,
    budget: WireBudget,
) -> CallToolResult {
    let result = compact_split_result(text_projection, structured_content, is_error);
    debug_assert!(
        serialized_at_most(&result, budget.compact_fallback_bytes),
        "compact MCP split result exceeded its reserved fallback budget"
    );
    result
}

fn render_error(error: BridgeError, budget: WireBudget) -> CallToolResult {
    render_error_borrowed(&error, budget)
}

fn render_error_borrowed(error: &BridgeError, budget: WireBudget) -> CallToolResult {
    render_error_borrowed_with_progress(error, budget, ErrorProgress::from_details(&error.details))
}

fn render_error_borrowed_with_progress(
    error: &BridgeError,
    budget: WireBudget,
    progress: ErrorProgress,
) -> CallToolResult {
    let details = &error.details;
    let (message, message_truncated) = safe_text(&error.message, SAFE_TEXT_BYTES);
    let (action, action_truncated) = details
        .suggested_action
        .as_deref()
        .map(|action| safe_text(action, SAFE_TEXT_BYTES))
        .map_or((None, false), |(action, truncated)| {
            (Some(action), truncated)
        });
    let context = rendered_error_context(details);
    let warnings = context
        .as_ref()
        .and_then(|context| context.shell.as_ref())
        .filter(|shell| shell.kind == "sh")
        .map(|_| vec![crate::remote::POSIX_SH_WARNING.to_owned()])
        .unwrap_or_default();
    let core = RenderedErrorCore {
        code: error.code,
        message,
        message_truncated,
        retryable: error.retryable,
        details: RenderedErrorDetails {
            operation: safe_optional(details.operation.as_deref()),
            path: safe_optional(details.path.as_deref()),
            elapsed_ms: details.elapsed_ms,
            exit_status: details.exit_status,
            remote_process_may_continue: details.remote_process_may_continue,
            bytes_seen: details.bytes_seen,
            mutation_may_have_applied: details.mutation_may_have_applied,
            failed_path: safe_optional(details.failed_path.as_deref()),
            changed_count: progress.changed_count,
            not_changed_count: progress.not_changed_count,
            outcome_unknown_count: progress.outcome_unknown_count,
        },
    };
    let document = RenderedErrorDocument {
        context: context.clone(),
        status: progress.status,
        error: &core,
        action: action.as_deref(),
        action_truncated,
        warnings: &warnings,
        warnings_truncated: false,
    };
    let text = serde_json::to_string(&document).expect("error projection is serializable");
    let structured = RenderedErrorDocument {
        context,
        status: progress.status,
        error: &core,
        action: action.as_deref(),
        action_truncated,
        warnings: &warnings,
        warnings_truncated: false,
    };
    let result = CallToolResult {
        content: vec![TextContent::new(text)],
        structured_content: serde_json::to_value(structured)
            .expect("error projection is serializable"),
        is_error: true,
    };
    if serialized_at_most(&result, total_budget(budget)) {
        result
    } else {
        budgeted_compact_result(result.structured_content, true, budget)
    }
}

#[derive(Clone, Copy)]
struct ErrorProgress {
    status: Option<&'static str>,
    changed_count: Option<usize>,
    not_changed_count: Option<usize>,
    outcome_unknown_count: Option<usize>,
}

impl ErrorProgress {
    fn from_details(details: &ErrorDetails) -> Self {
        Self {
            status: mutation_status(details),
            changed_count: details.changed_paths.as_ref().map(Vec::len),
            not_changed_count: details.not_changed_paths.as_ref().map(Vec::len),
            outcome_unknown_count: details.outcome_unknown_paths.as_ref().map(Vec::len),
        }
    }
}

fn mutation_status(details: &ErrorDetails) -> Option<&'static str> {
    if details.mutation_may_have_applied == Some(true)
        || details
            .outcome_unknown_paths
            .as_ref()
            .is_some_and(|paths| !paths.is_empty())
    {
        Some("unknown")
    } else if details
        .changed_paths
        .as_ref()
        .is_some_and(|paths| !paths.is_empty())
    {
        Some("partial")
    } else if details.changed_paths.is_some()
        || details.not_changed_paths.is_some()
        || details.mutation_may_have_applied.is_some()
    {
        Some("not_applied")
    } else {
        None
    }
}

async fn render_error_retained(
    bridge: Arc<RemoteBridge>,
    mut error: BridgeError,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    if let Some(result) = render_full_error(&mut error, budget) {
        return result;
    }
    let progress = ErrorProgress::from_details(&error.details);
    let changed_paths = error.details.changed_paths.take();
    let not_changed_paths = error.details.not_changed_paths.take();
    let outcome_unknown_paths = error.details.outcome_unknown_paths.take();
    let has_progress =
        changed_paths.is_some() || not_changed_paths.is_some() || outcome_unknown_paths.is_some();
    if !has_progress {
        return render_error(error, budget);
    }
    let provenance = error_retention_provenance(&error.details);
    let detail = RetainedMutationErrorDetail {
        code: error.code,
        mutation_may_have_applied: error.details.mutation_may_have_applied,
        failed_path: error.details.failed_path.as_deref().map(normalize_controls),
        changed_paths,
        not_changed_paths,
        outcome_unknown_paths,
    };
    let mut result = render_error_borrowed_with_progress(&error, budget, progress);
    let retained = match provenance {
        Some(provenance) => bridge
            .retain_serialized_detail(provenance, detail, cancel)
            .await
            .ok()
            .map(|reference| reference.as_str().to_owned()),
        None => None,
    };
    let mut structured = object(result.structured_content);
    structured.insert(
        "detail_retained".to_owned(),
        Value::Bool(retained.is_some()),
    );
    if let Some(output_ref) = retained {
        structured.insert("output_ref".to_owned(), Value::String(output_ref));
        structured.insert(
            "output_stream".to_owned(),
            Value::String("stdout".to_owned()),
        );
    }
    result = budgeted_compact_result(Value::Object(structured), true, budget);
    result
}

fn render_full_error(error: &mut BridgeError, budget: WireBudget) -> Option<CallToolResult> {
    normalize_progress_controls(&mut error.details);
    let details = &error.details;
    let (message, message_truncated) = safe_text(&error.message, SAFE_TEXT_BYTES);
    let (action, action_truncated) = details
        .suggested_action
        .as_deref()
        .map(|action| safe_text(action, SAFE_TEXT_BYTES))
        .map_or((None, false), |(action, truncated)| {
            (Some(action), truncated)
        });
    let context = rendered_error_context(details);
    let warnings = context
        .as_ref()
        .and_then(|context| context.shell.as_ref())
        .filter(|shell| shell.kind == "sh")
        .map(|_| vec![crate::remote::POSIX_SH_WARNING.to_owned()])
        .unwrap_or_default();
    let document = FullErrorDocument {
        context,
        status: mutation_status(details),
        error: FullErrorCore {
            code: error.code,
            message,
            message_truncated,
            retryable: error.retryable,
            details: FullErrorDetails {
                operation: safe_optional(details.operation.as_deref()),
                path: safe_optional(details.path.as_deref()),
                elapsed_ms: details.elapsed_ms,
                exit_status: details.exit_status,
                remote_process_may_continue: details.remote_process_may_continue,
                bytes_seen: details.bytes_seen,
                mutation_may_have_applied: details.mutation_may_have_applied,
                failed_path: safe_optional(details.failed_path.as_deref()),
                changed_paths: details.changed_paths.as_deref(),
                not_changed_paths: details.not_changed_paths.as_deref(),
                outcome_unknown_paths: details.outcome_unknown_paths.as_deref(),
            },
        },
        action,
        action_truncated,
        warnings,
        warnings_truncated: false,
    };
    let maximum = total_budget(budget);
    let text = serialize_capped(&document, maximum)?;
    let structured_content = render_error_borrowed(error, budget).structured_content;
    let result = CallToolResult {
        content: vec![TextContent::new(text)],
        structured_content,
        is_error: true,
    };
    serialized_at_most(&result, maximum).then_some(result)
}

fn normalize_progress_controls(details: &mut ErrorDetails) {
    for paths in [
        &mut details.changed_paths,
        &mut details.not_changed_paths,
        &mut details.outcome_unknown_paths,
    ]
    .into_iter()
    .flatten()
    {
        for path in paths {
            if path.chars().any(char::is_control) {
                *path = normalize_controls(path);
            }
        }
    }
}

fn error_retention_provenance(details: &ErrorDetails) -> Option<RetentionProvenance> {
    let host = details.host.clone()?;
    let physical_root = details.physical_root.clone()?;
    let shell = details.shell.as_ref()?;
    let kind = match shell.kind.as_str() {
        "bash" => ShellName::Bash,
        "sh" => ShellName::Sh,
        "login" => ShellName::Login,
        _ => return None,
    };
    Some(RetentionProvenance::Remote(RemoteContext {
        remote: true,
        host,
        physical_root,
        shell: ShellMetadata {
            kind,
            version: shell.version.clone(),
            fallback: shell.fallback,
        },
        helper_mode: None,
    }))
}

fn normalize_controls(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

fn rendered_error_context(details: &ErrorDetails) -> Option<RenderedContext> {
    let host = details.host.as_ref()?;
    Some(RenderedContext {
        remote: true,
        host: host.clone(),
        physical_root: details.physical_root.as_deref().map(normalize_controls),
        shell: details.shell.as_ref().map(|shell| RenderedShell {
            kind: shell.kind.clone(),
            version: shell
                .version
                .as_deref()
                .map(|version| safe_text(version, 256).0),
            fallback: shell.fallback,
        }),
    })
}

fn safe_optional(value: Option<&str>) -> Option<String> {
    value.map(|value| safe_text(value, SAFE_TEXT_BYTES).0)
}

fn safe_text(value: &str, maximum: usize) -> (String, bool) {
    let mut safe = String::with_capacity(value.len().min(maximum));
    let mut truncated = false;
    for character in value.chars() {
        let character = if character.is_control() {
            '?'
        } else {
            character
        };
        if safe.len() + character.len_utf8() > maximum {
            truncated = true;
            break;
        }
        safe.push(character);
    }
    (safe, truncated)
}

fn normalize_warnings(warnings: &mut Vec<String>) -> bool {
    let mut truncated = warnings.len() > MAX_WARNINGS;
    warnings.truncate(MAX_WARNINGS);
    for warning in warnings {
        let (safe, shortened) = safe_text(warning, SAFE_TEXT_BYTES);
        *warning = safe;
        truncated |= shortened;
    }
    truncated
}

fn with_context(context: &RemoteContext, fields: Value) -> Value {
    let mut fields = object(fields);
    fields.insert("remote".to_owned(), Value::Bool(true));
    fields.insert("host".to_owned(), Value::String(context.host.clone()));
    fields.insert(
        "physical_root".to_owned(),
        Value::String(context.physical_root.clone()),
    );
    fields.insert(
        "shell".to_owned(),
        serde_json::to_value(present_shell(&context.shell))
            .expect("shell metadata is serializable"),
    );
    if let Some(helper_mode) = context.helper_mode {
        fields.insert(
            "helper_mode".to_owned(),
            Value::String(helper_mode.as_str().to_owned()),
        );
    }
    Value::Object(fields)
}

fn present_shell(shell: &ShellMetadata) -> PresentedShell {
    PresentedShell {
        kind: shell.kind,
        version: shell
            .version
            .as_deref()
            .map(|version| safe_text(version, 256).0),
        fallback: shell.fallback,
    }
}

fn with_provenance(provenance: &RetentionProvenance, fields: Value) -> Value {
    match provenance {
        RetentionProvenance::Remote(context) => with_context(context, fields),
        RetentionProvenance::Aggregate { kind, source_count } => {
            let mut fields = object(fields);
            fields.insert("remote".to_owned(), Value::Bool(true));
            fields.insert(
                "aggregate".to_owned(),
                Value::String(
                    match kind {
                        AggregateKind::Hosts => "hosts",
                    }
                    .to_owned(),
                ),
            );
            fields.insert("source_count".to_owned(), json!(source_count));
            Value::Object(fields)
        }
    }
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(object) => object,
        _ => Map::new(),
    }
}

fn encode_bytes(bytes: &[u8], preferred: ValueEncoding) -> EncodedValue {
    if preferred == ValueEncoding::Utf8
        && let Ok(value) = std::str::from_utf8(bytes)
    {
        return EncodedValue {
            encoding: ValueEncoding::Utf8,
            value: value.to_owned(),
        };
    }
    EncodedValue {
        encoding: ValueEncoding::Base64,
        value: base64::engine::general_purpose::STANDARD.encode(bytes),
    }
}

fn total_budget(budget: WireBudget) -> usize {
    budget
        .result_bytes
        .saturating_add(budget.compact_fallback_bytes)
}

fn serialize_capped<T: Serialize>(value: &T, maximum: usize) -> Option<String> {
    let mut output = CappedVec::new(maximum);
    serde_json::to_writer(&mut output, value).ok()?;
    String::from_utf8(output.bytes).ok()
}

fn serialized_at_most<T: Serialize>(value: &T, maximum: usize) -> bool {
    let mut writer = CountingWriter { count: 0, maximum };
    serde_json::to_writer(&mut writer, value).is_ok()
}

struct CappedVec {
    bytes: Vec<u8>,
    maximum: usize,
}

impl CappedVec {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum.min(64 * 1024)),
            maximum,
        }
    }
}

impl Write for CappedVec {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > self.maximum {
            return Err(io::Error::other("MCP presentation exceeds its wire budget"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CountingWriter {
    count: usize,
    maximum: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count = self
            .count
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("MCP presentation size overflow"))?;
        if self.count > self.maximum {
            return Err(io::Error::other("MCP presentation exceeds its wire budget"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

trait HasRemoteContext {
    fn remote_context(&self) -> &RemoteContext;
}

macro_rules! impl_remote_context {
    ($($type:ty),+ $(,)?) => {$ (
        impl HasRemoteContext for $type {
            fn remote_context(&self) -> &RemoteContext {
                &self.context
            }
        }
    )+ };
}

impl_remote_context!(
    ListResult,
    StatResult,
    SearchResult,
    ReadResult,
    WriteResult,
    ApplyPatchResult,
);

#[derive(Serialize)]
struct HostsPresentation {
    remote: bool,
    hosts: Vec<crate::remote::HostInfo>,
}

#[derive(Serialize)]
struct PresentedShell {
    kind: ShellName,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    fallback: bool,
}

#[derive(Serialize)]
struct OutputReadPresentation<'a> {
    output_ref: &'a str,
    #[serde(flatten)]
    provenance: PresentedProvenance<'a>,
    output_stream: crate::output::StreamKind,
    offset: u64,
    next_offset: u64,
    raw_bytes: usize,
    eof: bool,
    truncated: bool,
    data: &'a EncodedValue,
}

fn present_provenance(provenance: &RetentionProvenance) -> PresentedProvenance<'_> {
    match provenance {
        RetentionProvenance::Remote(context) => PresentedProvenance::Remote(PresentedRemote {
            remote: true,
            host: &context.host,
            physical_root: &context.physical_root,
            shell: present_shell(&context.shell),
        }),
        RetentionProvenance::Aggregate { kind, source_count } => {
            PresentedProvenance::Aggregate(PresentedAggregate {
                remote: true,
                aggregate: match kind {
                    AggregateKind::Hosts => "hosts",
                },
                source_count: *source_count,
            })
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum PresentedProvenance<'a> {
    Remote(PresentedRemote<'a>),
    Aggregate(PresentedAggregate),
}

#[derive(Serialize)]
struct PresentedRemote<'a> {
    remote: bool,
    host: &'a str,
    physical_root: &'a str,
    shell: PresentedShell,
}

#[derive(Serialize)]
struct PresentedAggregate {
    remote: bool,
    aggregate: &'static str,
    source_count: usize,
}

#[derive(Clone, Serialize)]
struct RenderedContext {
    remote: bool,
    host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    physical_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shell: Option<RenderedShell>,
}

#[derive(Clone, Serialize)]
struct RenderedShell {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    fallback: bool,
}

#[derive(Serialize)]
struct RenderedErrorCore {
    code: ErrorCode,
    message: String,
    message_truncated: bool,
    retryable: bool,
    details: RenderedErrorDetails,
}

#[derive(Serialize)]
struct RenderedErrorDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_process_may_continue: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_seen: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mutation_may_have_applied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    changed_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_changed_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome_unknown_count: Option<usize>,
}

#[derive(Serialize)]
struct RenderedErrorDocument<'a> {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    context: Option<RenderedContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
    error: &'a RenderedErrorCore,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<&'a str>,
    action_truncated: bool,
    #[serde(skip_serializing_if = "slice_is_empty")]
    warnings: &'a [String],
    warnings_truncated: bool,
}

fn slice_is_empty(values: &&[String]) -> bool {
    values.is_empty()
}

#[derive(Serialize)]
struct RetainedMutationErrorDetail {
    code: ErrorCode,
    mutation_may_have_applied: Option<bool>,
    failed_path: Option<String>,
    changed_paths: Option<Vec<String>>,
    not_changed_paths: Option<Vec<String>>,
    outcome_unknown_paths: Option<Vec<String>>,
}

#[derive(Serialize)]
struct FullErrorDocument<'a> {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    context: Option<RenderedContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
    error: FullErrorCore<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    action_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    warnings_truncated: bool,
}

#[derive(Serialize)]
struct FullErrorCore<'a> {
    code: ErrorCode,
    message: String,
    message_truncated: bool,
    retryable: bool,
    details: FullErrorDetails<'a>,
}

#[derive(Serialize)]
struct FullErrorDetails<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_process_may_continue: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_seen: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mutation_may_have_applied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    changed_paths: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_changed_paths: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome_unknown_paths: Option<&'a [String]>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use base64::Engine as _;
    use serde_json::json;

    use super::*;
    use crate::config::{Config, HostLimitOverrides, HostProfile};
    use crate::output::{OutputStore, StreamKind};
    use crate::remote::{
        EncodedOutputPreview, HostInfo, ListEntry, ReadEntry, RemoteFileKind, RemoteMetadata,
        SearchMatch, StatEntry,
    };
    use crate::ssh::{RuntimePaths, SshRunner};

    fn result_value(result: CallToolResult) -> Value {
        serde_json::to_value(result).unwrap()
    }

    fn text_value(result: &Value) -> Value {
        serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
    }

    fn roomy_budget() -> WireBudget {
        WireBudget {
            result_bytes: 2 * 1024 * 1024,
            compact_fallback_bytes: maximum_compact_fallback_result_bytes(),
        }
    }

    fn compact_budget() -> WireBudget {
        WireBudget {
            result_bytes: 0,
            compact_fallback_bytes: 8 * 1024,
        }
    }

    fn bridge_fixture() -> (tempfile::TempDir, Arc<RemoteBridge>) {
        let runtime_base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
        let store = Arc::new(OutputStore::new(&runtime).unwrap());
        let config = Arc::new(Config {
            hosts: BTreeMap::from([(
                "dev".to_owned(),
                HostProfile {
                    root: "/srv/root".to_owned(),
                    description: None,
                    read_only: false,
                    limits: HostLimitOverrides::default(),
                },
            )]),
            ..Config::default()
        });
        let runner = Arc::new(SshRunner::new(config, runtime, store).unwrap());
        (runtime_base, Arc::new(RemoteBridge::new(runner)))
    }

    fn context() -> RemoteContext {
        RemoteContext {
            remote: true,
            host: "dev".to_owned(),
            physical_root: "/srv/root".to_owned(),
            shell: ShellMetadata {
                kind: ShellName::Sh,
                version: None,
                fallback: false,
            },
            helper_mode: None,
        }
    }

    fn encoded(value: impl Into<String>) -> EncodedValue {
        EncodedValue {
            encoding: ValueEncoding::Utf8,
            value: value.into(),
        }
    }

    fn metadata() -> RemoteMetadata {
        RemoteMetadata {
            kind: RemoteFileKind::File,
            size: 1,
            mode: 0o640,
            mtime_seconds: 1,
            mtime_nanoseconds: 2,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn helper_mode_is_rendered_in_remote_run_metadata() {
        let (_runtime, bridge) = bridge_fixture();
        let mut remote_context = context();
        remote_context.helper_mode = Some(crate::ssh::HelperMode::Persistent);
        let rendered = result_value(
            run(
                bridge,
                Ok(RemoteRunResult {
                    context: remote_context,
                    exit_status: 0,
                    elapsed_ms: 1,
                    stdout: EncodedOutputPreview {
                        head: encoded("ok"),
                        tail: encoded("ok"),
                        raw_bytes: 2,
                        truncated: false,
                    },
                    stderr: EncodedOutputPreview {
                        head: encoded(""),
                        tail: encoded(""),
                        raw_bytes: 0,
                        truncated: false,
                    },
                    aggregate_bytes: 2,
                    output_ref: None,
                    remote_process_may_continue: false,
                    warnings: Vec::new(),
                }),
                roomy_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(rendered["structuredContent"]["helper_mode"], "persistent");
        assert!(!rendered.to_string().contains("/home/"));
    }

    #[test]
    fn task8_error_rendering_roomy_text_preserves_exact_progress_partitions() {
        let mut error = BridgeError::new(ErrorCode::WriteConflict, "patch failed", false);
        error.details.changed_paths = Some(vec!["a".to_owned()]);
        error.details.not_changed_paths = Some(vec!["b".to_owned(), "c".to_owned()]);
        error.details.outcome_unknown_paths = Some(vec!["d".to_owned()]);
        error.details.mutation_may_have_applied = Some(true);
        let rendered = result_value(
            render_full_error(&mut error, roomy_budget()).expect("roomy error must render inline"),
        );
        let text = text_value(&rendered);
        assert_eq!(text["error"]["details"]["changed_paths"], json!(["a"]));
        assert_eq!(
            text["error"]["details"]["not_changed_paths"],
            json!(["b", "c"])
        );
        assert_eq!(
            text["error"]["details"]["outcome_unknown_paths"],
            json!(["d"])
        );
        assert!(
            rendered["structuredContent"]["error"]["details"]
                .get("changed_paths")
                .is_none()
        );
        assert_eq!(
            rendered["structuredContent"]["error"]["details"]["changed_count"],
            1
        );
        assert_eq!(rendered["structuredContent"]["status"], "unknown");
    }

    #[test]
    fn task8_error_rendering_normalizes_context_and_progress_controls() {
        let mut error = BridgeError::new(ErrorCode::WriteConflict, "patch failed", false);
        error.details.host = Some("dev".to_owned());
        error.details.physical_root = Some("/srv/\troot\n".to_owned());
        error.details.changed_paths = Some(vec!["changed\tpath".to_owned()]);
        error.details.not_changed_paths = Some(vec!["not\nchanged".to_owned()]);
        error.details.outcome_unknown_paths = Some(vec!["unknown\rpath".to_owned()]);

        let rendered = result_value(
            render_full_error(&mut error, roomy_budget()).expect("roomy error must render inline"),
        );
        let text = text_value(&rendered);

        assert_eq!(text["physical_root"], "/srv/?root?");
        assert_eq!(
            text["error"]["details"]["changed_paths"],
            json!(["changed?path"])
        );
        assert_eq!(
            text["error"]["details"]["not_changed_paths"],
            json!(["not?changed"])
        );
        assert_eq!(
            text["error"]["details"]["outcome_unknown_paths"],
            json!(["unknown?path"])
        );
        assert_eq!(
            rendered["structuredContent"]["physical_root"],
            "/srv/?root?"
        );
    }

    #[test]
    fn task8_error_action_exact_limit_and_plus_one_report_truncation() {
        for (length, truncated) in [(SAFE_TEXT_BYTES, false), (SAFE_TEXT_BYTES + 1, true)] {
            let mut error = BridgeError::new(ErrorCode::InvalidArgument, "bad request", false);
            error.details.suggested_action = Some("x".repeat(length));

            let rendered = result_value(render_error(error, roomy_budget()));
            let text = text_value(&rendered);
            assert_eq!(
                rendered["structuredContent"]["action"]
                    .as_str()
                    .unwrap()
                    .len(),
                SAFE_TEXT_BYTES
            );
            assert_eq!(rendered["structuredContent"]["action_truncated"], truncated);
            assert_eq!(text["action_truncated"], truncated);
        }
    }

    #[test]
    fn task8_error_rendering_normalizes_controls_without_damaging_json_characters() {
        let mut error = BridgeError::new(
            ErrorCode::RemoteExit,
            "bad\0line\nquote=\" slash=\\ snow=雪",
            false,
        );
        error.details.host = Some("dev".to_owned());
        error.details.physical_root = Some("/srv/root".to_owned());
        error.details.shell = Some(ErrorShellMetadata {
            kind: "sh".to_owned(),
            version: Some("v\0\n1".to_owned()),
            fallback: true,
        });
        error.details.suggested_action = Some("try\rquoted=\"\\".to_owned());
        let rendered = result_value(render_error(error, roomy_budget()));
        let message = rendered["structuredContent"]["error"]["message"]
            .as_str()
            .unwrap();
        assert_eq!(message, "bad?line?quote=\" slash=\\ snow=雪");
        assert_eq!(rendered["structuredContent"]["shell"]["version"], "v??1");
        assert_eq!(rendered["structuredContent"]["action"], "try?quoted=\"\\");
        assert!(text_value(&rendered).to_string().contains("POSIX sh"));
    }

    #[test]
    fn task8_single_copy_output_read_shrinks_utf8_on_raw_boundaries() {
        let original = "雪\"".repeat(8_192);
        let offset = 17_u64;
        let rendered = result_value(output_read(
            "0123456789abcdef0123456789abcdef",
            Ok(OutputReadResult {
                provenance: RetentionProvenance::Aggregate {
                    kind: AggregateKind::Hosts,
                    source_count: 9,
                },
                stream: StreamKind::Stdout,
                offset,
                next_offset: offset + original.len() as u64,
                eof: true,
                data: EncodedValue {
                    encoding: ValueEncoding::Utf8,
                    value: original,
                },
            }),
            WireBudget {
                result_bytes: 0,
                compact_fallback_bytes: 4 * 1024,
            },
        ));
        let text = text_value(&rendered);
        let inline = text["data"]["value"].as_str().unwrap().len() as u64;
        assert!(inline > 0);
        assert_eq!(text["next_offset"], offset + inline);
        assert_eq!(text["raw_bytes"], inline);
        assert_eq!(text["eof"], false);
        assert_eq!(text["aggregate"], "hosts");
    }

    #[test]
    fn task8_single_copy_output_read_shrinks_base64_using_decoded_byte_offsets() {
        let original = (0_u8..=255).cycle().take(32 * 1024).collect::<Vec<_>>();
        let offset = 123_u64;
        let rendered = result_value(output_read(
            "0123456789abcdef0123456789abcdef",
            Ok(OutputReadResult {
                provenance: RetentionProvenance::Aggregate {
                    kind: AggregateKind::Hosts,
                    source_count: 9,
                },
                stream: StreamKind::Stdout,
                offset,
                next_offset: offset + original.len() as u64,
                eof: true,
                data: EncodedValue {
                    encoding: ValueEncoding::Base64,
                    value: base64::engine::general_purpose::STANDARD.encode(&original),
                },
            }),
            WireBudget {
                result_bytes: 0,
                compact_fallback_bytes: 4 * 1024,
            },
        ));
        let text = text_value(&rendered);
        let inline = base64::engine::general_purpose::STANDARD
            .decode(text["data"]["value"].as_str().unwrap())
            .unwrap();
        assert!(!inline.is_empty());
        assert_eq!(text["next_offset"], offset + inline.len() as u64);
        assert_eq!(text["raw_bytes"], inline.len());
        assert_eq!(text["eof"], false);
    }

    #[tokio::test]
    async fn task8_retention_all_bulk_compact_fallbacks_preserve_truth_on_admission_failure() {
        let (_runtime, bridge) = bridge_fixture();
        let bulk = "BULK_SENTINEL".repeat(2_048);

        let hosts_result = result_value(
            hosts(
                Arc::clone(&bridge),
                Ok(HostsResult {
                    hosts: vec![HostInfo {
                        remote: true,
                        host: "dev".to_owned(),
                        configured_root: "/srv/root".to_owned(),
                        description: Some(bulk.clone()),
                        read_only: false,
                        physical_root: None,
                        shell: None,
                    }],
                }),
                compact_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(hosts_result["structuredContent"]["host_count"], 1);
        assert_eq!(hosts_result["structuredContent"]["detail_retained"], true);

        let list_result = result_value(
            list(
                Arc::clone(&bridge),
                Ok(ListResult {
                    context: context(),
                    actual_path: encoded("/srv/root"),
                    relative_path: encoded("."),
                    entries: vec![ListEntry {
                        actual_path: encoded(bulk.clone()),
                        relative_path: encoded("large"),
                        metadata: metadata(),
                    }],
                    truncated: false,
                }),
                compact_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(list_result["structuredContent"]["entry_count"], 1);
        assert_eq!(list_result["structuredContent"]["detail_retained"], false);
        assert_eq!(list_result["structuredContent"]["truncated"], true);
        assert_eq!(list_result["structuredContent"]["source_truncated"], false);

        let stat_result = result_value(
            stat(
                Arc::clone(&bridge),
                Ok(StatResult {
                    context: context(),
                    entries: vec![StatEntry::Success {
                        actual_path: encoded(bulk.clone()),
                        relative_path: encoded("large"),
                        metadata: metadata(),
                    }],
                }),
                compact_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(stat_result["structuredContent"]["entry_count"], 1);
        assert_eq!(stat_result["structuredContent"]["detail_retained"], false);

        let search_result = result_value(
            search(
                Arc::clone(&bridge),
                Ok(SearchResult {
                    context: context(),
                    engine: SearchEngine::Rg,
                    matches: vec![SearchMatch {
                        actual_path: encoded("/srv/root/large"),
                        relative_path: encoded("large"),
                        line: 1,
                        column: 1,
                        content: encoded(bulk.clone()),
                    }],
                    truncated: false,
                }),
                compact_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(search_result["structuredContent"]["match_count"], 1);
        assert_eq!(search_result["structuredContent"]["detail_retained"], false);

        let read_result = result_value(
            read(
                Arc::clone(&bridge),
                Ok(ReadResult {
                    context: context(),
                    files: vec![ReadEntry::Success {
                        actual_path: encoded("/srv/root/large"),
                        relative_path: encoded("large"),
                        content: encoded(bulk.clone()),
                        raw_bytes: bulk.len() as u64,
                        sha256: "0".repeat(64),
                        truncated_before: false,
                        truncated_after: true,
                        truncated: true,
                    }],
                    returned_raw_bytes: bulk.len() as u64,
                }),
                compact_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(read_result["structuredContent"]["file_count"], 1);
        assert_eq!(
            read_result["structuredContent"]["returned_raw_bytes"],
            bulk.len()
        );
        assert_eq!(read_result["structuredContent"]["source_truncated"], true);
        assert_eq!(read_result["structuredContent"]["detail_retained"], false);

        let run_result = result_value(
            run(
                Arc::clone(&bridge),
                Ok(RemoteRunResult {
                    context: context(),
                    exit_status: 0,
                    elapsed_ms: 1,
                    stdout: EncodedOutputPreview {
                        head: encoded(bulk.clone()),
                        tail: encoded("tail"),
                        raw_bytes: bulk.len() as u64,
                        truncated: true,
                    },
                    stderr: EncodedOutputPreview {
                        head: encoded(""),
                        tail: encoded(""),
                        raw_bytes: 0,
                        truncated: false,
                    },
                    aggregate_bytes: bulk.len() as u64,
                    output_ref: None,
                    remote_process_may_continue: false,
                    warnings: Vec::new(),
                }),
                compact_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(run_result["structuredContent"]["exit_status"], 0);
        assert_eq!(run_result["structuredContent"]["status"], "completed");
        assert_eq!(
            run_result["structuredContent"]["aggregate_bytes"],
            bulk.len()
        );
        assert_eq!(run_result["structuredContent"]["detail_retained"], false);
        assert_eq!(
            run_result["structuredContent"]["mutation_may_have_applied"],
            false
        );
    }
}
