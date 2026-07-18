use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::error::BridgeResult;
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::ssh::FixedRunRequest;

use super::protocol::{
    context, encode_bytes, entry_error, nul_fields, parse_u64, protocol_error, read_small_stream,
    utf8,
};
use super::{EntryError, EntryErrorCode, ReadEntry, ReadResult, RemoteBridge, ResolvedRead};

const READ_SCRIPT: &str = r#"
path=$1
start=$2
lines=$3
budget=$4
if ! tail -n +1 -- /dev/null >/dev/null 2>&1 ||
   ! head -n 1 /dev/null >/dev/null 2>&1 ||
   ! head -c 1 /dev/null >/dev/null 2>&1 ||
   ! tail -c 1 -- /dev/null >/dev/null 2>&1 ||
   ! wc -l </dev/null >/dev/null 2>&1; then
    printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=read_slice\000' >&2
    exit 0
fi
if ! stat --printf='%s' -- /dev/null >/dev/null 2>&1; then
    printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=stat_printf\000' >&2
    exit 0
fi
if ! sha256sum -- /dev/null >/dev/null 2>&1; then
    printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=sha256sum\000' >&2
    exit 0
fi
if [ ! -e "$path" ]; then printf 'NOT_FOUND\000' >&2; exit 0; fi
if [ ! -r "$path" ]; then printf 'PERMISSION_DENIED\000' >&2; exit 0; fi
if [ ! -f "$path" ]; then printf 'INVALID_ARGUMENT\000' >&2; exit 0; fi
size=$(stat --printf='%s' -- "$path" 2>/dev/null) || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
count=$(wc -l < "$path") || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
if [ "$size" -gt 0 ]; then
    final_lf=$(tail -c 1 -- "$path" | wc -l)
    if [ "$final_lf" -eq 0 ]; then count=$((count + 1)); fi
fi
hash1=$(sha256sum -- "$path" 2>/dev/null) || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
set -- $hash1
hash1=$1
look=$((budget + 1))
tail -n "+$start" -- "$path" 2>/dev/null | head -n "$lines" | head -c "$look"
hash2=$(sha256sum -- "$path" 2>/dev/null) || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
set -- $hash2
hash2=$1
printf 'OK\000%s\000%s\000%s\000%s\000' "$size" "$count" "$hash1" "$hash2" >&2
"#;

pub(super) async fn read(
    bridge: &RemoteBridge,
    request: ResolvedRead,
    cancel: CancellationToken,
) -> BridgeResult<ReadResult> {
    let runner = &bridge.runner;
    let limits = runner.config().host(&request.host)?.limits;
    let mut remaining = request.max_bytes;
    let mut files = Vec::with_capacity(request.paths.len());
    let mut returned_raw_bytes = 0u64;
    let mut operation_context = None;
    for path in request.paths {
        if cancel.is_cancelled() {
            return Err(crate::error::BridgeError::new(
                crate::error::ErrorCode::Cancelled,
                "remote read was cancelled",
                false,
            ));
        }
        let owner = InternalSpoolOwner::new();
        let result = bridge
            .execute_readonly_fixed(
                FixedRunRequest {
                    host: request.host.clone(),
                    script: READ_SCRIPT,
                    args: vec![
                        path.absolute().to_owned(),
                        request.start_line.to_string(),
                        request.max_lines.to_string(),
                        remaining.to_string(),
                    ],
                    stdin: None,
                    required_capabilities: &["read_slice", "stat_printf", "sha256sum"],
                    stdout_limit: (remaining as u64)
                        .checked_add(1)
                        .ok_or_else(|| protocol_error("read byte limit overflowed"))?,
                    stderr_limit: 1024,
                    timeout: Duration::from_millis(limits.command_timeout_ms),
                    cleanup: owner.registration(),
                },
                cancel.clone(),
            )
            .await?;
        if operation_context.is_none() {
            operation_context = Some(context(
                request.host.clone(),
                result.capability.physical_root.clone(),
                &result.shell,
            ));
        }
        let stderr = read_small_stream(&result.output, StreamKind::Stderr, 1024).await?;
        let fields = nul_fields(&stderr)?;
        let actual_path = encode_bytes(path.absolute().as_bytes());
        let relative_path = encode_bytes(path.relative().as_bytes());
        if fields.first() != Some(&b"OK".as_slice()) {
            if fields.len() != 1 {
                return Err(protocol_error("read error record is invalid"));
            }
            files.push(ReadEntry::Error {
                actual_path,
                relative_path,
                error: entry_error(
                    fields
                        .first()
                        .ok_or_else(|| protocol_error("read metadata is missing"))?,
                )?,
            });
            continue;
        }
        if fields.len() != 5 {
            return Err(protocol_error("read metadata field count is invalid"));
        }
        let size = parse_u64(fields[1])?;
        let total_lines = parse_u64(fields[2])?;
        let hash1 = utf8(fields[3])?;
        let hash2 = utf8(fields[4])?;
        if !valid_hash(hash1) || !valid_hash(hash2) {
            return Err(protocol_error("read hash is invalid"));
        }
        let stdout = read_small_stream(
            &result.output,
            StreamKind::Stdout,
            remaining.saturating_add(1),
        )
        .await?;
        if hash1 != hash2 {
            let conflict = crate::error::BridgeError::read_conflict();
            debug_assert_eq!(conflict.code, crate::error::ErrorCode::ReadConflict);
            files.push(ReadEntry::Error {
                actual_path,
                relative_path,
                error: EntryError {
                    code: EntryErrorCode::ReadConflict,
                    message: "remote file changed while being read",
                },
            });
            continue;
        }
        let byte_truncated = stdout.len() > remaining;
        let retained = &stdout[..stdout.len().min(remaining)];
        let truncated_before = request.start_line > 1 && size != 0;
        let line_end = request
            .start_line
            .saturating_sub(1)
            .saturating_add(request.max_lines);
        let truncated_after = byte_truncated || line_end < total_lines;
        let truncated = truncated_before || truncated_after;
        let sha256 = if !truncated {
            format!("{:x}", Sha256::digest(retained))
        } else {
            hash1.to_owned()
        };
        remaining -= retained.len();
        returned_raw_bytes = returned_raw_bytes
            .checked_add(retained.len() as u64)
            .ok_or_else(|| protocol_error("read byte count overflowed"))?;
        files.push(ReadEntry::Success {
            actual_path,
            relative_path,
            content: encode_bytes(retained),
            raw_bytes: retained.len() as u64,
            sha256,
            truncated_before,
            truncated_after,
            truncated,
        });
    }
    let context =
        operation_context.ok_or_else(|| protocol_error("read operation produced no context"))?;
    Ok(ReadResult {
        context,
        files,
        returned_raw_bytes,
    })
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
