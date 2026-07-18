use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use globset::GlobSetBuilder;
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::ssh::{FixedRunRequest, SshRunner};

use super::protocol::{context, encode_bytes, protocol_error, read_stream};
use super::{ResolvedSearch, SearchEngine, SearchMatch, SearchResult};

const CANDIDATE_SCRIPT: &str = r#"
root=$1
limit=$2
if [ ! -e "$root" ] && [ ! -L "$root" ]; then printf 'NOT_FOUND\000' >&2; exit 0; fi
if [ ! -d "$root" ]; then printf 'NOT_DIRECTORY\000' >&2; exit 0; fi
if [ ! -r "$root" ]; then printf 'PERMISSION_DENIED\000' >&2; exit 0; fi
umask 077
scratch=$(mktemp -d /tmp/codex-ssh-search.XXXXXX) || exit 2
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT HUP INT TERM
fifo=$scratch/fifo
data=$scratch/data
status=$scratch/status
mkfifo "$fifo" || exit 2
(
    find -H "$root" -type f -print0 2>/dev/null >"$fifo"
    printf '%s' "$?" >"$status"
) &
producer=$!
head -c "$limit" <"$fifo" >"$data" || exit 2
wait "$producer" || true
bytes=$(wc -c <"$data")
producer_status=$(cat "$status" 2>/dev/null || printf 2)
if [ "$bytes" -lt "$limit" ] && [ "$producer_status" -ne 0 ]; then exit 2; fi
cat "$data"
if [ "$bytes" -eq "$limit" ]; then printf 'CAPPED\000' >&2; fi
"#;

const RG_SCRIPT: &str = r#"
query=$1
binary=$2
limit=$3
umask 077
scratch=$(mktemp -d /tmp/codex-ssh-search.XXXXXX) || exit 2
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT HUP INT TERM
fifo=$scratch/fifo
data=$scratch/data
status=$scratch/status
engine_error=$scratch/engine-error
input=$scratch/input
cat >"$input" || exit 2
mkfifo "$fifo" || exit 2
(
xargs -0 -r sh -c '
query=$1
binary=$2
engine_error=$3
shift 3
if [ "$binary" = 1 ]; then rg --json --fixed-strings --hidden --no-ignore --text -- "$query" "$@" 2>/dev/null; else rg --json --fixed-strings --hidden --no-ignore -- "$query" "$@" 2>/dev/null; fi
status=$?
if [ "$status" -eq 1 ]; then exit 0; fi
if [ "$status" -gt 1 ]; then printf "%s" "$status" >"$engine_error"; exit 255; fi
exit "$status"
' codex-ssh-bridge-rg "$query" "$binary" "$engine_error" <"$input" >"$fifo" 2>/dev/null
printf '%s' "$?" >"$status"
) &
producer=$!
head -c "$limit" <"$fifo" >"$data" || exit 2
wait "$producer" || true
bytes=$(wc -c <"$data")
if [ -s "$engine_error" ] && [ "$bytes" -lt "$limit" ]; then exit 2; fi
producer_status=$(cat "$status" 2>/dev/null || printf 2)
if [ "$bytes" -lt "$limit" ] && [ "$producer_status" -ne 0 ]; then exit 2; fi
cat "$data"
if [ "$bytes" -eq "$limit" ]; then printf 'CAPPED\000' >&2; fi
"#;

const GREP_SCRIPT: &str = r#"
query=$1
limit=$2
umask 077
scratch=$(mktemp -d /tmp/codex-ssh-search.XXXXXX) || exit 2
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT HUP INT TERM
fifo=$scratch/fifo
data=$scratch/data
status=$scratch/status
engine_error=$scratch/engine-error
input=$scratch/input
cat >"$input" || exit 2
mkfifo "$fifo" || exit 2
(
xargs -0 -r sh -c '
query=$1
engine_error=$2
shift 2
grep -IHnZ -F -- "$query" "$@" 2>/dev/null
status=$?
if [ "$status" -eq 1 ]; then exit 0; fi
if [ "$status" -gt 1 ]; then printf "%s" "$status" >"$engine_error"; exit 255; fi
exit "$status"
' codex-ssh-bridge-grep "$query" "$engine_error" <"$input" >"$fifo" 2>/dev/null
printf '%s' "$?" >"$status"
) &
producer=$!
head -c "$limit" <"$fifo" >"$data" || exit 2
wait "$producer" || true
bytes=$(wc -c <"$data")
if [ -s "$engine_error" ] && [ "$bytes" -lt "$limit" ]; then exit 2; fi
producer_status=$(cat "$status" 2>/dev/null || printf 2)
if [ "$bytes" -lt "$limit" ] && [ "$producer_status" -ne 0 ]; then exit 2; fi
cat "$data"
if [ "$bytes" -eq "$limit" ]; then printf 'CAPPED\000' >&2; fi
"#;

pub(super) async fn search(
    runner: &Arc<SshRunner>,
    request: ResolvedSearch,
    cancel: CancellationToken,
) -> BridgeResult<SearchResult> {
    let limits = runner.config().host(&request.host)?.limits;
    let owner = InternalSpoolOwner::new();
    let candidates_result = runner
        .execute_fixed(
            FixedRunRequest {
                host: request.host.clone(),
                script: CANDIDATE_SCRIPT,
                args: vec![
                    request.path.absolute().to_owned(),
                    (limits.max_frame_bytes + 1).to_string(),
                ],
                stdin: None,
                required_capabilities: &["find_nul", "search_bound"],
                stdout_limit: (limits.max_frame_bytes + 1) as u64,
                stderr_limit: 1024,
                timeout: Duration::from_millis(limits.command_timeout_ms),
                cleanup: owner.registration(),
            },
            cancel.clone(),
        )
        .await?;
    let stderr = read_stream(&candidates_result.output, StreamKind::Stderr, 1024).await?;
    let candidate_capped = stderr == b"CAPPED\0";
    if !stderr.is_empty() && !candidate_capped {
        return match stderr.as_slice() {
            b"NOT_FOUND\0" => Err(BridgeError::not_found()),
            b"PERMISSION_DENIED\0" => Err(BridgeError::permission_denied()),
            b"NOT_DIRECTORY\0" => Err(BridgeError::not_directory()),
            _ => Err(protocol_error("search candidate control record is invalid")),
        };
    }
    let mut raw = read_stream(
        &candidates_result.output,
        StreamKind::Stdout,
        limits.max_frame_bytes + 1,
    )
    .await?;
    if candidate_capped {
        let Some(last) = raw.iter().rposition(|byte| *byte == 0) else {
            return Err(protocol_error("search candidate record is oversized"));
        };
        raw.truncate(last + 1);
    } else if !raw.is_empty() && raw.last() != Some(&0) {
        return Err(protocol_error("search candidate record is incomplete"));
    }
    let mut builder = GlobSetBuilder::new();
    for glob in &request.globs {
        builder.add(
            globset::Glob::new(glob)
                .map_err(|_| BridgeError::invalid_argument("search glob is invalid"))?,
        );
    }
    let globs = builder
        .build()
        .map_err(|_| BridgeError::invalid_argument("search glob is invalid"))?;
    let configured_root = runner.config().host(&request.host)?.profile.root.as_bytes();
    let mut candidates = Vec::new();
    for path in raw
        .strip_suffix(&[0])
        .unwrap_or_default()
        .split(|byte| *byte == 0)
    {
        if path.is_empty() {
            continue;
        }
        let relative = relative(configured_root, path)?;
        if request.globs.is_empty()
            || globs.is_match(Path::new(&OsString::from_vec(relative.to_vec())))
        {
            candidates.push(path.to_vec());
        }
    }
    candidates.sort_by(|left, right| {
        relative(configured_root, left)
            .unwrap_or(left)
            .cmp(relative(configured_root, right).unwrap_or(right))
    });
    let mut truncated = candidate_capped || candidates.len() > 10_000;
    candidates.truncate(10_000);
    let rg = candidates_result.capability.tools.get("rg_json") == Some(&true);
    if request.binary && !rg {
        return Err(BridgeError::new(
            ErrorCode::RemoteCapabilityMissing,
            "binary search requires remote rg JSON support",
            false,
        ));
    }
    let engine = if rg {
        SearchEngine::Rg
    } else {
        SearchEngine::Grep
    };
    let mut stdin = Vec::new();
    let source = if rg { RG_SCRIPT } else { GREP_SCRIPT };
    let command_reserve = source
        .len()
        .checked_add(source.bytes().filter(|byte| *byte == b'\'').count() * 4)
        .and_then(|value| value.checked_add(request.query.len() * 4))
        .and_then(|value| value.checked_add(512))
        .ok_or_else(|| protocol_error("search command bound overflowed"))?;
    for candidate in &candidates {
        if stdin
            .len()
            .checked_add(candidate.len() + 1)
            .is_none_or(|next| next + command_reserve > limits.max_frame_bytes)
        {
            truncated = true;
            break;
        }
        stdin.extend_from_slice(candidate);
        stdin.push(0);
    }
    if stdin.is_empty() {
        return Ok(SearchResult {
            context: context(
                request.host,
                candidates_result.capability.physical_root.clone(),
                &candidates_result.shell,
            ),
            engine,
            matches: Vec::new(),
            truncated,
        });
    }
    drop(owner);
    let owner = InternalSpoolOwner::new();
    let (script, args, required): (&'static str, Vec<String>, &'static [&'static str]) = if rg {
        (
            RG_SCRIPT,
            vec![
                request.query.clone(),
                if request.binary { "1" } else { "0" }.to_owned(),
                (limits.max_frame_bytes + 1).to_string(),
            ],
            &["rg_json", "xargs_nul", "search_bound"],
        )
    } else {
        (
            GREP_SCRIPT,
            vec![
                request.query.clone(),
                (limits.max_frame_bytes + 1).to_string(),
            ],
            &["grep_nul", "xargs_nul", "search_bound"],
        )
    };
    let result = runner
        .execute_fixed(
            FixedRunRequest {
                host: request.host.clone(),
                script,
                args,
                stdin: Some(stdin),
                required_capabilities: required,
                stdout_limit: (limits.max_frame_bytes + 1) as u64,
                stderr_limit: 1024,
                timeout: Duration::from_millis(limits.command_timeout_ms),
                cleanup: owner.registration(),
            },
            cancel,
        )
        .await?;
    let stderr = read_stream(&result.output, StreamKind::Stderr, 1024).await?;
    let content_capped = stderr == b"CAPPED\0";
    if !stderr.is_empty() && !content_capped {
        return Err(protocol_error("search engine control record is invalid"));
    }
    let mut stdout = read_stream(
        &result.output,
        StreamKind::Stdout,
        limits.max_frame_bytes + 1,
    )
    .await?;
    if content_capped {
        let Some(last) = stdout.iter().rposition(|byte| *byte == b'\n') else {
            return Err(protocol_error("search event is oversized"));
        };
        stdout.truncate(last + 1);
        truncated = true;
    }
    let mut matches = if rg {
        parse_rg(&stdout, configured_root)?
    } else {
        parse_grep(&stdout, configured_root, request.query.as_bytes())?
    };
    if matches.len() > request.max_results {
        truncated = true;
        matches.truncate(request.max_results);
    }
    Ok(SearchResult {
        context: context(
            request.host,
            result.capability.physical_root.clone(),
            &result.shell,
        ),
        engine,
        matches,
        truncated,
    })
}

fn parse_rg(bytes: &[u8], root: &[u8]) -> BridgeResult<Vec<SearchMatch>> {
    let mut matches = Vec::new();
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if line.last() != Some(&b'\n') {
            return Err(protocol_error("rg JSON event is incomplete"));
        }
        let value: serde_json::Value = serde_json::from_slice(&line[..line.len() - 1])
            .map_err(|_| protocol_error("rg JSON event is invalid"))?;
        let event = value
            .get("type")
            .and_then(|value| value.as_str())
            .ok_or_else(|| protocol_error("rg JSON event has no type"))?;
        if event != "match" {
            continue;
        }
        let data = value
            .get("data")
            .ok_or_else(|| protocol_error("rg match has no data"))?;
        let actual = json_bytes(
            data.get("path")
                .ok_or_else(|| protocol_error("rg match has no path"))?,
        )?;
        let relative = relative(root, &actual)?;
        let mut content = json_bytes(
            data.get("lines")
                .ok_or_else(|| protocol_error("rg match has no lines"))?,
        )?;
        if content.last() == Some(&b'\n') {
            content.pop();
        }
        let line_number = data
            .get("line_number")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| protocol_error("rg match line is invalid"))?;
        let column = data
            .get("submatches")
            .and_then(|value| value.as_array())
            .and_then(|values| values.first())
            .and_then(|value| value.get("start"))
            .and_then(|value| value.as_u64())
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| protocol_error("rg match column is invalid"))?;
        matches.push(SearchMatch {
            actual_path: encode_bytes(&actual),
            relative_path: encode_bytes(relative),
            line: line_number,
            column,
            content: encode_bytes(&content),
        });
    }
    Ok(matches)
}

fn json_bytes(value: &serde_json::Value) -> BridgeResult<Vec<u8>> {
    if let Some(text) = value.get("text").and_then(|value| value.as_str()) {
        return Ok(text.as_bytes().to_vec());
    }
    if let Some(bytes) = value.get("bytes").and_then(|value| value.as_str()) {
        return base64::engine::general_purpose::STANDARD
            .decode(bytes)
            .map_err(|_| protocol_error("rg byte field is invalid"));
    }
    Err(protocol_error("rg text/bytes field is missing"))
}

fn parse_grep(bytes: &[u8], root: &[u8], query: &[u8]) -> BridgeResult<Vec<SearchMatch>> {
    let mut matches = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let nul = bytes[cursor..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| protocol_error("grep filename is incomplete"))?
            + cursor;
        let actual = &bytes[cursor..nul];
        cursor = nul + 1;
        let newline = bytes[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| protocol_error("grep line is incomplete"))?
            + cursor;
        let record = &bytes[cursor..newline];
        cursor = newline + 1;
        let colon = record
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| protocol_error("grep line number is missing"))?;
        let line = std::str::from_utf8(&record[..colon])
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| protocol_error("grep line number is invalid"))?;
        let content = &record[colon + 1..];
        let column = find_bytes(content, query)
            .and_then(|value| u64::try_from(value + 1).ok())
            .ok_or_else(|| protocol_error("grep result does not contain the query"))?;
        matches.push(SearchMatch {
            actual_path: encode_bytes(actual),
            relative_path: encode_bytes(relative(root, actual)?),
            line,
            column,
            content: encode_bytes(content),
        });
    }
    Ok(matches)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn relative<'a>(root: &[u8], actual: &'a [u8]) -> BridgeResult<&'a [u8]> {
    actual
        .strip_prefix(root)
        .and_then(|rest| rest.strip_prefix(b"/"))
        .ok_or_else(|| protocol_error("search path escaped the configured root"))
}
