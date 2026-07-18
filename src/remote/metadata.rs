use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult};
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::ssh::{FixedRunRequest, SshRunner};

use super::protocol::{
    context, encode_bytes, entry_error, kind, nul_fields, parse_mode, parse_mtime, parse_u64,
    protocol_error, read_stream, trim_capped_nul_groups, utf8,
};
use super::{
    ListEntry, ListResult, RemoteFileKind, RemoteMetadata, ResolvedList, ResolvedStat, StatEntry,
    StatResult,
};

const LIST_SCRIPT: &str = r#"
root=$1
depth=$2
limit=$3
if [ ! -e "$root" ] && [ ! -L "$root" ]; then printf 'NOT_FOUND\000' >&2; exit 0; fi
if [ ! -d "$root" ]; then printf 'NOT_DIRECTORY\000' >&2; exit 0; fi
if [ ! -r "$root" ]; then printf 'PERMISSION_DENIED\000' >&2; exit 0; fi
umask 077
scratch=$(mktemp -d /tmp/codex-ssh-list.XXXXXX) || exit 2
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT HUP INT TERM
fifo=$scratch/fifo
data=$scratch/data
status=$scratch/status
mkfifo "$fifo" || exit 2
(
    find -H "$root" -mindepth 1 -maxdepth "$depth" -printf '%p\000%y\000%s\000%m\000%T@\000' 2>/dev/null >"$fifo"
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

const STAT_SCRIPT: &str = r#"
exec xargs -0 -r sh -c '
for path do
    printf "%s\000" "$path"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then printf "NOT_FOUND\000"; continue; fi
    mode=$(stat --printf="%f" -- "$path" 2>/dev/null) || { printf "PERMISSION_DENIED\000"; continue; }
    size=$(stat --printf="%s" -- "$path" 2>/dev/null) || { printf "PERMISSION_DENIED\000"; continue; }
    seconds=$(stat --printf="%Y" -- "$path" 2>/dev/null) || { printf "PERMISSION_DENIED\000"; continue; }
    human=$(stat --printf="%y" -- "$path" 2>/dev/null) || { printf "PERMISSION_DENIED\000"; continue; }
    fraction=$(printf "%s" "$human" | cut -d. -f2 | cut -d" " -f1)
    printf "OK\000%s\000%s\000%s.%s\000" "$mode" "$size" "$seconds" "$fraction"
done
' codex-ssh-bridge-stat
"#;

pub(super) async fn list(
    runner: &Arc<SshRunner>,
    request: ResolvedList,
    cancel: CancellationToken,
) -> BridgeResult<ListResult> {
    let limits = runner.config().host(&request.host)?.limits;
    let owner = InternalSpoolOwner::new();
    let result = runner
        .execute_fixed(
            FixedRunRequest {
                host: request.host.clone(),
                script: LIST_SCRIPT,
                args: vec![
                    request.path.absolute().to_owned(),
                    request.depth.to_string(),
                    (limits.max_frame_bytes + 1).to_string(),
                ],
                stdin: None,
                required_capabilities: &["find_nul", "search_bound"],
                stdout_limit: (limits.max_frame_bytes + 1) as u64,
                stderr_limit: 1024,
                timeout: Duration::from_millis(limits.command_timeout_ms),
                cleanup: owner.registration(),
            },
            cancel,
        )
        .await?;
    let stderr = read_stream(&result.output, StreamKind::Stderr, 1024).await?;
    let capped = stderr == b"CAPPED\0";
    if !stderr.is_empty() && !capped {
        return match stderr.as_slice() {
            b"NOT_FOUND\0" => Err(BridgeError::not_found()),
            b"PERMISSION_DENIED\0" => Err(BridgeError::permission_denied()),
            b"NOT_DIRECTORY\0" => Err(BridgeError::not_directory()),
            _ => Err(protocol_error("list control record is invalid")),
        };
    }
    let mut stdout = read_stream(
        &result.output,
        StreamKind::Stdout,
        limits.max_frame_bytes + 1,
    )
    .await?;
    if capped {
        trim_capped_nul_groups(&mut stdout, 5)?;
    }
    let fields = nul_fields(&stdout)?;
    if !capped && fields.len() % 5 != 0 {
        return Err(protocol_error("list field count is invalid"));
    }
    let root = request.path.absolute().as_bytes();
    let mut entries = Vec::new();
    for record in fields.chunks_exact(5) {
        let actual = record[0];
        let relative = relative(root, actual)?;
        if !request.include_hidden
            && relative
                .split(|byte| *byte == b'/')
                .any(|part| part.first() == Some(&b'.'))
        {
            continue;
        }
        let (mtime_seconds, mtime_nanoseconds) = parse_mtime(record[4])?;
        entries.push(ListEntry {
            actual_path: encode_bytes(actual),
            relative_path: encode_bytes(relative),
            metadata: RemoteMetadata {
                kind: kind(record[1])?,
                size: parse_u64(record[2])?,
                mode: parse_mode(record[3])?,
                mtime_seconds,
                mtime_nanoseconds,
            },
        });
    }
    entries.sort_by(|left, right| {
        decoded_sort_key(&left.relative_path).cmp(&decoded_sort_key(&right.relative_path))
    });
    let truncated = capped || entries.len() > request.max_entries;
    entries.truncate(request.max_entries);
    Ok(ListResult {
        context: context(
            request.host,
            result.capability.physical_root.clone(),
            &result.shell,
        ),
        actual_path: encode_bytes(root),
        relative_path: encode_bytes(request.path.relative().as_bytes()),
        entries,
        truncated,
    })
}

pub(super) async fn stat(
    runner: &Arc<SshRunner>,
    request: ResolvedStat,
    cancel: CancellationToken,
) -> BridgeResult<StatResult> {
    let limits = runner.config().host(&request.host)?.limits;
    let mut stdin = Vec::new();
    for path in &request.paths {
        stdin.extend_from_slice(path.absolute().as_bytes());
        stdin.push(0);
    }
    let owner = InternalSpoolOwner::new();
    let result = runner
        .execute_fixed(
            FixedRunRequest {
                host: request.host.clone(),
                script: STAT_SCRIPT,
                args: Vec::new(),
                stdin: Some(stdin),
                required_capabilities: &["stat_printf", "xargs_nul"],
                stdout_limit: limits.max_frame_bytes as u64,
                stderr_limit: 1024,
                timeout: Duration::from_millis(limits.command_timeout_ms),
                cleanup: owner.registration(),
            },
            cancel,
        )
        .await?;
    let stderr = read_stream(&result.output, StreamKind::Stderr, 1024).await?;
    if !stderr.is_empty() {
        return Err(protocol_error("stat control record is invalid"));
    }
    let stdout = read_stream(&result.output, StreamKind::Stdout, limits.max_frame_bytes).await?;
    let fields = nul_fields(&stdout)?;
    let mut cursor = 0;
    let mut entries = Vec::with_capacity(request.paths.len());
    for requested in &request.paths {
        let actual = fields
            .get(cursor)
            .ok_or_else(|| protocol_error("stat response is incomplete"))?;
        let status = fields
            .get(cursor + 1)
            .ok_or_else(|| protocol_error("stat response is incomplete"))?;
        if *actual != requested.absolute().as_bytes() {
            return Err(protocol_error("stat response order is invalid"));
        }
        cursor += 2;
        let actual_path = encode_bytes(actual);
        let relative_path = encode_bytes(requested.relative().as_bytes());
        if *status == b"OK" {
            let mode = fields
                .get(cursor)
                .ok_or_else(|| protocol_error("stat response is incomplete"))?;
            let size = fields
                .get(cursor + 1)
                .ok_or_else(|| protocol_error("stat response is incomplete"))?;
            let mtime = fields
                .get(cursor + 2)
                .ok_or_else(|| protocol_error("stat response is incomplete"))?;
            cursor += 3;
            let raw_mode = u32::from_str_radix(utf8(mode)?, 16)
                .map_err(|_| protocol_error("stat mode is invalid"))?;
            let (mtime_seconds, mtime_nanoseconds) = parse_mtime(mtime)?;
            entries.push(StatEntry::Success {
                actual_path,
                relative_path,
                metadata: RemoteMetadata {
                    kind: kind_from_mode(raw_mode),
                    size: parse_u64(size)?,
                    mode: raw_mode & 0o7777,
                    mtime_seconds,
                    mtime_nanoseconds,
                },
            });
        } else {
            entries.push(StatEntry::Error {
                actual_path,
                relative_path,
                error: entry_error(status)?,
            });
        }
    }
    if cursor != fields.len() {
        return Err(protocol_error("stat response has trailing fields"));
    }
    Ok(StatResult {
        context: context(
            request.host,
            result.capability.physical_root.clone(),
            &result.shell,
        ),
        entries,
    })
}

fn relative<'a>(root: &[u8], actual: &'a [u8]) -> BridgeResult<&'a [u8]> {
    if actual == root {
        return Ok(&[]);
    }
    actual
        .strip_prefix(root)
        .and_then(|rest| rest.strip_prefix(b"/"))
        .ok_or_else(|| protocol_error("remote path escaped the requested root"))
}

fn decoded_sort_key(value: &super::EncodedValue) -> Vec<u8> {
    match value.encoding {
        super::ValueEncoding::Utf8 => value.value.as_bytes().to_vec(),
        super::ValueEncoding::Base64 => {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &value.value)
                .unwrap_or_default()
        }
    }
}

fn kind_from_mode(mode: u32) -> RemoteFileKind {
    match mode & libc::S_IFMT {
        libc::S_IFREG => RemoteFileKind::File,
        libc::S_IFDIR => RemoteFileKind::Directory,
        libc::S_IFLNK => RemoteFileKind::Symlink,
        libc::S_IFBLK => RemoteFileKind::BlockDevice,
        libc::S_IFCHR => RemoteFileKind::CharacterDevice,
        libc::S_IFIFO => RemoteFileKind::Fifo,
        libc::S_IFSOCK => RemoteFileKind::Socket,
        _ => RemoteFileKind::Other,
    }
}
