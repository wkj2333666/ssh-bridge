use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult};
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::ssh::FixedRunRequest;

use super::protocol::{
    SpoolCursor, context, encode_bytes, entry_error, kind, parse_mode, parse_mtime, parse_u64,
    protocol_error, read_small_stream, utf8,
};
use super::{
    ListEntry, ListResult, RemoteBridge, RemoteFileKind, RemoteMetadata, ResolvedList,
    ResolvedStat, StatEntry, StatResult,
};

const LIST_SCRIPT: &str = r#"
root=$1
depth=$2
show_hidden=$3
max_entries=$4
limit=$5
cs() (
 d=$(mktemp -d /tmp/codex-sentinel-bound.XXXXXX 2>/dev/null)||exit 90
 trap 'rm -rf -- "$d"' 0 1 2 15
 f=$d/codex-sentinel-bound;o=$d/o
 m=$(stat -c %a "$d" 2>/dev/null)||exit 90
 [ "$m" = 700 ]||exit 11;mkfifo "$f"||exit 90;[ -p "$f" ]||exit 11
 (printf abcdef>"$f")&p=$!;exec 3<"$f"
 CODEX_SSH_SENTINEL=bound head -c 3 <&3 >"$o" 2>/dev/null;h=$?
 cat <&3 >/dev/null;r=$?;exec 3<&-;wait "$p" 2>/dev/null;w=$?
 [ "$r:$w" = 0:0 ]||exit 90;v=$(cat "$o")||exit 90;[ "$h:$v" = 0:abc ]||exit 11
 a=$d/a;z=$d/z;l=$d/codex-sentinel-list-find
 mkdir "$a" "$z"&&printf x>"$a/f"&&ln -s "$z" "$a/l"&&ln -s "$a" "$l"&&chmod 640 "$a/f"&&touch -d @7.25 "$a/f"&&touch -h -d @8.5 "$a/l"||exit 90
 find -H "$l" -mindepth 1 -maxdepth 1 -name f -type f -printf '%P\000%y\000%s\000%m\000%T@\000' >"$o" 2>/dev/null||exit 90
 find -H "$l" -mindepth 1 -maxdepth 1 -name l -type l -printf '%P\000%y\000%s\000%m\000%T@\000' >>"$o" 2>/dev/null||exit 90
 { printf 'f\000f\0001\000640\0007.2500000000\000';printf 'l\000l\000%s\000777\0008.5000000000\000' "${#z}"; }>"$d/e"||exit 90
 cmp -s "$d/e" "$o"||exit 12
 x=$(printf 'a\nb\000'|xargs -0 -r sh -c 'printf %s "$1"' codex-sentinel-list-xargs 2>/dev/null);s=$?
 printf x\000|xargs -0 -r sh -c 'exit 7' codex-sentinel-list-xargs >/dev/null 2>&1;q=$?
 [ "$s" -eq 0 ]&&[ "$q" -ne 0 ]&&[ "$x" = 'a
b' ]||exit 13
)
cs;s=$?
case $s in 0);;11)printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=search_bound\000' >&2;exit 0;;12)printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=find_nul\000' >&2;exit 0;;13)printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=xargs_nul\000' >&2;exit 0;;*)exit 2;;esac
if [ ! -e "$root" ] && [ ! -L "$root" ]; then printf 'NOT_FOUND\000' >&2; exit 0; fi
if [ ! -d "$root" ]; then printf 'NOT_DIRECTORY\000' >&2; exit 0; fi
if [ ! -r "$root" ]; then printf 'PERMISSION_DENIED\000' >&2; exit 0; fi
cd -- "$root" 2>/dev/null || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
umask 077
scratch=$(mktemp -d /tmp/codex-ssh-list.XXXXXX) || exit 2
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT HUP INT TERM
raw_fifo=$scratch/raw-fifo
out_fifo=$scratch/out-fifo
data=$scratch/data
find_status=$scratch/find-status
xargs_status=$scratch/xargs-status
count_file=$scratch/count
printf 0 >"$count_file"
mkfifo "$raw_fifo" "$out_fifo" || exit 2
(
if [ "$show_hidden" = 1 ];then
find -H . -mindepth 1 -maxdepth "$depth" -printf '%P\000%y\000%s\000%m\000%T@\000' 2>/dev/null
else
find -H . -mindepth 1 -maxdepth "$depth" \( -path './.*' -o -path '*/.*' \) -prune -o -printf '%P\000%y\000%s\000%m\000%T@\000' 2>/dev/null
fi >"$raw_fifo"
printf '%s' "$?" >"$find_status"
) &
find_pid=$!
(
xargs -0 -r -n 100 sh -c '
count_file=$1;max_entries=$2;shift 2
count=$(cat "$count_file")||exit 65
while [ "$#" -ge 5 ];do
if [ "$count" -lt $((max_entries+1)) ];then count=$((count+1));printf "%s\000%s\000%s\000%s\000%s\000" "$1" "$2" "$3" "$4" "$5";fi
shift 5
done
[ "$#" -eq 0 ]||exit 65
printf %s "$count">"$count_file"
' codex-ssh-list "$count_file" "$max_entries" <"$raw_fifo" >"$out_fifo" 2>/dev/null
printf '%s' "$?" >"$xargs_status"
) &
xargs_pid=$!
exec 3<"$out_fifo"
head -c "$limit" <&3 >"$data"
head_status=$?
cat <&3 >/dev/null
drain_status=$?
exec 3<&-
wait "$xargs_pid" 2>/dev/null
xargs_wait=$?
wait "$find_pid" 2>/dev/null
find_wait=$?
bytes=$(wc -c <"$data")
xargs_final=$(cat "$xargs_status" 2>/dev/null || printf 2)
find_final=$(cat "$find_status" 2>/dev/null || printf 2)
if [ "$head_status" -ne 0 ] || [ "$drain_status" -ne 0 ] ||
   [ "$xargs_wait" -ne 0 ] || [ "$find_wait" -ne 0 ] ||
   [ "$xargs_final" -ne 0 ] || [ "$find_final" -ne 0 ]; then exit 2; fi
cat "$data"
if [ "$bytes" -eq "$limit" ]; then printf 'CAPPED\000' >&2; fi
"#;

const STAT_SCRIPT: &str = r#"
codex_check_stat() (
    codex_stat_dir=$(mktemp -d /tmp/codex-sentinel-stat.XXXXXX 2>/dev/null) || exit 2
    cleanup_codex_stat() { rm -rf -- "$codex_stat_dir"; }
    trap cleanup_codex_stat EXIT HUP INT TERM
    codex_stat_file=$codex_stat_dir/file
    printf x >"$codex_stat_file" || exit 2
    chmod 640 "$codex_stat_file" || exit 2
    touch -d '@-1.123456789' -- "$codex_stat_file" || exit 2
    codex_stat_mode=$(stat --printf='%f' -- "$codex_stat_file" 2>/dev/null) || exit 1
    codex_stat_size=$(stat --printf='%s' -- "$codex_stat_file" 2>/dev/null) || exit 1
    codex_stat_seconds=$(stat --printf='%Y' -- "$codex_stat_file" 2>/dev/null) || exit 1
    codex_stat_human=$(stat --printf='%y' -- "$codex_stat_file" 2>/dev/null) || exit 1
    codex_stat_fraction=$(printf '%s' "$codex_stat_human" | cut -d. -f2 | cut -d' ' -f1)
    [ "$codex_stat_mode:$codex_stat_size:$codex_stat_seconds:$codex_stat_fraction" = \
      '81a0:1:-2:876543211' ]
)
codex_stat_status=0
codex_check_stat || codex_stat_status=$?
if [ "$codex_stat_status" -eq 1 ]; then
    printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=stat_printf\000' >&2
    exit 0
fi
if [ "$codex_stat_status" -ne 0 ]; then exit 2; fi
codex_xargs_newline='line
name'
codex_xargs_out=$(printf 'line\nname\000' |
    xargs -0 -r sh -c 'printf %s "$1"' codex-sentinel-stat-xargs 2>/dev/null)
codex_xargs_ok=$?
printf 'x\000' |
    xargs -0 -r sh -c 'exit 7' codex-sentinel-stat-xargs >/dev/null 2>&1
codex_xargs_failure=$?
if [ "$codex_xargs_ok" -ne 0 ] || [ "$codex_xargs_failure" -eq 0 ] ||
   [ "$codex_xargs_out" != "$codex_xargs_newline" ]; then
    printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=xargs_nul\000' >&2
    exit 0
fi
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
    bridge: &RemoteBridge,
    request: ResolvedList,
    cancel: CancellationToken,
) -> BridgeResult<ListResult> {
    let runner = &bridge.runner;
    let limits = runner.config().host(&request.host)?.limits;
    let owner = InternalSpoolOwner::new();
    let result = bridge
        .execute_readonly_fixed(
            FixedRunRequest {
                host: request.host.clone(),
                script: LIST_SCRIPT,
                args: vec![
                    request.path.absolute().to_owned(),
                    request.depth.to_string(),
                    if request.include_hidden { "1" } else { "0" }.to_owned(),
                    request.max_entries.to_string(),
                    (limits.max_frame_bytes + 1).to_string(),
                ],
                stdin: None,
                required_capabilities: &["find_nul", "xargs_nul", "search_bound"],
                stdout_limit: (limits.max_frame_bytes + 1) as u64,
                stderr_limit: 1024,
                timeout: Duration::from_millis(limits.command_timeout_ms),
                cleanup: owner.registration(),
            },
            cancel,
        )
        .await?;
    let stderr = read_small_stream(&result.output, StreamKind::Stderr, 1024).await?;
    let capped = stderr == b"CAPPED\0";
    if !stderr.is_empty() && !capped {
        return match stderr.as_slice() {
            b"NOT_FOUND\0" => Err(BridgeError::not_found()),
            b"PERMISSION_DENIED\0" => Err(BridgeError::permission_denied()),
            b"NOT_DIRECTORY\0" => Err(BridgeError::not_directory()),
            _ => Err(protocol_error("list control record is invalid")),
        };
    }
    let root = request.path.absolute().as_bytes();
    let mut cursor = SpoolCursor::new(
        &result.output,
        StreamKind::Stdout,
        limits.max_frame_bytes + 1,
    )?;
    let mut entries = Vec::with_capacity(request.max_entries.saturating_add(1));
    let mut qualifying = 0usize;
    let mut completed_records = 0usize;
    'records: loop {
        let first = if capped {
            cursor.next_field_capped(limits.max_frame_bytes).await?
        } else {
            cursor.next_field(limits.max_frame_bytes).await?
        };
        let Some(actual) = first else { break };
        let mut record = Vec::with_capacity(5);
        record.push(actual);
        for _ in 1..5 {
            let field = if capped {
                cursor.next_field_capped(limits.max_frame_bytes).await?
            } else {
                cursor.next_field(limits.max_frame_bytes).await?
            };
            let Some(field) = field else {
                if capped {
                    break 'records;
                }
                return Err(protocol_error("list field count is invalid"));
            };
            record.push(field);
        }
        let discovered = record[0].as_slice();
        if discovered.is_empty() || discovered.starts_with(b"/") {
            return Err(protocol_error("list relative path is invalid"));
        }
        let actual = join_raw(root, discovered);
        let relative = join_raw(request.path.relative().as_bytes(), discovered);
        completed_records += 1;
        if !request.include_hidden
            && relative
                .split(|byte| *byte == b'/')
                .any(|part| part.first() == Some(&b'.'))
        {
            return Err(protocol_error("list returned a hidden path after pruning"));
        }
        qualifying = qualifying
            .checked_add(1)
            .ok_or_else(|| protocol_error("list entry count overflowed"))?;
        let (mtime_seconds, mtime_nanoseconds) = parse_mtime(&record[4])?;
        if entries.len() < request.max_entries.saturating_add(1) {
            entries.push(ListEntry {
                actual_path: encode_bytes(&actual),
                relative_path: encode_bytes(&relative),
                metadata: RemoteMetadata {
                    kind: kind(&record[1])?,
                    size: parse_u64(&record[2])?,
                    mode: parse_mode(&record[3])?,
                    mtime_seconds,
                    mtime_nanoseconds,
                },
            });
        }
    }
    if capped && cursor.discarded_incomplete() && completed_records == 0 {
        return Err(protocol_error("list record is oversized"));
    }
    entries.sort_by(|left, right| {
        decoded_sort_key(&left.relative_path).cmp(&decoded_sort_key(&right.relative_path))
    });
    let truncated = capped || qualifying > request.max_entries;
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
    bridge: &RemoteBridge,
    request: ResolvedStat,
    cancel: CancellationToken,
) -> BridgeResult<StatResult> {
    let runner = &bridge.runner;
    let limits = runner.config().host(&request.host)?.limits;
    let mut stdin = Vec::new();
    for path in &request.paths {
        stdin.extend_from_slice(path.absolute().as_bytes());
        stdin.push(0);
    }
    let owner = InternalSpoolOwner::new();
    let result = bridge
        .execute_readonly_fixed(
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
    let stderr = read_small_stream(&result.output, StreamKind::Stderr, 1024).await?;
    if !stderr.is_empty() {
        return Err(protocol_error("stat control record is invalid"));
    }
    let mut cursor = SpoolCursor::new(&result.output, StreamKind::Stdout, limits.max_frame_bytes)?;
    let mut entries = Vec::with_capacity(request.paths.len());
    for requested in &request.paths {
        let actual = cursor
            .next_field(limits.max_frame_bytes)
            .await?
            .ok_or_else(|| protocol_error("stat response is incomplete"))?;
        let status = cursor
            .next_field(64)
            .await?
            .ok_or_else(|| protocol_error("stat response is incomplete"))?;
        if actual != requested.absolute().as_bytes() {
            return Err(protocol_error("stat response order is invalid"));
        }
        let actual_path = encode_bytes(&actual);
        let relative_path = encode_bytes(requested.relative().as_bytes());
        if status == b"OK" {
            let mode = cursor
                .next_field(64)
                .await?
                .ok_or_else(|| protocol_error("stat response is incomplete"))?;
            let size = cursor
                .next_field(64)
                .await?
                .ok_or_else(|| protocol_error("stat response is incomplete"))?;
            let mtime = cursor
                .next_field(128)
                .await?
                .ok_or_else(|| protocol_error("stat response is incomplete"))?;
            let raw_mode = u32::from_str_radix(utf8(&mode)?, 16)
                .map_err(|_| protocol_error("stat mode is invalid"))?;
            let (mtime_seconds, mtime_nanoseconds) = parse_mtime(&mtime)?;
            entries.push(StatEntry::Success {
                actual_path,
                relative_path,
                metadata: RemoteMetadata {
                    kind: kind_from_mode(raw_mode),
                    size: parse_u64(&size)?,
                    mode: raw_mode & 0o7777,
                    mtime_seconds,
                    mtime_nanoseconds,
                },
            });
        } else {
            entries.push(StatEntry::Error {
                actual_path,
                relative_path,
                error: entry_error(&status)?,
            });
        }
    }
    if cursor.next_field(limits.max_frame_bytes).await?.is_some() {
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

fn join_raw(base: &[u8], relative: &[u8]) -> Vec<u8> {
    let needs_separator = !base.is_empty() && !base.ends_with(b"/");
    let mut joined = Vec::with_capacity(base.len() + usize::from(needs_separator) + relative.len());
    joined.extend_from_slice(base);
    if needs_separator {
        joined.push(b'/');
    }
    joined.extend_from_slice(relative);
    joined
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
