#!/bin/sh
set -u
umask 077
PROTOCOL_TAG=${1-}
[ "$PROTOCOL_TAG" = codex-ssh-dispatcher-1 ] || exit 64
MAX_FRAME_BYTES=8388608
STREAM_CHUNK_BYTES=262144
BASE_ROOT=${TMPDIR:-/tmp}
BASE=$BASE_ROOT/codex-ssh-bridge-dispatcher.$$
base_suffix=0
while ! mkdir "$BASE" 2>/dev/null; do
    base_suffix=$((base_suffix + 1))
    [ "$base_suffix" -le 100 ] || exit 73
    BASE=$BASE_ROOT/codex-ssh-bridge-dispatcher.$$.$base_suffix
done
OUTPUT_LOCK=$BASE/output.lock

cleanup_request() {
    request_dir=$1
    if [ -f "$request_dir/pid" ]; then
        request_pid=$(cat "$request_dir/pid" 2>/dev/null || true)
        case "$request_pid" in
            ''|*[!0-9]*) ;;
            *) kill -TERM -"$request_pid" 2>/dev/null || true ;;
        esac
    fi
    rm -rf "$request_dir"
}
cleanup() {
    for request_dir in "$BASE"/[0-9]*; do
        [ -d "$request_dir" ] || continue
        cleanup_request "$request_dir"
    done
    rm -rf "$BASE"
}
trap cleanup EXIT HUP INT TERM

has_command() { command -v "$1" >/dev/null 2>&1; }

send_file() {
    send_kind=$1
    send_id=$2
    send_path=$3
    send_length=$(wc -c <"$send_path" | tr -d '[:space:]')
    case "$send_length" in ''|*[!0-9]*) exit 74 ;; esac
    [ "$send_length" -le "$MAX_FRAME_BYTES" ] || exit 75
    while ! mkdir "$OUTPUT_LOCK" 2>/dev/null; do sleep 0; done
    printf 'CXSB1 %s %s %s\n' "$send_kind" "$send_id" "$send_length"
    if [ "$send_length" -gt 0 ]; then cat "$send_path"; fi
    rmdir "$OUTPUT_LOCK" 2>/dev/null || true
}
send_text() {
    send_kind=$1
    send_id=$2
    send_value=$3
    send_path=$BASE/text.$send_kind.$send_id
    printf '%s' "$send_value" >"$send_path"
    send_file "$send_kind" "$send_id" "$send_path"
    rm -f "$send_path"
}

copy_capped() {
    input_path=$1
    output_path=$2
    marker_path=$3
    limit=$4
    full_path=$output_path.full
    remainder_path=$output_path.remainder
    extra_path=$output_path.extra
    : >"$full_path"
    : >"$remainder_path"
    : >"$extra_path"
    : >"$marker_path"
    exec 3<"$input_path" || return 74
    full_blocks=$((limit / 65536))
    remainder_bytes=$((limit % 65536))
    if [ "$full_blocks" -gt 0 ]; then
        dd of="$full_path" bs=65536 count="$full_blocks" <&3 2>/dev/null || true
    fi
    if [ "$remainder_bytes" -gt 0 ]; then
        dd of="$remainder_path" bs=1 count="$remainder_bytes" <&3 2>/dev/null || true
    fi
    dd of="$extra_path" bs=1 count=1 <&3 2>/dev/null || true
    if [ "$(wc -c <"$extra_path" | tr -d '[:space:]')" -gt 0 ]; then : >"$marker_path"; fi
    cat <&3 >/dev/null 2>&1 || true
    exec 3<&-
    cat "$full_path" "$remainder_path" >"$output_path"
    rm -f "$full_path" "$remainder_path" "$extra_path"
}
send_stream() {
    stream_kind=$1
    stream_id=$2
    stream_path=$3
    stream_dir=$4
    stream_block=0
    while :; do
        stream_chunk=$stream_dir/chunk.$stream_block
        dd if="$stream_path" of="$stream_chunk" bs=65536 skip="$stream_block" count=4 2>/dev/null || true
        stream_length=$(wc -c <"$stream_chunk" | tr -d '[:space:]')
        [ "$stream_length" -gt 0 ] || { rm -f "$stream_chunk"; break; }
        send_file "$stream_kind" "$stream_id" "$stream_chunk"
        rm -f "$stream_chunk"
        stream_block=$((stream_block + 4))
        [ "$stream_length" -lt "$STREAM_CHUNK_BYTES" ] && break
    done
}

run_request() {
    run_id=$1
    run_shell=$2
    run_cwd_file=$3
    run_command_file=$4
    run_stdin_file=$5
    run_login_shell=$6
    run_timeout_ms=$7
    run_stdout_limit=$8
    run_stderr_limit=$9
    run_dir=$BASE/$run_id
    run_stdout_fifo=$run_dir/stdout.fifo
    run_stderr_fifo=$run_dir/stderr.fifo
    run_stdout=$run_dir/stdout
    run_stderr=$run_dir/stderr
    run_stdout_marker=$run_dir/stdout.truncated
    run_stderr_marker=$run_dir/stderr.truncated
    run_cwd=$(cat "$run_cwd_file"; printf .) || exit 74
    run_cwd=${run_cwd%.}
    run_command=$(cat "$run_command_file"; printf .) || exit 74
    run_command=${run_command%.}
    mkfifo "$run_stdout_fifo" "$run_stderr_fifo" || exit 74
    copy_capped "$run_stdout_fifo" "$run_stdout" "$run_stdout_marker" "$run_stdout_limit" &
    run_stdout_collector=$!
    copy_capped "$run_stderr_fifo" "$run_stderr" "$run_stderr_marker" "$run_stderr_limit" &
    run_stderr_collector=$!
    setsid sh -c '
        run_cwd=$1
        run_shell=$2
        run_command=$3
        CDPATH= cd -P -- "$run_cwd" || exit 126
        case "$run_shell" in
            bash) exec bash --noprofile --norc -c "$run_command" ;;
            sh) exec sh -c "$run_command" ;;
            login) exec "$run_login_shell" -c "$run_command" ;;
            *) exit 126 ;;
        esac
    ' codex-ssh-dispatcher "$run_cwd" "$run_shell" "$run_command" \
        <"$run_stdin_file" >"$run_stdout_fifo" 2>"$run_stderr_fifo" &
    run_pid=$!
    printf '%s\n' "$run_pid" >"$run_dir/pid"
    send_text READY "$run_id" started
    run_watchdog=
    case "$run_timeout_ms" in ''|*[!0-9]*) run_timeout_ms=0 ;; esac
    if [ "$run_timeout_ms" -gt 0 ]; then
        run_timeout_seconds=$(( (run_timeout_ms + 999) / 1000 ))
        ( sleep "$run_timeout_seconds"; if kill -0 "$run_pid" 2>/dev/null; then
            kill -TERM -"$run_pid" 2>/dev/null || true
            sleep 1
            kill -KILL -"$run_pid" 2>/dev/null || true
        fi ) &
        run_watchdog=$!
    fi
    if wait "$run_pid"; then run_status=$?; else run_status=$?; fi
    if [ -n "$run_watchdog" ]; then kill "$run_watchdog" 2>/dev/null || true; fi
    wait "$run_stdout_collector" 2>/dev/null || true
    wait "$run_stderr_collector" 2>/dev/null || true
    send_stream STDOUT "$run_id" "$run_stdout" "$run_dir"
    send_stream STDERR "$run_id" "$run_stderr" "$run_dir"
    run_stdout_truncated=0
    run_stderr_truncated=0
    [ -s "$run_stdout_marker" ] && run_stdout_truncated=1
    [ -s "$run_stderr_marker" ] && run_stderr_truncated=1
    run_exit_file=$run_dir/exit
    printf '%s\n%s\n%s\n' "$run_status" "$run_stdout_truncated" "$run_stderr_truncated" >"$run_exit_file"
    send_file EXIT "$run_id" "$run_exit_file"
    rm -rf "$run_dir"
}

read_frame() {
    frame_magic=
    frame_kind=
    frame_id=
    frame_length=
    frame_extra=
    IFS=' ' read -r frame_magic frame_kind frame_id frame_length frame_extra || return 1
    [ "$frame_magic" = CXSB1 ] || return 1
    [ -n "$frame_kind" ] && [ -n "$frame_id" ] && [ -n "$frame_length" ] || return 1
    [ -z "$frame_extra" ] || return 1
    case "$frame_id" in ''|*[!0-9]*) return 1 ;; esac
    case "$frame_length" in ''|*[!0-9]*) return 1 ;; esac
    [ "$frame_length" -le "$MAX_FRAME_BYTES" ] || return 1
    frame_path=$BASE/input.$frame_id
    : >"$frame_path"
    if [ "$frame_length" -gt 0 ]; then
        dd of="$frame_path" bs="$frame_length" count=1 2>/dev/null || return 1
    fi
    return 0
}
expect_data() {
    expected_id=$1
    expected_length=$2
    expected_path=$3
    if [ "$expected_length" -eq 0 ]; then : >"$expected_path"; return 0; fi
    read_frame || return 1
    [ "$frame_kind" = DATA ] || return 1
    [ "$frame_id" = "$expected_id" ] || return 1
    [ "$frame_length" -eq "$expected_length" ] || return 1
    mv "$frame_path" "$expected_path"
}
handle_open() {
    open_id=$1
    open_meta=$2
    open_dir=$BASE/$open_id
    [ "$open_id" -gt 0 ] || return 1
    if [ -e "$open_dir" ]; then send_text ERROR "$open_id" duplicate-request-id; return 0; fi
    mkdir "$open_dir" || return 1
    open_shell=
    open_cwd_length=
    open_command_length=
    open_stdin_length=
    open_login_shell=
    open_timeout_ms=0
    open_stdout_limit=0
    open_stderr_limit=0
    while IFS='=' read -r open_key open_value; do
        case "$open_key" in
            shell) open_shell=$open_value ;;
            cwd_length) open_cwd_length=$open_value ;;
            command_length) open_command_length=$open_value ;;
            stdin_length) open_stdin_length=$open_value ;;
            login_shell) open_login_shell=$open_value ;;
            timeout_ms) open_timeout_ms=$open_value ;;
            stdout_limit) open_stdout_limit=$open_value ;;
            stderr_limit) open_stderr_limit=$open_value ;;
            '') ;;
            *) send_text ERROR "$open_id" invalid-open-metadata; rm -rf "$open_dir"; return 0 ;;
        esac
    done <"$open_meta"
    case "$open_shell" in
        bash|sh) [ -z "$open_login_shell" ] || { send_text ERROR "$open_id" invalid-open-metadata; rm -rf "$open_dir"; return 0; } ;;
        login)
            case "$open_login_shell" in
                /*) [ -f "$open_login_shell" ] && [ -x "$open_login_shell" ] || { send_text ERROR "$open_id" login-shell-unavailable; rm -rf "$open_dir"; return 0; } ;;
                *) send_text ERROR "$open_id" invalid-login-shell; rm -rf "$open_dir"; return 0 ;;
            esac
            ;;
        *) send_text ERROR "$open_id" unsupported-shell; rm -rf "$open_dir"; return 0 ;;
    esac
    for open_number in "$open_cwd_length" "$open_command_length" "$open_stdin_length" "$open_timeout_ms" "$open_stdout_limit" "$open_stderr_limit"; do
        case "$open_number" in ''|*[!0-9]*) send_text ERROR "$open_id" invalid-open-number; rm -rf "$open_dir"; return 0 ;; esac
    done
    cwd_file=$open_dir/cwd
    command_file=$open_dir/command
    stdin_file=$open_dir/stdin
    expect_data "$open_id" "$open_cwd_length" "$cwd_file" || { rm -rf "$open_dir"; return 1; }
    expect_data "$open_id" "$open_command_length" "$command_file" || { rm -rf "$open_dir"; return 1; }
    expect_data "$open_id" "$open_stdin_length" "$stdin_file" || { rm -rf "$open_dir"; return 1; }
    run_request "$open_id" "$open_shell" "$cwd_file" "$command_file" "$stdin_file" \
        "$open_login_shell" "$open_timeout_ms" "$open_stdout_limit" "$open_stderr_limit" &
}
missing_command=
for required_command in dd mkdir cat wc mkfifo setsid sleep kill mv rm rmdir tr; do
    if ! has_command "$required_command"; then missing_command=$required_command; break; fi
done
if [ -n "$missing_command" ]; then
    missing_file=$BASE/missing
    printf 'DISPATCHER_CAPABILITY_MISSING=%s\n' "$missing_command" >"$missing_file"
    send_file ERROR 0 "$missing_file"
    exit 78
fi
send_text HELLO_ACK 0 'protocol=codex-ssh-dispatcher/1;shell=sh;'
while read_frame; do
    case "$frame_kind" in
        HELLO) send_text HELLO_ACK "$frame_id" 'protocol=codex-ssh-dispatcher/1;shell=sh;' ;;
        OPEN) handle_open "$frame_id" "$frame_path" || exit 74; rm -f "$frame_path" ;;
        CANCEL)
            cancel_dir=$BASE/$frame_id
            if [ -f "$cancel_dir/pid" ]; then
                cancel_pid=$(cat "$cancel_dir/pid" 2>/dev/null || true)
                case "$cancel_pid" in ''|*[!0-9]*) ;; *) kill -TERM -"$cancel_pid" 2>/dev/null || true ;; esac
            fi
            rm -f "$frame_path"
            ;;
        CLOSE) rm -f "$frame_path"; exit 0 ;;
        *) send_text ERROR "$frame_id" unexpected-frame; rm -f "$frame_path" ;;
    esac
done
exit 0
