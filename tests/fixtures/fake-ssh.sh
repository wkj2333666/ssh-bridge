#!/bin/sh
set -eu

is_config=0
for argument do
    if [ "$argument" = -G ]; then
        is_config=1
    fi
done

run_fake_sleep() {
    fake_sleep_seconds=$1
    if [ "${FAKE_SSH_IGNORE_TERM:-0}" = 1 ]; then
        trap '' TERM
    fi
    sleep "$fake_sleep_seconds" &
    fake_sleep_pid=$!
    if [ -n "${FAKE_SSH_CHILD_PID_FILE:-}" ]; then
        printf '%s\n' "$fake_sleep_pid" >"$FAKE_SSH_CHILD_PID_FILE"
    fi
    wait "$fake_sleep_pid"
}

log_call() {
    if [ -n "${FAKE_SSH_LOG:-}" ]; then
        {
            printf '%s\n' "$1"
            shift
            for logged_argument do
                printf 'arg=%s\n' "$logged_argument"
            done
            printf '%s\n' END
        } >>"$FAKE_SSH_LOG"
    fi
}

emit_bytes() {
    byte_count=$1
    target=$2
    blocks=$((byte_count / 65536))
    remainder=$((byte_count % 65536))
    if [ "$blocks" -gt 0 ]; then
        if [ "$target" = stdout ]; then
            dd if=/dev/zero bs=65536 count="$blocks" 2>/dev/null
        else
            dd if=/dev/zero bs=65536 count="$blocks" >&2 2>/dev/null
        fi
    fi
    if [ "$remainder" -gt 0 ]; then
        if [ "$target" = stdout ]; then
            dd if=/dev/zero bs=1 count="$remainder" 2>/dev/null
        else
            dd if=/dev/zero bs=1 count="$remainder" >&2 2>/dev/null
        fi
    fi
}

emit_fake_error() {
    case "$1" in
        host-key)
            printf '%s\n' 'Host key verification failed.' 'VERY_SECRET_HOST_DIAGNOSTIC' >&2
            ;;
        host-key-ed25519)
            printf '%s\n' 'No ED25519 host key is known for fake.internal and you have requested strict checking.' >&2
            ;;
        host-key-rsa)
            printf '%s\n' 'No RSA host key is known for fake.internal and you have requested strict checking.' >&2
            ;;
        host-key-ecdsa)
            printf '%s\n' 'No ECDSA host key is known for fake.internal and you have requested strict checking.' >&2
            ;;
        auth)
            printf '%s\n' 'fixture@fake.internal: Permission denied (publickey).' 'VERY_SECRET_AUTH_DIAGNOSTIC' >&2
            ;;
        connect-timeout)
            printf '%s\n' 'ssh: connect to host fake.internal port 22: Connection timed out' 'VERY_SECRET_CONNECT_DIAGNOSTIC' >&2
            ;;
        diagnostic)
            printf '%s\n' "${FAKE_SSH_DIAGNOSTIC:-}" >&2
            ;;
        remote)
            printf '%s\n' 'VERY_SECRET_REMOTE_DIAGNOSTIC' >&2
            exit "${FAKE_SSH_EXIT_STATUS:-7}"
            ;;
    esac
    exit "${FAKE_SSH_ERROR_STATUS:-255}"
}

if [ "$is_config" = 1 ]; then
    log_call G "$@"
    if [ -n "${FAKE_SSH_G_ERROR:-}" ]; then
        emit_fake_error "$FAKE_SSH_G_ERROR"
    fi
    if [ -n "${FAKE_SSH_G_SLEEP_SECONDS:-}" ]; then
        run_fake_sleep "$FAKE_SSH_G_SLEEP_SECONDS"
    fi
    if [ -n "${FAKE_SSH_G_STDOUT_BYTES:-}" ]; then
        emit_bytes "$FAKE_SSH_G_STDOUT_BYTES" stdout
    else
        if [ "${FAKE_SSH_G_NON_UTF8:-0}" = 1 ]; then
            printf '\377'
        fi
        printf 'hostname fake.internal\nuser fixture\nport 22\n'
    fi
    if [ -n "${FAKE_SSH_G_STDERR_BYTES:-}" ]; then
        emit_bytes "$FAKE_SSH_G_STDERR_BYTES" stderr
    fi
    exit 0
fi

remote_command=
for argument do
    remote_command=$argument
done

case "$remote_command" in
	*CODEX_SSH_PROBE*)
		log_call P "$@"
		if [ "${FAKE_SSH_MODE:-echo-argv}" = local-fixed ]; then
			exec /bin/sh -c "$remote_command"
		fi
		if [ -n "${FAKE_SSH_PROBE_ERROR:-}" ]; then
            emit_fake_error "$FAKE_SSH_PROBE_ERROR"
        fi
        if [ -n "${FAKE_SSH_PROBE_SLEEP_SECONDS:-}" ]; then
            run_fake_sleep "$FAKE_SSH_PROBE_SLEEP_SECONDS"
        fi
        fake_root=${FAKE_SSH_ROOT:-/srv/project}
        fake_shell=${FAKE_SSH_SHELL:-sh}
        fake_timeout=${FAKE_SSH_HAS_TIMEOUT:-0}
        if [ "$fake_shell" = bash ]; then
            bash_version=5.2.15
        else
            bash_version=
        fi
        printf 'CODEX_SSH_PROBE=1\0'
        printf 'REQUESTED_ROOT=%s\0' "$fake_root"
        printf 'ROOT=%s\0' "$fake_root"
        printf 'SHELL_KIND=%s\0' "$fake_shell"
        printf 'BASH_VERSION=%s\0' "$bash_version"
        printf 'TOOL_mktemp=1\0'
        printf 'TOOL_dd_nofollow=1\0'
        printf 'TOOL_sha256sum=1\0'
        printf 'TOOL_stat=1\0'
        printf 'TOOL_find=1\0'
        printf 'TOOL_grep=1\0'
        printf 'TOOL_rg=1\0'
        printf 'TOOL_timeout=%s\0' "$fake_timeout"
        printf 'TOOL_ln=1\0'
        printf 'TOOL_mv=1\0'
        printf 'TOOL_read_slice=%s\0' "${FAKE_SSH_HAS_READ_SLICE:-1}"
        printf 'TOOL_find_nul=%s\0' "${FAKE_SSH_HAS_FIND_NUL:-1}"
        printf 'TOOL_stat_printf=%s\0' "${FAKE_SSH_HAS_STAT_PRINTF:-1}"
        printf 'TOOL_rg_json=%s\0' "${FAKE_SSH_HAS_RG_JSON:-1}"
        printf 'TOOL_grep_nul=%s\0' "${FAKE_SSH_HAS_GREP_NUL:-1}"
        printf 'TOOL_xargs_nul=%s\0' "${FAKE_SSH_HAS_XARGS_NUL:-1}"
        printf 'TOOL_search_bound=%s\0' "${FAKE_SSH_HAS_SEARCH_BOUND:-1}"
        printf 'TOOL_safe_write=%s\0' "${FAKE_SSH_HAS_SAFE_WRITE:-1}"
        printf 'TOOL_guarded_delete=%s\0' "${FAKE_SSH_HAS_GUARDED_DELETE:-1}"
        exit 0
        ;;
esac

log_call C "$@"

if [ -n "${FAKE_SSH_MISMATCH_FILE:-}" ] && [ ! -e "$FAKE_SSH_MISMATCH_FILE" ]; then
    : >"$FAKE_SSH_MISMATCH_FILE"
    printf 'CODE=CAPABILITY_MISMATCH\0CAPABILITY=%s\0' "${FAKE_SSH_MISMATCH_KEY:-find_nul}" >&2
    exit 0
fi

if [ -n "${FAKE_SSH_FIXED_SLEEP_SECONDS:-}" ]; then
    if [ -n "${FAKE_SSH_FIXED_STDOUT_BYTES:-}" ]; then
        emit_bytes "$FAKE_SSH_FIXED_STDOUT_BYTES" stdout
    fi
    run_fake_sleep "$FAKE_SSH_FIXED_SLEEP_SECONDS"
fi

case "${FAKE_SSH_MODE:-echo-argv}" in
    local-fixed)
        if [ -n "${FAKE_SSH_LOCAL_FIXED_PATH_ONCE:-}" ] &&
           [ -n "${FAKE_SSH_LOCAL_FIXED_PATH_MARKER:-}" ] &&
           [ ! -e "$FAKE_SSH_LOCAL_FIXED_PATH_MARKER" ]; then
            : >"$FAKE_SSH_LOCAL_FIXED_PATH_MARKER"
            PATH=$FAKE_SSH_LOCAL_FIXED_PATH_ONCE
            export PATH
        fi
        case "${FAKE_SSH_LOCAL_FIXED_POST:-}" in
            disconnect)
                if /bin/sh -c "$remote_command" >/dev/null; then
                    exit 255
                else
                    exit $?
                fi
                ;;
            malformed)
                if /bin/sh -c "$remote_command" >/dev/null; then
                    printf GARBAGE
                    exit 0
                else
                    exit $?
                fi
                ;;
            trailing)
                if /bin/sh -c "$remote_command"; then
                    printf GARBAGE
                    exit 0
                else
                    exit $?
                fi
                ;;
            stderr)
                if /bin/sh -c "$remote_command"; then
                    printf POST_COMMIT_DIAGNOSTIC >&2
                    exit 0
                else
                    exit $?
                fi
                ;;
        esac
        exec /bin/sh -c "$remote_command"
        ;;
    echo-argv)
        for argument do
            printf '%s\0' "$argument"
        done
        ;;
    echo-command)
        printf '%s' "$remote_command"
        ;;
    streams)
        printf '%s' "${FAKE_SSH_STDOUT:-stdout}"
        printf '%s' "${FAKE_SSH_STDERR:-stderr}" >&2
        ;;
    stdin)
        cat
        ;;
	bytes)
        (emit_bytes "${FAKE_SSH_STDOUT_BYTES:-0}" stdout) &
        stdout_pid=$!
        (emit_bytes "${FAKE_SSH_STDERR_BYTES:-0}" stderr) &
        stderr_pid=$!
        wait "$stdout_pid"
		wait "$stderr_pid"
		;;
	large-candidates)
		fake_root=${FAKE_SSH_ROOT:-/srv/project}
		record_bytes=838
		leaf_bytes=$((record_bytes - ${#fake_root} - 2))
		if [ "$leaf_bytes" -le 0 ]; then exit 2; fi
		leaf=$(dd if=/dev/zero bs=1 count="$leaf_bytes" 2>/dev/null | tr '\000' x)
		awk -v root="$fake_root" -v leaf="$leaf" 'BEGIN {
			for (i = 0; i < 10000; i++) printf "%s/%s%c", root, leaf, 0
		}'
		lookahead_leaf_bytes=$((8608 - ${#fake_root} - 2))
		lookahead_leaf=$(dd if=/dev/zero bs=1 count="$lookahead_leaf_bytes" 2>/dev/null | tr '\000' y)
		printf '%s/%s\000' "$fake_root" "$lookahead_leaf"
		if [ -n "${FAKE_SSH_FIXED_SLEEP_SECONDS:-}" ]; then
			run_fake_sleep "$FAKE_SSH_FIXED_SLEEP_SECONDS"
		fi
		;;
	sleep)
        run_fake_sleep "${FAKE_SSH_SLEEP_SECONDS:-1}"
        ;;
    orphan-streams)
        (
            trap '' TERM HUP
            sleep "${FAKE_SSH_SLEEP_SECONDS:-10}"
        ) &
        orphan_pid=$!
        if [ -n "${FAKE_SSH_CHILD_PID_FILE:-}" ]; then
            printf '%s\n' "$orphan_pid" >"$FAKE_SSH_CHILD_PID_FILE"
        fi
        if [ -n "${FAKE_SSH_PARENT_EXIT_FILE:-}" ]; then
            printf '%s\n' exited >"$FAKE_SSH_PARENT_EXIT_FILE"
        fi
        exit 0
        ;;
    orphan-stdin)
        exec 3<&0
        (
            trap '' TERM HUP
            exec 0<&3 3<&-
            exec >/dev/null 2>/dev/null
            if [ -n "${FAKE_SSH_CHILD_READY_FILE:-}" ]; then
                printf '%s\n' ready >"$FAKE_SSH_CHILD_READY_FILE"
            fi
            sleep "${FAKE_SSH_SLEEP_SECONDS:-10}"
        ) &
        orphan_pid=$!
        exec 3<&-
        if [ -n "${FAKE_SSH_CHILD_PID_FILE:-}" ]; then
            printf '%s\n' "$orphan_pid" >"$FAKE_SSH_CHILD_PID_FILE"
        fi
        if [ -n "${FAKE_SSH_CHILD_READY_FILE:-}" ]; then
            while [ ! -f "$FAKE_SSH_CHILD_READY_FILE" ]; do
                sleep 0.005
            done
        fi
        if [ -n "${FAKE_SSH_PARENT_EXIT_FILE:-}" ]; then
            printf '%s\n' exited >"$FAKE_SSH_PARENT_EXIT_FILE"
        fi
        exit 0
        ;;
    error)
        emit_fake_error "${FAKE_SSH_ERROR:-remote}"
        ;;
    *)
        printf '%s\n' 'unknown fake SSH mode' >&2
        exit 2
        ;;
esac
