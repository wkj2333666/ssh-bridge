#![allow(
    clippy::result_large_err,
    reason = "Task 1 fixes BridgeResult<T> to an inline BridgeError representation"
)]

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::Arc;

use tokio::sync::{Mutex, OnceCell, watch};

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::path::RemotePath;

const TOOL_NAMES: &[&str] = &[
    "mktemp",
    "dd_nofollow",
    "sha256sum",
    "stat",
    "find",
    "grep",
    "rg",
    "timeout",
    "ln",
    "mv",
    "read_slice",
    "find_nul",
    "stat_printf",
    "rg_json",
    "grep_nul",
    "xargs_nul",
    "search_bound",
];

pub const CAPABILITY_PROBE_SCRIPT: &str = r#"
set -u

requested_root=$1
cd -- "$requested_root" || exit 1
physical_plus=$(pwd -P && printf x) || exit 1
physical_with_delimiter=${physical_plus%x}
newline='
'
physical_root=${physical_with_delimiter%"$newline"}

emit_record() {
    printf '%s=%s\000' "$1" "$2"
}

has_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        printf 1
    else
        printf 0
    fi
}

has_gnu_timeout() {
    if timeout --signal=TERM --kill-after=1s 1.000s sh -c 'exit 0' >/dev/null 2>&1; then
        printf 1
    else
        printf 0
    fi
}

shell_kind=sh
bash_version=
if command -v bash >/dev/null 2>&1; then
    candidate=$(bash --noprofile --norc -c 'printf %s "$BASH_VERSION"') || candidate=
    if [ -n "$candidate" ]; then
        shell_kind=bash
        bash_version=$candidate
    fi
fi

tool_mktemp=$(has_tool mktemp)
tool_dd_nofollow=0
probe_tmp=
cleanup_probe_tmp() {
    if [ -n "$probe_tmp" ]; then
        rm -rf -- "$probe_tmp"
        probe_tmp=
    fi
}
trap cleanup_probe_tmp EXIT HUP INT TERM

if [ "$tool_mktemp" = 1 ]; then
    probe_tmp=$(mktemp -d "${TMPDIR:-/tmp}/codex-ssh-bridge.XXXXXX") || {
        tool_mktemp=0
        probe_tmp=
    }
fi
if [ -n "$probe_tmp" ] && command -v dd >/dev/null 2>&1; then
    if dd if=/dev/null of="$probe_tmp/dd-output" oflag=nofollow >/dev/null 2>&1; then
        tool_dd_nofollow=1
    fi
fi

tool_read_slice=0
tool_find_nul=0
tool_stat_printf=0
tool_rg_json=0
tool_grep_nul=0
tool_xargs_nul=0
tool_search_bound=0
if [ -n "$probe_tmp" ]; then
    read_file=$probe_tmp/codex-probe-read
    read_tail=$probe_tmp/read-tail
    read_lines=$probe_tmp/read-lines
    read_bytes=$probe_tmp/read-bytes
    read_last=$probe_tmp/read-last
    read_expected=$probe_tmp/read-expected
    printf 'a\000b\nc' >"$read_file"
    printf 'a\000b\n' >"$read_expected"
    if tail -n +1 -- "$read_file" >"$read_tail" 2>/dev/null &&
       head -n 1 "$read_tail" >"$read_lines" 2>/dev/null &&
       head -c 4 "$read_lines" >"$read_bytes" 2>/dev/null &&
       tail -c 1 -- "$read_file" >"$read_last" 2>/dev/null &&
       read_count=$(wc -l <"$read_file") &&
       cmp -s "$read_expected" "$read_bytes" &&
       [ "$(cat "$read_last")" = c ] && [ "$read_count" -eq 1 ]; then
        tool_read_slice=1
    fi

    find_actual=$probe_tmp/codex-probe-find
    find_link=$probe_tmp/codex-probe-find-link
    find_out=$probe_tmp/find-output
    mkdir -p "$find_actual/visible/nested" "$find_actual/.hidden" "$probe_tmp/find-outside"
    newline_name='line
name'
    : >"$find_actual/$newline_name"
    : >"$find_actual/visible/leaf"
    : >"$find_actual/visible/nested/too-deep"
    : >"$find_actual/.hidden/secret"
    : >"$probe_tmp/find-outside/not-followed"
    ln -s "$probe_tmp/find-outside" "$find_actual/descendant-link"
    ln -s "$find_actual" "$find_link"
    if (cd -- "$probe_tmp" &&
        find -H codex-probe-find-link -mindepth 1 -maxdepth 2 \
        \( -path '*/.*' -prune -o -printf '%P\000%y\000%s\000%m\000%T@\000' \)) \
        >"$find_out" 2>/dev/null; then
        find_fields=$(tr -cd '\000' <"$find_out" | wc -c)
        if [ "$find_fields" -eq 25 ]; then tool_find_nul=1; fi
    fi

    stat_file=$probe_tmp/codex-probe-stat
    printf x >"$stat_file"
    if touch -d '@-1.123456789' -- "$stat_file" 2>/dev/null; then
        stat_mode=$(stat --printf='%f' -- "$stat_file" 2>/dev/null) || stat_mode=
        stat_size=$(stat --printf='%s' -- "$stat_file" 2>/dev/null) || stat_size=
        stat_seconds=$(stat --printf='%Y' -- "$stat_file" 2>/dev/null) || stat_seconds=
        stat_human=$(stat --printf='%y' -- "$stat_file" 2>/dev/null) || stat_human=
        stat_fraction=$(printf '%s' "$stat_human" | cut -d. -f2 | cut -d' ' -f1)
        case "$stat_mode:$stat_size:$stat_seconds:$stat_fraction" in
            [0-9a-f]*:1:-2:876543211) tool_stat_printf=1 ;;
        esac
    fi

    rg_file=$probe_tmp/codex-probe-rg
    printf 'before\000needle\n' >"$rg_file"
    if command -v rg >/dev/null 2>&1; then
        rg_json=$(rg --json --fixed-strings --hidden --no-ignore --text -- needle "$rg_file" 2>/dev/null)
        rg_status=$?
        rg --json --fixed-strings --hidden --no-ignore -- absent "$rg_file" >/dev/null 2>&1
        rg_empty_status=$?
        case "$rg_json" in
            *'"type":"begin"'*'"type":"match"'*'"type":"end"'*'"type":"summary"'*)
                if [ "$rg_status" -eq 0 ] && [ "$rg_empty_status" -eq 1 ]; then tool_rg_json=1; fi
                ;;
        esac
    fi

    grep_file=$probe_tmp/codex-probe-grep
    grep_binary=$probe_tmp/grep-binary
    grep_out=$probe_tmp/grep-output
    grep_expected=$probe_tmp/grep-expected
    printf 'needle\n' >"$grep_file"
    printf 'before\000needle\n' >"$grep_binary"
    if grep -IHnZ -F -- needle "$grep_file" "$grep_binary" >"$grep_out" 2>/dev/null; then
        { printf '%s\000' "$grep_file"; printf '1:needle\n'; } >"$grep_expected"
        if cmp -s "$grep_expected" "$grep_out"; then tool_grep_nul=1; fi
    fi

    xargs_out=$probe_tmp/xargs-output
    printf 'line\nname\000' |
        xargs -0 -r sh -c 'printf %s "$1"' codex-ssh-probe-xargs >"$xargs_out" 2>/dev/null
    xargs_ok=$?
    printf 'x\000' |
        xargs -0 -r sh -c 'exit 7' codex-ssh-probe-xargs >/dev/null 2>&1
    xargs_failure=$?
    if [ "$xargs_ok" -eq 0 ] && [ "$xargs_failure" -ne 0 ] &&
       [ "$(cat "$xargs_out")" = "$newline_name" ]; then
        tool_xargs_nul=1
    fi

    if command -v mkfifo >/dev/null 2>&1; then
        bound_fifo=$probe_tmp/bound-fifo
        bound_status=$probe_tmp/bound-status
        bound_out=$probe_tmp/codex-probe-bound
        mkfifo "$bound_fifo"
        (
            printf abcdef >"$bound_fifo"
            printf '%s' "$?" >"$bound_status"
        ) &
        bound_pid=$!
        exec 3<"$bound_fifo"
        head -c 3 <&3 >"$bound_out" 2>/dev/null
        bound_head_status=$?
        cat <&3 >/dev/null
        bound_drain_status=$?
        exec 3<&-
        wait "$bound_pid" 2>/dev/null
        bound_wait_status=$?
        bound_producer_status=$(cat "$bound_status" 2>/dev/null || printf 2)
        bound_mode=$(stat -c '%a' -- "$probe_tmp" 2>/dev/null || printf 0)
        if [ "$bound_head_status" -eq 0 ] && [ "$bound_drain_status" -eq 0 ] &&
           [ "$bound_wait_status" -eq 0 ] &&
           [ "$bound_producer_status" -eq 0 ] && [ "$bound_mode" = 700 ] &&
           [ "$(cat "$bound_out")" = abc ]; then
            tool_search_bound=1
        fi
    fi
fi

emit_record CODEX_SSH_PROBE 1
emit_record REQUESTED_ROOT "$requested_root"
emit_record ROOT "$physical_root"
emit_record SHELL_KIND "$shell_kind"
emit_record BASH_VERSION "$bash_version"
emit_record TOOL_mktemp "$tool_mktemp"
emit_record TOOL_dd_nofollow "$tool_dd_nofollow"
emit_record TOOL_sha256sum "$(has_tool sha256sum)"
emit_record TOOL_stat "$(has_tool stat)"
emit_record TOOL_find "$(has_tool find)"
emit_record TOOL_grep "$(has_tool grep)"
emit_record TOOL_rg "$(has_tool rg)"
emit_record TOOL_timeout "$(has_gnu_timeout)"
emit_record TOOL_ln "$(has_tool ln)"
emit_record TOOL_mv "$(has_tool mv)"
emit_record TOOL_read_slice "$tool_read_slice"
emit_record TOOL_find_nul "$tool_find_nul"
emit_record TOOL_stat_printf "$tool_stat_printf"
emit_record TOOL_rg_json "$tool_rg_json"
emit_record TOOL_grep_nul "$tool_grep_nul"
emit_record TOOL_xargs_nul "$tool_xargs_nul"
emit_record TOOL_search_bound "$tool_search_bound"
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellKind {
    Bash { version: String },
    PosixSh,
    Login,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub physical_root: String,
    pub shell: ShellKind,
    pub bash_version: Option<String>,
    pub tools: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellRequest {
    Auto,
    Bash,
    Login,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellSelection {
    pub shell: ShellKind,
    pub fallback: bool,
}

pub fn select_shell(
    capability: &Capability,
    requested: ShellRequest,
) -> BridgeResult<ShellSelection> {
    match requested {
        ShellRequest::Auto => match &capability.shell {
            shell @ ShellKind::Bash { .. } => Ok(ShellSelection {
                shell: shell.clone(),
                fallback: false,
            }),
            ShellKind::PosixSh | ShellKind::Login => Ok(ShellSelection {
                shell: ShellKind::PosixSh,
                fallback: true,
            }),
        },
        ShellRequest::Bash => match &capability.shell {
            shell @ ShellKind::Bash { .. } => Ok(ShellSelection {
                shell: shell.clone(),
                fallback: false,
            }),
            ShellKind::PosixSh | ShellKind::Login => Err(BridgeError::new(
                ErrorCode::RemoteCapabilityMissing,
                "Bash is not available on the remote host",
                false,
            )),
        },
        ShellRequest::Login => Ok(ShellSelection {
            shell: ShellKind::Login,
            fallback: false,
        }),
    }
}

pub fn parse_probe_output(
    output: &[u8],
    expected_requested_root: &RemotePath,
) -> BridgeResult<Capability> {
    if output.last() != Some(&0) {
        return Err(protocol_error("capability output is not NUL terminated"));
    }

    let mut records = BTreeMap::new();
    for raw_record in output[..output.len() - 1].split(|byte| *byte == 0) {
        if raw_record.is_empty() {
            return Err(protocol_error("capability output contains an empty record"));
        }
        let record = std::str::from_utf8(raw_record)
            .map_err(|_| protocol_error("capability output is not valid UTF-8"))?;
        let (key, value) = record
            .split_once('=')
            .ok_or_else(|| protocol_error("capability record has no value"))?;
        validate_key_value(key, value)?;
        if records.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(protocol_error("capability output contains a duplicate key"));
        }
    }

    if required(&records, "CODEX_SSH_PROBE")? != "1" {
        return Err(protocol_error("unsupported capability protocol version"));
    }
    if required(&records, "REQUESTED_ROOT")? != expected_requested_root.absolute() {
        return Err(protocol_error(
            "capability output does not match the requested root",
        ));
    }

    let physical_root = required(&records, "ROOT")?;
    if !physical_root.starts_with('/') {
        return Err(protocol_error("physical root is not absolute"));
    }
    let normalized = RemotePath::resolve("/", physical_root)
        .map_err(|_| protocol_error("physical root is invalid"))?;
    if normalized.absolute() != physical_root {
        return Err(protocol_error("physical root is not normalized"));
    }

    let bash_version = required(&records, "BASH_VERSION")?;
    let (shell, bash_version) = match required(&records, "SHELL_KIND")? {
        "bash" if !bash_version.is_empty() => (
            ShellKind::Bash {
                version: bash_version.to_owned(),
            },
            Some(bash_version.to_owned()),
        ),
        "bash" => return Err(protocol_error("Bash capability has no version")),
        "sh" if bash_version.is_empty() => (ShellKind::PosixSh, None),
        "sh" => return Err(protocol_error("sh capability has a Bash version")),
        _ => return Err(protocol_error("unknown shell capability")),
    };

    let tools = records
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("TOOL_")
                .map(|name| (name.to_owned(), value == "1"))
        })
        .collect();

    Ok(Capability {
        physical_root: physical_root.to_owned(),
        shell,
        bash_version,
        tools,
    })
}

fn validate_key_value(key: &str, value: &str) -> BridgeResult<()> {
    match key {
        "CODEX_SSH_PROBE" | "REQUESTED_ROOT" | "ROOT" | "SHELL_KIND" | "BASH_VERSION" => Ok(()),
        _ => match key.strip_prefix("TOOL_") {
            Some(name) if TOOL_NAMES.contains(&name) && matches!(value, "0" | "1") => Ok(()),
            Some(name) if !TOOL_NAMES.contains(&name) => {
                Err(protocol_error("unknown capability tool key"))
            }
            Some(_) => Err(protocol_error("capability tool value must be 0 or 1")),
            None => Err(protocol_error("unknown capability key")),
        },
    }
}

fn required<'a>(records: &'a BTreeMap<String, String>, key: &str) -> BridgeResult<&'a str> {
    records
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| protocol_error("capability output is missing a required key"))
}

fn protocol_error(message: &str) -> BridgeError {
    BridgeError::new(ErrorCode::ProtocolError, message, false)
}

#[derive(Debug, Default)]
struct CacheState {
    entries: HashMap<String, Arc<OnceCell<Arc<Capability>>>>,
    in_flight: HashMap<String, Arc<ProbeFlight>>,
}

#[derive(Debug)]
struct ProbeFlight {
    cell: Arc<OnceCell<Arc<Capability>>>,
    outcome: watch::Receiver<Option<BridgeResult<Arc<Capability>>>>,
}

enum CacheLookup {
    Ready(Arc<Capability>),
    Leader {
        flight: Arc<ProbeFlight>,
        sender: watch::Sender<Option<BridgeResult<Arc<Capability>>>>,
    },
    Follower(Arc<ProbeFlight>),
}

#[derive(Debug, Default)]
pub struct CapabilityCache {
    state: Mutex<CacheState>,
}

impl CapabilityCache {
    pub(crate) async fn get(&self, host: &str) -> Option<Arc<Capability>> {
        let state = self.state.lock().await;
        state
            .entries
            .get(host)
            .and_then(|cell| cell.get())
            .map(Arc::clone)
    }

    pub async fn get_or_probe<F, Fut>(&self, host: &str, probe: F) -> BridgeResult<Arc<Capability>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = BridgeResult<Capability>>,
    {
        let mut probe = Some(probe);
        loop {
            let lookup = {
                let mut state = self.state.lock().await;
                let cell = Arc::clone(
                    state
                        .entries
                        .entry(host.to_owned())
                        .or_insert_with(|| Arc::new(OnceCell::new())),
                );
                if let Some(capability) = cell.get() {
                    CacheLookup::Ready(Arc::clone(capability))
                } else if let Some(flight) = state.in_flight.get(host) {
                    CacheLookup::Follower(Arc::clone(flight))
                } else {
                    let (sender, outcome) = watch::channel(None);
                    let flight = Arc::new(ProbeFlight { cell, outcome });
                    state.in_flight.insert(host.to_owned(), Arc::clone(&flight));
                    CacheLookup::Leader { flight, sender }
                }
            };

            match lookup {
                CacheLookup::Ready(capability) => return Ok(capability),
                CacheLookup::Follower(flight) => match wait_for_probe(&flight).await {
                    ProbeWait::Completed(outcome) => return outcome,
                    ProbeWait::Abandoned => {
                        self.remove_generation(host, &flight, true).await;
                    }
                },
                CacheLookup::Leader { flight, sender } => {
                    let run_probe = probe.take().expect("only a leader consumes its probe");
                    let outcome = run_probe().await.map(Arc::new);
                    if let Ok(capability) = &outcome {
                        let _ = flight.cell.set(Arc::clone(capability));
                    }

                    self.remove_generation(host, &flight, outcome.is_err())
                        .await;
                    sender.send_replace(Some(outcome.clone()));
                    return outcome;
                }
            }
        }
    }

    async fn remove_generation(&self, host: &str, flight: &Arc<ProbeFlight>, remove_cell: bool) {
        let mut state = self.state.lock().await;
        if remove_cell
            && state
                .entries
                .get(host)
                .is_some_and(|current| Arc::ptr_eq(current, &flight.cell))
        {
            state.entries.remove(host);
        }
        if state
            .in_flight
            .get(host)
            .is_some_and(|current| Arc::ptr_eq(current, flight))
        {
            state.in_flight.remove(host);
        }
    }

    pub async fn invalidate(&self, host: &str) -> bool {
        let mut state = self.state.lock().await;
        let entry_removed = state.entries.remove(host).is_some();
        let flight_removed = state.in_flight.remove(host).is_some();
        entry_removed || flight_removed
    }
}

enum ProbeWait {
    Completed(BridgeResult<Arc<Capability>>),
    Abandoned,
}

async fn wait_for_probe(flight: &ProbeFlight) -> ProbeWait {
    let mut receiver = flight.outcome.clone();
    loop {
        if let Some(outcome) = receiver.borrow().clone() {
            return ProbeWait::Completed(outcome);
        }
        if receiver.changed().await.is_err() {
            if let Some(outcome) = receiver.borrow().clone() {
                return ProbeWait::Completed(outcome);
            }
            return ProbeWait::Abandoned;
        }
    }
}
