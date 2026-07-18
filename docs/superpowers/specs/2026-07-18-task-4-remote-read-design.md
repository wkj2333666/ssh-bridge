# Task 4 High-Level Remote Read Design

Date: 2026-07-18

Status: Controller-bound requirements; implementation review pending

## 1. Scope

Task 4 adds the Rust high-level read-only facade for configured SSH hosts:

- `RemoteBridge::hosts`
- `RemoteBridge::list`
- `RemoteBridge::stat`
- `RemoteBridge::read`
- `RemoteBridge::search`
- `RemoteBridge::output_read`

It does not add writes, deletes, patching, MCP, a CLI, SSHFS, or a Python
runtime. Every remote process continues to be launched by `SshRunner`; the
`remote` module never launches SSH or a local shell.

The binding decisions in `.superpowers/sdd/task-4-clarifications.md` are part
of this design. If this document and that file ever differ, the clarification
file wins.

## 2. Architecture

`RemoteBridge` owns one `Arc<SshRunner>`. The runner remains the only component
that resolves OpenSSH configuration, applies the hardened policy, probes a
host, enforces global/per-host concurrency, starts a process group, handles
cancellation/deadlines, and captures output.

Task 4 adds a crate-private fixed-protocol runner path. It accepts only a
`&'static str` script plus separately quoted positional arguments and optional
raw stdin. It renders exactly:

```text
exec sh -c <quoted compile-time script> codex-ssh-bridge-op <quoted args...>
```

This path never passes through the arbitrary `remote_run` command renderer.
The fixed interpreter is always POSIX sh and is reported as such. Fixed output
is forced into private local spool files even when small, then consumed in
bounded pages. Internal references are discarded and never returned to a tool
caller.

The remote facade is split by responsibility:

- `src/remote/mod.rs`: public request/result types, validation, common
  envelopes, host listing, output paging, and the facade.
- `src/remote/protocol.rs`: bounded spool cursors, NUL/length/newline record
  readers, strict number/UTF-8 parsing, and cleanup.
- `src/remote/read.rs`: one-file raw read protocol and request-order batch
  orchestration.
- `src/remote/metadata.rs`: list/stat fixed scripts and parsers.
- `src/remote/search.rs`: candidate enumeration, local `globset` filtering,
  rg/grep execution, and match parsing.

## 3. Public API

Requests use `Option` only for fields with bridge-owned defaults. MCP handlers
in Task 8 will deserialize tool input and pass these typed requests through
without reimplementing defaults.

```rust
pub struct RemoteBridge {
    runner: Arc<SshRunner>,
}

impl RemoteBridge {
    pub fn new(runner: Arc<SshRunner>) -> Self;
    pub async fn hosts(&self) -> BridgeResult<HostsResult>;
    pub async fn list(
        &self,
        request: ListRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<ListResult>;
    pub async fn stat(
        &self,
        request: StatRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<StatResult>;
    pub async fn read(
        &self,
        request: ReadRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<ReadResult>;
    pub async fn search(
        &self,
        request: SearchRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<SearchResult>;
    pub async fn output_read(
        &self,
        request: OutputReadRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<OutputReadResult>;
}

pub struct ListRequest {
    pub host: String,
    pub path: Option<String>,
    pub depth: Option<u32>,
    pub include_hidden: Option<bool>,
    pub max_entries: Option<usize>,
}

pub struct StatRequest {
    pub host: String,
    pub paths: Vec<String>,
}

pub struct ReadRequest {
    pub host: String,
    pub paths: Vec<String>,
    pub start_line: Option<u64>,
    pub max_lines: Option<u64>,
    pub max_bytes: Option<usize>,
}

pub struct SearchRequest {
    pub host: String,
    pub query: String,
    pub path: Option<String>,
    pub globs: Vec<String>,
    pub max_results: Option<usize>,
    pub binary: Option<bool>,
}

pub struct OutputReadRequest {
    pub output_ref: String,
    pub stream: StreamKind,
    pub offset: u64,
    pub max_bytes: usize,
}
```

Every contacted-host result contains one flattened envelope:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteContext {
    pub remote: bool,              // always true
    pub host: String,
    pub physical_root: String,
    pub shell: ShellMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShellMetadata {
    pub kind: ShellName,            // "bash", "sh", or "login"
    pub version: Option<String>,
    pub fallback: bool,
}
```

Fixed operations return `Sh`, no version, and `fallback=false`. Output paging
returns the shell recorded on the command that created its reference. Context
is not repeated on nested list entries, stat entries, read files, or search
matches.

`hosts()` returns one self-labelling item per configured alias:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostInfo {
    pub remote: bool,
    pub host: String,
    pub configured_root: String,
    pub description: Option<String>,
    pub read_only: bool,
    pub physical_root: Option<String>,
    pub shell: Option<ShellMetadata>,
}
```

It reads only configuration and the already-populated capability cache. It
never invokes `ssh -G`, a capability probe, or a remote command.

### 3.1 Exact result and serde contract

All public result structs derive `Serialize`. There are no
`skip_serializing_if` attributes in Task 4 result types: optional values are
serialized as JSON `null`. Enums use the explicit rename rules shown below.
Nested success/error values use a closed tagged representation rather than
serializing Rust `Result`.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellName { Bash, Sh, Login }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueEncoding { Utf8, Base64 }

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EncodedValue {
    pub encoding: ValueEncoding,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteFileKind {
    File, Directory, Symlink, BlockDevice, CharacterDevice, Fifo, Socket, Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteMetadata {
    pub kind: RemoteFileKind,
    pub size: u64,
    pub mode: u32,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntryErrorCode {
    ReadConflict,
    NotFound,
    PermissionDenied,
    InvalidArgument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryError {
    pub code: EntryErrorCode,
    pub message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostsResult { pub hosts: Vec<HostInfo> }

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListEntry {
    pub actual_path: EncodedValue,
    pub relative_path: EncodedValue,
    pub metadata: RemoteMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListResult {
    #[serde(flatten)] pub context: RemoteContext,
    pub actual_path: EncodedValue,
    pub relative_path: EncodedValue,
    pub entries: Vec<ListEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StatEntry {
    Success {
        actual_path: EncodedValue,
        relative_path: EncodedValue,
        metadata: RemoteMetadata,
    },
    Error {
        actual_path: EncodedValue,
        relative_path: EncodedValue,
        error: EntryError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatResult {
    #[serde(flatten)] pub context: RemoteContext,
    pub entries: Vec<StatEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ReadEntry {
    Success {
        actual_path: EncodedValue,
        relative_path: EncodedValue,
        content: EncodedValue,
        raw_bytes: u64,
        sha256: String,
        truncated_before: bool,
        truncated_after: bool,
        truncated: bool,
    },
    Error {
        actual_path: EncodedValue,
        relative_path: EncodedValue,
        error: EntryError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadResult {
    #[serde(flatten)] pub context: RemoteContext,
    pub files: Vec<ReadEntry>,
    pub returned_raw_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchEngine { Rg, Grep }

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchMatch {
    pub actual_path: EncodedValue,
    pub relative_path: EncodedValue,
    pub line: u64,
    pub column: u64,
    pub content: EncodedValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchResult {
    #[serde(flatten)] pub context: RemoteContext,
    pub engine: SearchEngine,
    pub matches: Vec<SearchMatch>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutputReadResult {
    #[serde(flatten)] pub context: RemoteContext,
    pub stream: StreamKind,
    pub offset: u64,
    pub next_offset: u64,
    pub eof: bool,
    pub data: EncodedValue,
}
```

`StreamKind` gains `Serialize` with lowercase `stdout`/`stderr`. `HostInfo`,
`RemoteContext`, and `ShellMetadata` serialize exactly the fields shown in
their declarations; their `Option` fields are present with `null` when not
cached. `StatEntry` and `ReadEntry` serialize `status: "success"` or
`status: "error"`; a success never contains `error`, and an error never
contains payload/metadata fields.

Closed per-entry messages are exactly:

| code | message |
|---|---|
| `READ_CONFLICT` | `remote file changed while being read` |
| `NOT_FOUND` | `remote path was not found` |
| `PERMISSION_DENIED` | `remote path permission was denied` |
| `INVALID_ARGUMENT` | `remote path is not a regular file` |

`NOT_DIRECTORY` is an operation-level `BridgeError` for list/search roots; it
does not appear in `EntryErrorCode`.

## 4. Lossless Values and Metadata

All caller-supplied paths are UTF-8. Discovered remote path bytes and returned
content are lossless:

Bytes are UTF-8 only when they are valid UTF-8 and contain no NUL. Otherwise
they are RFC 4648 standard padded Base64 encoded locally. `actual_path` is the
normalized configured-root absolute operand sent to SSH. `relative_path` is
configured-root-relative. Both use `EncodedValue`. The implementation never
constructs a purported canonical path from `physical_root`.

File kinds are exact and closed:

List/stat use lstat semantics. The configured root may itself be a symlink;
directory operations dereference only that starting root and do not follow
symlinks encountered below it. Read follows the final file symlink, including
one that reaches outside the configured root.

## 5. Validation and Bounds

All fields in a request are validated before the first runner call, including
the call that would resolve `ssh -G` or probe capabilities. A batch with one
invalid path launches no process for any path.

The fixed limits are:

| Field | Default | Hard maximum |
|---|---:|---:|
| UTF-8 input path | n/a | 64 KiB |
| stat paths | n/a | 256 |
| read paths | n/a | 32 |
| list depth | 1 | 32 |
| list entries | 1,000 | 10,000 |
| search results | 100 | 10,000 |
| query | n/a | 64 KiB |
| globs | 0 | 128 |
| one glob | n/a | 4 KiB |
| read start line | 1 | `u64` checked range |
| read max lines | 2,000 | 100,000 |
| read raw bytes | `read_chunk_bytes` | host `max_read_bytes` (1 MiB compiled) |

List/stat/search protocol bytes are capped by the effective 8 MiB frame bound.
Read bytes are an aggregate batch budget consumed in request order. Arithmetic
uses checked operations, including `start_line + max_lines - 1`, `max_bytes +
1`, record counts, offsets, and Base64 sizing.

Empty host/query, embedded NUL, absolute globs, traversal globs, negative
globs, and invalid ranges fail locally. Empty path means `.` only for list and
search, whose signatures declare that default. Search query additionally
rejects carriage return and line feed so both engines produce one-line records
with identical literal semantics.

Before launch, each resolved request computes its total logical data size with
checked addition: every UTF-8 scalar field byte, every normalized path byte,
every glob byte, and one framing byte per vector item. The sum must not exceed
the host's effective `max_frame_bytes`. Each concrete fixed invocation then
checks `rendered_command_bytes + raw_stdin_bytes` against that same ceiling
after shell quoting. A field present in stdin is not also rendered as an argv
value. These two checks bound the whole logical batch, avoid an `ARG_MAX`
dependency, and prevent quote expansion from bypassing the transport bound. A
violation is `RequestTooLarge` and launches no process.

## 6. Runner and Output Store Extensions

The fixed runner request is crate-private:

```rust
pub(crate) struct FixedRunRequest {
    pub host: String,
    pub script: &'static str,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    pub required_capabilities: &'static [&'static str],
    pub stdout_limit: u64,
    pub stderr_limit: u64,
    pub timeout: Duration,
    pub cleanup: InternalSpoolRegistration,
}

pub(crate) struct FixedRunResult {
    pub capability: Arc<Capability>,
    pub shell: ShellSelection,
    pub output: InternalCapturedOutput,
}
```

The runner validates all bounds, initializes the host through its existing
cache, verifies required functional capabilities, renders the fixed script,
and calls the existing process-group lifecycle. Capture uses independent
stream ceilings plus an aggregate checked ceiling. Both streams are forced to
private spools so previews are never used as protocol data. Internal captures
are not inserted into `OutputStore`'s public token map and cannot be paged by
`output_read`; `InternalCapturedOutput` exposes only crate-private bounded page
reads.

A fixed script emits an explicit `CAPABILITY_MISMATCH` result only when a tool
that was functionally probed is no longer usable. It exits zero and emits the
strict stderr record `CODE=CAPABILITY_MISMATCH\0CAPABILITY=<key>\0`, with no
other field or byte. `<key>` must occur exactly once in that invocation's
compile-time `required_capabilities`; an unknown key, duplicate/extra field,
nonterminal record, or nonzero exit is `ProtocolError`, never a retry trigger.
The facade invalidates that host and repeats the same already-validated
read-only request once. A cached `false` capability fails immediately without
a retry. No transport, timeout, cancellation, filesystem, output-limit, or
other framing failure is retried.

Every facade entry that can start a fixed operation first creates an
`InternalSpoolOwner`. It owns an `Arc<Mutex<CleanupState>>`; the request gives
capture only a registration handle containing a `Weak` reference. Capture
registers each mode-0600 path under the mutex before using it. If the owner has
already closed or the weak upgrade fails, capture immediately unlinks the new
path and fails. Owner drop atomically closes the registry and synchronously
unlinks every registered pathname. Capture tasks and `InternalCapturedOutput`
never retain a strong owner, so aborting the facade future triggers cleanup
even while file descriptors are still open; Unix unlink then leaves only the
already-open descriptor until process/capture teardown. The facade retains the
owner through parsing and explicit normal cleanup. This is the ordinary
internal-spool lifecycle, not TTL cleanup.

`OutputStore` entries gain optional provenance:

```rust
pub(crate) struct OutputProvenance {
    pub host: String,
    pub physical_root: String,
    pub shell: ShellSelection,
}
```

Normal command captures attach provenance. `output_read` rejects references
without it. The existing 32-hex opaque token, expiry, mode-0600 files, and
unknown/expired error remain unchanged. Page offsets and sizes count raw
bytes. Page data uses `EncodedValue` after local classification.

## 7. Functional Capabilities

The capability probe continues to use its private probe directory and strict
NUL records. Task 4 adds functional flags rather than assuming a GNU-looking
binary is compatible:

- `read_slice`: the chosen stat/wc/tail/sed/head/cat pipeline preserves NUL,
  missing-final-newline, byte ceilings, and line boundaries.
- `find_nul`: find can emit raw paths and fixed metadata as NUL records and can
  honor the required no-follow/depth behavior.
- `stat_printf`: stat emits the hexadecimal mode, size, epoch seconds, and
  nanosecond timestamp form the parser expects.
- `rg_json`: rg fixed-string JSON produces the required text/byte forms and
  exit statuses.
- `grep_nul`: grep fixed-string/no-binary output uses a NUL filename boundary.
- `xargs_nul`: NUL-delimited stdin reaches child argv without altering
  non-UTF-8 path bytes.
- `search_bound`: private mode-0700 `mktemp -d`, `mkfifo`, `head -c`, trapped
  scratch cleanup, sequential `xargs -0`, and the expected planned-cutoff
  status signature work together without `pipefail`.

Probe parsing still rejects unknown keys, duplicates, malformed booleans, or a
wrong protocol version. Existing flags needed by later write tasks remain.

## 8. List and Stat Protocols

### List

The list script validates the root and emits fixed groups of NUL fields for at
most `max_entries + 1` qualifying entries. Depth 1 means direct children and
the root itself is excluded. With `include_hidden=false`, any relative
component beginning with `.` is pruned. The configured root operand is
dereferenced, while descendant symlinks are not followed.

Each record contains raw actual-path bytes plus kind, size, mode, mtime seconds,
and mtime nanoseconds. The local parser checks the exact field count, numeric
ranges, and terminal NUL, strips only the normalized configured-root prefix,
sorts by raw relative path bytes, retains at most the requested count, and
sets `truncated` only after observing one additional qualifying record.

A missing root returns `NotFound`; an unreadable root returns
`PermissionDenied`; a non-directory root returns `NotDirectory`. No raw remote
diagnostic is copied into an error.

### Stat

All stat paths are normalized before launch and encoded, in request order, as
one NUL-delimited stdin body. No path is placed in the remote command line.
Functionally probed sequential `xargs -0` divides that body into bounded argv
batches below the remote `ARG_MAX` and invokes one fixed inner script. The
inner script emits one metadata or safe-error record per input in the same
order. GNU stat is used without dereference. Missing and permission failures
become closed per-entry errors. Protocol corruption, a count/order mismatch, or
a transport failure aborts the entire batch.

## 9. Read Protocol

One API batch uses one fixed SSH operation per file. Files within that batch are
processed sequentially in request order so the single aggregate byte budget
cannot amplify to one budget per file. Independent requests, including the
expected five-host peak, still run concurrently through the runner's existing
global/per-host semaphores. All paths are validated before the first file
operation starts.

For each file:

1. The script verifies existence, readability, and regular-file semantics
   (following the final symlink).
2. It computes file size and LF-aware line count using the functionally probed
   read primitives.
3. If `start_line=1`, the line window includes the complete file, and the
   remaining aggregate byte budget covers its size, it streams the raw file to
   stdout. Rust hashes those exact bytes locally.
4. Otherwise it computes a whole-file SHA-256 before selection, streams at most
   `remaining_budget + 1` selected raw bytes to stdout, computes the whole-file
   SHA-256 again, and emits both digests in stderr metadata.
5. If the two remote digests differ, Rust discards stdout and returns a
   per-file `ReadConflict`.
6. Rust retains at most the remaining budget, uses the one extra byte to prove
   byte truncation, classifies/encodes the retained bytes locally, and updates
   the checked aggregate budget.

`start_line` is one-based. LF terminates a line and a non-empty final segment
without LF is also a line. The same selection applies to binary bytes.
`truncated_before` is true only when existing bytes precede the selected
window. `truncated_after` is true when a line or byte ceiling omits existing
bytes. `truncated` is their OR.

Every successful file has a complete-file 64-character lowercase `sha256`.
Later entries remain represented after the byte budget reaches zero; they use
one byte of lookahead plus the guarded remote digest to report accurate
truncation without retaining content.

Expected file errors are nested per-file results. A directory or other
non-regular value uses a fixed `InvalidArgument` message, because the four new
filesystem codes intentionally include `NotDirectory` for directory-required
operations but do not add an `IsDirectory` code. Transport, cancellation,
protocol, and aggregate output failures abort the batch.

## 10. Search Protocol

Search is a literal fixed-string operation. It includes hidden and ignored
files and never follows descendant symlinks.

Search uses one bounded-output helper for both phases. The helper creates a
private mode-0700 directory with functionally probed `mktemp -d`, installs
signal/exit traps before creating a FIFO and status files, and starts the fixed
producer in the background with stdout attached to that FIFO. In the
foreground, functionally probed `head -c` copies at most the caller-supplied
`remaining_protocol_bytes + 1` raw bytes from the FIFO into a private scratch
file; this is never greater than `max_frame_bytes + 1`. It then waits for the
producer, records whether the extra byte was observed, and copies only that
already-bounded scratch file to SSH stdout. POSIX sh never uses or assumes
`pipefail`.

The producer uses sequential, functionally probed `xargs -0` batches. Each
fixed inner wrapper suppresses utility diagnostics, maps engine status 0 to
match success and status 1 to no-match success, and writes the first status
greater than 1 into a separate private status record before stopping xargs.
The outer wrapper also records xargs' aggregate status. The `search_bound`
functional probe freezes the exact signal/xargs status produced when the
foreground byte cutoff intentionally closes the FIFO. A pre-cutoff engine
error is never reclassified as truncation; only the probed cutoff signature is
accepted when the extra byte proves a planned cutoff. An unrecognized nonzero
producer status is a fixed operation error. Scratch files and the FIFO are
removed by the trap on success, error, cancellation, and signal termination.

Search then has two uses of that helper:

1. A fixed find operation enumerates regular-file candidates as raw
   NUL-delimited actual paths. It returns at most 10,001 records and at most
   `max_frame_bytes + 1` bytes. Rust parses the entire bounded capture while
   retaining no more than 10,001 paths, derives lossless relative paths,
   applies all positive slash-aware `globset` matchers to raw Unix path bytes,
   and sorts selected candidates by raw relative bytes. Hitting the candidate
   count or planned byte ceiling sets `truncated=true`.
2. The filtered raw paths are divided into bounded stdin batches, each of which
   satisfies `rendered_command_bytes + stdin_bytes <= max_frame_bytes`. Each
   batch is sent as NUL-delimited bytes to a fixed POSIX-sh script.
   Functionally probed `xargs -0` reconstructs exact argv values, including
   non-UTF-8 names. No discovered path is converted to a shell command string.
   The facade initializes one aggregate content-protocol allowance of
   `max_frame_bytes`, subtracts each batch's complete captured bytes with
   checked arithmetic, and passes only the remaining allowance to the next
   batch. It stops scheduling after a planned byte cutoff or after observing
   `max_results + 1` matches, so multiple candidate batches cannot multiply the
   output bound.

When `rg_json=true`, rg runs with JSON and fixed-string semantics. With
`binary=false` it ignores binary files; with `binary=true` it uses rg's byte
form. Its bounded raw JSON stream may contain the documented non-match event
kinds; Rust validates their framing and strictly parses every match event,
requiring the path, line, first byte-column, and line text/bytes forms. It
rejects an oversized event and does not expose submatch arrays.

When rg is unavailable, find+grep is used. `binary=true` fails with
`RemoteCapabilityMissing` before the content-search phase. Grep uses fixed
strings, ignores binary files, and frames raw filenames with NUL. Rust parses
the following line record, finds the literal query bytes locally to obtain the
one-based byte column, and losslessly encodes the line content.

Rust consumes every completed batch within the global bounded
`max_frame_bytes + 1` content budget but retains only `max_results + 1`
matching records. It returns the first
`max_results` and sets `truncated=true` if the extra match exists, candidate
enumeration was incomplete, or the planned byte cutoff was reached. An
incomplete first record/event is an oversized-record `ProtocolError`. If at
least one complete record precedes a trailing partial record exactly at the
planned cutoff, Rust discards only that partial suffix and reports truncation;
the same partial record without a proved planned cutoff is `ProtocolError`.
This helper's explicit one-byte lookahead is below `OutputStore`'s hard capture
limit: an `OutputLimit` always discards the capture and aborts the operation,
and is never converted to partial success. rg/grep exit 1 is a successful
empty result. Any genuine engine failure is converted to a fixed safe error
without copying stderr.

## 11. Errors and Framing

Task 4 adds these stable error codes:

- `READ_CONFLICT`
- `NOT_FOUND`
- `PERMISSION_DENIED`
- `NOT_DIRECTORY`

Caller validation uses `INVALID_ARGUMENT` or `REQUEST_TOO_LARGE`. Root escape
uses `PATH_OUTSIDE_ROOT` before launch. Missing or stale behavior uses
`REMOTE_CAPABILITY_MISSING`. Malformed field counts, invalid UTF-8 metadata,
invalid numbers, oversized single events, nonterminal records, and unexpected
engine JSON use `PROTOCOL_ERROR` with no partial result.

Remote scripts never emit an arbitrary utility diagnostic into protocol
metadata. They suppress it and emit only a fixed status token. Rust error
messages are fixed and do not contain remote stderr or untrusted remote path
bytes.

Every stderr control protocol is parsed as a closed sequence with an exact
field count and terminal NUL. In particular, only an exit-zero
`CODE=CAPABILITY_MISMATCH\0CAPABILITY=<required-key>\0` record becomes the
private retry marker. Unknown capability names, extra/duplicate fields,
malformed UTF-8, trailing bytes, and the same record accompanying a nonzero
remote exit are `ProtocolError`.

## 12. Cancellation, Cleanup, and Performance

Every remote method passes its cancellation token to every runner operation.
Read orchestration stops scheduling work after cancellation; in-flight SSH
process groups are terminated by the runner. `output_read` selects between the
local page read and cancellation.

Fixed captures use private forced spools, so five hosts can each produce an
8 MiB bounded protocol without five full raw frames residing in Rust heap.
Parsers consume 64 KiB pages, retain only one incomplete record/event plus the
typed result (and the explicitly bounded search lookahead), and hash read data
incrementally. The facade-entry `InternalSpoolOwner` removes internal paths on
success, handled error, dropped future, or runtime task abort; capture owns
only a weak registration handle. TTL cleanup remains defense-in-depth for
public output references and crash/orphan recovery, never the ordinary
internal cleanup path.

No operation invokes a local shell. Test-only fake SSH may execute the rendered
fixed command as a simulated remote Linux host.

## 13. Test Strategy

Tests use red-green-refactor and the existing shell fake-SSH fixture. The fake
transport gains a local-filesystem mode and functional capability flags; it
does not use Python.

Coverage includes:

- local-only hosts and cached optional capability state;
- provenanced output paging and unprovenanced-reference rejection;
- traversal and all invalid batch fields launching zero processes;
- quote/newline/leading-hyphen paths and non-UTF-8 discovered names;
- list depth, hidden pruning, exact types, ordering, and exact truncation;
- stat order plus per-entry not-found/permission errors;
- full/truncated/binary/budget-exhausted reads, local/remote hashing, final
  non-LF lines, hash races, and request-order results;
- rg selection, grep fallback, literal query semantics, positive globs,
  candidate/result truncation, binary policy, JSON bytes, and malformed/large
  records;
- forced-spool cleanup, cancellation, capability reprobe once, no retry for
  transport/protocol/filesystem failures, and five-host bounded execution;
- serialization with one remote envelope and no repeated roots or payloads.

The Task 4 gate is:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test remote_ops -- --nocapture
cargo test --all-targets
```
