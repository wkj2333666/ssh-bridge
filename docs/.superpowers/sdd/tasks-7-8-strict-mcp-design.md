# Tasks 7–8 Strict MCP and High-Level Tool Surface Design

Date: 2026-07-18

Status: Ready for implementation after strict MCP security/performance review

## 1. Purpose

Tasks 7 and 8 add the local stdio MCP boundary to the existing Rust bridge.
The result is a strict, bounded, asynchronous JSON-RPC server exposing exactly
nine high-level `remote_` tools. The Agent expresses remote intent; the bridge,
not the Agent or MCP adapter, owns host resolution, capability probing, shell
selection, path validation, quoting, byte decoding, limits, retries, mutation
truthfulness, and SSH error classification.

This document expands Tasks 7 and 8 from the approved main design and plan. It
also closes one prerequisite gap in the current Rust architecture: arbitrary
remote command execution exists only as `SshRunner::execute`. Before the MCP
tool can be thin, a public `RemoteBridge::run` facade must own its complete
high-level contract.

Task 6 is consumed as designed:

- `ApplyPatchRequest { host, patch }`;
- `ApplyPatchResult { context, changed_paths }`;
- the original typed `BridgeError` on failure; and
- `failed_path`, `changed_paths`, `not_changed_paths`, and
  `outcome_unknown_paths` progress details without MCP reinterpretation.

## 2. Binding Decisions

The following decisions supplement the main design and are binding for Tasks
7 and 8.

1. The supported MCP protocol set is exactly `2025-11-25` and `2025-06-18`,
   preferred in that order. The bridge advertises only tools and does not
   advertise experimental task execution, resources, prompts, sampling, or
   logging.
2. A valid `notifications/cancelled` notification cancels the matching token
   and suppresses the original MCP response. The bridge may still produce a
   typed `Cancelled` error internally, for direct Rust/CLI callers, or when an
   operation is cancelled by a non-MCP source while the connection remains
   valid. EOF cancels outstanding calls and sends no response.
3. The expected peak is five hosts. Every tool call names one host; Tasks 7 and
   8 add no `hosts[]` fanout and no implicit multi-host loop. Five independent
   calls exercise the existing global and per-host semaphores. The approved
   main specification does not make five a configuration-file hard ceiling.
4. Bulk payload bytes have one wire owner. They appear in the single text
   content block and never in `structuredContent`. Structured content contains
   context, counters, hashes, truncation, progress, shell metadata, and opaque
   references. Small success scalars and safe error summaries may be repeated.
5. MCP has no generic Base64 content-block type. Binary file, output, or stdin
   values use an ordinary text string containing Base64 plus an explicit
   `encoding="base64"` metadata field. No private content-block variant is
   invented.
6. Malformed JSON-RPC or `tools/call` envelopes and unknown tool names are
   `-32602 Invalid params` and never reach `RemoteBridge`. Once `name` selects a
   known tool, missing/unknown/wrong-type/range/enum fields in `arguments` are a
   normal `CallToolResult` with `isError=true`, a stable `INVALID_ARGUMENT`
   code, and safe actionable text. A dispatched tool that returns `BridgeError`
   is likewise a normal `tools/call` result with `isError=true`.
7. Tool annotations are hints only. Read-only enforcement remains in
   `RemoteBridge`/`SshRunner`; a read-only host never becomes writable because
   a client ignores annotations.

The verified MCP references used for these decisions are:

- `https://modelcontextprotocol.io/docs/learn/versioning`
- `https://modelcontextprotocol.io/specification/2025-11-25/schema`
- `https://modelcontextprotocol.io/specification/2025-06-18/schema`
- `https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation`
- `https://modelcontextprotocol.io/specification/2025-06-18/basic/transports`
- `https://modelcontextprotocol.io/specification/2025-06-18/server/tools`

## 3. Goals and Non-Goals

### 3.1 Goals

- Bound every input frame, output frame, in-flight tool call, queue, SSH
  operation, and retained payload.
- Preserve a responsive stdin loop while remote operations are running.
- Prevent response interleaving through a single writer owner.
- Reject duplicate JSON object keys before they can collapse in
  `serde_json::Value`.
- Preserve exact string or numeric request IDs and cancellation identity.
- Expose exactly the nine approved high-level tools with closed schemas.
- Make Bash selection and POSIX sh fallback explicit in every run result after
  shell selection.
- Keep all hostile path/query/glob/cwd values out of fixed shell source.
- Return large file and command payloads exactly once.
- Preserve Task 5 mutation unknown semantics and Task 6 partial-progress
  semantics without MCP retry or post-hoc reclassification.

### 3.2 Non-Goals

- HTTP, SSE, authentication, resources, prompts, sampling, elicitation, MCP
  tasks, or server-to-client requests.
- A raw SSH command builder, a capability-probe tool, a guarded-delete tool,
  or an SSHFS tool.
- Per-client sessions beyond the lifetime of the local stdio process.
- Multi-host fanout inside a single tool call.
- A general environment-variable API for `remote_run`.
- Backward compatibility with the Python prototype's `ssh_*` tool names.
- Duplicating output solely for clients that do not consume the selected MCP
  result representation.

## 4. Architecture and File Boundaries

The implementation uses these focused units:

- `src/config.rs`: exports the bridge-wide
  `MAX_REMOTE_CONTEXT_ROOT_BYTES=65_536` constant and enforces it on configured
  roots by UTF-8 byte length.
- `src/remote/run.rs`: high-level run admission, cwd resolution, stdin
  decoding, read-only enforcement, shell request mapping, result conversion,
  and stable sh warnings.
- `src/capability.rs`: adds explicit `ShellRequest::Sh`, enforces the shared
  root-byte ceiling while parsing probed physical `ROOT`, and remains the sole
  automatic Bash/sh selection authority.
- `src/ssh/process.rs`: safely renders cwd and user command at the remote shell
  boundary, enforces rendered-command bounds, and attaches selected-shell
  metadata to errors after selection.
- `src/error.rs` and remote facades: optional bounded physical-root error
  context plus one non-overwriting `attach_available_remote_context` helper,
  including errors created while parsing successful fixed-script output.
- `src/mcp/protocol.rs`: protocol versions, `RequestId`, strict JSON parsing,
  JSON-RPC envelopes, lifecycle method validation, response constructors, and
  tool-service boundary types.
- `src/mcp/stdio.rs`: bounded newline framing and capped compact JSON
  serialization.
- `src/mcp/mod.rs`: lifecycle owner, in-flight registry, cancellation,
  concurrent dispatch, EOF handling, and the public `McpServer`.
- `src/mcp/tools.rs`: exact schemas, closed argument types, annotations, and
  bridge-only dispatch.
- `src/mcp/render.rs`: one-content-block success/error projection and bulk
  payload ownership.
- `src/main.rs`: process bootstrap for `codex-ssh-bridge mcp`; it writes no
  diagnostics to stdout.
- `tests/mcp_protocol.rs`: framing, strict JSON, lifecycle, concurrency,
  cancellation, writer, and stdout tests with a stub tool service.
- `tests/mcp_tools.rs`: exact schemas, thin dispatch, fake-SSH integration,
  single-copy results, shell behavior, mutation errors, and five-host
  acceptance.
- `tests/core.rs` and `tests/ssh_transport.rs`: configured/probed root byte
  boundary tests shared by bridge and MCP.

`src/mcp/tools.rs` may import `RemoteBridge` and public request/result types
from `remote`. It must not import `SshRunner`, `RemotePath`, the quote module,
capability cache internals, fixed scripts, or `OutputStore` internals. That
dependency boundary is the mechanical expression of “the bridge owns the
logic.”

## 5. Bridge-Owned `remote_run`

### 5.0 Shared remote-context bounds

`src/config.rs` owns and exports:

```rust
pub const MAX_REMOTE_CONTEXT_ROOT_BYTES: usize = 65_536;
```

Configuration validation rejects a normalized configured root whose UTF-8 byte
length exceeds the constant. Capability parsing applies the same constant to
the probed physical `ROOT` before caching or constructing `RemoteContext`.
MCP imports this bridge constant for wire-budget calculations; it does not
redeclare or assume it. Exact tests accept 65,536 ASCII bytes, reject 65,537,
and use non-ASCII roots straddling the byte boundary to prove the check is bytes
rather than Unicode scalar count. The same matrix covers configuration input
and capability `ROOT` records.

`src/capability.rs` also exports and enforces:

```rust
pub const MAX_SHELL_VERSION_BYTES: usize = 256;
```

The probe parser checks Bash version UTF-8 bytes before caching shell metadata.
Tests accept exactly 256 bytes, reject 257, and include a malicious fake Bash
version plus a non-ASCII byte boundary. MCP imports the shared bound and its
real maximum-fallback counting fixture includes both maximum root and maximum
shell version in Text and structured context.

### 5.1 Public types

The new high-level remote API is:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunShell {
    Auto,
    Bash,
    Sh,
    Login,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunStdin {
    pub encoding: WriteEncoding,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRunRequest {
    pub host: String,
    pub command: String,
    pub cwd: Option<String>,
    pub shell: RunShell,
    pub timeout_ms: Option<u64>,
    pub stdin: Option<RunStdin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EncodedOutputPreview {
    pub head: EncodedValue,
    pub tail: EncodedValue,
    pub raw_bytes: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteRunResult {
    #[serde(flatten)]
    pub context: RemoteContext,
    pub exit_status: i32,
    pub elapsed_ms: u64,
    pub stdout: EncodedOutputPreview,
    pub stderr: EncodedOutputPreview,
    pub aggregate_bytes: u64,
    pub output_ref: Option<String>,
    pub remote_process_may_continue: bool,
    pub warnings: Vec<String>,
}
```

`RemoteBridge::run(RemoteRunRequest, CancellationToken)` is the only method
used by the MCP `remote_run` handler. The existing lower-level
`ssh::RunRequest` remains a transport type.

### 5.2 Admission and lowering

Before launching a command child, `RemoteBridge::run`:

1. Resolves the exact allowlisted host and rejects a read-only profile.
2. Validates command NUL absence and byte limits.
3. Resolves `cwd.unwrap_or(".")` lexically beneath the configured root.
4. Decodes stdin as strict UTF-8 bytes or canonical Base64 and enforces the
   effective raw `max_write_bytes` ceiling.
5. Selects the effective timeout, bounded by the host's
   `command_timeout_ms`.
6. Maps `RunShell` to `ShellRequest`, including the new explicit `Sh` case.

The lower runner still performs capability initialization and selects the
actual shell. `Auto` selects non-profile Bash when available. Otherwise it
selects POSIX sh with `fallback=true`. Explicit `Sh` selects POSIX sh with
`fallback=false`. Explicit `Bash` returns `RemoteCapabilityMissing` before the
command child when Bash is unavailable. `Login` records `kind=login`, no
version, and no fallback.

Every successful sh selection adds one fixed actionable warning against
Bash-only arrays, `[[ ]]`, `source`, `pipefail`, and Bash substitutions. The
same warning is attached to every later error after sh was selected: use POSIX
syntax, or request `shell=bash` and ensure Bash is installed. It is present for
explicit sh as well as fallback sh; fallback truth is carried separately.

### 5.3 Remote command boundary

For Bash and sh, the remote login shell receives a fixed wrapper plus encoded
positional parameters. The wrapper performs `cd -- "$1"` and then executes
the selected interpreter with the user command in `"$2"` as the interpreter's
`-c` operand. The cwd and command are never interpolated into the fixed wrapper
source.

For login mode, the user command is intentionally shell source for the remote
account shell. The bridge prepends only `cd -- <encoded-cwd> &&` using the sole
audited word encoder. Login mode uses the local deadline because wrapping an
unknown login shell in the probed GNU-timeout form would change its semantics.

After rendering, the complete remote command byte length must fit the host's
effective `max_frame_bytes`. This check closes quote-amplification cases that
are smaller before shell encoding.

Once shell selection succeeds, any later remote exit, timeout, output limit,
or cancellation error carries:

```rust
pub struct ErrorShellMetadata {
    pub kind: String,
    pub version: Option<String>,
    pub fallback: bool,
}
```

as optional `ErrorDetails.shell`. Errors before shell selection omit it.

`ErrorDetails` also adds:

```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub physical_root: Option<String>,
```

Once a capability/probe result has supplied a bounded physical root, every
later error carries it. This includes transport exit/timeout/cancel/output-limit
and domain/protocol errors created after an exit-zero fixed child is parsed
(read/snapshot/write-conflict/patch result parsing). A single bridge helper
`attach_available_remote_context(error, host, physical_root, shell)` fills only
missing safe fields and never overwrites richer existing details. Transport and
each remote facade/parser boundary call it before returning. Pre-probe errors
and rejection of an oversized probe `ROOT` omit physical root.

## 6. Strict JSON and JSON-RPC Model

### 6.1 Supported versions

```rust
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18"];
```

If the client requests a supported version, the server validates `clientInfo`
with that requested version's shape and returns the same version. For an
unsupported `protocolVersion`, it first validates `clientInfo` against the
bounded union represented by the current `2025-11-25` shape, then returns the
first supported version; a client unable to use it must disconnect. Thus
latest-only fields are admitted for an unsupported version, but fields outside
the bounded current union are rejected. Both supported sessions expose the same
nine-tool subset.

### 6.2 Request IDs

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestId {
    String(String),
    Number(serde_json::Number),
}
```

Number IDs must be integral (`is_i64()` or `is_u64()`). Null, Boolean, float,
array, and object IDs are invalid. Serialization reproduces the exact string
or integer category. Numeric `1` and string `"1"` are distinct registry keys.

### 6.3 Duplicate keys and strict shapes

The server does not first call `serde_json::from_slice::<Value>`. It uses a
recursive custom visitor with explicit budgets: maximum depth 64, maximum
262,144 total scalar/container nodes, maximum 131,072 aggregate object members,
and maximum 1,048,576 aggregate UTF-8 key bytes per frame. Every counter uses
checked arithmetic and fails before allocating the next over-budget value.
While constructing each `serde_json::Map`, duplicate detection calls that map's
`contains_key` before insertion; it must not allocate a parallel
`HashSet<String>` or clone every key merely to detect duplicates.

A shared parser failure marker distinguishes `DuplicateKey` from
`StructuralBudget`. Depth/node/member/key-byte checks set
`StructuralBudget` before returning the visitor's fixed custom error; duplicate
checks set `DuplicateKey`. `StrictJsonError::Syntax` is used only when neither
marker was set and serde reports genuine malformed JSON/trailing data. No
budget breach may be accidentally reclassified as syntax.

A duplicate at any nesting depth makes the complete wire request `-32600
Invalid Request` with `id=null`; it is never dispatched and is never
last-key-wins. This uniform rule avoids trusting a partially parsed ID or method
to reclassify a duplicate nested under `params.arguments`. A structural-budget
failure is also a fixed `-32600` with `id=null`. JSON syntax failures are
`-32700 Parse error` with `id=null`.

Top-level request/notification objects accept only `jsonrpc`, `id`, `method`,
and `params`. `jsonrpc` is exactly `"2.0"`. Parameter validation is negotiated-
version specific. In `2025-06-18`, official base Request/Notification params
are open: initialize, ping, initialized, list, call, and cancelled accept and
ignore bounded additional top-level extension fields without reflecting them.
All required standard fields/types are still validated, and `tools/call`
`arguments` plus its nested objects remain closed. In `2025-11-25`, each
supported method accepts only its official fields plus an open-object `_meta`;
unknown top-level params fields are `-32602`. Task augmentation fields are
rejected because this server does not negotiate/advertise tasks.

Every admitted `_meta` value and client `capabilities` remain open JSON objects
in both versions. Neither is deserialized through a closed payload type. For an
unsupported initialize version, the bounded current 2025-11 params/clientInfo
union is used before selecting latest, so June-only openness does not turn the
pre-negotiation request into an unbounded extension surface.

The supported method shapes retain MCP's common request fields: initialize,
ping, `notifications/initialized`, `tools/list`, `tools/call`, and
`notifications/cancelled` accept optional open-object `_meta` values.
`tools/list` also recognizes the optional string `cursor`. This server never
emits `nextCursor`, so a nonempty cursor is a fixed `-32602` instead of
repeating the full page. `tools/call` requires string `name`, accepts an absent
`arguments` as `{}`, and requires an object when present. Its other top-level
params fields follow the negotiated June-open/November-closed rule. A
missing/wrong-type name, non-object arguments, unknown tool name, or
other malformed `tools/call` envelope is `-32602`. After a known name is
selected, its argument-schema failures are normal `isError=true` tool results.
The server does not echo or interpret `_meta`.

`clientInfo` is validated against the negotiated request version before any
state transition. For `2025-06-18` it has required `name` and `version`, plus
optional `title`. For `2025-11-25` it has required `name` and `version`, plus
optional `title`, `icons`, `description`, and `websiteUrl`. Icon counts and all
strings have fixed length budgets; icon `src` and `websiteUrl` must be bounded
absolute URIs, and icon subobjects follow that version's MCP fields. Validation
errors are fixed and never echo a URI, description, client name, or rejected
field value. Fields belonging only to the other version are rejected.

The local defensive limits are: name/title/version at most 256 UTF-8 bytes,
description at most 4,096 bytes, websiteUrl at most 2,048 bytes, at most 16
icons, and icon `src` at most 65,536 bytes. A 2025-11-25 icon admits exactly
required `src` plus optional `mimeType`, `sizes`, and `theme`; MIME type is at
most 256 bytes, sizes has at most 16 strings of at most 32 bytes, and theme is
`light|dark`. `src` may use any syntactically valid absolute URI including
`data:`; `websiteUrl` is likewise an absolute URI. The bridge never fetches,
logs, or reflects either URI.

The implementation uses a conservative dependency-free RFC 3986 subset, not
browser-style URL normalization. Bounds are checked before syntax. The URI is
ASCII, contains no whitespace, controls, backslash, or ASCII byte values
`0x22, 0x3c, 0x3e, 0x5e, 0x60, 0x7b, 0x7c, 0x7d`, starts with
`[A-Za-z][A-Za-z0-9+.-]*:`, has a nonempty suffix made only from RFC 3986
unreserved/gen-delim/sub-delim bytes, and uses only complete two-hex-digit
percent escapes. For HTTP(S), the suffix starts `//`; authority is the bytes
after it through the first `/`, `?`, `#`, or end and must be nonempty.
For every `//` authority, userinfo is rejected; bracketed hosts must parse as
`std::net::Ipv6Addr`; other hosts must parse as IPv4 or be DNS-like labels of
at most 63 bytes and 253 bytes total with ASCII alphanumeric edges and only
interior hyphens. A digits-and-dots host must parse as IPv4. Optional ports are
nonempty decimal `u16`; empty host/label/port, unbracketed IPv6, and trailing
junk fail. The scanner allocates no normalized URL and performs no resolution.
This accepts ordinary `https:`, `urn:`, and `data:` absolute URIs while failing
closed on relative, IRI, ambiguous-backslash, or normalization-dependent input.
November's closed method-field validator is a project security policy for the
supported version, not a claim that upstream mechanically enforces closure.

The protocol never copies a serde error containing caller data into a response
or log. Public errors use fixed messages and stable numeric codes.

## 7. Bounded Stdio Transport

### 7.1 Input framing

`FrameReader<R>` owns one reusable buffer and uses `AsyncBufRead::fill_buf` and
`consume` to scan bytes until `\n`.

- A frame contains at most effective `max_frame_bytes` bytes excluding the
  delimiter.
- A frame of exactly the bound is accepted.
- On the next byte without a delimiter, the reader records `Oversized`, stops
  retaining bytes, and drains through the next delimiter.
- An oversized frame returns an error with `id=null` because the ID was not
  trusted through a complete parse.
- EOF with no retained bytes is orderly shutdown.
- EOF with a partial frame is a parse error followed by shutdown.
- `\r\n` is accepted because the trailing CR is JSON whitespace; an unescaped
  raw newline inside a JSON string terminates the frame and therefore fails
  parsing.

The reader never calls `read_line` or allocates a string before the byte bound
is known.

### 7.2 Output framing

One writer task owns stdout. Every response is compact JSON followed by one
newline delimiter. `max_frame_bytes` and every response budget exclude that
delimiter. `CappedJsonBuffer` implements `std::io::Write` and refuses the first
serialized byte beyond `max_frame_bytes`, so checking cannot occur after an
unbounded allocation.

The writer channel capacity and each queued message are bounded.
The lifecycle owner's main select continuously monitors the writer
`JoinHandle`. Writer error, panic, or unexpected success while its channel is
open, reader EOF/partial EOF, and bounded-channel backpressure all enter one
idempotent Closing transition. It first rejects dispatch; partial EOF alone
attempts its fixed parse error; then the owner globally suppresses call
responses and cancels tasks. Writer messages are tagged call/control; queued
call messages whose write has not committed past the final suppression check
are discarded after suppression. That atomic check is the non-retractable
write-start boundary. After the 250 ms MCP task
grace the owner aborts/drains leftovers through a separate bounded 250 ms
abort-drain grace, drops the sender, allows the writer to drain, and awaits its own
250 ms MCP writer grace before abort/drain. Hostile writer error text is never
reflected; writer/backpressure failure returns fixed `MCP transport failed`.
`MIN_MCP_FRAME_BYTES` is a compiled 1 MiB lower bound and imports the bridge's
shared 65,536-byte physical-root ceiling. Root appears inside the TextContent
inner JSON and that whole string is escaped again by the outer MCP JSON, while
`structuredContent` repeats the root directly. The conservative combined
expansion is therefore thirteen bytes per root byte (inner/outer path about
seven plus structured path six), not six. A compile-time checked formula proves
1 MiB covers `MAX_REMOTE_CONTEXT_ROOT_BYTES * 13`, a 256-byte serialized request
ID, and a 64 KiB fixed envelope/error/fallback reserve. Compact fallback never
truncates a known physical root.

The formula is only a coarse proof. Error rendering first constructs a
`RenderedErrorCore` from the real `BridgeError`: the core contains code,
bounded message, retryability, mutation/progress/byte facts, and other
non-context detail, but excludes host, physical root, and shell. Text JSON
contains the core plus context once; `structuredContent.error` contains the
same core without context, while the structured top level contains context
once. Thus a physical root occurs only in the inner Text JSON (then escaped by
the outer MCP JSON) and once at the structured top level. It is never repeated
inside `structuredContent.error.details`.

The authoritative construction check uses a counting serializer over the real
largest compact fallback model. It starts with an actual maximum `BridgeError`
whose `ErrorDetails` contains a maximum control-heavy physical root and maximum
control-heavy shell version, projects it through `RenderedErrorCore`, and
proves the root occurs in exactly the two intended contexts. It also uses maximum bounded safe
message/action/warnings using the worst legal alternating quote/backslash
pattern and the synthetic maximum ID. Control-heavy message/action/warning
inputs are not legal projections: Task 7 replaces every Unicode
`char::is_control()` with the single ASCII byte `?` before or while applying
the UTF-8-byte bound. `McpServer::new` also
counting-serializes its trusted
`service.definitions()` with that ID to calculate the exact complete,
non-degradable `tools/list` response. The effective minimum is the maximum of
the compiled constant, real fallback count, and exact tools/list count;
construction rejects `max_frame_bytes` below it.

A `WireBudget` reserves only the JSON-RPC envelope, bounded request ID, and a
preconstructed compact fallback before a renderer receives its result budget.
It does not subtract the newline delimiter because that delimiter is appended
after successful capped serialization and remains outside `max_frame_bytes`.
The `compact_fallback_bytes` argument
to `required_mcp_frame_bytes` and `WireBudget::for_response` always means the
serialized fallback `result` value alone; it excludes the JSON-RPC envelope,
request ID, and newline. `MIN_MCP_FRAME_BYTES` is a complete-frame floor and
must never be passed as that result-only argument. Task 5 passes zero until a
real tool-result fallback exists; Task 7 replaces zero with the counting-
serialized real largest fallback result. In each phase the effective minimum
is exact: the maximum of the compiled full-frame floor, full tools/list frame,
and envelope plus the phase's result-only fallback.
The server stores that result-only count once. Construction passes the stored
value to `required_mcp_frame_bytes`, and every accepted request passes the same
unmodified value to `WireBudget::for_response`; tests assert this propagation.
These invariants guarantee that all minimum
responses and the exact nine-tool list can always be serialized.

Tool tasks send already budgeted response models. Every bulk-bearing renderer
(`remote_hosts`, list, stat, search, read, output-read, and run) first attempts
the complete single-copy result, then selects a compact fallback before
serialization. Hosts/list/stat/search/read retain omitted canonical detail
through the bridge-owned logical-stdout facade. Output-read keeps its existing
ref but recomputes its next offset and EOF from the raw bytes actually included;
run keeps its existing ref or retains omitted detail.
Mutation renderers must never turn an already completed
write/patch/run into `-32603`: if the full response does not fit, they select a
preconstructed compact result preserving `applied|partial|unknown|not_applied`,
`mutation_may_have_applied`, changed/not-changed/unknown counts, safe failure
status, and an opaque pageable `output_ref` for omitted detail. If an operation
does not already own a suitable reference, it asks a bridge-owned internal
result-retention facade to store the detail; MCP code never imports, opens, or
addresses `OutputStore` directly. The normal `remote_output_read` bridge path
pages that opaque reference and its provenance.

Detail retention is best-effort and never controls mutation truth. On success,
the compact fallback has `detail_retained=true`, `output_ref`, and
`output_stream="stdout"`. On storage/admission/cancellation failure, it still
returns the same compact applied/partial/unknown/completion truth and counts
with `detail_retained=false` and no ref. Retention failure is neither `-32603`
nor a reason to discard or reclassify the completed operation.

Read-only bulk fallbacks always preserve `remote` context where available,
total/returned counts, `truncated=true`, and `detail_retained`. A successful
new retention adds ref/stream; failure keeps count/truncation with
`detail_retained=false` and no ref. `remote_output_read` instead preserves its
original ref while reducing the current page. Its offset unit is always raw
stored bytes for UTF-8 and Base64. If the renderer includes
`actual_inline_raw_bytes`, it sets
`next_offset = requested_offset + actual_inline_raw_bytes`; `eof` is true only
when that raw position reaches the stored stream end. UTF-8 shrinkage stops on
a code-point boundary, while Base64 shrinkage selects raw bytes before
encoding. Multi-page tests must reassemble the original bytes exactly with no
gap or overlap. `remote_hosts` is not capped at five entries: five is only expected peak
concurrency, so a large configured host list must use the same retained compact
fallback without probing any host.

Retention provenance is explicit and truthful:

```rust
pub enum RetentionProvenance {
    Remote(RemoteContext),
    Aggregate { kind: AggregateKind, source_count: usize },
}

pub async fn retain_serialized_detail<T: Serialize + Send + 'static>(
    &self,
    provenance: RetentionProvenance,
    owned: T,
    cancel: CancellationToken,
) -> BridgeResult<OutputReference>;
```

`OutputReadResult` carries this provenance enum. A remote page may expose its
host/root/shell; an aggregate page exposes aggregate kind and source count and
must omit, rather than invent, single-host context. `remote_hosts` retention is
`Aggregate { kind: Hosts, source_count }`; list/stat/search/read use their real
single-host `RemoteContext`. The bridge serializes the owned value directly to
a bounded private spool (moving blocking serializer work off the async runtime
where needed), so neither bridge nor MCP first builds a second large `Vec<u8>`
or `serde_json::Value`. Admission, cancellation, expiry, and byte counting stay
inside the bridge-owned facade.

The facade imports the crate-root compiled `MAX_OUTPUT_BYTES = 64 MiB` and
enforces it against serialized
canonical bytes, not an estimate of the source model or its raw input. A
counting/capped spool writer accepts exactly the limit and fails on the first
byte over it. Overflow, cancellation, serializer failure, or admission failure
removes the temporary spool and returns no reference; the renderer treats this
as best-effort retention failure (`detail_retained=false`) without changing
truth or counts.

Admission is globally bounded with explicit config fields and ceilings:

```rust
pub const DEFAULT_GLOBAL_SPOOL_QUOTA_BYTES: u64 = 512 * 1024 * 1024;
pub const MIN_GLOBAL_SPOOL_QUOTA_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_GLOBAL_SPOOL_QUOTA_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_RETENTION_SERIALIZATION_JOBS: usize = 2;
pub const MAX_RETENTION_SERIALIZATION_JOBS: usize = 4;
pub const MAX_SPOOL_ENTRIES: usize = 1024;

pub struct Limits {
    pub global_spool_quota_bytes: u64,
    pub retention_serialization_jobs: usize,
}
```

Config validation accepts `global_spool_quota_bytes` only in the inclusive
range `[MIN_GLOBAL_SPOOL_QUOTA_BYTES, MAX_GLOBAL_SPOOL_QUOTA_BYTES]`.
The MCP bootstrap copies both validated limit values before moving the loaded
config, then passes them explicitly to `OutputStore::with_limits`. Constructor
tests use non-default quotas throughout 64--511 MiB and job counts 1--4, so
neither configuration field can silently fall back to a store default.

The quota covers actual committed and temporary bytes for every bridge-owned
spool, including command stdout/stderr, fixed-command `capture_internal`, and
serialized retained detail. Command and internal capture reserve each next
chunk atomically; a partial write releases its unused tail and a failed write
rolls the chunk back. Their two streams share the ledger. Exact quota succeeds
and the next racing byte fails. On a fresh store, five simultaneous maximum
outputs total 320 MiB and two default retention reservations add 128 MiB, so
the 448 MiB combination fits the 512 MiB default with 64 MiB remaining. Later
light-output/internal calls are not rejected by a theoretical reservation.

Generic detail retention uses a deliberately different admission order:
`try_acquire` one of the two/four serializer jobs, acquire one pending entry
slot, then atomically reserve the full 64 MiB `MAX_OUTPUT_BYTES`, all before
starting `spawn_blocking`. Any miss returns best-effort false/no-ref without
spending serialization CPU. The blocking capped writer checks cancellation at
least every 64 KiB. Once started, the async caller always awaits the blocking
join and cleanup; it never detaches work. A successful commit shrinks the
64 MiB reservation to actual serialized length.

`MAX_SPOOL_ENTRIES=1024` is a compiled pending-plus-committed entry-slot limit,
and each entry owns at most two spool files. A slot is acquired before any temp
file is created, preventing empty/small files from bypassing the byte quota.
Quota saturation during command/internal capture follows typed `OUTPUT_LIMIT`
termination; detail saturation returns false/no-ref. Cancellation, overflow,
or serializer failure unlinks partial files. Accounted bytes and the entry slot
are released only after unlink succeeds or reports `NotFound`; another unlink
error keeps the charge and a tombstone for bounded retry, never releases first.
Expiry, explicit removal, and shutdown use the same rule; the entry slot is
released only after all files for the entry are gone. Job permits are released
after the awaited serializer/cleanup completes.

Under the entry lock, `remote_output_read` checks expiry and synchronously opens
a new independent handle for the selected private pathname. Only after open
succeeds does it create the ref-counted byte/entry lease and release the lock.
It neither publishes a lease before open nor keeps handles on committed
entries, and separate readers never share an open-file-description cursor. TTL
expiry or explicit discard that wins the lock removes and unlinks the entry; a
reader that wins finishes from its independent handle. Ledger charge and entry
slot remain pinned until the final reader lease closes.

Therefore default and hard-configured worst-case spool disk are both 512 MiB,
and at most 2,048 spool files exist, all independent of
`max_inflight`. Tests cover exact quota/next-byte races, exact 1,024-slot and
next-slot rejection, two-file enforcement, job saturation, exact/+1 serialized
payload, partial writes, 64 KiB cancellation checks, awaited joins, unlink
success/`NotFound`/failure tombstone retry, zero premature ledger/slot release,
TTL/discard-versus-reader lock orders, a directed regression for the former
lease-before-open window, 1,024 committed entries without resident-FD
amplification, concurrent pages at different offsets, last-reader release, and
shutdown cleanup.

The outcome vocabulary is truthful per operation: successful guarded
write/patch can be `applied`, Task 6 can be `partial`, Task 5 uncertainty is
`unknown`, and pre-mutation rejection is `not_applied`. Because arbitrary shell
effects cannot be inferred, `remote_run` never claims its effects were applied;
its compact fallback preserves execution completion/exit status,
`remote_process_may_continue`, output counts, and an unknown mutation-effect
indicator. Progress counts are included only where meaningful.

The capped writer is a final invariant check, not a semantic fallback engine.
An unexpected overflow before any mutation result exists may become a fixed
`-32603`; overflow of a truth-bearing tool result closes the connection rather
than replacing its mutation truth. No partial line is ever written.

Nothing else writes stdout. Server diagnostics go to stderr with caller and
remote values omitted. Captured remote stderr is data owned by the output
store and never becomes local MCP logging.

## 8. Lifecycle, Dispatch, and Cancellation

### 8.1 State machine

```text
AwaitInitialize --initialize/result--> AwaitInitialized
AwaitInitialized --notifications/initialized--> Ready
Ready --EOF/process shutdown--> Closing
```

- Only `initialize` is accepted in `AwaitInitialize`.
- A second initialize is invalid.
- `notifications/initialized` is accepted exactly once after the initialize
  result.
- `ping` is accepted in both `AwaitInitialized` and `Ready`.
- `tools/list` and `tools/call` require `Ready`.
- Unknown requests return `-32601`; unknown notifications are ignored.
- Notifications never receive JSON-RPC responses.
- MCP defines no shutdown request for this surface; EOF and process signals
  are the orderly shutdown path.

The initialize request requires `protocolVersion`, open-object `capabilities`,
and version-specific `clientInfo` as defined in Section 6.3. The result contains
the selected version, server name/version, `capabilities.tools.listChanged=false`,
and short instructions that all data is remote/untrusted, Bash selection is
explicit, and cancelling a mutating call can leave partial or unknown remote
effects. The client must inspect state/results and must not blindly retry.

### 8.2 Tool-service boundary

Task 7 is independently testable through a stub service:

```rust
pub struct ToolCallContext {
    pub cancel: CancellationToken,
    pub wire_budget: WireBudget,
}

pub type ToolFuture = Pin<
    Box<
        dyn Future<Output = CallToolResult> + Send + 'static,
    >,
>;

pub trait ToolService: Send + Sync + 'static {
    fn definitions(&self) -> &[ToolDefinition];
    fn call(
        &self,
        name: String,
        arguments: serde_json::Value,
        context: ToolCallContext,
    ) -> ToolFuture;
}
```

The lifecycle owner validates the `tools/call` envelope and registry name before
calling the service. For a known tool, the service's first step is typed
argument decoding. Any known-tool schema failure returns
`CallToolResult::invalid_argument(actionable_safe_text)` and launches no bridge
operation; it is not a protocol error. The safe text identifies the accepted
field/shape or corrective action without including serde diagnostics or caller
data. Unknown names never enter `ToolService::call`.

The lifecycle owner computes `WireBudget` for the accepted request ID before it
spawns the future and passes that budget together with the cancellation token
in `ToolCallContext`. Dispatch passes `context.cancel` unchanged to the one
bridge operation and passes `context.wire_budget` unchanged to success,
validation, and error renderers. No tool implementation reads a global frame
limit or guesses its own response allowance.

`McpServer<S>` owns `Arc<S>`, the effective frame bound, and an in-flight tool
limit equal to the validated configured global concurrency. Protocol parsing,
ping, and cancellation do not consume a tool permit.

Request-versus-notification shape is decided before any method side effect.
`initialize`, `ping`, `tools/list`, and `tools/call` without an ID are ignored
as invalid notifications with zero state/service effect and no response.
Any present null, fractional, object/array/bool, or overlong ID is an invalid
request with fixed `-32600` and `id=null`, never a notification.
`notifications/initialized` and `notifications/cancelled` carrying a valid
nonduplicate ID are invalid requests: they receive fixed `-32600 Invalid
Request` for that ID and have zero state/cancellation effect. A duplicate legal
ID follows the earlier global duplicate rule. Every malformed notification is
response-free and side-effect-free.

The lifecycle owner selects between the next input frame and the next joined
tool completion. It therefore continues reading cancellation notifications
while calls are blocked. Each accepted `tools/call` inserts exactly one
request ID and token before spawning. Duplicate in-flight IDs and calls above
the bound receive fixed errors without spawning a tool future.

Duplicate outstanding IDs receive fixed `-32600`, message
`Duplicate request id`, and `id=null` to avoid an ambiguous second response for
the original ID. Validation order is strict JSON and envelope/legal ID,
duplicate ID globally, lifecycle/method params, known name, then saturation.
Thus every repeated legal in-flight ID gets the duplicate error regardless of
the second method/params/name/load. String `"1"` and number `1` are distinct.
The second request never overwrites the first, consumes no slot, and a later
cancellation still targets the original. Reuse is allowed after removal.

`ToolService::call` executes inside the spawned task so a panic during future
construction or polling cannot unwind the owner. A panic-safe task-ID-to-
request-ID association, such as `JoinSet::join_next_with_id`, recovers the ID
from every `JoinError`. Every success, error, panic, cancellation, and shutdown
path removes both associations and releases its owned slot exactly once. While
the connection remains active and the call was not client-cancelled, a
recoverable panic produces fixed `-32603` without panic payload; otherwise its
response is suppressed. An association
invariant failure closes the connection rather than guessing.

### 8.3 Cancellation races

A valid cancellation notification refers only to an outstanding client
request. The owner removes no registry entry at notification time; it marks
the entry cancelled and triggers its token. When the task finishes, the owner
removes the entry and discards its response. This ordering handles:

- cancellation before the tool observes the token;
- cancellation racing a successful completion already queued to the owner;
- duplicate cancellation;
- a late cancellation after the response was written; and
- unknown numeric/string IDs.

An unknown, completed, malformed, or initialize-targeting cancellation
notification is ignored. Its optional reason is neither reflected nor logged.

Cancellation params are an object with required bounded string/integer
`requestId`, optional at-most-1,024-UTF-8-byte string `reason`, and optional
open-object `_meta`. Missing/null/fractional/oversized IDs, non-string reasons,
and non-object params are invalid and side-effect-free. June negotiation
discards other bounded top-level params; November rejects them. Unnegotiated
`task` is rejected in both. A cancellation notification always needs
`requestId`; task-only cancellation is not supported. All fields and version-
specific closure are validated before any registry lookup or token trigger.
Reason is borrow-validated in place and never cloned.

The biased select orders writer result first, input second, and tool completion
third. Writer failure cannot be input-starved, and an already-buffered
cancellation wins over its simultaneously ready completion. Immediately after
each handled frame the owner invokes `try_join_next_with_id` at most once and
processes the result if present, preventing notification floods from starving
tool cleanup.

On EOF, all tokens are cancelled. The owner continues reaping tasks through a
MCP-specific 250 ms task-cleanup grace and then aborts and drains remaining
local tasks. Closing rejects dispatch; partial EOF may enqueue only its fixed
parse error; then the global suppression/cancellation phase ensures
cooperative, uncooperative, panicked, or simultaneously ready completions emit
nothing. A call line past the writer's suppression-check commit is not
retractable.
Clean EOF enqueues nothing and returns success after healthy cleanup. Partial
EOF returns fixed `PROTOCOL_ERROR`/`partial MCP frame at EOF` after delivering
its parse error; failure to enqueue that error becomes fixed MCP transport
failure. `SshRunner`
remains responsible for terminating process groups and reporting whether a
remote process may continue.

## 9. Exact Nine-Tool Surface

All schema roots and nested objects use `type="object"` and
`additionalProperties=false`. JSON Schema length constraints are advisory
character counts; bridge byte checks remain authoritative.

Every `host` property has `minLength=1`, `maxLength=128`, and pattern
`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. Path and cwd properties have
`minLength=1` and `maxLength=65536`. Query has the same 65,536-character
advisory maximum. Command has `minLength=1` and `maxLength=8388608`; the
rendered shell command still must fit the effective byte frame. Patch text has
`minLength=1` and `maxLength=4194304`. Encoded write content and encoded stdin
have `maxLength=5592408`, the padded Base64 width of a 4 MiB raw value; the
bridge enforces the smaller decoded byte ceiling for both encodings.

### 9.1 `remote_hosts`

- Arguments: empty object.
- Does not force network access or probing.
- Annotations: read-only, non-destructive, idempotent, closed world.

### 9.2 `remote_list`

- Required: `host`.
- Optional: `path` default `.`, `depth` 1–32, `include_hidden` default false,
  `max_entries` 1–10,000.
- Annotations: read-only, non-destructive, idempotent, open world.

### 9.3 `remote_stat`

- Required: `host`, `paths` with 1–256 strings.
- Annotations: read-only, non-destructive, idempotent, open world.

### 9.4 `remote_search`

- Required: `host`, nonempty `query`.
- Optional: `path` default `.`, `globs` up to 128 strings of at most 4,096
  characters, `max_results` 1–10,000, `binary` default false.
- Annotations: read-only, non-destructive, idempotent, open world.

### 9.5 `remote_read`

- Required: `host`, `paths` with 1–32 strings.
- Optional: `start_line` at least 1, `max_lines` 1–100,000, `max_bytes`
  1–1,048,576.
- Annotations: read-only, non-destructive, idempotent, open world.

### 9.6 `remote_output_read`

- Required: `output_ref` matching `^[0-9a-f]{32}$`, `stream` in
  `stdout|stderr`.
- Optional: `offset` default 0, `max_bytes` 1–1,048,576 with default 262,144.
- Does not accept host; provenance supplies host/root/shell.
- Annotations: read-only, non-destructive, idempotent, closed world.

### 9.7 `remote_apply_patch`

- Required: `host`, `patch`.
- Patch text is bounded to 4 MiB by bridge byte admission; Task 6's file,
  hunk, line, path, base, and output limits remain authoritative.
- Annotations: mutating, destructive, non-idempotent, open world.

### 9.8 `remote_write`

- Required: `host`, `path`, `content`, `encoding`, `mode`.
- `encoding` is `utf8|base64`.
- `mode` is exactly one of:

```json
{"kind":"create"}
{"kind":"replace","expected_sha256":"optional 64-character lowercase hex"}
```

- Content decodes to at most 4 MiB; encoded Base64 may be longer.
- Annotations: mutating, destructive, non-idempotent, open world.

### 9.9 `remote_run`

- Required: `host`, nonempty `command`.
- Optional: `cwd` default `.`, `shell` in `auto|bash|sh|login` default auto,
  `timeout_ms` 1–3,600,000, and closed `stdin` object:

```json
{"encoding":"utf8","value":"..."}
{"encoding":"base64","value":"..."}
```

- The host's effective timeout and decoded stdin limits may be lower.
- Annotations: mutating, destructive, non-idempotent, open world.

No `outputSchema` is advertised in Tasks 7 and 8 because structured content is
deliberately metadata-only for payload-bearing tools. Advertising a full
result schema while omitting bulk fields from structured content would be
false.

## 10. Thin Dispatch

`RemoteMcpTools` is constructed with `Arc<RemoteBridge>`. For each tool it:

1. Deserializes the already duplicate-free `arguments` into one dedicated
   `deny_unknown_fields` type.
2. Converts only presentation enums/objects into the public remote request
   type.
3. Calls exactly one `RemoteBridge` method with the request token.
4. Passes the typed success or original `BridgeError` to `mcp::render`.

It does not pre-resolve hosts or paths, probe capabilities, decode Base64,
calculate hashes, construct shell strings, open spool files, retry, or infer
whether a mutation applied. Invalid known-tool arguments return an actionable
`isError=true` result and never call the bridge. Valid arguments call the bridge
once, even for capability mismatch,
disconnect, cancellation, `MutationOutcomeUnknown`, or Task 6 partial failure.

## 11. Single-Copy Result Model

Every tool result has exactly one `TextContent` block whose `text` is compact
JSON, not a prose-only success sentence. For a single-host operation that JSON
contains `remote=true`, `host`, physical `root`, actual `shell` metadata when
known, and the one Agent-visible bulk payload or complete small result. For
`remote_hosts`, the top-level JSON has `remote=true` and each host row includes
host/configured root plus cached physical root/shell when already available.
`structuredContent` repeats only small context, counters, status, hashes,
progress, shell metadata, and opaque references; it never repeats bulk.

Bulk ownership is:

| Tool | Text content owns | Structured content owns |
|---|---|---|
| `remote_hosts` | host list | count and cache-summary flags |
| `remote_list` | entries | remote context, requested path, count, truncated |
| `remote_stat` | per-path entries | remote context and entry count |
| `remote_search` | matches including line content | remote context, engine, count, truncated |
| `remote_read` | per-file content/error payload | remote context, count, returned bytes |
| `remote_output_read` | page data | remote context, stream, encoding, offsets, EOF |
| `remote_apply_patch` | context plus complete small result | context, status, progress/counts, optional ref |
| `remote_write` | context plus complete small result | context, status/counts, optional ref |
| `remote_run` | stdout/stderr head/tail payload | context, shell, lengths, truncation, ref, status |

Bulk fields must not occur in both columns. Tests use unique sentinels and count
their serialized occurrences in the complete MCP line.

UTF-8 payloads remain JSON strings. Non-UTF-8 payloads are Base64 strings with
an encoding tag. Control-heavy valid UTF-8, including NUL, is JSON-escaped by
the compact serializer and remains one framed response. Capped serialization
is authoritative, but renderers budget escaped wire bytes and degrade previews
before reaching it.

Large command output returns bounded head/tail previews and one opaque
`output_ref`. Oversized hosts/list/stat/search/read results and mutation detail
use the same bridge-owned internal result-retention facade so their compact
response can contain a pageable opaque reference. `remote_output_read` pages
only through such references and returns stored host/root/shell or aggregate
provenance. The MCP layer never accepts or constructs a spool path and never
imports `OutputStore`. For non-command retained detail, compact metadata includes
`detail_retained=true` and `output_stream="stdout"`; the bridge stores canonical
detail bytes in that logical stream so the existing nine-tool schema remains
unchanged. If retention fails, `detail_retained=false` and both ref/stream are
absent.

## 12. Error Rendering

Protocol errors use fixed JSON-RPC messages and contain no caller value:

- `-32700` parse error;
- `-32600` invalid request;
- `-32601` method not found;
- `-32602` invalid params;
- `-32603` internal error;
- `-32002` server not initialized;
- `-32001` request too large; and
- `-32000` server busy.

Tool errors use:

```json
{
  "content": [{
    "type":"text",
    "text":"{\"remote\":true,\"host\":\"dev\",\"root\":\"/srv/app\",\"shell\":{\"kind\":\"sh\",\"fallback\":true},\"error\":{\"code\":\"REMOTE_EXIT\",\"message\":\"remote command failed\"},\"warnings\":[\"use POSIX syntax, or request Bash and ensure it is installed\"]}"
  }],
  "structuredContent": {
    "error": {
      "code":"REMOTE_EXIT",
      "message":"<safe bridge message>",
      "retryable":false,
      "details":{"mutation_may_have_applied":false}
    },
    "remote":true,
    "host":"dev",
    "root":"/srv/app",
    "shell":{"kind":"sh","fallback":true}
  },
  "isError":true
}
```

The error text is always compact JSON. It includes every available safe remote
context field (`remote`, host, physical root, selected shell), safe error
code/message, and actionable warnings. Fields not yet known are omitted rather
than invented. `structuredContent` repeats only the same small context/error
metadata and never contains command, stderr, rejected input, or other bulk.
Known-tool argument validation normally has no remote context and may therefore
contain only its safe `INVALID_ARGUMENT` object/action in text JSON.

Rendering does not serialize `BridgeError` directly. It derives a typed
`RenderedErrorCore` containing code, projected message, retryability, and only
non-context details such as mutation truth, progress, byte counts, retention,
and truncation flags. Host, physical root, and shell are extracted from
`ErrorDetails` into one separately rendered context object.
`structuredContent.error` uses `RenderedErrorCore` and therefore cannot repeat
those fields inside `error.details`; the structured top level carries context
once, and Text JSON carries it once. Renderers construct both projections
directly and never serialize a complete error/result and then delete or clone
bulk/context fields.

Wire-safe projections bound all remaining human strings: error message and
suggested action are each at most 1,024 UTF-8 bytes, at most 16 warnings are
emitted, and each warning is at most 1,024 bytes. Stable fixed strings normally
fit unchanged. Before or during UTF-8-bound truncation, every Unicode
`char::is_control()` is normalized to the single ASCII byte `?`; quotes,
backslashes, ordinary Unicode, and other non-control characters are preserved.
An unexpectedly longer safe string is truncated at a UTF-8 boundary and the
metadata sets `message_truncated` or `warnings_truncated`.
Error code, remote context, mutation truth/status/counts, retention status, and
progress are never truncated. The real maximum compact-fallback counting model
starts from a maximum actual `ErrorDetails`, applies `RenderedErrorCore`, and
uses maximum message/action/warnings as well as maximum root and shell version;
the maximum shell version is control-heavy to exercise its largest permitted
JSON expansion, and its safe strings use the worst legal alternating
quote/backslash pattern. It
asserts the root is absent from nested structured error detail and counts only
the intended Text and structured-top-level context copies. Task 4 uses an
equivalent test-only projection; Task 7 must replace it with the real sanitizer
and `RenderedErrorCore` projection.

Known-tool argument validation uses the same result channel with stable code
`INVALID_ARGUMENT`; its text gives a safe correction such as “provide
`arguments.host` as a configured host alias” without copying the rejected
value. It is never JSON-RPC `-32602`. JSON-RPC `-32602` is reserved for malformed
method parameters/envelopes and unknown tool names.

The original `BridgeError` code, retryability, safe message, shell metadata,
remote context, mutation flag, and Task 6 progress remain intact. Rendering
never uses `Debug`, serde's data-bearing error text, SSH stderr, command text,
stdin, patch text, remote file bytes, local runtime paths, ControlPath, agent
socket paths, or OpenSSH resolved configuration.

When selected shell metadata is sh, both success and error rendering include
the fixed actionable Bashism warning: use POSIX syntax, or request Bash and
ensure it is installed. The warning never includes the command text.

## 13. Security Invariants

1. No local subprocess is invoked through a shell.
2. The only intentional caller shell source is `remote_run.command`.
3. Cwd, paths, hashes, queries, globs, modes, output refs, and stdin are data,
   never fixed-script source.
4. Host aliases remain exact allowlist lookups and can never become SSH argv
   options.
5. Unknown fields, duplicate fields, malformed enums, invalid Base64, NUL
   paths/commands, traversal, and over-limit values fail before the affected
   remote operation.
6. MCP does not retry mutations or reclassify unknown outcomes.
7. Remote output is untrusted success data; it is JSON-escaped and never
   printed as server logging or evaluated.
8. Read-only enforcement occurs in the bridge for `remote_write`,
   `remote_apply_patch`, and `remote_run`.
9. `remote_output_read` references are opaque, process-scoped, expiring, and
   provenance-checked by the existing output store.
10. A panic or join failure in one active, non-client-cancelled tool task
    becomes a fixed internal error for that ID; Closing/cancelled responses are
    suppressed, and neither case corrupts another response line.
11. Malformed notifications and request-only methods without IDs perform no
    state transition, cancellation, service invocation, future poll, or remote
    work.
12. Closing suppresses all tool responses globally, and writer/task shutdown is
    bounded, aborted, and drained without reflecting hostile I/O or panic text.

## 14. Resource and Performance Bounds

- Input and output MCP frames: effective configured bound, compiled maximum
  8 MiB.
- In-flight MCP tool calls: configured validated global concurrency, default
  eight and compiled maximum 32.
- Per-host SSH work: existing effective per-host concurrency, default two and
  compiled maximum eight.
- File/output page: at most 1 MiB.
- Patch/write/decoded command stdin: at most 4 MiB.
- Command aggregate output: existing 64 MiB cap; MCP returns only previews and
  opaque paging metadata.
- All bridge-owned spool temp/committed actual bytes share one atomic quota:
  default and compiled ceiling 512 MiB; a fresh store fits five 64 MiB outputs
  plus two 64 MiB retention reservations (448 MiB, leaving 64 MiB).
- Retained-detail serializer jobs: default two, compiled maximum four; this
  semaphore does not cap ordinary light-output commands.
- Pending plus committed spool entries: compiled maximum 1,024, at most two
  files each; unlink errors keep ledger/slot charge behind a retry tombstone.
- Reader retention: at most one frame plus its bounded parsed representation.
- Writer retention: bounded channel times one capped response each.
- No queued frame or task may multiply an unchecked 4–8 MiB payload.
- Parsed JSON: depth 64, 262,144 nodes, 131,072 aggregate object members, and
  1,048,576 aggregate key bytes; duplicate checks reuse the destination map.
- Request ID: at most 256 serialized wire bytes, preserving room for a minimum
  response under every accepted frame configuration.

Five concurrent one-second calls to five different hosts must finish within
1.5 seconds in the release acceptance environment. Cancellation must reach
the existing process-group termination path within 250 ms. Tests also prove
that a sixth or later call above the configured MCP in-flight bound is rejected
without spawning its tool future; the exact rejection point follows the test
configuration rather than the number five.

Release gates also keep bridge dispatch p95 below 2 ms, complete fake-SSH call
p95 below 10 ms, and 64 MiB streamed-output RSS growth below 16 MiB. Wide JSON
array and object tests each run in a separate fresh release child, sample peak
from an idle/warmed baseline, and enforce a 48 MiB delta at maximum accepted
structural budgets. They record raw baseline/peak/delta and avoid allocator
retention or parallel-test contamination while detecting accidental parallel
key-set amplification. Task 11 repeats these measurements as final
whole-product acceptance.

## 15. Test and Acceptance Strategy

### 15.1 Protocol and framing

- both supported version negotiations and an unsupported request;
- exact version-specific `clientInfo` fields, bounded absolute URI/icon
  validation, open capabilities, and open `_meta` on every supported method;
- a six-method golden matrix proving June accepts/discards bounded extra
  top-level params while November applies the project's closed validator to
  the official method fields, with
  closed tool arguments and rejected unnegotiated `task` in both;
- supported 2025-06 rejecting latest-only fields, supported 2025-11 accepting
  them, and an unsupported version accepting the bounded latest union while
  still rejecting fields outside that union;
- missing initialize fields, duplicate initialize, early initialized, and
  pre-ready tool calls;
- JSON-RPC 1.0, non-object JSON, null/fraction/object IDs, duplicate IDs, and
  duplicate object keys at every nesting level;
- exact-limit and limit-plus-one lines, invalid UTF-8, CRLF, multiple buffered
  frames, partial EOF, and recovery after an oversized frame;
- over-depth and over-node/member/key-byte requests plus wide arrays/objects,
  with release RSS evidence that no parallel duplicate-key set amplifies them;
- exact `DuplicateKey` versus `StructuralBudget` versus genuine `Syntax`
  classification, all with fixed non-echoing wire errors;
- `MIN_MCP_FRAME_BYTES`, service-specific exact minimum, exact-min success, and
  min-minus-one construction rejection, including the full nine-tool list and
  a synthetic maximum-size ID;
- the real maximum compact fallback with a worst-case 65,536-byte control-heavy
  physical root present in inner Text JSON and direct structured context, then
  outer-serialized with a maximum ID; it fits at the computed minimum and
  minimum-minus-one construction fails with no root truncation;
- one valid compact output line per response and no stdout diagnostics.

### 15.2 Concurrency and cancellation

- a blocked tool while ping and cancellation remain responsive;
- separate synchronous invocation and first-poll counters proving rejected
  calls consume no service invocation or admission slot;
- request-only methods without IDs and notification-only methods with IDs
  producing zero side effect;
- string/numeric cancellation identity, unknown/duplicate/late cancellation,
  malformed/versioned cancellation shapes, and buffered completion races;
- exact duplicate-ID response and priority versus malformed params, unknown
  name, and saturation, with string/number identity kept distinct;
- suppression of a notification-cancelled call's response;
- propagation of the exact cancellation token and `WireBudget` through
  `ToolCallContext` into validation, dispatch, and render tests;
- future-construction/first-poll/later panic recovery by task ID with one-time
  registry and slot cleanup;
- EOF global suppression, writer failure/backpressure monitoring, and bounded
  MCP-specific task/writer cleanup, including token-ignoring futures;
- in-flight saturation without unbounded task creation; and
- concurrent responses completing out of request order without interleaving;
- buffered-cancel priority plus one `try_join_next_with_id` after every handled
  frame, preventing notification starvation; and
- every async wait protected by a timeout and durable predicate/semaphore gates
  rather than sleeps or lossy `Notify` events.

### 15.3 Schemas and bridge boundary

- exact nine names and order, `remote_` prefix, no SSHFS/probe/delete/raw SSH;
- required fields, defaults, ranges, enums, patterns, root and nested
  `additionalProperties=false`;
- exact read-only/destructive/idempotent/open-world annotations;
- invalid shape, unknown host, read-only, traversal, and request-size failures
  launching zero command children where the bridge contract permits;
- malformed `tools/call` envelopes/unknown names returning `-32602`, while
  every known-tool argument-schema failure returns actionable `isError=true`;
- `remote_hosts` not forcing a probe; and
- shared configured/probed root bounds accepting exactly 65,536 UTF-8 bytes,
  rejecting one byte more, and handling non-ASCII byte boundaries identically;
- one bridge invocation per valid tool call with no MCP retry.

### 15.4 Shell and escaping

- auto Bash, auto-to-sh fallback, explicit sh, explicit Bash missing, and
  login shell metadata;
- actionable sh warning presence on success and later errors, plus
  selected-shell/fallback truthfulness;
- cwd containing quotes, spaces, newlines, glob text, leading hyphen, Unicode,
  backticks, and `$()` remaining one literal path;
- command NUL rejection and rendered-command quote-amplification bound;
- exact UTF-8/Base64 stdin bytes; and
- no unintended local or remote sentinel creation from data-only fields.

### 15.5 Results, errors, and performance

- every network-backed remote result labeled with host and physical root;
  `remote_hosts` labels each entry with host/configured root and includes the
  physical root only when already cached, without probing;
- 1 MiB NUL-heavy and binary payload sent once and within the response bound;
- command stdout/stderr preview, truncation, output ref, paging provenance, and
  expiry;
- aggregate host-list provenance never fabricating host/root/shell, plus
  UTF-8/Base64 raw-byte multi-page reassembly without offset gaps/overlap;
- hostile output resembling JSON-RPC unable to inject another line;
- no SSH stderr, command, stdin, patch, file bytes, socket path, or ControlPath
  in errors;
- Task 5 unknown and Task 6 partial/unknown progress preserved exactly;
- forced response-budget fallback for hosts/list/stat/search/read/output-read/
  run, preserving context, counts, truncation/offset truth, and a pageable ref
  where retained; `remote_hosts` uses a configured list larger than five;
- injected retention failure for every new read-only bulk ref, preserving
  count/truncation with `detail_retained=false`, plus mutation fallbacks with no
  `-32603`;
- injected result-retention storage/admission failure for applied write,
  partial/unknown patch, and completed run, proving `detail_retained=false`, no
  ref, and unchanged compact truth; successful retention proves the true/ref
  pair;
- bridge-error text parsed as compact JSON with all available remote context,
  safe bounded error/warning fields, context-free `RenderedErrorCore`, and no
  bulk or nested-context duplication;
- direct serialization exact at 64 MiB/+1, a 512 MiB default/hard
  actual-byte spool ledger, concurrent last-byte races, two/four serializer job
  saturation, five maximum command captures plus two default retention
  reservations in one fresh store, light internal captures, and zero
  leaked file/ledger/permit state after failure/TTL/shutdown;
- five hosts completing the acceptance workload concurrently; and
- release-only dispatch, cancellation, and RSS acceptance remaining within the
  main specification.

## 16. Delivery Order

1. Add the high-level run facade and explicit sh semantics with transport and
   remote-operation tests.
2. Add strict JSON/protocol types with pure unit tests.
3. Add bounded stdio reader/writer tests and implementation.
4. Add the asynchronous lifecycle owner, registry, cancellation, and stub tool
   tests.
5. Add exact schemas and closed argument types.
6. Add bridge-only handlers and single-copy rendering.
7. Wire `mcp` process bootstrap.
8. Run focused protocol/tool/security tests, the existing Rust suite, and the
   release acceptance subset before claiming Tasks 7 and 8 complete.
