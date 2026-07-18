# Task 4 High-Level Remote Read Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded, lossless, read-only high-level SSH operations for hosts,
list, stat, read, search, and output paging without Python or direct SSH
launches outside `SshRunner`.

**Architecture:** `RemoteBridge` is a typed facade over one `Arc<SshRunner>`.
The runner gains a crate-private compile-time POSIX-sh protocol path whose
stdout/stderr are always privately spooled and incrementally parsed. Remote
operations use fixed scripts plus positional data, local glob/Base64/hash
processing, strict framing, and the existing SSH lifecycle/concurrency limits.

**Tech Stack:** Rust 1.91.1, Tokio, Serde/serde_json, SHA-256, Base64,
globset, system OpenSSH, POSIX sh, functionally probed Linux utilities.

**Formal-review note:** Tasks 1-8 record the original implementation plan.
Tasks 9-15 below supersede any earlier step that places mismatch retry in
`SshRunner`, aggregates a protocol frame in `read_stream`, filters hidden list
entries locally, or treats planned SIGPIPE as truncation success.

## Global Constraints

- Work only in `/home/wkj/projects/codex-ssh-bridge/.worktrees/rust-ssh-bridge`
  on `feature/rust-ssh-bridge`; preserve the unrelated untracked
  `ssh_bridge/__pycache__/` and `tests/__pycache__/` trees.
- Implement only Task 4. Do not add write/delete/patch behavior, MCP, CLI,
  SSHFS, packaging, or Python runtime/test fixtures.
- No production operation may spawn SSH or a local shell outside `SshRunner`.
- Every fixed command is a `&'static str` script plus separately shell-quoted
  positional values. Never interpolate a caller value into script source.
- Validate every request, including every path in a batch, before `ssh -G` or
  capability probing can start.
- Force-spool fixed protocol streams under a facade-entry cleanup owner and
  consume bounded pages. Do not parse `OutputPreview` as protocol data or rely
  on TTL for ordinary internal cleanup.
- Preserve NUL framing, raw-byte lengths, checked arithmetic, strict caps,
  local padded Base64, local streaming hash where the full file is returned,
  and one guarded remote whole-file hash identity when truncated.
- `remote=true`, host, physical root, and shell occur once per operation
  envelope. Do not repeat them for nested entries.
- Follow red-green-refactor strictly. Run and observe the specified RED before
  each production change.
- The controller requires one final Task 4 commit, not intermediate commits.

---

## File Map

- Modify `Cargo.toml`: add `base64`, `globset`, and runtime `serde_json`.
- Modify `src/error.rs`: add the four stable Task 4 error codes and fixed
  constructors.
- Modify `src/capability.rs`: functionally probe/parse Task 4 utility behavior.
- Modify `src/output.rs`: forced-spool capture and optional output provenance.
- Modify `src/ssh/process.rs`: fixed-protocol execution and minimal crate-private
  cache/config/output views.
- Modify `src/lib.rs`: export `remote`.
- Create `src/remote/mod.rs`: facade, public types, validation, hosts, and
  output paging.
- Create `src/remote/protocol.rs`: incremental spool cursors and strict framing.
- Create `src/remote/read.rs`: raw per-file read protocol and ordered batches.
- Create `src/remote/metadata.rs`: list/stat protocols.
- Create `src/remote/search.rs`: candidate enumeration, glob filtering, and
  rg/grep protocols.
- Modify `tests/fixtures/fake-ssh.sh`: non-Python simulated-remote fixed-command
  execution and functional capability controls.
- Modify `tests/support/mod.rs`: shared Task 4 fixture builders.
- Modify `tests/ssh_transport.rs`: fixed-runner/output/capability regression
  tests.
- Create `tests/remote_ops.rs`: public Task 4 behavior and adversarial tests.
- Create `.superpowers/sdd/task-4-report.md`: final evidence and self-review.

---

### Task 1: Freeze Public Types, Stable Errors, Dependencies, and Preflight Validation

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/error.rs`
- Create: `src/remote/mod.rs`
- Modify: `src/lib.rs`
- Create: `tests/remote_ops.rs`

**Interfaces:**
- Produces `RemoteBridge::new(Arc<SshRunner>)`.
- Produces request types `ListRequest`, `StatRequest`, `ReadRequest`,
  `SearchRequest`, and `OutputReadRequest` exactly as defined in the Task 4
  design.
- Produces `EncodedValue`, `RemoteContext`, `ShellMetadata`, `HostInfo`,
  `RemoteMetadata`, and the six public result types.
- Adds `ErrorCode::{ReadConflict, NotFound, PermissionDenied, NotDirectory}`.
- Adds private validators that resolve all `RemotePath`s before runner access.

- [ ] **Step 1: Add compile-failing public-shape tests**

Add `tests/remote_ops.rs` with `#![deny(unsafe_code)]`, `mod support;`, imports
for every Task 4 type, and construction plus exact JSON snapshot tests. The
snapshots cover every top-level result, every success/error tag, every enum
spelling, flattened envelope fields, and explicit JSON `null` for each absent
optional field:

```rust
#[test]
fn task4_request_and_result_shapes_are_closed_and_serializable() {
    let request = ReadRequest {
        host: "dev".to_owned(),
        paths: vec!["src/main.rs".to_owned()],
        start_line: None,
        max_lines: None,
        max_bytes: None,
    };
    assert_eq!(request.start_line, None);

    let error = BridgeError::new(ErrorCode::ReadConflict, "remote file changed while being read", false);
    assert_eq!(serde_json::to_value(error).unwrap()["code"], "READ_CONFLICT");
}
```

Also add table tests for the bound constants and invalid requests: empty host,
empty query, CR/LF query, 64-KiB-plus-one path/query, 257 stat paths, 33 read
paths, depth 0/33, entries 10,001, results 10,001, 129 globs,
4-KiB-plus-one glob, leading-`!`, absolute/traversal/NUL glob, start line 0,
max lines 0/100,001, and `max_bytes` above the host limit. Add aggregate-size
cases where individually valid fields exceed `max_frame_bytes`, including many
maximum-length stat paths; assert `RequestTooLarge` and zero runner access.

- [ ] **Step 2: Run the new target and verify RED**

Run:

```bash
cargo test --test remote_ops task4_request_and_result_shapes_are_closed_and_serializable -- --nocapture
```

Expected: compilation fails because `codex_ssh_bridge::remote` and the four
new error variants do not exist.

- [ ] **Step 3: Add dependencies, error variants, public types, and pure validators**

Move `serde_json` to normal dependencies and add:

```toml
base64 = "0.22"
globset = "0.4"
serde_json = "1.0"
```

Add the four `ErrorCode` variants in `src/error.rs`. Add constructors with
fixed messages and no untrusted text:

```rust
pub(crate) fn read_conflict() -> BridgeError {
    BridgeError::new(ErrorCode::ReadConflict, "remote file changed while being read", false)
}

pub(crate) fn not_found() -> BridgeError {
    BridgeError::new(ErrorCode::NotFound, "remote path was not found", false)
}

pub(crate) fn permission_denied() -> BridgeError {
    BridgeError::new(ErrorCode::PermissionDenied, "remote path permission was denied", false)
}

pub(crate) fn not_directory() -> BridgeError {
    BridgeError::new(ErrorCode::NotDirectory, "remote path is not a directory", false)
}
```

Create the exact public structs/enums and serde attributes from the design and
private resolved request types. Validation must call `config.host` first only
as a local lookup, resolve every path with `RemotePath::resolve`, validate the
entire vector, and checked-sum the full logical request frame before returning
a fully resolved request. It must not call an async runner method.

Use these exact defaults/constants:

```rust
const MAX_INPUT_PATH_BYTES: usize = 64 * 1024;
const MAX_STAT_PATHS: usize = 256;
const MAX_READ_PATHS: usize = 32;
const DEFAULT_LIST_DEPTH: u32 = 1;
const MAX_LIST_DEPTH: u32 = 32;
const DEFAULT_LIST_ENTRIES: usize = 1_000;
const MAX_LIST_ENTRIES: usize = 10_000;
const DEFAULT_SEARCH_RESULTS: usize = 100;
const MAX_SEARCH_RESULTS: usize = 10_000;
const MAX_QUERY_BYTES: usize = 64 * 1024;
const MAX_GLOBS: usize = 128;
const MAX_GLOB_BYTES: usize = 4 * 1024;
const DEFAULT_START_LINE: u64 = 1;
const DEFAULT_MAX_LINES: u64 = 2_000;
const MAX_LINES: u64 = 100_000;
```

Export `pub mod remote;` from `src/lib.rs`.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run:

```bash
cargo test --test remote_ops task4_request_and_result_shapes_are_closed_and_serializable -- --nocapture
cargo test --test remote_ops request_validation -- --nocapture
```

Expected: the public-shape test and all pure validation cases pass. Remote
methods may still return a fixed internal “not implemented” error; no test may
pretend remote behavior is green yet.

---

### Task 2: Add Forced-Spool Fixed Execution and Output Provenance

**Files:**
- Modify: `src/output.rs`
- Modify: `src/ssh/process.rs`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/fixtures/fake-ssh.sh`

**Interfaces:**
- Produces crate-private `FixedRunRequest` and `FixedRunResult`.
- Produces `SshRunner::execute_fixed`, `cached_capability`,
  `invalidate_capability`, `config`, `read_output`, `output_provenance`, and
  `discard_output` as crate-private APIs.
- Produces `CaptureMode::{Adaptive, ForceSpool}`, `InternalSpoolOwner`,
  `InternalSpoolRegistration`, `InternalCapturedOutput`, and
  `OutputProvenance`.
- Preserves public `SshRunner::execute` and `OutputStore::read` behavior.

- [ ] **Step 1: Write failing fixed-runner/output tests**

Because the new runner/output APIs are deliberately crate-private, add their
direct tests to the existing `#[cfg(test)]` modules in `src/ssh/process.rs` and
`src/output.rs`. Keep `tests/ssh_transport.rs` for public regression coverage:

```rust
#[tokio::test]
async fn fixed_runner_quotes_every_value_as_a_positional_and_forces_a_spool() {
    // Use values containing quote, newline, leading hyphen, $(...), and backticks.
    // Assert the fixed script text occurs once, values are recovered as $1..,
    // stdout bytes are complete even above the normal preview share, the
    // returned reference exists, and shell is explicit PosixSh/fallback=false.
}

#[tokio::test]
async fn command_output_reference_carries_host_root_and_shell_provenance() {
    // Execute a normal command that spills. Assert provenance can be read by
    // token and contains dev, /srv/project, and the selected shell.
}

#[tokio::test]
async fn fixed_internal_capture_never_enters_the_public_token_map() {
    // Consume a fixed result, then assert no public token exists and the
    // private spool directory is empty after owner close.
}
```

Add stream-ceiling, pre-cancelled, deadline, stdin-NUL, malformed executable,
and hostile positional tests. Add a deterministic blocked-capture test that
aborts the facade future after both spool paths are registered and asserts the
paths disappear immediately without advancing TTL. Add the inverse race where
the owner drops before capture registers: the late-created path must be
unlinked immediately. Extend the fake fixture with
`FAKE_SSH_MODE=local-fixed`, which executes only the already-rendered final
remote command via `/bin/sh -c`; it remains test-only.

- [ ] **Step 2: Run the fixed-runner tests and verify RED**

Run:

```bash
cargo test --lib fixed_runner -- --nocapture
cargo test --lib output_provenance -- --nocapture
```

Expected: library-test compilation fails for missing fixed
request/capture/provenance APIs.

- [ ] **Step 3: Implement force-spool and provenance in `OutputStore`**

Extend capture internals without changing existing adaptive defaults:

```rust
pub(crate) enum CaptureMode {
    Adaptive,
    ForceSpool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutputProvenance {
    pub host: String,
    pub physical_root: String,
    pub shell: ShellSelection,
}
```

`ForceSpool` must create both mode-0600 stream files before draining, including
for empty streams. Add independent post-capture stream-length validation.
Internal captures bypass the public token map and expose only crate-private
bounded page reads. `InternalSpoolOwner` owns the strong cleanup registry;
capture receives only a weak registration handle, registers paths atomically,
and immediately unlinks a late path after owner closure. Owner drop closes the
registry and unlinks all registered names synchronously. Store optional
provenance only in public `SpoolEntry`; keep `read` backward-compatible and add
crate-private provenance lookup. Never expose a spool path.

- [ ] **Step 4: Implement fixed rendering/execution in `SshRunner`**

Add:

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

Render by quoting the static script and each argument with `shell_word`; use a
fixed literal argv-zero. Validate stdin and output sums with checked arithmetic
against compiled bounds. Reuse host initialization, semaphores, process groups,
deadlines, and cancellation. Capture tasks/results must never retain a strong
cleanup owner. Attach provenance only for normal command output, not fixed
internal captures.

- [ ] **Step 5: Run fixed transport regression and verify GREEN**

Run:

```bash
cargo test --test ssh_transport exact_64_mib -- --nocapture
cargo test --test ssh_transport cancellation -- --nocapture
cargo test --lib fixed_runner -- --nocapture
cargo test --lib output_provenance -- --nocapture
```

Expected: all selected tests pass; existing adaptive preview/spill and
cancellation timing behavior is unchanged.

---

### Task 3: Functionally Probe Task 4 Protocol Behaviors

**Files:**
- Modify: `src/capability.rs`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/fixtures/fake-ssh.sh`

**Interfaces:**
- Produces capability keys `read_slice`, `find_nul`, `stat_printf`, `rg_json`,
  `grep_nul`, `xargs_nul`, and `search_bound` in `Capability::tools`.
- Existing capability keys and strict parser behavior remain supported.

- [ ] **Step 1: Add failing functional-probe tests**

Create a real temporary probe tree containing a NUL byte, an empty line, a
missing final newline, a hidden directory, a symlink, and a filename with a
newline. Run `CAPABILITY_PROBE_SCRIPT` and assert each new true flag corresponds
to observed functional output, not only `command -v`.

Add fake incompatible binaries ahead of `PATH` one at a time for `rg`, `find`,
`grep`, `stat`, the selected read primitive, `xargs`, `mktemp`, `mkfifo`, and
`head`. Break the same-fd drain/final-status behavior separately. Assert only the
matching functional flag becomes false. Add malformed/duplicate new-key parser
cases.

- [ ] **Step 2: Run probe tests and verify RED**

Run:

```bash
cargo test --test ssh_transport task4_capability -- --nocapture
```

Expected: failures show the new keys are missing or rejected as unknown.

- [ ] **Step 3: Implement exact functional probes**

Inside the probe's existing private directory, create fixed sample files and
test the exact commands chosen by the fixed protocols. For `search_bound`,
probe mode-0700 scratch creation, FIFO flow, `head -c` byte-plus-one cutoff,
trap cleanup, sequential NUL xargs, and final-status precedence after draining
without `pipefail`. Emit only `0` or `1`. Extend `TOOL_NAMES` with the
exact seven keys and keep unknown-key rejection.

The fake probe must expose environment switches such as
`FAKE_SSH_HAS_RG_JSON=0` while defaulting other functional Task 4 flags true.
Do not infer one flag from another in Rust.

- [ ] **Step 4: Run capability suite and verify GREEN**

Run:

```bash
cargo test --test ssh_transport task4_capability -- --nocapture
cargo test --test ssh_transport parser_ -- --nocapture
cargo test --test ssh_transport fixed_probe_script -- --nocapture
```

Expected: functional and strict-parser cases pass, and the probe directory is
empty after execution.

---

### Task 4: Implement Incremental Protocol Cursors, Hosts, and Output Paging

**Files:**
- Create: `src/remote/protocol.rs`
- Modify: `src/remote/mod.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Produces `SpoolCursor` over `InternalCapturedOutput` with bounded `read_page`, `read_until_nul`,
  `read_json_line`, `read_exact_bytes`, and EOF validation.
- Produces local `RemoteBridge::hosts` and provenanced
  `RemoteBridge::output_read`.

- [ ] **Step 1: Add failing cursor/hosts/output tests**

Write tests proving:

- hosts are sorted by alias, include configured root/read-only/description,
  show cached physical root/shell only after a prior operation, and log zero SSH
  calls when invoked alone;
- output pages preserve raw offsets and use UTF-8 only for valid no-NUL bytes,
  otherwise padded Base64;
- an unprovenanced internal token, expired token, malformed token, oversized
  page, and pre-cancelled page are rejected;
- NUL and JSON records split at every page boundary parse correctly;
- an overlong/incomplete record, invalid number, invalid UTF-8 metadata, extra
  field, and trailing bytes return `ProtocolError` and discard the spool.
- aborting each fixed-operation facade while its cursor is blocked drops the
  entry owner and removes all registered internal paths without waiting for
  TTL.

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```bash
cargo test --test remote_ops hosts_ -- --nocapture
cargo test --test remote_ops output_read_ -- --nocapture
cargo test --test remote_ops protocol_cursor_ -- --nocapture
```

Expected: unimplemented remote methods fail the focused behavior assertions.

- [ ] **Step 3: Implement the cursor and common encoders**

Read fixed 64-KiB pages from `InternalCapturedOutput`, retain only the
unfinished record, and check each addition before allocation. Implement local
value classification:

```rust
fn encode_bytes(bytes: &[u8]) -> EncodedValue {
    match std::str::from_utf8(bytes).ok().filter(|_| !bytes.contains(&0)) {
        Some(text) => EncodedValue::utf8(text.to_owned()),
        None => EncodedValue::base64(STANDARD.encode(bytes)),
    }
}
```

Create the cleanup owner before any async runner access and retain it through
the full facade parse. Normal completion explicitly closes it; handled errors
and future abort use drop. Ensure every parser path releases its internal
capture, including fixed remote errors.

- [ ] **Step 4: Implement hosts and output paging**

`hosts()` reads config/cached capabilities only. `output_read()` parses the
opaque reference, races the local page read against cancellation, requires
provenance, and returns one `RemoteContext` plus encoded page bytes and raw
offset metadata.

- [ ] **Step 5: Run focused tests and verify GREEN**

Run:

```bash
cargo test --test remote_ops hosts_ -- --nocapture
cargo test --test remote_ops output_read_ -- --nocapture
cargo test --test remote_ops protocol_cursor_ -- --nocapture
```

Expected: all focused cases pass and private spool files are removed.

---

### Task 5: Implement List and Batched Stat

**Files:**
- Create: `src/remote/metadata.rs`
- Modify: `src/remote/mod.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Produces `RemoteBridge::list(ListRequest, CancellationToken)`.
- Produces `RemoteBridge::stat(StatRequest, CancellationToken)`.
- Uses exact six-field NUL list records and one status-plus-metadata stat record
  per requested path.

- [ ] **Step 1: Add failing list tests**

Build a temporary fake-remote tree with regular file, directory, symlink,
FIFO, Unix socket, hidden children at multiple depths, quote/newline/glob text,
leading hyphen, and a non-UTF-8 filename. Assert:

```rust
assert_eq!(result.context.remote, true);
assert_eq!(result.context.host, "dev");
assert_eq!(result.entries[0].metadata.kind, RemoteFileKind::Directory);
assert!(matches!(non_utf8.relative_path.encoding, ValueEncoding::Base64));
```

Cover depth 1/2/32, root exclusion, hidden pruning, raw-byte sorting, exact
metadata, `max_entries + 1` truncation, configured-root symlink dereference,
descendant symlink no-follow, and operation-level not-found/permission/not-dir.

- [ ] **Step 2: Run list tests and verify RED**

Run:

```bash
cargo test --test remote_ops list_ -- --nocapture
```

Expected: `RemoteBridge::list` still returns its temporary unimplemented error.

- [ ] **Step 3: Implement the fixed list script and strict parser**

Use the configured root operand with an explicit dereferencing `/.` only at
the starting point. For hidden=false, enumerate visible starting children and
use fixed find pruning for nested dot basenames. Emit raw actual path, kind,
size, low-12-bit mode, mtime seconds, and nanoseconds as six NUL fields. Cap at
`max_entries + 1` complete entries remotely. Parse incrementally, derive raw
relative paths by an exact root-prefix boundary, sort locally, retain the
requested count, and set exact truncation.

The script suppresses utility stderr and emits one fixed error token for root
failures. A missing functional tool exits zero and emits only the strict
required-key `CAPABILITY_MISMATCH` record from the design.

- [ ] **Step 4: Run list tests and verify GREEN**

Run:

```bash
cargo test --test remote_ops list_ -- --nocapture
```

Expected: every list case passes and traversal/invalid-limit cases show zero
fake-SSH log entries.

- [ ] **Step 5: Add failing stat tests**

Cover all exact kinds, request-order preservation, lstat of symlinks, mode,
size, negative/pre-epoch and nanosecond timestamps where supported, newline and
leading-hyphen paths, plus mixed success/not-found/permission entries. Inject a
malformed numeric/stat record and require whole-batch `ProtocolError`.
Exercise 256 operands through NUL stdin, including names near 64 KiB, and prove
that xargs splits them while preserving order. An aggregate request above 8
MiB must fail locally with zero SSH calls; no test may rely on host `ARG_MAX`.

- [ ] **Step 6: Run stat tests and verify RED**

Run:

```bash
cargo test --test remote_ops stat_ -- --nocapture
```

Expected: `RemoteBridge::stat` still returns its temporary unimplemented error.

- [ ] **Step 7: Implement batched stat and verify GREEN**

Encode every normalized UTF-8 path in request order into one NUL-delimited
stdin body. Use functionally probed sequential `xargs -0` to form bounded inner
argv batches; no operand enters the outer command line and no host `ARG_MAX`
assumption is allowed. GNU stat must not dereference. Parse mode hex locally to
the exact kind and low 12 bits; parse seconds/nanoseconds with checked ranges.
Require exactly one ordered record per input and map only fixed remote status
tokens to nested errors.

Run:

```bash
cargo test --test remote_ops stat_ -- --nocapture
```

Expected: success/error ordering and protocol fail-closed cases pass.

---

### Task 6: Implement Ordered Batched Raw Reads and Version Hashing

**Files:**
- Create: `src/remote/read.rs`
- Modify: `src/remote/mod.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Produces `RemoteBridge::read(ReadRequest, CancellationToken)`.
- Uses one fixed SSH operation per file, raw stdout, strict NUL stderr metadata,
  and request-order aggregation.

- [ ] **Step 1: Add failing full-read and binary tests**

Cover empty text, UTF-8 text, NUL binary, invalid UTF-8, missing final newline,
quote/newline/leading-hyphen filenames, final-symlink follow, and complete-file
local SHA-256. Assert Base64 is padded and `raw_bytes` counts decoded bytes.

- [ ] **Step 2: Run selected read tests and verify RED**

Run:

```bash
cargo test --test remote_ops read_full_ -- --nocapture
cargo test --test remote_ops read_binary_ -- --nocapture
```

Expected: the temporary unimplemented read path fails.

- [ ] **Step 3: Implement the one-file fixed read and full-file fast path**

The fixed script receives absolute path, start line, inclusive end line, and
remaining byte budget. It checks the exact read capabilities, existence,
readability, and regular-file semantics. It calculates size/LF-aware line
count. Only when the complete file fits does it stream the file directly and
mark `FULL=1`; Rust hashes stdout incrementally and retains no extra byte.

Expected filesystem failures are stderr metadata with exit 0 so the runner
does not replace them with a transport error. No arbitrary diagnostic is
included.

- [ ] **Step 4: Run full/binary tests and verify GREEN**

Run:

```bash
cargo test --test remote_ops read_full_ -- --nocapture
cargo test --test remote_ops read_binary_ -- --nocapture
```

Expected: full reads, local hashes, and encoding pass.

- [ ] **Step 5: Add failing truncation/race/batch tests**

Cover start lines before/at/past EOF, max lines, byte ceiling, a line exactly at
the ceiling, empty final segment, binary LF selection, aggregate budget across
32 paths, zero remaining budget entries, deterministic request-order results,
missing/unreadable/wrong-kind per-file errors, and a hash-before/hash-after race
returning `ReadConflict` with no content. Run two independent host batches and
assert they can overlap through the runner's global concurrency.

Add cancellation after two file tasks start and assert no new file operation is
scheduled. Add an invalid last path and assert zero total launches.

- [ ] **Step 6: Run truncation tests and verify RED**

Run:

```bash
cargo test --test remote_ops read_truncated_ -- --nocapture
cargo test --test remote_ops read_batch_ -- --nocapture
cargo test --test remote_ops read_conflict_ -- --nocapture
```

Expected: missing guarded-truncation behavior fails.

- [ ] **Step 7: Implement guarded truncated reads and ordered orchestration**

For a non-full selection, hash the whole file before, stream no more than
`remaining + 1` selected bytes, then hash again. Validate both as lowercase
64-hex. If they differ, discard the bytes and return `ReadConflict`. Otherwise
retain at most remaining, classify/encode locally, and compute exact before/
after truncation from file size, line count, and lookahead.

Process files sequentially within one batch so each operation receives the
actual remaining aggregate byte budget. This makes retained bytes, lookahead,
and zero-budget entries deterministic without downloading up to 1 MiB for each
of 32 files. Do not add a second semaphore: independent requests and hosts
remain concurrent through the runner's authoritative semaphores. Stop the loop
immediately after cancellation; the in-flight fixed SSH operation receives the
same token.

- [ ] **Step 8: Run all read tests and verify GREEN**

Run:

```bash
cargo test --test remote_ops read_ -- --nocapture
```

Expected: all full, binary, line, byte, batch, race, error, and cancellation
cases pass.

---

### Task 7: Implement Literal Search with Shared Local Glob Semantics

**Files:**
- Create: `src/remote/search.rs`
- Modify: `src/remote/mod.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Produces `RemoteBridge::search(SearchRequest, CancellationToken)`.
- Produces public serialized `SearchEngine::{Rg, Grep}` and private bounded
  FIFO/scratch producer helpers.
- Sends filtered non-UTF-8 candidate paths back to the fixed script only as
  NUL-delimited stdin, never as shell-rendered arguments.

- [ ] **Step 1: Add failing candidate/glob tests**

Cover hidden and ignored files, root-relative `*`, `?`, classes, `**`, multiple
positive globs, slash awareness, no descendant symlink follow, regular-file
only candidates, non-UTF-8 names, raw-byte ordering, 10,001-candidate
truncation, and an 8-MiB-plus-one enumeration. Cover a single candidate record
larger than the bound, a trailing partial record after complete records, find
status 1/2, same-fd FIFO drain, unexpected producer/xargs status, and
scratch/trap cleanup after success, error, cancellation, and facade abort.

Assert invalid negative/absolute/traversal globs launch no process.

- [ ] **Step 2: Run candidate tests and verify RED**

Run:

```bash
cargo test --test remote_ops search_candidates_ -- --nocapture
cargo test --test remote_ops search_globs_ -- --nocapture
```

Expected: search remains unimplemented.

- [ ] **Step 3: Implement bounded candidate enumeration and `globset` filtering**

Implement a shared bounded-output shell helper first. It uses a mode-0700
`mktemp -d`, installs cleanup traps, creates FIFO/status/scratch files, starts
the fixed producer in the background, holds one parent FIFO read fd, and uses
foreground `head -c (remaining_protocol_bytes + 1)` from that fd to scratch,
never above `max_frame_bytes + 1`. It then drains the remainder from the same fd
to `/dev/null`, waits, and emits only bounded scratch after every real
producer/engine/xargs status is zero. POSIX sh does not use `pipefail` and no
planned SIGPIPE status is accepted. A genuine producer error remains an error
even when the extra byte was observed.

The fixed find producer dereferences only the configured search root and emits
regular-file actual paths with NUL. Rust streams the bounded capture,
retaining at most 10,001 candidates, strips the exact root boundary, builds all
positive slash-aware globset matchers, matches raw Unix path bytes, and
preserves a lossless actual/relative pair sorted by raw relative bytes.
Candidate count or byte lookahead sets `truncated=true`. An oversized
first record or unexplained partial record is `ProtocolError`.

Build NUL-delimited stdin from the selected raw actual paths with checked total
length no greater than the frame bound.

- [ ] **Step 4: Add failing rg tests**

Cover literal metacharacters, Unicode query, CR/LF prelaunch rejection,
one-based byte column, multiple
matches on one line using the first submatch, JSON text and bytes forms,
binary=false/true, exit 1 empty, result limit plus one, malformed JSON, missing
required fields, unknown event kind/form, one oversized first event, a capped trailing
partial after a complete event, the same partial without a cap proof, and
remote engine failure redaction. Assert envelope engine `rg` and POSIX-sh
metadata.

- [ ] **Step 5: Run rg tests and verify RED**

Run:

```bash
cargo test --test remote_ops search_rg_ -- --nocapture
```

Expected: missing rg phase/parser fails.

- [ ] **Step 6: Implement rg fixed batches and strict JSON parsing**

Use functionally probed sequential `xargs -0` to reconstruct exact candidate
argv in bounded batches. Query remains a positional argument to a fixed inner
sh script. Run rg with `--json --fixed-strings` and deterministic path order;
add the bound binary option. The inner wrapper records the first status greater
than 1 in its private status file before stopping xargs. Status 1 is success;
no engine diagnostic reaches protocol stderr.

Maintain one checked aggregate content-protocol byte budget initialized to
`max_frame_bytes`. Each candidate stdin batch also satisfies
`rendered_command_bytes + stdin_bytes <= max_frame_bytes`; pass the remaining
output budget to its helper and subtract its complete bytes before scheduling
the next batch. Stop after the planned byte cutoff or the
`max_results + 1`-th match so candidate batching cannot multiply the global
output bound. The byte cap never stops or reclassifies a producer; the helper
drains and waits so a later status greater than one wins over a full prefix.

Feed raw rg JSON through the shared FIFO/scratch byte bound. Parse the entire
bounded event stream incrementally with `serde_json`, accept the documented
non-match event kinds, require exact supported text/bytes objects for matches,
use the first submatch start for the one-based byte column, retain only
`max_results + 1` matches, and never serialize submatches. The first incomplete
event is `ProtocolError`; a trailing partial is truncation only with the
explicit byte-cutoff proof. Configure the capture hard limit above this
bounded scratch limit and assert an `OutputLimit` aborts instead of returning partial
success.

- [ ] **Step 7: Run rg tests and verify GREEN**

Run:

```bash
cargo test --test remote_ops search_rg_ -- --nocapture
```

Expected: rg selection, binary policy, strict parsing, and truncation pass.

- [ ] **Step 8: Add failing grep fallback tests**

Disable only `rg_json`. Cover fixed-string no-match/match, filename newline,
non-UTF-8 filename, line content encoding, first literal byte column, result
truncation, malformed NUL framing, engine failure redaction, and
`binary=true -> RemoteCapabilityMissing` before content search. Repeat the
byte-cutoff, real engine-status, oversized-first-record, partial-suffix, and
cleanup cases for grep framing.

- [ ] **Step 9: Run fallback tests and verify RED**

Run:

```bash
cargo test --test remote_ops search_grep_ -- --nocapture
```

Expected: fallback is missing.

- [ ] **Step 10: Implement grep fallback and verify GREEN**

Use NUL-delimited candidate stdin, the shared bounded FIFO/scratch helper, and
functionally probed xargs/grep. Grep must use fixed-string and binary-ignore
behavior and a NUL filename boundary. Its inner wrapper records real status
before xargs aggregation. Parse raw filename then the line record, derive the
byte column by searching query bytes locally, and encode content locally. Treat
exit 1 as empty. Parse all bounded records but retain only
`max_results + 1`; set truncation for extra match, candidate incompleteness, or
byte cutoff.

Run:

```bash
cargo test --test remote_ops search_ -- --nocapture
```

Expected: candidate, rg, grep, binary, glob, framing, and truncation tests all
pass with identical semantics.

---

### Task 8: Capability Retry, Adversarial Audit, Full Verification, Report, and Commit

**Files:**
- Modify: `src/remote/mod.rs`
- Modify: `tests/remote_ops.rs`
- Modify: any Task 4 file only when a failing audit test proves a gap
- Create: `.superpowers/sdd/task-4-report.md`

**Interfaces:**
- Completes the one-reprobe read-only wrapper.
- Produces final Task 4 evidence and commit.

- [ ] **Step 1: Add failing retry and fail-closed tests**

For list, stat, read, and both search engines, simulate a capability present at
probe and an exit-zero exact stderr record
`CODE=CAPABILITY_MISMATCH\0CAPABILITY=<required-key>\0` at first fixed
execution. Assert exactly one invalidation, one reprobe, and one retry. Then
simulate a second mismatch and require `RemoteCapabilityMissing`.

For an unknown key, a key not present in that invocation's compile-time
required list, duplicate/extra/missing fields, nonterminal NUL framing, trailing
bytes, or the same record with nonzero remote exit, require `ProtocolError` and
zero retry.

For transport error, cancel, timeout, protocol corruption, not-found,
permission, read conflict, and output limit, assert exactly zero retries.

- [ ] **Step 2: Run retry tests and verify RED**

Run:

```bash
cargo test --test remote_ops capability_retry_ -- --nocapture
```

Expected: retry counts differ from the binding.

- [ ] **Step 3: Implement one explicit read-only capability retry**

Centralize a two-attempt helper. It retries only the internal
strictly parsed exit-zero `CAPABILITY_MISMATCH` record naming exactly one key in
the operation's static required-capability set, calls
`invalidate_capability(host)` once, and reuses the same already-validated
request. It must not revalidate by reading new mutable caller data and must not
match on a generic public error code alone.

- [ ] **Step 4: Run retry tests and verify GREEN**

Run:

```bash
cargo test --test remote_ops capability_retry_ -- --nocapture
```

Expected: exact probe/operation counts pass.

- [ ] **Step 5: Add and run final adversarial tests**

Add cases for all shell metacharacter classes in host-safe paths/query/globs,
NUL rejection, record counts near `usize`/`u64` overflow, 8-MiB boundaries,
five concurrent hosts, cancellation cleanup, no local-shell production calls,
and serialization amplification:

```rust
let value = serde_json::to_value(&result).unwrap();
assert_eq!(count_json_string(&value, "/physical/root"), 1);
assert_eq!(value["remote"], true);
```

Run:

```bash
cargo test --test remote_ops -- --nocapture
```

Expected: all focused Task 4 behavior passes.

- [ ] **Step 6: Perform the security/self-review checkpoint**

Inspect every fixed script and every `execute_fixed` call. Record evidence that:

- script arguments are positional and the script pointer is `&'static str`;
- every batch validates all paths before runner access;
- every parser has entry, byte, and incomplete-record bounds;
- raw non-UTF-8 paths never enter `shell_word`;
- every facade installs a strong cleanup owner before runner access, capture
  holds only a weak registration, and fixed paths disappear on success, error,
  cancellation, and task abort without TTL;
- stat operands and search candidates are NUL stdin, never an unbounded argv;
- search scratch is mode 0700, trapped, byte-plus-one bounded, preserves the
  first genuine engine/xargs status, and never maps `OutputLimit` to partial;
- no expected error copies utility stderr/path bytes;
- only explicit capability mismatch retries;
- no Task 5/7 behavior or Python runtime entered the diff.

Use:

```bash
git diff --check
git diff -- Cargo.toml src tests .superpowers/sdd/task-4-report.md
rg -n "Command::new|/usr/bin/ssh|python|remote_write|apply_patch|mcp" src/remote tests/remote_ops.rs
```

Expected: no whitespace error, no direct process launch in `src/remote`, and no
out-of-scope runtime path.

- [ ] **Step 7: Write the Task 4 report**

Create `.superpowers/sdd/task-4-report.md` with:

- exact files changed;
- RED commands and the expected failures observed;
- GREEN commands and counts;
- fixed-script/positional/framing review findings;
- capability retry evidence;
- list/stat/read/search/output limits;
- known threat-model statement that symlinks may escape the lexical root;
- `__pycache__` preservation status;
- final commit hash after committing.

- [ ] **Step 8: Run fresh completion verification**

Run in this exact order:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test remote_ops -- --nocapture
cargo test --all-targets
git diff --check
git status --short
```

Expected: every command exits 0; all tests report zero failures; status contains
only Task 4 changes plus the two preserved untracked `__pycache__` directories.
Do not claim completion from an earlier or partial run.

- [ ] **Step 9: Commit Task 4**

Stage only Task 4 files and the Task 4 design/plan/report; do not stage either
`__pycache__` tree:

```bash
git add Cargo.toml Cargo.lock src/error.rs src/capability.rs src/output.rs \
  src/ssh/process.rs src/lib.rs src/remote tests/fixtures/fake-ssh.sh \
  tests/support/mod.rs tests/ssh_transport.rs tests/remote_ops.rs \
  docs/superpowers/specs/2026-07-18-task-4-remote-read-design.md \
  docs/superpowers/plans/2026-07-18-task-4-remote-read.md \
  .superpowers/sdd/task-4-report.md
git commit -m "feat: add high-level remote read operations"
```

After committing, write the commit hash into the report only if doing so does
not require amending without controller approval; otherwise report the hash to
the controller in the handoff message.

---

## Formal Review Rework

### Task 9: Exact Functional Probes and Real `local-fixed`

**Files:**
- Modify: `src/capability.rs`
- Modify: `tests/fixtures/fake-ssh.sh`
- Modify: `tests/ssh_transport.rs`

**Interfaces:**
- Keeps the seven existing `Capability::tools` keys.
- Changes each key to certify its production command form independently.
- Makes `local-fixed` execute `CAPABILITY_PROBE_SCRIPT` instead of synthetic
  records unless a test explicitly selects another fake mode.

- [ ] **Step 1: Write independent incompatible-PATH RED tests**

Add a table-driven test that prepends one executable shim at a time for the
exact selected primitive. Each shim behaves incompatibly for the operation
under test and forwards every unrelated invocation to the system executable.
Assert `read_slice`, `find_nul`, `stat_printf`, `rg_json`, `grep_nul`,
`xargs_nul`, and `search_bound` become false one at a time; assert the private
probe directory is empty after each run. Add explicit fixtures for binary NUL,
descendant-symlink no-follow, depth, a pre-epoch nanosecond timestamp, child
status failure, and same-fd FIFO drain.

- [ ] **Step 2: Verify RED**

Run `cargo test --test ssh_transport capability_probe_rejects_each_incompatible_exact_behavior -- --nocapture`.
Expected: the old shallow probes incorrectly leave one or more flags true.

- [ ] **Step 3: Implement the exact probes and fixture routing**

Use only the existing private probe directory. Exercise the exact option forms
from list/stat/read/search, check output bytes and statuses, and emit `0` on any
setup or cleanup failure. Route `local-fixed` probe commands to `/bin/sh -c
"$remote_command"`; retain synthetic capabilities only for non-local fake
modes that are explicitly transport-only.

- [ ] **Step 4: Verify GREEN**

Run the RED command plus `cargo test --test ssh_transport fixed_probe_script -- --nocapture`.
Expected: all exact behaviors and cleanup assertions pass.

### Task 10: Read-Only Facade Retry and Genuine Mismatch Markers

**Files:**
- Modify: `src/ssh/process.rs`
- Modify: `src/remote/mod.rs`
- Modify: `src/remote/{metadata,read,search}.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- `SshRunner::execute_fixed` performs exactly one attempt.
- `RemoteBridge::execute_readonly_fixed` accepts `FixedRunRequest`, parses one
  strict exit-zero mismatch, invalidates/reprobes, and retries once.
- Every fixed read-only script preflights only keys in its static required set
  and emits `CODE=CAPABILITY_MISMATCH\0CAPABILITY=<key>\0` only on a genuine
  stale behavior.

- [ ] **Step 1: Write real-execution retry RED tests**

Use `local-fixed` plus stateful PATH shims, not `FAKE_SSH_MISMATCH_FILE`.
Prove one probe succeeds, the first actual script detects stale behavior and
emits its own marker, reprobe succeeds, and exactly one second operation runs.
In separate cases force transport, filesystem, normal nonzero exit, and
malformed/unknown mismatch; assert one operation attempt and no retry.

- [ ] **Step 2: Verify RED**

Run `cargo test --test remote_ops readonly_real_mismatch -- --nocapture`.
Expected: current fixture-level injection or runner-global retry violates
attempt ownership/counting.

- [ ] **Step 3: Move retry and add script preflights**

Remove `fixed_capability_mismatch` calls from `SshRunner`. Put strict parsing
and exactly-once retry in `RemoteBridge`. Convert every metadata/read/search
call to that wrapper. Add fixed safe marker helpers inline in each static shell
script; never copy utility stderr.

- [ ] **Step 4: Verify GREEN**

Run all `readonly_real_mismatch` tests plus existing fixed-runner lifecycle
tests. Expected: only a genuine required-key stale marker retries once.

### Task 11: Real `SpoolCursor` and Streaming Retention

**Files:**
- Modify: `src/remote/protocol.rs`
- Modify: `src/remote/{metadata,read,search}.rs`
- Modify: `tests/fixtures/fake-ssh.sh`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- `SpoolCursor<'a>` owns stream, offset, length, one 64-KiB page, page index,
  and a checked record limit.
- `next_field`, `next_line`, and bounded small-stream/content helpers preserve
  delimiters split across pages.
- List/stat/search retain only the incomplete current record and their
  count-plus-one result ceilings.

- [ ] **Step 1: Write cursor and RSS RED tests**

Create protocol unit captures where a NUL field and an rg JSON newline cross
the 64-KiB boundary. Add an explicit fake mode that spools 8 MiB of complete,
valid but glob-rejected candidate records for each of five hosts. All five
search calls must return successfully, overlap, leave no spools, and grow
`VmRSS` by less than 32 MiB.

- [ ] **Step 2: Verify RED**

Run `cargo test --lib spool_cursor_ -- --nocapture` and
`cargo test --test remote_ops five_hosts_successfully_stream_forty_mib_below_rss_bound -- --nocapture`.
Expected: the former API is absent and the latter exceeds the bound or cannot
parse the synthetic valid stream.

- [ ] **Step 3: Implement streaming parsers**

Delete whole-frame `read_stream`. Parse list groups, stat's tagged variable
records, candidates, grep records, and rg lines directly from `SpoolCursor`.
Continue consuming/validating the bounded stream after the retention ceiling,
but never retain more than list `max+1`, 10,001 candidates, or search
`max_results+1`.

- [ ] **Step 4: Verify GREEN**

Run both RED commands twice and the existing 8-MiB-plus-one framing tests.
Expected: boundary records and five-host success pass with cleanup and the RSS
ceiling.

### Task 12: Remote List Qualification and Count Lookahead

**Files:**
- Modify: `src/remote/metadata.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- `LIST_SCRIPT` positional args are root, depth, show-hidden, max-entries, and
  byte lookahead.
- Remote find prunes hidden relative components and sequential NUL grouping
  emits at most `max_entries + 1` qualifying records.

- [ ] **Step 1: Write hidden-flood RED tests**

Create more than the cap in hidden roots and hidden nested directories plus a
small visible set. With `include_hidden=false`, assert every visible entry is
returned and `truncated=false`. With `include_hidden=true`, assert exactly cap
entries and `truncated=true`. Assert a remote command log includes the explicit
show-hidden and max-entry operands.

- [ ] **Step 2: Verify RED**

Run `cargo test --test remote_ops list_hidden_flood_does_not_consume_remote_cap -- --nocapture`.
Expected: current local filtering consumes the byte/count budget or truncates.

- [ ] **Step 3: Implement remote qualification/counting**

Use root-relative find output and a hidden-prune expression before metadata
emission. Feed NUL field groups through bounded sequential xargs with a private
counter file, emit only max-plus-one groups, and use the same-fd bounded helper
with final status precedence.

- [ ] **Step 4: Verify GREEN**

Run the RED command and all metadata tests. Expected: hidden flood is invisible
to both returned count and truncation.

### Task 13: One Slash-Aware Glob Compiler

**Files:**
- Modify: `src/remote/mod.rs`
- Modify: `src/remote/search.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- `compile_glob`/`compile_globs` build with
  `GlobBuilder::literal_separator(true)` in validation and matching.

- [ ] **Step 1: Write nested glob RED tests**

Add nested files that distinguish `*.txt`, `dir/?.txt`, `dir/[ab].txt`, and
`**/*.txt`. Assert `*`, `?`, and classes never cross `/`, while `**` does.

- [ ] **Step 2: Verify RED**

Run `cargo test --test remote_ops search_globs_are_slash_aware -- --nocapture`.
Expected: default `Glob::new` matching crosses a separator or validation and
execution use different builders.

- [ ] **Step 3: Implement one constructor and verify GREEN**

Use the same helper during request validation and raw-byte path matching. Run
the RED command for both rg and grep fixtures.

### Task 14: Search Final-Status Priority and Strict Bounded Decode

**Files:**
- Modify: `src/capability.rs`
- Modify: `src/remote/search.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Candidate, rg, and grep bounded helpers keep a parent read fd open, capture
  limit-plus-one to scratch, drain from the same fd, wait, and inspect all final
  statuses before emitting scratch.
- Candidate retention is 10,001; match retention is `max_results + 1`.
- Known rg events are `begin`, `match`, `end`, `summary`; all others fail.

- [ ] **Step 1: Write error-priority/strict-event RED tests**

Use a real PATH engine shim that emits a full valid prefix beyond the byte cap,
then exits 2. Assert `RemoteExit`, no partial success, and redacted diagnostics.
Add an unknown syntactically valid rg event and assert `ProtocolError`. Add
streams far beyond the result/candidate count and assert only lookahead is
retained while later malformed data is still rejected.

- [ ] **Step 2: Verify RED**

Run `cargo test --test remote_ops search_full_prefix_then_exit_two_is_error -- --nocapture` and
`cargo test --test remote_ops search_unknown_rg_event_is_protocol_error -- --nocapture`.
Expected: current cap path reclassifies the later error or ignores the event.

- [ ] **Step 3: Implement same-fd drain and strict streaming decode**

Replace planned-SIGPIPE logic in all three scripts and `search_bound` probe.
After draining and waiting, make engine-error, xargs-status, and producer-status
checks precede capped output. Parse every bounded event incrementally while
limiting retained candidates/matches to their lookahead ceilings.

- [ ] **Step 4: Verify GREEN**

Run all search tests, including rg/grep parity, oversized first event,
full-prefix-later-error, unknown events, cancellation, and cleanup.

### Task 15: Final-Symlink Read Errors and Completion Gate

**Files:**
- Modify: `src/remote/read.rs`
- Modify: `tests/remote_ops.rs`
- Modify: the Task 4 design, plan, clarifications, and report

- [ ] **Step 1: Write final-symlink RED tests**

Create a dangling final symlink and assert a closed `NotFound` entry. Create an
existing mode-000 target behind a final symlink and, where the effective uid can
observe permission denial, assert `PermissionDenied`. Add the deterministic
parent-directory ambiguity case available on the current platform and assert a
fixed safe error containing neither stderr nor the path.

- [ ] **Step 2: Verify RED, implement, and verify GREEN**

Run `cargo test --test remote_ops read_final_symlink_errors -- --nocapture`.
Change the script's first check to following `-e`; classify deterministic
existing-but-`! -r` separately. Re-run the focused test and all read tests.

- [ ] **Step 3: Fresh completion gate and new commit**

Run in this exact order:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test remote_ops -- --nocapture
cargo test --all-targets
git diff --check
git status --short
```

Update `.superpowers/sdd/task-4-report.md` with every observed RED/GREEN and
fresh count, force-stage the clarification/report because `.superpowers` is
ignored, preserve both `__pycache__` trees, and create one new commit.

### Task 16: R2 Exact Probe Oracles

**Files:**
- Modify: `src/capability.rs`
- Modify: `tests/ssh_transport.rs`

**Interfaces:**
- `find_nul` compares the complete raw five-field output for the expected
  `%P/%y/%s/%m/%T@` records, including a newline name, root symlink follow,
  descendant symlink no-follow, depth 2, and hidden pruning.
- `rg_json` proves text and bytes forms, binary false/true, required match
  fields, and statuses 0, 1, and greater than 1.
- `search_bound` runs the production-shaped parent-held same-fd head/drain
  helper, sequential NUL xargs, child/xargs failure propagation, later-error
  precedence after a full prefix, mode-0700 scratch, and cleanup.

- [x] **Step 1: Add fine-grained incompatible-PATH tests**

Extend the table in `capability_probe_rejects_each_incompatible_exact_behavior`
with shims that keep `command -v` and ordinary invocations working but corrupt
one semantic detail at a time. Include find field/path/type corruption, rg
text/bytes/status corruption, head, xargs child-status masking, `mktemp`, and
`mkfifo`. Assert only the target functional flag becomes false and each probe
scratch root is empty.

- [x] **Step 2: Verify RED**

Run `cargo test --test ssh_transport capability_probe_rejects_each_incompatible_exact_behavior -- --exact --nocapture`.
Expected: one or more fine-grained semantic shims still leave the target flag
true.

- [x] **Step 3: Implement exact raw-output/status oracles**

Build fixed expected files inside the existing private probe directory and use
`cmp -s` plus exact exit-status assertions. The search-bound probe must emit no
protocol bytes, drain before wait, and leave all failure/scratch state private.

- [x] **Step 4: Verify GREEN**

Re-run the exact RED command and the existing real-probe cleanup tests.

### Task 17: R2 Cheap Exact Operation Sentinels

**Files:**
- Modify: `src/remote/metadata.rs`
- Modify: `src/remote/read.rs`
- Modify: `src/remote/search.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Each fixed read-only script runs a cheap, discriminating self-test for each
  production form it will use before touching caller paths or starting the
  real engine.
- Only sentinel failure emits the strict exit-zero mismatch for a key in the
  request's static required set; real filesystem/engine failures retain their
  ordinary fixed errors.

- [x] **Step 1: Add stateful stale-sentinel RED tests**

Use PATH shims that pass the full capability probe, then corrupt one production
form only. Cover list find format/no-follow, stat printf, read slicing,
sequential xargs, rg/grep modes, and the mktemp/mkfifo/head same-fd helper.
Assert success-after-one-stale gives exactly `P=2/C=2`; a sentinel that remains
bad after reprobe returns `RemoteCapabilityMissing`; filesystem and genuine
engine errors do not become mismatch records.

- [x] **Step 2: Verify RED**

Run the new `readonly_stale_sentinel_` tests. Expected: shallow sentinels miss
at least one corrupted production behavior or misclassify the failure.

- [x] **Step 3: Implement minimal per-script self-tests**

Keep sentinel data under a mode-0700 `mktemp -d`, suppress utility diagnostics,
compare exact small outputs/statuses, and trap cleanup. Do not run the full
capability probe and do not add an SSH round trip. Record focused-test elapsed
time in the report as the integration-level performance guard.

- [x] **Step 4: Verify GREEN**

Run the RED tests plus all existing retry, filesystem-error, engine-error, and
cleanup regressions.

### Task 18: R2 Root Slash Join and Completion

**Files:**
- Modify: `src/remote/metadata.rs`
- Modify: `tests/remote_ops.rs`
- Modify: Task 4 design, plan, clarifications, and report

- [x] **Step 1: Add a real root-slash list RED test**

Configure the host root as `/`, list a known direct child selected from the
actual filesystem, and assert every returned `actual_path` begins with exactly
one `/`; specifically reject `//etc` when `/etc` is present.

- [x] **Step 2: Verify RED, implement, and verify GREEN**

Run the focused test. Change `join_raw` to append a separator only when the
base is nonempty and does not already end in `/`, then re-run the test and all
metadata regressions.

- [x] **Step 3: Fresh completion gate and commit**

Update the binding clarification list and report with all R2 RED/GREEN evidence
and sentinel timing. Run, in order, `cargo fmt --check`, strict clippy,
`cargo test --test remote_ops -- --nocapture`, `cargo test --all-targets`,
`git diff --check`, and `git status --short`. Preserve both user-owned
`__pycache__` trees and create one new commit.

### Task 19: Close Final Focused Review Findings

**Files:**
- Modify: `src/remote/read.rs`
- Modify: `src/remote/search.rs`
- Modify: operation/capability tests and Task 4 binding documents

- [x] **Step 1: Add four focused RED regressions**

Cover quote-amplified rendered commands at 4 KiB, configured root `/` search,
an unreadable parent that makes file existence indeterminate, and sentinel
scratch setup failure. Observe respectively empty-truncated success,
`ProtocolError`, `NotFound`, and retry to `RemoteCapabilityMissing`.

- [x] **Step 2: Separate setup errors and exact semantic mismatches**

Return `RequestTooLarge` when the engine command alone cannot fit a candidate;
derive root-relative search paths from one existing root slash; classify the
nearest inaccessible parent as `PermissionDenied`; and make nonzero sentinel
setup ordinary `RemoteExit` while successful wrong mktemp mode/mkfifo type
remains a genuine `search_bound` mismatch.

- [x] **Step 3: Verify GREEN and rerun completion gates**

Run the four focused tests, stale table, exact capability cleanup table, both
4-KiB regressions, then every completion gate before committing.

### Task 20: R3 Share Exact List Production Forms

**Files:**
- Modify: `src/remote/metadata.rs`
- Modify: `tests/remote_ops.rs`
- Modify: Task 4 design, plan, clarifications, and report

- [x] **Step 1: Add the production-form stale RED table**

Add `readonly_stale_list_production_forms_retry_exactly_once`. Stateful PATH
shims pass the real capability probe, then corrupt only the list sentinel call
using caller depth, the hidden prune expression, or `xargs -n 100`. Assert the
first stale behavior gives exactly two probes and two list commands. Also cover
a persistent semantic mismatch as `RemoteCapabilityMissing` and an ordinary
missing list root as `NotFound` with one probe/one command.

- [x] **Step 2: Verify RED**

Run the exact new test. Expected: the current fixed-depth/non-pruning sentinel
misses all three production-only corruptions, so list returns `RemoteExit` and
the log remains `P=1/C=1`.

- [x] **Step 3: Share compact production functions**

Define one compact POSIX find function consuming root, dynamic depth, and
hidden flag, plus one compact sequential NUL xargs function containing
`-n 100`. Invoke only those functions from both the controlled sentinel and
real producer. Preserve setup-error classification and strict mismatch keys.

- [x] **Step 4: Verify GREEN and the 4-KiB boundary**

Run the exact RED test, existing stale/setup/error tests, hidden-flood and root
list tests with the 4-KiB fixture, then record source/rendered size evidence.

- [x] **Step 5: Fresh completion gate and commit**

Update the binding clarification and report. Run format, strict clippy,
`remote_ops`, all targets, diff check, and status. Preserve both user-owned
`__pycache__` directories and create one R3 commit.

---

## Plan Self-Review Checklist

- Every clarification item 1-51 maps to at least one task above.
- All production changes follow a named failing test and observed RED.
- Public type names are defined before later tasks consume them.
- List/stat/read/search protocols each have explicit field and byte ceilings.
- Non-UTF-8 search candidates use raw NUL stdin, never shell quoting.
- Stat uses bounded sequential NUL/xargs batches and never relies on `ARG_MAX`.
- Every internal spool has an abort-safe facade-entry owner; TTL is fallback.
- Search has explicit global `max_results + 1` retention and
  `max_frame_bytes + 1` byte lookahead with same-fd drain and final-status
  precedence.
- The final gate includes format, clippy, focused tests, all targets, diff, and
  status evidence.
- Every implementation step is concrete; there are no Python runtime steps,
  Task 5 writes, or Task 7 MCP steps.
