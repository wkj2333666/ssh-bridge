# Tasks 7–8 Strict MCP and High-Level Tool Surface Implementation Plan

Status: Ready for implementation after strict MCP security/performance review

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a strict bounded stdio MCP server exposing exactly nine high-level remote tools while keeping shell, path, capability, mutation, output, and retry logic inside the Rust bridge.

**Architecture:** First close the missing bridge-owned `remote_run` facade, including explicit Bash/sh selection, cwd, stdin, limits, and shell metadata. Then build a hand-written strict JSON-RPC core with bounded framing, one writer, lifecycle ownership, cancellation, and a generic tool-service seam. Finally add exact schemas, a thin `RemoteBridge` dispatcher, single-copy rendering, binary bootstrap, and adversarial five-host acceptance.

**Tech Stack:** Rust 1.91.1, Tokio, tokio-util `CancellationToken`, Serde/serde_json, Base64 0.22, existing `RemoteBridge`/`SshRunner`/`OutputStore`, non-Python fake SSH fixtures.

## Global Constraints

- The runtime, installer, benchmarks, and test fixtures use no Python.
- Task 6's frozen `ApplyPatchRequest`, `ApplyPatchResult`, original error code, and four progress fields are consumed without reinterpretation.
- System OpenSSH remains the transport. No local operation is invoked through a shell.
- Only `remote_run.command` is intentional caller-provided shell source.
- Paths, cwd, hashes, globs, queries, modes, stdin, output refs, and file bytes remain data and use the audited bridge boundary.
- MCP supports exactly protocol versions `2025-11-25` and `2025-06-18`, preferred in that order.
- MCP exposes exactly `remote_hosts`, `remote_list`, `remote_stat`, `remote_search`, `remote_read`, `remote_output_read`, `remote_apply_patch`, `remote_write`, and `remote_run`.
- SSHFS, raw SSH, probing, quoting, hashing, temporary-file, and guarded-delete tools are absent.
- All tool schema roots and nested argument objects reject unknown fields.
  Protocol `_meta` and client `capabilities` remain open objects as MCP requires.
- Malformed `tools/call` envelopes and unknown tool names return `-32602`;
  known-tool argument validation returns an actionable normal
  `CallToolResult` with `isError=true` and never launches the bridge.
- A valid `notifications/cancelled` cancels the operation and suppresses its MCP response.
- The default frame bound is 8 MiB, read/output pages are at most 1 MiB, patch/write/decoded stdin are at most 4 MiB, and command output remains capped at 64 MiB.
- In-flight MCP calls are bounded by validated global concurrency; existing per-host semaphores remain authoritative.
- Five concurrent one-second calls to five hosts complete within 1.5 seconds in release acceptance.
- Bulk payload appears in one text content block and is absent from `structuredContent`.
- Mutations are never automatically retried by MCP, and unknown outcomes are never reclassified.
- A response-budget fallback never rewrites completed mutation truth as
  `-32603`; it preserves status/counts and an opaque pageable reference.
- Strict JSON parsing enforces depth, node, object-member, and aggregate-key-byte
  budgets and duplicate detection reuses each destination JSON map.
- Follow red-green-refactor. Every implementation task ends with focused tests and an independently reviewable commit.

## File Map

- Create `src/remote/run.rs`: high-level command admission and result conversion.
- Modify `src/config.rs`: bridge-wide remote-context root byte ceiling and
  configured-root enforcement.
- Modify `src/remote/mod.rs`: public run request/result types and facade.
- Modify `src/capability.rs`: explicit POSIX sh request.
- Modify `src/ssh/process.rs`: cwd-aware safe command rendering, rendered bound, physical root, and shell error metadata.
- Modify `src/error.rs`: optional serializable selected-shell error details.
- Create `src/mcp/protocol.rs`: strict JSON, IDs, versions, envelopes, response constructors, and tool-service types.
- Create `src/mcp/stdio.rs`: bounded frame reader and capped compact serializer.
- Create `src/mcp/mod.rs`: lifecycle owner, registry, cancellation, concurrent dispatch, and public server.
- Create `src/mcp/tools.rs`: exact schemas, closed argument types, and thin dispatch.
- Create `src/mcp/render.rs`: single-copy success/error projections.
- Modify `src/remote/mod.rs`: bridge-owned opaque retention for oversized
  result detail; MCP never sees `OutputStore`.
- Modify `src/output.rs`: typed remote/aggregate retention provenance,
  direct-to-spool serialization, and truthful raw-byte paging metadata.
- Modify `src/lib.rs`: export MCP module.
- Modify `src/main.rs`: `mcp` bootstrap only; Task 9 may later extend CLI modes.
- Modify `Cargo.toml`: Tokio stdio and multi-thread runtime features only.
- Modify `tests/ssh_transport.rs`: shell selection, cwd rendering, bounds, and selected-shell error tests.
- Modify `tests/core.rs`: exact configured-root UTF-8 byte-bound tests.
- Modify `tests/remote_ops.rs`: bridge-owned run API, read-only, stdin, result, and fake-SSH tests.
- Create `tests/mcp_protocol.rs`: strict protocol/framing/lifecycle/cancellation tests.
- Create `tests/mcp_tools.rs`: schemas, dispatch, rendering, security, and five-host tests.

## Mapping to the Main Plan

The numbered tasks below are implementation slices, not renumbering of the
approved main plan:

- Main Task 7 (strict MCP core) is implemented by slices 3–5.
- Main Task 8 (schemas, high-level dispatch, and single-copy results) is
  implemented by slices 6–9.
- Slices 1–2 close the bridge-owned `remote_run` prerequisite that must exist
  before Main Task 8 can remain thin. They do not add another MCP tool.
- The completed main Task 6 patch API is consumed unchanged throughout.

---

### Task 1: Freeze the Bridge-Owned Run Contract and Explicit sh Selection

**Files:**
- Modify: `src/config.rs`
- Modify: `src/capability.rs`
- Modify: `src/error.rs`
- Modify: `src/remote/mod.rs`
- Modify: `src/remote/read.rs`
- Modify: `src/remote/write.rs`
- Modify: `src/remote/patch.rs`
- Modify: `src/ssh/process.rs`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/core.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Consumes: existing `WriteEncoding`, `RemoteContext`, `EncodedValue`, `OutputPreview`, `ShellSelection`, and `SshRunner`.
- Produces: shared `MAX_REMOTE_CONTEXT_ROOT_BYTES`, enforced configured/probed
  root bounds, shared `MAX_SHELL_VERSION_BYTES`, `RunShell`, `RunStdin`, `RemoteRunRequest`,
  `EncodedOutputPreview`, `RemoteRunResult`, `ErrorShellMetadata`,
  optional error physical root, non-overwriting
  `attach_available_remote_context`, `ShellRequest::Sh`, and
  `RunResult.physical_root`.

- [ ] **Step 1: Add failing public-shape and shell-selection tests**

Add this shape test to `tests/remote_ops.rs`:

```rust
#[test]
fn task78_remote_run_public_shapes_are_closed() {
    use codex_ssh_bridge::remote::{
        RemoteRunRequest, RunShell, RunStdin, WriteEncoding,
    };

    let request = RemoteRunRequest {
        host: "dev".to_owned(),
        command: "printf ok".to_owned(),
        cwd: Some("sub dir".to_owned()),
        shell: RunShell::Sh,
        timeout_ms: Some(1_250),
        stdin: Some(RunStdin {
            encoding: WriteEncoding::Base64,
            value: "AAE=".to_owned(),
        }),
    };
    assert_eq!(request.shell, RunShell::Sh);
    assert_eq!(request.timeout_ms, Some(1_250));
}
```

Extend the existing shell selection test in `tests/ssh_transport.rs`:

```rust
let explicit_sh = select_shell(&bash, ShellRequest::Sh).unwrap();
assert_eq!(explicit_sh.shell, ShellKind::PosixSh);
assert!(!explicit_sh.fallback);

let explicit_sh_without_bash = select_shell(&sh, ShellRequest::Sh).unwrap();
assert_eq!(explicit_sh_without_bash.shell, ShellKind::PosixSh);
assert!(!explicit_sh_without_bash.fallback);
```

Add serialization coverage for error shell metadata:

```rust
#[test]
fn task78_error_shell_metadata_is_closed() {
    let mut error = codex_ssh_bridge::BridgeError::new(
        codex_ssh_bridge::ErrorCode::RemoteExit,
        "remote command failed",
        false,
    );
    error.details.shell = Some(codex_ssh_bridge::error::ErrorShellMetadata {
        kind: "sh".to_owned(),
        version: None,
        fallback: true,
    });
    assert_eq!(
        serde_json::to_value(error).unwrap()["details"]["shell"],
        serde_json::json!({"kind":"sh","version":null,"fallback":true})
    );
}
```

Extend it with `details.physical_root="/srv/app"` and assert the safe root is
serialized; a fresh pre-probe error must omit the field. Add transport tests for
remote exit/timeout/cancel/output-limit after capability selection carrying the
exact root. Add remote-operation tests where an exit-zero fixed child produces
malformed read/snapshot protocol output, write conflict, and patch result/progress
parse failure; each must carry host/root/shell without overwriting its domain
code/progress. Rejection of an oversized probed root must omit physical root.

In `tests/core.rs`, construct normalized absolute configured roots at exactly
65,536 UTF-8 bytes and one byte over. Repeat with non-ASCII components whose
character counts are smaller but encoded byte lengths straddle the same edge.
Assert exact succeeds and +1 returns fixed invalid configuration.

In `tests/ssh_transport.rs`, feed capability records whose physical `ROOT` uses
the same ASCII/non-ASCII byte-boundary matrix. Assert exact values are cached
unchanged and +1 is rejected before any `RemoteContext` is built.
Feed Bash versions at exactly 256 UTF-8 bytes and 257 bytes, including
non-ASCII boundaries and malicious fake-Bash output. Exact is cached unchanged;
+1 fails before shell metadata enters an error or result.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
cargo test --test ssh_transport shell_selection_records_profile_free_bash_posix_fallback_and_login_semantics -- --exact --nocapture
cargo test --test ssh_transport task78_physical_root_byte_bound_ -- --nocapture
cargo test --test core task78_configured_root_byte_bound_ -- --nocapture
cargo test --test remote_ops task78_remote_run_public_shapes_are_closed -- --exact --nocapture
cargo test --test remote_ops task78_error_shell_metadata_is_closed -- --exact --nocapture
cargo test --test remote_ops task78_domain_error_remote_context_ -- --nocapture
```

Expected: compilation fails because the shared root bound/context helper,
`ShellRequest::Sh`, and public remote-run/error-context shapes do not exist.

- [ ] **Step 3: Add the exact public types**

Add to `src/error.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorShellMetadata {
    pub kind: String,
    pub version: Option<String>,
    pub fallback: bool,
}
```

Add to `src/config.rs` and use in configured-root validation:

```rust
pub const MAX_REMOTE_CONTEXT_ROOT_BYTES: usize = 65_536;
```

Compare `normalized_root.as_bytes().len()` to the constant. Import the same
constant in `src/capability.rs` and reject an over-limit parsed physical `ROOT`
before caching it. No MCP module declares its own root ceiling.

Add and enforce in `src/capability.rs`:

```rust
pub const MAX_SHELL_VERSION_BYTES: usize = 256;
```

MCP wire budgeting imports both shared bounds; neither is redeclared there.

Add this omitted-when-absent field to `ErrorDetails`:

```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub shell: Option<ErrorShellMetadata>,
#[serde(skip_serializing_if = "Option::is_none")]
pub physical_root: Option<String>,
```

Add one bridge-wide helper:

```rust
pub fn attach_available_remote_context(
    error: &mut BridgeError,
    host: Option<&str>,
    physical_root: Option<&str>,
    shell: Option<&ErrorShellMetadata>,
);
```

It fills only missing safe fields. Call it from transport failure conversion
and from remote read/snapshot/write/patch parser boundaries after an exit-zero
fixed child creates a new domain/protocol error. It never changes code,
retryability, mutation truth, or progress.

Add to `src/remote/mod.rs`:

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

Add `Sh` to `ShellRequest` and this exact branch to `select_shell`:

```rust
ShellRequest::Sh => Ok(ShellSelection {
    shell: ShellKind::PosixSh,
    fallback: false,
}),
```

Add `pub physical_root: String` to `ssh::RunResult` and populate it from the selected capability on successful execution. This avoids a second cache lookup in `RemoteBridge::run`.

- [ ] **Step 4: Run shape, shell, and existing error tests**

Run:

```bash
cargo test --test ssh_transport shell_selection_records_profile_free_bash_posix_fallback_and_login_semantics -- --exact --nocapture
cargo test --test ssh_transport task78_physical_root_byte_bound_ -- --nocapture
cargo test --test core task78_configured_root_byte_bound_ -- --nocapture
cargo test --test remote_ops task78_remote_run_public_shapes_are_closed -- --exact --nocapture
cargo test --test remote_ops task78_error_shell_metadata_is_closed -- --exact --nocapture
cargo test --test remote_ops task78_domain_error_remote_context_ -- --nocapture
cargo test --lib error::tests -- --nocapture
```

Expected: all selected tests pass; existing serialized errors omit `details.shell` when it is `None`.

- [ ] **Step 5: Commit the contract slice**

```bash
git add src/config.rs src/capability.rs src/error.rs src/remote/mod.rs src/remote/read.rs src/remote/write.rs src/remote/patch.rs src/ssh/process.rs tests/core.rs tests/ssh_transport.rs tests/remote_ops.rs
git commit -m "feat: define high-level remote run contract"
```

---

### Task 2: Implement Secure cwd-Aware Remote Run in the Bridge

**Files:**
- Create: `src/remote/run.rs`
- Modify: `src/remote/mod.rs`
- Modify: `src/ssh/process.rs`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Consumes: Task 1 public shapes, `RemotePath`, `Config::host`, `SshRunner::execute`, `protocol::encode_bytes`, and the existing output store.
- Produces: `RemoteBridge::run(RemoteRunRequest, CancellationToken) -> BridgeResult<RemoteRunResult>` and cwd-aware `ssh::RunRequest`.

- [ ] **Step 1: Add failing bridge-run admission and result tests**

Add focused fake-SSH tests covering these exact cases:

```rust
#[tokio::test]
async fn task78_remote_run_is_bridge_owned_and_reports_explicit_shell() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(remote.path().join("sub dir")).unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);

    let result = bridge
        .run(
            RemoteRunRequest {
                host: "dev".to_owned(),
                command: "pwd; od -An -tx1".to_owned(),
                cwd: Some("sub dir".to_owned()),
                shell: RunShell::Sh,
                timeout_ms: Some(2_000),
                stdin: Some(RunStdin {
                    encoding: WriteEncoding::Base64,
                    value: "AAEJ".to_owned(),
                }),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(result.context.shell.kind, ShellName::Sh);
    assert!(!result.context.shell.fallback);
    assert!(result.warnings.iter().any(|warning| warning.contains("[[ ]]")));
    assert_eq!(result.exit_status, 0);
    assert_eq!(result.context.physical_root, remote.path().to_str().unwrap());
}
```

Add separate tests asserting:

- read-only host returns `ReadOnlyHost` before the command child;
- `cwd="../escape"` returns `PathOutsideRoot` before the command child;
- noncanonical Base64, URL-safe Base64, and decoded input over 4 MiB return local errors;
- auto without Bash reports sh with `fallback=true` and the warning;
- explicit Bash without Bash returns `RemoteCapabilityMissing` before the command child;
- a later timeout/remote-exit error carries `details.shell`;
- cwd containing quote, newline, glob, leading hyphen, backtick, and `$(...)` is literal; and
- command containing NUL launches no child.

- [ ] **Step 2: Add failing transport rendering and amplification tests**

In `tests/ssh_transport.rs` construct `RunRequest` with an absolute cwd and assert:

```rust
assert!(rendered.contains("codex-ssh-bridge-run"));
assert!(!rendered.contains("touch /tmp/cwd-injection"));
```

Use a cwd containing the literal text `'; touch /tmp/cwd-injection; '` and verify no sentinel is created. Add a command whose raw bytes fit but whose single-quote expansion exceeds `max_frame_bytes`; expect `RequestTooLarge` before command-child launch.

- [ ] **Step 3: Run the focused tests and verify RED**

Run:

```bash
cargo test --test remote_ops task78_remote_run_ -- --nocapture
cargo test --test ssh_transport task78_run_ -- --nocapture
```

Expected: compilation fails because `RemoteBridge::run`, `src/remote/run.rs`, and cwd-aware transport rendering are absent.

- [ ] **Step 4: Implement strict local admission**

Declare `mod run;` and add:

```rust
pub async fn run(
    &self,
    request: RemoteRunRequest,
    cancel: CancellationToken,
) -> BridgeResult<RemoteRunResult> {
    run::run(self, request, cancel).await
}
```

In `src/remote/run.rs` implement this control flow:

```rust
pub(super) async fn run(
    bridge: &RemoteBridge,
    request: RemoteRunRequest,
    cancel: CancellationToken,
) -> BridgeResult<RemoteRunResult> {
    let host = bridge.runner.config().host(&request.host)?;
    if host.profile.read_only {
        return Err(BridgeError::new(
            ErrorCode::ReadOnlyHost,
            "remote host is configured read-only",
            false,
        ));
    }
    if request.command.is_empty() || request.command.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "remote command must be nonempty and contain no NUL",
        ));
    }

    let requested_cwd = request.cwd.as_deref().unwrap_or(".");
    super::validate_path(requested_cwd)?;
    let cwd = RemotePath::resolve(&host.profile.root, requested_cwd)?;
    let stdin = decode_stdin(request.stdin, host.limits.max_write_bytes)?;
    let timeout_ms = request
        .timeout_ms
        .unwrap_or(host.limits.command_timeout_ms);
    if timeout_ms == 0 || timeout_ms > host.limits.command_timeout_ms {
        return Err(BridgeError::invalid_argument(
            "command timeout exceeds the configured limit",
        ));
    }

    let result = bridge
        .runner
        .execute(
            crate::ssh::RunRequest {
                host: request.host.clone(),
                command: request.command,
                cwd: cwd.absolute().to_owned(),
                shell: map_shell(request.shell),
                stdin,
                timeout: Duration::from_millis(timeout_ms),
            },
            cancel,
        )
        .await?;
    Ok(convert_result(request.host, result))
}
```

Implement `decode_stdin` with `base64::engine::general_purpose::STANDARD`. For Base64, decode and then require `STANDARD.encode(&decoded) == value` so whitespace, missing padding, and URL-safe variants fail. Enforce the decoded byte ceiling. Map shells exactly:

```rust
fn map_shell(shell: RunShell) -> ShellRequest {
    match shell {
        RunShell::Auto => ShellRequest::Auto,
        RunShell::Bash => ShellRequest::Bash,
        RunShell::Sh => ShellRequest::Sh,
        RunShell::Login => ShellRequest::Login,
    }
}
```

Move preview byte vectors into `protocol::encode_bytes`, expose the output reference with `as_str()`, and add the fixed sh warning whenever the selected shell is `PosixSh`.

- [ ] **Step 5: Implement safe transport rendering**

Add `cwd: String` to low-level `ssh::RunRequest`. For Bash and sh, use fixed scripts selected by Rust:

```sh
set -u
[ "$#" -eq 3 ] || exit 2
cd -- "$1" || exit 126
if [ -n "$3" ]; then
    exec timeout --signal=TERM --kill-after=1s "$3" bash --noprofile --norc -c "$2"
fi
exec bash --noprofile --norc -c "$2"
```

The sh variant replaces the two interpreter invocations with `sh -c "$2"`.
Render the fixed script with the audited word encoder and pass cwd, command,
and either the validated timeout duration or an empty string as encoded
positional arguments.

For login mode render exactly:

```text
cd -- <shell_word(cwd)> || exit 126
<caller command>
```

After rendering and before `build_ssh_argv`, reject a command longer than
`limits.max_frame_bytes` with `RequestTooLarge`. Wrap all failures after
`select_shell` to attach `ErrorShellMetadata`. Add `physical_root` to successful
`RunResult`.

- [ ] **Step 6: Run bridge, transport, and existing command tests**

Run:

```bash
cargo test --test remote_ops task78_remote_run_ -- --nocapture
cargo test --test ssh_transport task78_run_ -- --nocapture
cargo test --test ssh_transport selected_shell_and_remote_gnu_timeout_are_reported_and_rendered_exactly -- --exact --nocapture
cargo test --test ssh_transport command_stdin_is_streamed_and_oversized_input_is_rejected_before_ssh -- --exact --nocapture
```

Expected: focused tests pass; existing timeout and stdin tests pass with the newly required cwd field added to their fixtures.

- [ ] **Step 7: Commit the complete bridge-run slice**

```bash
git add src/remote/run.rs src/remote/mod.rs src/ssh/process.rs tests/ssh_transport.rs tests/remote_ops.rs
git commit -m "feat: add bridge-owned remote command execution"
```

---

### Task 3: Add Strict JSON Values, Request IDs, and Protocol Constructors

**Files:**
- Create: `src/mcp/protocol.rs`
- Create: `src/mcp/mod.rs`
- Modify: `src/lib.rs`
- Create: `tests/mcp_protocol.rs`

**Interfaces:**
- Consumes: serde/serde_json and `CancellationToken`.
- Produces: `SUPPORTED_PROTOCOL_VERSIONS`, `RequestId`, `parse_strict_json`,
  `ProtocolState`, `ToolDefinition`, `CallToolResult`, `WireBudget`,
  `ToolCallContext`, `ToolService`, structural JSON budgets, and fixed JSON-RPC
  response constructors.

- [ ] **Step 1: Add failing strict-JSON and ID tests**

Create `tests/mcp_protocol.rs` with tests for:

```rust
#[test]
fn task7_strict_json_rejects_duplicate_keys_at_every_depth() {
    for input in [
        br#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"ping"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","name":"y"}}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"host":"a","host":"b"}}}"#,
    ] {
        assert!(parse_strict_json(input).is_err());
    }
}

#[test]
fn task7_request_ids_preserve_exact_string_and_integer_identity() {
    assert_ne!(
        RequestId::try_from(serde_json::json!(1)).unwrap(),
        RequestId::try_from(serde_json::json!("1")).unwrap()
    );
    for invalid in [
        serde_json::Value::Null,
        serde_json::json!(1.5),
        serde_json::json!({}),
        serde_json::json!([]),
    ] {
        assert!(RequestId::try_from(invalid).is_err());
    }
}
```

Add tests that `SUPPORTED_PROTOCOL_VERSIONS` is exactly newest-first, protocol
error messages do not contain hostile method/field values, and serialized
numeric IDs remain numeric. Assert genuine syntax input returns
`StrictJsonError::Syntax`, every duplicate-key case above returns
`StrictJsonError::DuplicateKey`, and every structural-limit breach returns
`StrictJsonError::StructuralBudget`; server-code mapping and no-dispatch behavior
are tested after `McpServer` exists in Task 5.

Add exact boundary tests for depth 64/65, 262,144/262,145 nodes,
131,072/131,073 aggregate object members, 1,048,576/1,048,577 aggregate key
bytes, and request-ID serialized wire length 256/257. Include very wide arrays
and objects. A source test rejects `HashSet<String>` in the strict visitor and
requires `serde_json::Map::contains_key` duplicate checks before insertion.

- [ ] **Step 2: Run the protocol test and verify RED**

Run:

```bash
cargo test --test mcp_protocol task7_strict_json_ -- --nocapture
```

Expected: compilation fails because `codex_ssh_bridge::mcp` does not exist.

- [ ] **Step 3: Define the protocol boundary**

Export `pub mod mcp;` from `src/lib.rs`. In `src/mcp/protocol.rs` define:

```rust
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18"];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestId {
    String(String),
    Number(serde_json::Number),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolState {
    AwaitInitialize,
    AwaitInitialized,
    Ready,
    Closing,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: String,
    pub title: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub annotations: ToolAnnotations,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    pub content: Vec<TextContent>,
    pub structured_content: serde_json::Value,
    #[serde(skip_serializing_if = "is_false")]
    pub is_error: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl CallToolResult {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![TextContent::new(text)],
            structured_content: serde_json::json!({}),
            is_error: false,
        }
    }
}
```

Define `TextContent::new` so its serialized object is exactly
`{"type":"text","text":"..."}`, define `ToolAnnotations` with all four
Boolean hints, and:

```rust
pub type ToolFuture = Pin<
    Box<
        dyn Future<Output = CallToolResult> + Send + 'static,
    >,
>;

#[derive(Debug, Clone, Copy)]
pub struct WireBudget {
    pub result_bytes: usize,
    pub compact_fallback_bytes: usize,
}

pub struct ToolCallContext {
    pub cancel: CancellationToken,
    pub wire_budget: WireBudget,
}

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

Implement fixed constructors for parse error `-32700`, invalid request
`-32600`, method not found `-32601`, invalid params `-32602`, internal error
`-32603`, server not initialized `-32002`, request too large `-32001`, and
server busy `-32000`. Constructors accept a trusted `RequestId` where
appropriate and never accept a caller-derived public message.

Add `CallToolResult::invalid_argument(actionable_safe_text)` that produces a
normal tool result with `isError=true`, stable `INVALID_ARGUMENT` structured
code, and one compact-JSON corrective text block. It normally has no remote
context and omits those fields. It never accepts serde's diagnostic or a
rejected caller value.

- [ ] **Step 4: Implement duplicate-rejecting recursive JSON parsing**

Implement a `DeserializeSeed`/`Visitor` pair that:

- enforces depth 64, 262,144 total nodes, 131,072 aggregate object members, and
  1,048,576 aggregate key bytes with checked counters before allocation;
- checks the `serde_json::Map` currently being built with `contains_key` before
  inserting a key, without a parallel `HashSet` or extra key clone;
- sets a shared failure marker to `DuplicateKey` on the second occurrence;
- sets that same marker to `StructuralBudget` before returning from every
  depth/node/member/key-byte breach;
- recursively uses the same seed for arrays and objects;
- builds `serde_json::Value` for strings, integral/floating numbers, Booleans,
  null, arrays, and objects; and
- invokes `Deserializer::end()` so trailing data fails.

Define the public classification explicitly:

```rust
pub enum StrictJsonError {
    Syntax,
    DuplicateKey,
    StructuralBudget,
}
```

Use an `Rc<Cell<StrictFailureMarker>>` shared by every recursive seed, with
`None`, `DuplicateKey`, and `StructuralBudget` states. `parse_strict_json` maps
the latter two exactly and uses `StrictJsonError::Syntax` only when the marker
remains None and serde reports malformed JSON/trailing data. No variant retains
or displays serde's error or input text. The lifecycle owner maps duplicate and
structural failures to `-32600` and genuine syntax to `-32700`, always with
`id=null` and without dispatching. No code attempts to recover a request ID
from a failed parse.
`RequestId::try_from` accepts strings and integral serde numbers only.
It rejects IDs whose compact serialized form exceeds 256 bytes. Structural
budget failures map to fixed invalid request with `id=null` and do not expose
the counter, key, or input.

- [ ] **Step 5: Run strict protocol unit tests**

Run:

```bash
cargo test --test mcp_protocol task7_strict_json_ -- --nocapture
cargo test --test mcp_protocol task7_request_ids_ -- --nocapture
cargo test --test mcp_protocol task7_protocol_constants_ -- --nocapture
```

Expected: all strict JSON, ID, and constructor tests pass.

- [ ] **Step 6: Commit the protocol model**

```bash
git add src/mcp/protocol.rs src/mcp/mod.rs src/lib.rs tests/mcp_protocol.rs
git commit -m "feat: define strict MCP protocol model"
```

---

### Task 4: Implement Bounded Stdio Framing and Capped Serialization

**Files:**
- Create: `src/mcp/stdio.rs`
- Modify: `src/mcp/mod.rs`
- Modify: `tests/mcp_protocol.rs`

**Interfaces:**
- Consumes: effective frame bytes, bounded request IDs, protocol `WireBudget`
  and response values, trusted tool definitions, and renderer-provided compact
  fallbacks.
- Produces: `FrameReader<R>::next_frame`, `FrameEvent`,
  `MIN_MCP_FRAME_BYTES`, service-specific exact minimum calculation,
  `CappedJsonBuffer`, and `write_json_line`.

- [ ] **Step 1: Add exact-boundary frame tests**

Use `tokio::io::BufReader` over byte slices and assert:

```rust
#[tokio::test]
async fn task7_frame_reader_accepts_exact_limit_and_recovers_after_plus_one() {
    let wire = b"12345678\n123456789\n{}\n";
    let mut reader = FrameReader::new(
        tokio::io::BufReader::new(wire.as_slice()),
        8,
    );
    assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::Frame(b"12345678".to_vec()));
    assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::Oversized);
    assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::Frame(b"{}".to_vec()));
    assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::Eof);
}
```

Add integration cases for multiple frames in one buffer, CRLF, invalid UTF-8
passed as raw bytes to the parser, empty lines, EOF with no bytes, and EOF with
a partial frame. Put the multi-megabyte no-newline retention case in a
`#[cfg(test)] mod tests` inside the newly created `src/mcp/stdio.rs`; the unit
test may inspect the private `retained.capacity()` directly and asserts it
never grows beyond the configured bound. Add `mod stdio;` before the RED run;
do not expose a production capacity accessor only for this test.

- [ ] **Step 2: Add capped writer and stdout-injection tests**

Test `CappedJsonBuffer` at exact N and N+1. Serialize a text content value
containing newline, NUL, Unicode, and a fake `{"jsonrpc":"2.0"}` response;
assert the serialized bytes contain no raw newline before the final delimiter
and parse as one JSON object.

Define:

```rust
use crate::config::MAX_REMOTE_CONTEXT_ROOT_BYTES;
use crate::capability::MAX_SHELL_VERSION_BYTES;

pub const MAX_CONTEXT_ROOT_WIRE_EXPANSION: usize = 13;
pub const MAX_REQUEST_ID_WIRE_BYTES: usize = 256;
pub const MIN_FIXED_RESPONSE_RESERVE: usize = 64 * 1024;
pub const MIN_MCP_FRAME_BYTES: usize = 1024 * 1024;
const _: () = assert!(
    MAX_REMOTE_CONTEXT_ROOT_BYTES
        <= usize::MAX / MAX_CONTEXT_ROOT_WIRE_EXPANSION
);
const _: () = assert!(
    MIN_MCP_FRAME_BYTES
        >= MAX_REMOTE_CONTEXT_ROOT_BYTES * MAX_CONTEXT_ROOT_WIRE_EXPANSION
            + MAX_REQUEST_ID_WIRE_BYTES
            + MIN_FIXED_RESPONSE_RESERVE
);
```

At Task 4, add exact tests for the compiled formula, a maximum 256-byte
serialized ID, the generic full tools/list counting helper, and an equivalent
test-only worst-response projection. That projection starts with an actual
maximum `BridgeError`/`ErrorDetails`, an untruncated absolute 65,536-byte
control-heavy root, a worst-escaped control-heavy 256-byte shell version, and
maximum bounded safe error/action/warnings using alternating quote/backslash
bytes. It asserts host/root/shell are absent from its nested error core, root
occurs only in Text context and structured top-level context, exact projected
bytes succeed, minus one fails, and the compiled 1 MiB floor fits. This is only
an authoritative size projection: Task 7 must replace it with the real
sanitizer and `RenderedErrorCore` assertions.

With trusted stub definitions, use a counting serializer and synthetic
maximum-wire ID to derive the non-degradable complete `tools/list` size and
prove definition/description growth changes it. Task 5 owns initialize, ping,
all fixed protocol-response fit tests, and `McpServer::new` exact/minus-one
assertions once those production objects exist. Task 7 owns every real compact
tool fallback, all bulk/mutation degradation assertions, the real largest
fallback count, and repeated constructor exact/minus-one assertions. No Task 4
test may claim production coverage for a type or renderer not yet implemented.

Assert ID length cannot consume its reserve, and `WireBudget` subtracts only
envelope/ID/fallback bytes with checked arithmetic; it must not subtract the
newline delimiter. Here and in `required_mcp_frame_bytes`, fallback bytes mean
the serialized fallback `result` alone, excluding envelope, ID, and newline;
the compiled full-frame minimum must never be passed as that argument. The
real per-tool over-budget and mutation-truth assertions are assigned to Task 7.

- [ ] **Step 3: Run framing tests and verify RED**

Run:

```bash
cargo test --test mcp_protocol task7_frame_ -- --nocapture
cargo test --test mcp_protocol task7_capped_writer_ -- --nocapture
cargo test --test mcp_protocol task7_min_frame_ -- --nocapture
cargo test --lib mcp::stdio::tests::task7_frame_retention_ -- --nocapture
```

Expected: compilation fails because `mcp::stdio` does not exist.

- [ ] **Step 4: Implement the bounded reader**

Define:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameEvent {
    Frame(Vec<u8>),
    Oversized,
    PartialEof,
    Eof,
}

pub struct FrameReader<R> {
    reader: R,
    limit: usize,
    retained: Vec<u8>,
    discarding: bool,
}
```

`next_frame` repeatedly calls `fill_buf`, searches for `b'\n'`, copies only up
to the remaining allowance, switches permanently to discard mode for that
frame on the first byte over the bound, and calls `consume` for every inspected
byte. At a delimiter it returns `Oversized` or moves out the retained bytes.
At EOF it returns `PartialEof` only when bytes were retained or discarded.

- [ ] **Step 5: Implement capped compact JSON lines**

Define a `CappedJsonBuffer` implementing `std::io::Write`. Its `write` method
uses checked addition and returns a private capacity error before extending
beyond the limit. Implement:

```rust
pub fn serialize_json_line<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<Vec<u8>, SerializeLineError> {
    let mut output = CappedJsonBuffer::new(limit);
    serde_json::to_writer(&mut output, value)
        .map_err(SerializeLineError::from)?;
    let mut bytes = output.into_inner();
    bytes.push(b'\n');
    Ok(bytes)
}
```

The limit excludes the delimiter, matching input framing. Append the one
newline only after capped serialization succeeds; it is not part of
`WireBudget` or `max_frame_bytes`. Do not use
`serde_json::to_vec` or `to_string` before the cap.

`WireBudget::for_response` reserves the compact JSON-RPC envelope, the at-most
256-byte serialized ID, and the result-only largest fixed compact fallback
before returning a renderer budget. It does not reserve the delimiter.
`required_mcp_frame_bytes` takes that same result-only fallback size, adds the
exact envelope with checked arithmetic, and compares the complete response to
the compiled full-frame floor and exact tools/list frame. Task 5 wires
`McpServer::new`; Task 4 only supplies and tests these generic calculators. The
writer accepts only budgeted response models; it is the final invariant check
and never invents a different semantic result.

- [ ] **Step 6: Run framing and serializer tests**

Run:

```bash
cargo test --test mcp_protocol task7_frame_ -- --nocapture
cargo test --test mcp_protocol task7_capped_writer_ -- --nocapture
cargo test --test mcp_protocol task7_min_frame_ -- --nocapture
cargo test --lib mcp::stdio::tests::task7_frame_retention_ -- --nocapture
```

Expected: all framing, memory-retention, recovery, and injection tests pass.

- [ ] **Step 7: Commit bounded stdio**

```bash
git add src/mcp/stdio.rs src/mcp/mod.rs tests/mcp_protocol.rs
git commit -m "feat: add bounded MCP stdio framing"
```

---

### Task 5: Implement the Asynchronous MCP Lifecycle Owner and Cancellation Registry

**Files:**
- Modify: `src/mcp/mod.rs`
- Modify: `src/mcp/protocol.rs`
- Modify: `tests/mcp_protocol.rs`

**Interfaces:**
- Consumes: strict frames, protocol constructors, `ToolService`, `CancellationToken`, and capped output.
- Produces: `McpServer<S>::new`, `McpServer<S>::serve<R, W>`, exact lifecycle transitions, bounded in-flight calls, response suppression after MCP cancellation, and orderly EOF.

- [ ] **Step 1: Add a deterministic, separately instrumented stub service**

In `tests/mcp_protocol.rs` define a service whose `block` call waits on a
durable semaphore gate and records token cancellation, whose `echo` call
returns one text block, and whose two counters distinguish synchronous service
invocation from future polling:

```rust
#[derive(Clone)]
struct StubTools {
    definitions: Arc<Vec<ToolDefinition>>,
    synchronous_calls: Arc<AtomicUsize>,
    first_polls: Arc<AtomicUsize>,
    bridge_ops: Arc<AtomicUsize>,
    observed_cancel: Arc<AtomicBool>,
    entered: Arc<AtomicBool>,
    entered_notify: Arc<Notify>,
    release: Arc<Semaphore>,
    contexts: Arc<Mutex<Vec<ToolCallContext>>>,
}

impl ToolService for StubTools {
    fn definitions(&self) -> &[ToolDefinition] {
        self.definitions.as_slice()
    }

    fn call(
        &self,
        name: String,
        arguments: serde_json::Value,
        context: ToolCallContext,
    ) -> ToolFuture {
        self.synchronous_calls.fetch_add(1, Ordering::SeqCst);
        let first_polls = Arc::clone(&self.first_polls);
        let bridge_ops = Arc::clone(&self.bridge_ops);
        let observed_cancel = Arc::clone(&self.observed_cancel);
        let entered = Arc::clone(&self.entered);
        let entered_notify = Arc::clone(&self.entered_notify);
        let release = Arc::clone(&self.release);
        let contexts = Arc::clone(&self.contexts);
        Box::pin(async move {
            first_polls.fetch_add(1, Ordering::SeqCst);
            contexts.lock().await.push(context.clone());
            entered.store(true, Ordering::Release);
            entered_notify.notify_waiters();
            if name == "block" {
                bridge_ops.fetch_add(1, Ordering::SeqCst);
                tokio::select! {
                    () = context.cancel.cancelled() => {
                        observed_cancel.store(true, Ordering::SeqCst);
                        return CallToolResult::text("cancelled internally");
                    }
                    permit = release.acquire() => {
                        permit.expect("test release semaphore remains open").forget();
                    }
                }
            }
            if name == "echo" {
                return match arguments.get("text").and_then(Value::as_str) {
                    Some(text) => {
                        bridge_ops.fetch_add(1, Ordering::SeqCst);
                        CallToolResult::text(text)
                    }
                    None => CallToolResult::invalid_argument(
                        "provide arguments.text as a string",
                    ),
                };
            }
            unreachable!("the lifecycle owner rejects unknown names")
        })
    }
}
```

Use exact closed test definitions for `block` and `echo`; do not use the final
nine-tool registry in protocol-core tests.
The synchronous counter records `ToolService::call`; the first-poll counter
records actual future admission; `bridge_ops` records only valid work after
known-tool argument decoding. Separate gates prove whether a future was
only constructed or also consumed a slot and was first polled. Record the
received `ToolCallContext`, compare both `WireBudget` fields exactly, cancel
the recorded token from the test and observe the service's clone, then cancel
through MCP and observe the recorded clone. These two directions prove shared
token semantics rather than only equal initial state.

Every async test and every wait for a response, `Notify`, join, or EOF uses
`tokio::time::timeout`: five seconds around each complete test and one second
around focused events. The entered waiter loops over the durable
`AtomicBool::load(Ordering::Acquire)` predicate and a pre-created
`Notify::notified()` future, so `notify_waiters` cannot lose the event. Release
uses a semaphore permit, which is also durable. Use these gates, never an
unbounded wait or a sleep as synchronization; Task 5 does not add Tokio's
`test-util` feature.

- [ ] **Step 2: Add RED constructor and fixed-response budget tests**

Counting-serialize initialize, ping, every fixed protocol error, and
tools/list with the synthetic maximum wire ID. Also cover scalar, batch, null,
fractional, and overlong IDs plus extra JSON-RPC envelope keys. With the stub
definitions and the Task 5 result-only fallback exactly zero, assert:

- `McpServer::new(service, required, max_inflight)` succeeds at the exact
  service-specific requirement;
- required-minus-one and `crate::MAX_FRAME_BYTES + 1` fail with fixed
  `BridgeError::invalid_argument` messages containing no ID, definition, or
  serde text;
- nominal 1 MiB succeeds whenever the exact tools/list frame fits it; and
- accepted calls prove `McpServer` propagates its one stored Task 5 zero
  result-only fallback unchanged into every per-ID `WireBudget`.

Run `cargo test --test mcp_protocol task7_constructor_ -- --nocapture` and
observe the expected compile failure because `McpServer` is absent.

- [ ] **Step 3: GREEN the constructor from the one fallback source**

Define:

```rust
pub struct McpServer<S> {
    service: Arc<S>,
    max_frame_bytes: usize,
    max_inflight: usize,
    compact_fallback_result_bytes: usize,
}

impl<S: ToolService> McpServer<S> {
    pub fn new(
        service: Arc<S>,
        max_frame_bytes: usize,
        max_inflight: usize,
    ) -> BridgeResult<Self> {
        let compact_fallback_result_bytes = 0;
        let synthetic_id = RequestId::synthetic_max_wire();
        let required = required_mcp_frame_bytes(
            service.definitions(),
            compact_fallback_result_bytes,
            &synthetic_id,
        )
        .map_err(|_| {
            BridgeError::invalid_argument("MCP response budget is invalid")
        })?;
        if max_frame_bytes < required || max_frame_bytes > crate::MAX_FRAME_BYTES {
            return Err(BridgeError::invalid_argument("MCP frame bound is invalid"));
        }
        if max_inflight == 0 || max_inflight > 32 {
            return Err(BridgeError::invalid_argument("MCP in-flight bound is invalid"));
        }
        Ok(Self {
            service,
            max_frame_bytes,
            max_inflight,
            compact_fallback_result_bytes,
        })
    }
}
```

Pass the synthetic request ID by reference and never clone or reconstruct it
inside a calculator. Map the counting helper's error to the fixed
`BridgeError::invalid_argument("MCP response budget is invalid")`; do not
propagate serde text. Validate
`required <= max_frame_bytes <= crate::MAX_FRAME_BYTES` and
`1 <= max_inflight <= 32` with fixed non-echoing invalid-argument errors.

`compact_fallback_result_bytes` is the only stored fallback count. Task 5 sets
it to zero exactly once; Task 7 changes only that initializer to
`maximum_compact_fallback_result_bytes()`. Never pass `MIN_MCP_FRAME_BYTES` as
this result-only value. Rerun `task7_constructor_` to GREEN before continuing.

- [ ] **Step 4: Add RED envelope, request/notification, and lifecycle tests**

Create an in-memory helper around `tokio::io::duplex` that writes compact
frames and reads complete response lines. Cover:

- valid initialize → initialized → ping → tools/list;
- required initialize `protocolVersion`, `capabilities`, and `clientInfo`;
- supported `2025-06-18` validates only name/title/version and rejects
  icons/description/websiteUrl; supported `2025-11-25` accepts its latest-only
  fields; an unsupported version validates the bounded current 2025-11 shape
  before selecting `2025-11-25`, accepting latest-only fields but rejecting any
  field outside that union;
- optional open-object `_meta` values on initialize, ping,
  notifications/initialized, tools/list, tools/call, and
  notifications/cancelled are accepted and ignored; non-object `_meta` fails;
- a versioned project-policy golden matrix based on the official methods for
  initialize/ping/initialized/list/call/
  cancelled: 2025-06 accepts, ignores, and never reflects additional bounded
  top-level params extensions; the project's 2025-11 validator rejects fields
  outside each method's known official field set, and invalid initialized/
  cancelled notifications cause no state/cancel effect; `task` is rejected
  because tasks were not negotiated;
- capabilities is an open object; for `2025-06-18`, clientInfo accepts exactly
  required name/version plus optional title; for `2025-11-25`, it additionally
  accepts icons/description/websiteUrl, with bounded strings/icon count and
  bounded absolute URI validation whose fixed errors echo no value;
- exact client limits are 256 UTF-8 bytes for name/title/version, 4,096 for
  description, 2,048 for websiteUrl, 16 icons, and 65,536 for icon src; each
  2025-11-25 icon is closed to required src plus optional mimeType/sizes/theme,
  with MIME type 256 bytes, at most 16 size strings of 32 bytes, theme
  light/dark, and absolute-URI validation that accepts data URIs but performs no
  fetch;
- ping succeeds after initialize while AwaitInitialized and again in Ready;
- tools/list without a cursor returns all definitions and no `nextCursor`; a
  nonempty cursor is `-32602` rather than a repeated page;
- tool call before initialize and before initialized;
- duplicate initialize and duplicate initialized;
- syntax failure maps to `-32700`, every nested duplicate-key failure maps to
  `-32600` with `id=null`, and neither reaches the stub service;
- a malformed tools/call envelope or unknown name maps to `-32602`, while a
  known tool with a duplicate-free invalid argument object returns a normal
  actionable `isError=true` result and performs no bridge/remote work;
- unknown request method versus unknown notification;
- notifications producing no response;
- request-only `initialize`, `ping`, `tools/list`, and `tools/call` without an
  ID producing no response, state transition, synchronous service invocation,
  or future poll;
- any envelope where `id` is present but null, fractional, object/array/bool,
  or overlong producing fixed `-32600 Invalid Request` with `id=null`, never
  being reclassified as a notification;
- notification-only `notifications/initialized` and
  `notifications/cancelled` with a valid nonduplicate ID returning fixed
  `-32600 Invalid Request` for that ID and producing no state/cancellation
  effect (an ID matching an active tool task follows the active-task duplicate
  rule);
- invalid params container types and extra JSON-RPC envelope keys; and
- malformed envelope, lifecycle, and unknown-name failures leaving
  `synchronous_calls == 0`, `first_polls == 0`, and `bridge_ops == 0`; while a
  known-tool invalid argument returns its normal error with
  `synchronous_calls == 1`, `first_polls == 1`, and `bridge_ops == 0`.

This Task 5 suite also counting-serializes initialize, ping, and every fixed
protocol error with the maximum wire ID and proves each fits the compiled
full-frame floor. With the stub definitions and result-only fallback size zero,
it computes `required_mcp_frame_bytes`, proves `McpServer::new` accepts that
exact value and rejects one byte less, and proves the nominal 1 MiB floor is
accepted whenever tools/list does not exceed it. These production assertions
were intentionally not claimed by Task 4. The stub also records the
`ToolCallContext` and proves its `wire_budget.compact_fallback_bytes` is exactly
the server's stored zero result-only value. Task 5 does not claim nonzero server
propagation: Task 7 replaces the initializer with the real nonzero fallback and
owns that end-to-end constructor/per-ID propagation test.

The initialize frame used by all positive tests is:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test-client","version":"1"}}}
```

Run `cargo test --test mcp_protocol task7_lifecycle_ -- --nocapture` and expect
failures from absent envelope/state behavior, not fixture timeouts.

- [ ] **Step 5: GREEN strict envelopes and lifecycle state transitions**

Classify request versus notification before method side effects. A request has
a present `id`; a notification has no `id`. Validate a present ID immediately:
only bounded string/integer IDs are legal, while every invalid present ID gets
fixed `-32600` with `id=null` and is never notification-shaped. Request-only
methods received as notifications are ignored with zero effect. Notification-
only methods received as nonduplicate requests return the fixed invalid-request
response for their trusted ID and have zero effect. A duplicate legal ID is
handled earlier only when it matches an active tool task. Malformed notifications never emit
a response and never change state, cancel a token, invoke the service, or poll
a future. Malformed requests with a trusted ID receive the method-appropriate
fixed error.

Validate the JSON-RPC envelope and method params before changing state. Only
after a valid initialize response is accepted by the bounded writer channel
does state advance to `AwaitInitialized`; only a valid ID-less initialized
notification advances to `Ready`. Run `task7_lifecycle_` to GREEN before adding
dispatch.

Use a dependency-free, allocation-free RFC 3986 state machine. Validate the
UTF-8 byte ceiling, ASCII-only requirement, forbidden whitespace/control/
backslash, and ASCII bytes `0x22, 0x3c, 0x3e, 0x5e, 0x60, 0x7b, 0x7c, 0x7d`
before scanning. States and transitions are exact:

1. `scheme`: first byte ASCII alpha, then ASCII alphanumeric/`+-.`, terminated
   by one required `:` with at least one following suffix byte; compare
   HTTP/HTTPS ASCII-case-insensitively;
2. `authority`: enter only when the two bytes immediately after `:` are `//`;
   stop at the first `/`, `?`, `#`, or end. Internal `//` after path begins is
   path data, never a late authority transition;
3. `path`: scan RFC `pchar` or `/` until the first `?` or `#`; `[` and `]` are
   illegal here;
4. `query`: at most one transition on the first `?`, then scan `pchar`, `/`, or
   `?` until `#` (later `?` is query data, not a second transition); and
5. `fragment`: at most one transition on `#`, then scan `pchar`, `/`, or `?` to
   end; a second `#` is illegal.

In every component, `%` consumes exactly two following hexadecimal digits.
`pchar` is precisely unreserved, sub-delims, `:`, or `@`; brackets are admitted
only around an authority IPv6 host. HTTP/HTTPS, in any ASCII case, requires the
immediate authority transition. For any authority reject userinfo; parse a
bracketed host interior with `std::net::Ipv6Addr`; otherwise accept
`std::net::Ipv4Addr` or DNS-like nonempty labels of at most 63 bytes and 253
bytes total, with ASCII-alphanumeric edges and only interior `-`. A dotted
digits-only host must parse as IPv4. An optional port is `:` plus nonempty ASCII
digits parsed as `u16`; reject unbracketed IPv6, empty labels/host/port, and
trailing authority junk. No state allocates a normalized URL or resolves a
name.

Tests accept lower/upper-case HTTPS, `urn:example:test`, `data:,hello`, internal
path `//`, query data containing `?`, bracketed IPv6, IPv4, DNS, and ports.
Reject relative/empty input, a second `#`, brackets in path, malformed percent
escapes, forbidden bytes, non-ASCII, userinfo, malformed authority/IP/DNS/port,
and exact-limit +1 input. No URI is fetched, reflected, or logged. November's
method-field closure is an explicit project security
policy layered on the supported protocol version, not a claim that the upstream
schema mechanically enforces closure.

- [ ] **Step 6: Add RED dispatch, active-task duplicate-ID, saturation, panic, and ordering tests**

Start a first `block` call and wait for its durable entered predicate. Then send
a second immediate `echo`, read the echo response first, release the first
call's semaphore, and read its response second. This deterministic test does
not depend on semaphore waiter wake order and proves exact out-of-request-order
IDs without line interleaving. With `max_inflight=2`, submit a
third valid unique known-name request and assert fixed `-32000 Server busy`,
`synchronous_calls == 2`, and `first_polls == 2`.

Freeze an ID matching an active tool task as exactly:

```json
{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Duplicate request id"}}
```

Numeric `1` and string `"1"` remain distinct. Validation priority is: strict
JSON and envelope/legal ID; match against the active tool-task registry;
lifecycle and method-params shape; known tool-name lookup; then saturation.
Any legal ID matching an active tool task therefore gets the duplicate error
with `id=null`, even if the second envelope has illegal params, is not currently
lifecycle-valid, has an unknown name, or arrives while saturated. Null/
fractional/object/oversized IDs are not legal duplicates: they receive fixed
`-32600 Invalid Request` with `id=null`. The duplicate consumes no new slot,
never calls or polls the service, never overwrites the active entry, and later
cancellation still reaches the original task.

The protection ends at task join/removal, before its response is queued. Gate a
completion while the writer is backlogged, let the owner join/remove the task
and enqueue its first response, then submit a second request with the same ID.
Assert the second request is admitted and both responses may be queued in
completion order. The lifecycle owner does not retain an ID merely because a
response is waiting in the writer channel.

Add services that panic synchronously inside `ToolService::call`, on first
future poll, and after first poll. Assert one fixed `-32603 Internal error` for
the correct request, no panic payload or caller data in the wire response or
returned `BridgeError` or bridge-authored diagnostics, one-time
registry/slot release, continued service for other requests, and an empty
registry after every success, error, panic, cancellation, and close. Verify
this group RED with:

```bash
cargo test --test mcp_protocol task7_dispatch_ -- --nocapture
cargo test --test mcp_protocol task7_inflight_ -- --nocapture
cargo test --test mcp_protocol task7_panic_ -- --nocapture
```

Expected: failures identify missing dispatch/admission/panic behavior, not a
fixture timeout.

Task 5 does not install or replace a process-global panic hook. Rust's existing
host-selected panic hook may write to stderr before unwind is caught; that
runtime-owned behavior is outside the bridge diagnostic contract. Tests inspect
only MCP output, returned errors, and diagnostics explicitly emitted by the
bridge.

- [ ] **Step 7: GREEN bounded panic-safe dispatch and admission**

Call `service.call(...)` inside the spawned task so future-construction and
poll panics both become `JoinError` instead of unwinding the owner. Maintain a
task-ID-to-request-ID map driven by `JoinSet::join_next_with_id`, or an exactly
equivalent panic-safe association, in addition to the request registry. Insert
the registry entry only after `try_acquire_owned` succeeds, and store that
`OwnedSemaphorePermit` in the owner-held `InFlight`, never inside the task;
then spawn and associate the returned task ID immediately. Every join path
removes both maps and drops the owner-held permit exactly once. Closing clears
remaining `InFlight` entries after abort/drain, so even a drain timeout cannot
leak slots. A missing association is an internal invariant failure
that enters Closing rather than guessing an ID.

Use the one stored fallback count for exact per-ID `WireBudget`; pass both
fields and the token unchanged in `ToolCallContext`. Run `task7_dispatch_`,
`task7_inflight_`, and `task7_panic_` to GREEN.

- [ ] **Step 8: Add RED cancellation-shape, race, and fairness tests**

Send a `block` call with ID `"job"` followed by:

```json
{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"job","reason":"hostile\nreason"}}
```

Assert the stub observes cancellation, no response for `"job"` is written, and
a following ping still succeeds. Repeat for numeric ID, unknown ID, duplicate
cancel, late cancel, malformed params, and a cancellation targeting initialize.

Explicitly test missing/null/fractional/oversized `requestId`, a non-string or
over-1,024-byte `reason`, non-object params, and an ID-bearing cancelled method.
After June negotiation, extra bounded top-level cancellation params are
ignored; after November negotiation they are rejected. In both versions,
`requestId` is required, `reason` is optional bounded UTF-8 text, `_meta` is an
optional open object, and unnegotiated `task` is rejected. Invalid
notifications produce no response and no cancellation effect. The reason is
borrow-validated in place, never cloned, reflected, or logged. Fully validate
requestId, reason, `_meta`, version-
specific unknown fields, and `task` before looking up any registry entry or
triggering any token.

For the hard race, make the tool completion and cancellation frame both
already buffered/ready before the owner polls either. Assert cancellation wins,
the call response is suppressed, and registry/slot are released. Then stream a
bounded sequence of continuously ready notifications while one completion is
ready and prove the completion is reaped within a fixed number of owner
iterations. Add an idle-Ready server with an empty `JoinSet`: under a current-
thread runtime, a timeout-wrapped sibling yield/heartbeat must progress and a
later ping must succeed, proving the owner does not busy-loop on `None`. Run
`cargo test --test mcp_protocol task7_cancellation_ -- --nocapture` and verify
RED from missing shape/race behavior, not a timeout.

- [ ] **Step 9: GREEN cancellation races with bounded notification fairness**

Maintain:

```rust
struct InFlight {
    cancel: CancellationToken,
    cancelled_by_client: bool,
    _permit: OwnedSemaphorePermit,
}

struct CompletedCall {
    id: RequestId,
    outcome: CallToolResult,
}
```

Use a biased select ordered writer-result first, input second, and tool
completion third. Guard the join branch exactly with
`if !join_set.is_empty()` because `join_next_with_id()` on an empty set returns
`None` immediately and otherwise creates a busy loop. The writer can therefore
never be starved by input, while input still wins over a simultaneously ready
tool completion. Immediately after every processed input frame, check the same
nonempty condition, call `try_join_next_with_id` at most once, and process that
completion if present before selecting the next frame. This exact one-frame/one-try-reap rule
preserves cancel-wins and prevents a continuously ready notification stream
from starving completion cleanup.

Handle methods exactly:

- `initialize` only in AwaitInitialize;
- `notifications/initialized` only in AwaitInitialized;
- `ping` in AwaitInitialized or Ready;
- `tools/list` and `tools/call` only in Ready;
- `notifications/cancelled` only as a notification;
- unknown requests as `-32601` and unknown notifications as no-op.

Select a protocol-shape validator. After supported 2025-06 negotiation, all six
supported method params validate required standard fields but collect/discard
additional top-level extension entries; they are never reflected or logged.
After 2025-11 negotiation, apply the project's closed validator to the official
method fields.
For initialize, inspect requested `protocolVersion` from the already strict
Value: supported versions select their matching shape, while unsupported uses
the bounded closed current-2025-11 union before latest selection. `_meta` and
initialize capabilities are explicitly open objects in every shape.

Initialize, ping, initialized, `tools/list`, `tools/call`, and cancelled admit
optional object `_meta` and discard it. `tools/list`
admits optional string `cursor`; because this server returns one complete page
and never emits `nextCursor`, reject any nonempty cursor with `-32602`.
Validate `tools/call.params` as containing required string `name`, object
`arguments` defaulting to `{}`. Its `arguments` object and nested tagged inputs
remain closed in both versions. Other top-level params follow June-open versus
November-closed rules. Reject unnegotiated `task` fields.
Reject an unknown name before spawn by checking `service.definitions()` after
the active-task ID check and before saturation.
Compute `WireBudget::for_response(self.max_frame_bytes, &id,
self.compact_fallback_result_bytes)` for that exact request ID and construct
`ToolCallContext { cancel: token.clone(), wire_budget }`. Insert the ID/token
before spawning and invoke `service.call` only inside the task. On join,
remove the task association and active request entry and release the slot
before attempting to queue any response. Then suppress output if
`cancelled_by_client`, otherwise return the `CallToolResult` as the JSON-RPC
result. A queued response retains no registry ID. Known-tool argument validation stays inside the normal result channel;
only envelope/name validation can produce `-32602`.

Validate version-specific `clientInfo` before changing state. Supported
versions use their requested schema. An unsupported version uses the bounded
current 2025-11 union first and only then selects the latest supported version.
Use fixed length, icon-count, and absolute-URI bounds and fixed errors with no rejected value.
Initialize instructions explicitly warn that cancellation of a mutating call
may leave partial/unknown effects and tell the client to inspect rather than
blindly retry.

Rerun `cargo test --test mcp_protocol task7_cancellation_ -- --nocapture` to
GREEN before adding shutdown behavior.

- [ ] **Step 10: Add RED EOF, writer-failure, backpressure, and shutdown tests**

Use writer fixtures that fail the first write, fail after a controlled prefix,
write one byte per successful poll, and remain pending forever after a prefix.
Monitor the writer task in the owner's main select,
not only during final shutdown. Test clean EOF, partial EOF, queue saturation,
writer early return, writer panic, and a writer that never completes. For each,
cover cooperative cancellation, a future that ignores its token, and a tool
completion already ready in the `JoinSet` when Closing begins.

For clean EOF, test zero calls plus cooperative and token-ignoring active calls:
the server returns success whenever cancellation, bounded task reap/abort-drain,
and writer drain/shutdown all finish healthily. Inject a task-drain or writer-
shutdown failure and require fixed MCP transport failure. For partial EOF,
assert fixed ProtocolError only after the parse-error control response has been
healthily written and writer shutdown completes; a full/closed writer channel,
later write error, shutdown error, or writer timeout takes precedence as fixed
MCP transport failure.

Freeze these assertions:

- entering Closing first rejects dispatch; partial EOF then attempts only fixed
  `-32700` with `id=null`; next the owner sets one global
  `suppress_call_responses` flag and cancels every token; no completion, panic
  conversion, or not-yet-started queued call result is sent afterward; a line
  whose writer already committed past its final suppression check is not
  retractable; clean EOF queues nothing;
- writer failure/backpressure sends no replacement to the broken writer,
  exposes no hostile `io::Error` text, and returns only fixed local
  `BridgeError::io("MCP transport failed")`;
- serializer/capacity overflow is detected before the first transport write and
  therefore emits zero bytes; a transport `write_all` error or writer abort may
  leave a prefix of the current frame, so the connection closes immediately and
  no later frame is attempted;
- on a healthy successful transport, complete JSON lines never interleave,
  including with the one-byte writer; and
- all registries are empty and all slots are released after shutdown.

Use MCP-specific constants, not SSH process constants:

```rust
const MCP_TASK_CLEANUP_GRACE: Duration = Duration::from_millis(250);
const MCP_ABORT_DRAIN_GRACE: Duration = Duration::from_millis(250);
const MCP_WRITER_SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
```

With durable gates and outer timeouts, prove cooperative tasks reap before the
task grace; token-ignoring tasks are aborted no later than the grace plus a
small scheduler allowance and drained within the abort-drain grace; and a
pending writer is likewise aborted and drained within that bound. The test
never sleeps for synchronization and does not require Tokio paused time. Run:

```bash
cargo test --test mcp_protocol task7_writer_ -- --nocapture
cargo test --test mcp_protocol task7_eof_ -- --nocapture
```

Expected: failures show absent writer monitoring/cleanup/suppression, and the
outer timeout still terminates every fixture.

- [ ] **Step 11: GREEN one-owner Closing and bounded writer/task cleanup**

`serve<R, W>` accepts `R: AsyncRead + Unpin + Send + 'static` and
`W: AsyncWrite + Unpin + Send + 'static`. It wraps the reader in
`BufReader`/`FrameReader`, spawns one writer task, and gives it the only stdout
handle. The channel capacity is `max_inflight + 8`; `try_send` ensures the
owner never waits for stdout while cancellation input is pending.

The main select simultaneously monitors input, tool joins, and the writer
`JoinHandle`. Writer error, panic, or unexpected success while the channel is
open enters Closing immediately. Reader EOF/partial EOF and `try_send` full or
closed use the same idempotent transition. The exact sequence is: set Closing
and reject dispatch; on partial EOF only, `try_send` its fixed parse error;
set global call-response suppression and cancel every token; reap through
`MCP_TASK_CLEANUP_GRACE`; abort leftovers and drain only through
`MCP_ABORT_DRAIN_GRACE`; drop the last sender so a
healthy writer drains and shuts down; await its join through
`MCP_WRITER_SHUTDOWN_GRACE`; then abort and drain it only through
`MCP_ABORT_DRAIN_GRACE` if needed; and return only the fixed MCP transport
failure for writer/backpressure faults.

Store the writer handle as `Option<JoinHandle<_>>`. If the main select observes
it first, take it and retain only its sanitized success/failure outcome; the
shutdown path must not poll a completed handle twice. If it is still present
after the sender is dropped, the writer drains the channel, calls
`AsyncWriteExt::shutdown`, and is awaited through the writer grace.

The writer serializes already budgeted responses through `serialize_json_line`
and `write_all`. Channel messages are tagged `CallResponse` or `Control`; before
starting each queued `CallResponse`, the writer checks the shared suppression
flag and discards it when Closing has reached suppression. Define the
non-retractable write start as the instant this check atomically commits to
false for the dequeued message. A line past that commit cannot be retracted;
the EOF race test therefore
targets a completion simultaneously ready in the owner, which is never queued.
Serialization/capacity overflow occurs while building the capped buffer before
the first transport write and therefore emits zero bytes. Once `write_all`
starts, an I/O error or abort may leave the current frame prefix; immediately
close the transport and never attempt the next queued frame. The writer invents
no semantic fallback. Every tool join/abort path removes both
associations and releases slots exactly once.

For a valid cancellation, find the exact ID, set `cancelled_by_client=true`,
and call `cancel.cancel()`. Ignore unknown/completed/malformed IDs and reasons.
Do not cancel initialize.

Clean EOF with or without active calls returns success exactly when token
cancellation, bounded task reap/abort-drain, writer drain, and writer shutdown
all complete healthily. Otherwise return fixed MCP transport failure. If the
partial-EOF parse-error `try_send` succeeds and that control response is
healthily drained through writer shutdown, return fixed
`BridgeError::new(ErrorCode::ProtocolError, "partial MCP frame at EOF", false)`.
Any full/closed channel, later writer/write/shutdown error, writer timeout, or
cleanup failure takes precedence and returns fixed MCP transport failure.
Completion already ready at either EOF is globally suppressed once the
transition reaches its cancel/suppress phase.

Rerun `task7_writer_` and `task7_eof_` to GREEN before the complete suite.

- [ ] **Step 12: Run all protocol-core tests and invariant searches**

Run:

```bash
cargo test --test mcp_protocol task7_constructor_ -- --nocapture
cargo test --test mcp_protocol task7_lifecycle_ -- --nocapture
cargo test --test mcp_protocol task7_dispatch_ -- --nocapture
cargo test --test mcp_protocol task7_inflight_ -- --nocapture
cargo test --test mcp_protocol task7_panic_ -- --nocapture
cargo test --test mcp_protocol task7_cancellation_ -- --nocapture
cargo test --test mcp_protocol task7_writer_ -- --nocapture
cargo test --test mcp_protocol task7_eof_ -- --nocapture
cargo test --test mcp_protocol -- --nocapture
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
rg -n 'tokio::spawn|JoinSet|join_next_with_id|suppress_call_responses|MCP_TASK_CLEANUP_GRACE|MCP_WRITER_SHUTDOWN_GRACE' src/mcp tests/mcp_protocol.rs
```

Expected: lifecycle, version, strict-shape, framing, concurrency, cancellation,
writer, and EOF tests pass; the registry is empty on every terminal path; the
writer join is monitored in the owner select; and no client-cancelled or
Closing-suppressed call response is written.

- [ ] **Step 13: Commit the protocol core**

```bash
git add src/mcp/mod.rs src/mcp/protocol.rs tests/mcp_protocol.rs
git commit -m "feat: add asynchronous MCP lifecycle core"
```

---

### Task 6: Define the Exact Nine Tool Schemas and Closed Argument Types

**Files:**
- Create: `src/mcp/tools.rs`
- Modify: `src/mcp/mod.rs`
- Create: `tests/mcp_tools.rs`

**Interfaces:**
- Consumes: `ToolDefinition` and the compiled ceilings in config/remote modules.
- Produces: public read-only `tool_definitions() -> &'static [ToolDefinition]`
  for registry introspection, plus private parsing and one closed argument type
  per tool.

- [ ] **Step 1: Add an exact registry test**

Create `tests/mcp_tools.rs` and assert:

```rust
#[test]
fn task8_registry_contains_exactly_the_nine_high_level_remote_tools() {
    let tools = tool_definitions();
    let names = tools.iter().map(|tool| tool.name.as_str()).collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "remote_hosts",
            "remote_list",
            "remote_stat",
            "remote_search",
            "remote_read",
            "remote_output_read",
            "remote_apply_patch",
            "remote_write",
            "remote_run",
        ]
    );
    let serialized = serde_json::to_string(tools).unwrap();
    for forbidden in ["sshfs", "guarded_delete", "probe", "shell_word", "raw_ssh"] {
        assert!(!serialized.contains(forbidden));
    }
}
```

For every root and nested object recursively assert
`additionalProperties == false`. Assert no tool has `outputSchema`.
Using these actual nine definitions, counting-serialize the full tools/list
response with a synthetic 256-byte wire ID, assert its exact service minimum is
included in `required_mcp_frame_bytes`, and assert no degradation/removal of
tools is permitted to fit a smaller frame. Exact constructor min/minus-one is
repeated after `RemoteMcpTools` exists.

- [ ] **Step 2: Add exact schema-bound and annotation tests**

Assert these exact properties:

Every host property uses `minLength=1`, `maxLength=128`, and
`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. Every path/cwd uses `minLength=1` and
`maxLength=65536`. Query uses `minLength=1`, `maxLength=65536`. Command uses
`minLength=1`, `maxLength=8388608`. Patch uses `minLength=1`,
`maxLength=4194304`. Encoded write content and encoded stdin values use
`maxLength=5592408`; the bridge still enforces decoded raw bytes.

| Tool | Required | Exact schema bounds |
|---|---|---|
| remote_hosts | none | empty properties |
| remote_list | host | depth 1–32; max_entries 1–10000 |
| remote_stat | host, paths | paths minItems 1, maxItems 256 |
| remote_search | host, query | globs maxItems 128, item maxLength 4096; max_results 1–10000 |
| remote_read | host, paths | paths 1–32; start_line ≥1; max_lines 1–100000; max_bytes 1–1048576 |
| remote_output_read | output_ref, stream | ref pattern `^[0-9a-f]{32}$`; max_bytes 1–1048576 |
| remote_apply_patch | host, patch | patch maxLength 4194304 as advisory character bound |
| remote_write | host, path, content, encoding, mode | encoding utf8/base64; closed create/replace mode |
| remote_run | host, command | shell auto/bash/sh/login; timeout 1–3600000; closed stdin |

Assert annotations:

- `remote_hosts` and `remote_output_read`: read-only, non-destructive,
  idempotent, open-world false.
- `remote_list/stat/search/read`: read-only, non-destructive, idempotent,
  open-world true.
- `remote_apply_patch/write/run`: non-read-only, destructive, non-idempotent,
  open-world true.

- [ ] **Step 3: Add argument deserialization unit tests**

Put these tests in a `#[cfg(test)] mod tests` inside `src/mcp/tools.rs`. This
keeps `parse_tool_arguments` private while testing the exact parser used by
dispatch; do not expose argument structs or a validation-only production API
for integration-test convenience.

For each tool deserialize one valid object and reject missing required,
wrong-type, unknown root field, and unknown nested field cases. Include:

```rust
let replace = serde_json::json!({
    "host":"dev",
    "path":"a",
    "content":"eA==",
    "encoding":"base64",
    "mode":{"kind":"replace","expected_sha256":"0".repeat(64)}
});
assert!(parse_tool_arguments("remote_write", replace).is_ok());

let bad_nested = serde_json::json!({
    "host":"dev",
    "command":"true",
    "stdin":{"encoding":"utf8","value":"","extra":true}
});
assert!(parse_tool_arguments("remote_run", bad_nested).is_err());
```

- [ ] **Step 4: Run schema tests and verify RED**

Run:

```bash
cargo test --test mcp_tools task8_registry_ -- --nocapture
cargo test --test mcp_tools task8_schema_ -- --nocapture
cargo test --lib mcp::tools::tests::task8_arguments_ -- --nocapture
```

Expected: compilation fails because `mcp::tools` does not exist.

- [ ] **Step 5: Define closed argument types**

Use `#[derive(Deserialize)]` and `#[serde(deny_unknown_fields)]` on:

```rust
struct HostsArgs {}
struct ListArgs {
    host: String,
    path: Option<String>,
    depth: Option<u32>,
    include_hidden: Option<bool>,
    max_entries: Option<usize>,
}
struct StatArgs { host: String, paths: Vec<String> }
struct SearchArgs {
    host: String,
    query: String,
    path: Option<String>,
    #[serde(default)]
    globs: Vec<String>,
    max_results: Option<usize>,
    binary: Option<bool>,
}
struct ReadArgs {
    host: String,
    paths: Vec<String>,
    start_line: Option<u64>,
    max_lines: Option<u64>,
    max_bytes: Option<usize>,
}
struct OutputReadArgs {
    output_ref: String,
    stream: ToolStream,
    #[serde(default)]
    offset: u64,
    max_bytes: Option<usize>,
}
struct ApplyPatchArgs { host: String, patch: String }
struct WriteArgs {
    host: String,
    path: String,
    content: String,
    encoding: ToolEncoding,
    mode: ToolWriteMode,
}
struct RunArgs {
    host: String,
    command: String,
    cwd: Option<String>,
    #[serde(default)]
    shell: ToolRunShell,
    timeout_ms: Option<u64>,
    stdin: Option<ToolEncodedInput>,
}
```

Every struct above receives its own `deny_unknown_fields` attribute. Define
closed `ToolEncoding`, `ToolStream`, `ToolRunShell`, `ToolEncodedInput`, and
internally tagged `ToolWriteMode`. Default run shell is Auto.

`parse_tool_arguments` returns a private enum with one variant per typed
argument object. For a known tool it maps every serde/schema failure to a
stable private validation category and then to
`CallToolResult::invalid_argument` with tool-specific actionable safe text. It
does not retain serde's message or any rejected value. Unknown tool names are
filtered by the lifecycle registry and never enter this function.

After deserialization, validate every advertised required/range/length/item,
enum, pattern, and cross-field constraint before calling `RemoteBridge`.
Bridge byte/host/policy admission remains authoritative and repeats security
ceilings; this tool-layer validation exists to satisfy the MCP schema contract
and produce the correct known-tool result semantics without remote work.

- [ ] **Step 6: Build exact static definitions**

Use `OnceLock<Vec<ToolDefinition>>` and `serde_json::json!`. Repeat every range,
enum, pattern, required list, default, and nested
`additionalProperties:false` from Step 2. Handlers mirror the advertised
constraints as described in Step 5, but never trust schema validation instead
of bridge byte/host/policy admission.

Descriptions say:

- all paths/results are remote;
- remote output is untrusted;
- `remote_hosts` does not probe;
- `remote_run` is always mutating;
- auto shell may fall back to sh and the actual shell is in results; and
- `remote_apply_patch` is sequential across files and reports partial progress.

- [ ] **Step 7: Run schema and argument tests**

Run:

```bash
cargo test --test mcp_tools task8_registry_ -- --nocapture
cargo test --test mcp_tools task8_schema_ -- --nocapture
cargo test --lib mcp::tools::tests::task8_arguments_ -- --nocapture
```

Expected: exact registry, all schema bounds/annotations, and all closed argument
tests pass.

- [ ] **Step 8: Commit the schema slice**

```bash
git add src/mcp/tools.rs src/mcp/mod.rs tests/mcp_tools.rs
git commit -m "feat: define exact remote MCP schemas"
```

---

### Task 7: Implement Thin Bridge Dispatch and Single-Copy Results

**Files:**
- Create: `src/mcp/render.rs`
- Modify: `src/mcp/tools.rs`
- Modify: `src/mcp/mod.rs`
- Modify: `src/config.rs`
- Modify: `config.example.toml`
- Modify: `src/remote/mod.rs`
- Modify: `src/output.rs`
- Modify: `src/ssh/process.rs`
- Modify: `tests/mcp_tools.rs`
- Modify: `tests/core.rs`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Consumes: all nine `RemoteBridge` operations, Task 6 patch API, Task 2 run API,
  typed output-store paging, tool argument types, `CallToolResult`, and
  `ToolCallContext`.
- Produces: `RemoteMcpTools::new(Arc<RemoteBridge>)`, `ToolService`
  implementation, one renderer per typed result, stable tool-error rendering,
  generic bridge-owned direct-to-spool result retention, typed aggregate/remote
  provenance, and opaque refs with truthful raw-byte paging.

- [ ] **Step 1: Add zero-launch and one-call dispatch tests**

Construct `RemoteMcpTools` over the existing fake-SSH bridge. Through
`ToolService::call` assert:

- every known-tool malformed argument case returns a normal
  `CallToolResult` with `isError=true`, stable `INVALID_ARGUMENT`, and
  tool-specific actionable text that includes no rejected value or serde text;
- unknown host, traversal, read-only write/patch/run, and request-size errors
  preserve their bridge code;
- malformed arguments and local admission failures that precede bridge launch
  create no `C` fake-SSH entry;
- a valid call invokes its bridge operation once;
- the exact `context.cancel` reaches that bridge call and exact
  `context.wire_budget` reaches validation/success/error rendering; and
- capability mismatch, disconnect, mutation unknown, and Task 6 partial failure
  are never retried by the MCP layer.

Add an architecture test that reads `src/mcp/tools.rs` and rejects these tokens:

```rust
for forbidden in [
    "SshRunner", "RemotePath", "shell_word", "build_ssh_argv",
    "CAPABILITY_PROBE_SCRIPT", "OutputStore", "guarded_delete",
] {
    assert!(!source.contains(forbidden), "{forbidden} escaped into MCP dispatch");
}
```

- [ ] **Step 2: Add single-copy payload tests**

Use a unique payload sentinel and serialize the entire JSON-RPC response:

```rust
let wire = String::from_utf8(serialized_response_bytes).unwrap();
assert_eq!(wire.matches("TASK8_UNIQUE_PAYLOAD").count(), 1);
let response: serde_json::Value = serde_json::from_str(&wire).unwrap();
assert!(!response["result"]["structuredContent"]
    .to_string()
    .contains("TASK8_UNIQUE_PAYLOAD"));
assert_eq!(response["result"]["content"].as_array().unwrap().len(), 1);
```

Repeat with:

- a configured host list large enough to exceed the small test wire budget;
- list entries and stat per-path entries;
- a 1 MiB valid-UTF-8 NUL-heavy read payload;
- non-UTF-8 read bytes represented as Base64;
- search match line content;
- command stdout and stderr previews;
- an output page; and
- Task 6 patch text that must never be echoed on error.

Assert every serialized result remains within the configured response frame.
For every payload-bearing tool, parse `content[0].text` as JSON and assert it
contains `remote`, host/root/shell context as applicable, plus the bulk field;
assert `structuredContent` repeats only small context/metadata and no bulk.
For each of hosts/list/stat/search/read/output-read/run, force a valid small
wire budget and assert the compact fallback preserves context, total/returned
counts and truncation/offset truth. Hosts/list/stat/search/read use a
bridge-retained logical-stdout ref on success; output-read preserves its
existing ref while recomputing `next_offset` and `eof` from the raw bytes that
actually remain inline; run preserves or creates its ref. Exercise UTF-8 and
Base64 pages, assert offsets always count raw stored bytes, and reassemble
several budget-shrunk pages byte-for-byte with no gap or overlap. The host-list case
uses substantially more than five configured profiles and performs no probes.

- [ ] **Step 3: Add exact result and error metadata tests**

Assert:

- every network-backed remote success has `remote=true`, host, and physical
  root; `remote_hosts` entries have `remote=true`, host/configured root, and
  only an already-cached optional physical root without probing;
- run success includes actual shell/version/fallback, warning, lengths,
  truncation, status, and optional ref;
- run failure after shell selection includes `details.shell` and bounded
  `details.physical_root`; pre-probe failure omits both;
- read/snapshot/write-conflict/patch domain or protocol errors created after an
  exit-zero fixed child render physical root in Text JSON and structured
  metadata while preserving their original code/progress;
- output paging uses stored `Remote(RemoteContext)` provenance, while retained
  `remote_hosts` pages use `Aggregate { kind: Hosts, source_count }` and omit
  rather than fabricate host/root/shell;
- Task 5 unknown keeps `mutation_may_have_applied=true`;
- Task 6 failure keeps exact failed/changed/not-changed/unknown partitions; and
- forced tiny-but-valid wire budgets keep write/patch/run mutation status,
  `mutation_may_have_applied`, exact progress counts, and a pageable
  `output_ref`, never `-32603`;
- injected result-retention storage and admission failures after an applied
  write, partial/unknown patch, and completed run keep the compact truth/counts
  with `detail_retained=false` and no ref; successful retention returns
  `detail_retained=true`, output_ref, and output_stream;
- inject the same failures for hosts/list/stat/search/read: each keeps total and
  returned counts, `truncated=true`, and `detail_retained=false` with no new
  ref; successful retention has the true/ref/stream trio;
- oversized read/run previews shrink until they fit and retain an `output_ref`;
- large retained host/list/stat/search values page successfully, and release
  RSS tests prove direct-to-spool serialization does not create another large
  `Vec<u8>` or `serde_json::Value` clone;
- error output excludes command, stdin, patch, remote file bytes, fake SSH
  stderr, ControlPath, runtime directory, and agent-socket sentinel strings.
- maximum 1,024-byte safe message/action, 16 warnings of 1,024 bytes using the
  worst legal alternating quote/backslash pattern, and
  maximum control-heavy 256-byte shell version fit the real compact-fallback
  count; +1 inputs
  normalize every Unicode `char::is_control()` to one ASCII `?`, truncate at
  UTF-8 boundaries with explicit truncation flags, and preserve quotes,
  backslashes, ordinary Unicode, code, context, truth, counts, and progress.

- [ ] **Step 4: Run dispatch/render tests and verify RED**

Run:

```bash
cargo test --test mcp_tools task8_dispatch_ -- --nocapture
cargo test --test mcp_tools task8_single_copy_ -- --nocapture
cargo test --test mcp_tools task8_error_rendering_ -- --nocapture
cargo test --test mcp_tools task8_retention_ -- --nocapture
```

Expected: tests fail because `RemoteMcpTools` and renderers are absent.

- [ ] **Step 5: Implement bridge-only dispatch**

Define:

```rust
#[derive(Clone)]
pub struct RemoteMcpTools {
    bridge: Arc<RemoteBridge>,
}

impl RemoteMcpTools {
    pub fn new(bridge: Arc<RemoteBridge>) -> Self {
        Self { bridge }
    }
}
```

Implement `ToolService` by cloning the bridge into each `'static` future.
Deserialize with `parse_tool_arguments` before any bridge call. A known-tool
parse failure immediately returns its actionable `isError=true` result. Map only
presentation types:

- `ToolEncoding` → `WriteEncoding`;
- `ToolWriteMode` → `WriteMode`;
- `ToolStream` → `StreamKind`;
- `ToolRunShell` → `RunShell`; and
- `ToolEncodedInput` → `RunStdin`.

Use `max_bytes.unwrap_or(256 * 1024)` for `remote_output_read`. Pass
`context.cancel` unchanged to the one bridge operation and
`context.wire_budget` unchanged to every validation/success/error renderer.
Each branch performs one awaited `RemoteBridge` call and passes its result to
the matching renderer.

- [ ] **Step 6: Implement payload projections**

In `src/mcp/render.rs` define one typed renderer per result. Each returns
exactly one `TextContent` whose text is compact JSON. For single-host results it
contains `remote=true`, host, physical root, actual shell when known, plus the
bulk payload or complete small mutation result. `remote_hosts` uses
`remote=true` at top level and carries per-entry host/configured root plus only
already-cached physical-root/shell data.

Structured metadata contains:

- hosts: count/cache summary only;
- list/stat/search/read: context, counts, engine/truncation/returned bytes, but
  no entries, matches, or file content;
- output page: context, stream, encoding, offsets, EOF, but no page value;
- run: context, status, lengths, truncation, ref, aggregate bytes, may-continue,
  and warnings, but no head/tail values;
- write and patch: context, status/progress/counts, and optional ref, but no
  repeated detail retained behind that ref.

Do not serialize a complete result to a `Value` and then remove payload fields;
construct metadata directly so bulk values are never cloned into structured
content.

For tool errors, never serialize `BridgeError` directly. Derive a typed
`RenderedErrorCore` with code, projected safe message, retryability, and only
non-context details such as mutation/progress/byte facts. Extract host,
physical root, and shell into one context projection. The one text block is
compact JSON containing that context once plus the core and actionable
warnings. `structuredContent.error` contains only the core; the structured top
level contains context once, so `error.details` never repeats host/root/shell.
Unknown context fields are omitted; known-tool argument validation may contain
only its safe action/error object. Set `isError=true`. Construct both models
directly—never serialize a complete error/result and delete fields or clone
bulk data—and never include `Debug` output, serde's rejected input, or remote
bulk.

Bound the wire projection—not the semantic error code—to 1,024 UTF-8 bytes for
message and action, 16 warnings, and 1,024 bytes per warning. Truncate only at a
UTF-8 boundary and set `message_truncated`/`warnings_truncated`. Before or
during truncation, replace every Unicode `char::is_control()` with the single
ASCII byte `?`; preserve quotes, backslashes, ordinary Unicode, and all other
non-control characters. Never truncate code, physical root, shell kind/version
within its shared bound, mutation truth/status/counts, retention status, or
Task 6 progress.

Render against the `WireBudget` supplied by the lifecycle owner. Preconstruct a
compact fallback before the full projection. Hosts/list/stat/search/read retain
omitted canonical detail through the bridge facade; output-read reduces its page
while preserving the existing ref and recomputing truthful offsets; run reduces previews while keeping
or creating a ref. Every read-only fallback preserves context, total/returned
counts, `truncated=true`, and retention status. Mutation fallbacks preserve
`applied|partial|unknown|not_applied`, `mutation_may_have_applied`, safe status,
and changed/not-changed/unknown counts. Omitted detail is retained through a
generic bridge-owned internal result-spool facade and returned as an opaque ref
pageable through the normal bridge output-read path. `src/mcp` must never import
or call `OutputStore` directly. Non-command retained detail is stored as
canonical bytes in the reference's logical `stdout` stream, and compact
metadata includes `detail_retained=true`, `output_ref`, and
`output_stream="stdout"`, preserving the frozen nine-tool schema.

Once these real renderers exist, counting-serialize the largest compact
fallback `result` value into `maximum_compact_fallback_result_bytes()` and
replace Task 5's temporary zero initializer inside `McpServer::new`. Store that
one derived value in `McpServer::compact_fallback_result_bytes`; both
`required_mcp_frame_bytes` during construction and every per-ID
`WireBudget::for_response` must read that same field. This helper
returns result-only bytes—never the full frame, envelope, ID, newline, or
`MIN_MCP_FRAME_BYTES`. Recompute the exact effective constructor minimum as the
maximum of compiled floor, full tools/list frame, and envelope plus that real
fallback result; repeat exact/minus-one tests before any end-to-end acceptance.

Define truthful provenance and expose only a generic bridge facade:

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

`OutputReadResult` carries the same provenance enum. Remote provenance renders
host/root/shell; aggregate provenance renders kind/source count and omits
single-host context. The bridge owns byte admission, private storage, expiry,
provenance, and paging. It moves blocking serializer work off the async runtime
as needed and writes `owned` directly to the bounded private spool through a
counting/capped writer; neither MCP nor bridge first materializes a second large
byte vector or `serde_json::Value`. MCP receives only an opaque reference and
cannot choose a path or inspect store internals.

Import crate-root `MAX_OUTPUT_BYTES = 64 * 1024 * 1024` and apply it to
serialized canonical bytes. The direct spool writer
counts and caps actual serializer writes: exactly 64 MiB succeeds and the first
byte over fails. On +1 overflow, cancellation, serializer error, or admission
failure, close and delete the temporary spool before returning and issue no
reference.

Add to `Limits` with validation against compiled ceilings:

```rust
pub const DEFAULT_GLOBAL_SPOOL_QUOTA_BYTES: u64 = 512 * 1024 * 1024;
pub const MIN_GLOBAL_SPOOL_QUOTA_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_GLOBAL_SPOOL_QUOTA_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_RETENTION_SERIALIZATION_JOBS: usize = 2;
pub const MAX_RETENTION_SERIALIZATION_JOBS: usize = 4;
pub const MAX_SPOOL_ENTRIES: usize = 1024;

pub global_spool_quota_bytes: u64,
pub retention_serialization_jobs: usize,
```

Reject config values outside the inclusive
`MIN_GLOBAL_SPOOL_QUOTA_BYTES..=MAX_GLOBAL_SPOOL_QUOTA_BYTES` range.

One shared quota accounts for actual command, fixed-command internal capture,
and retained-detail bytes, temporary and committed. Command/internal writers
atomically reserve each intended chunk, release a partial write's unused tail,
and roll back a failed chunk. Stdout/stderr share the ledger. Exact quota is
writable; only the next competing byte fails. Five maximum outputs consume
320 MiB; together with two default 64 MiB retention reservations, the fresh
store uses 448 MiB of the 512 MiB default and retains 64 MiB headroom. Light
calls do not reserve 64 MiB.

For generic serialized detail, use this order before any CPU-intensive work:
`try_acquire` the two/four default/hard job semaphore, acquire one pending entry
slot, then atomically reserve full crate-root `MAX_OUTPUT_BYTES`. On any miss,
release prior permits and return false/no-ref without `spawn_blocking`. Once
started, the capped blocking writer polls cancellation at least every 64 KiB;
the async path always awaits its join and cleanup, never detaches it. Successful
commit shrinks the full reservation to actual serialized length.

`MAX_SPOOL_ENTRIES=1024` counts pending plus committed entries, each with at
most two files. Acquire the slot before creating a temp. Command/internal quota
saturation keeps existing typed `OUTPUT_LIMIT` cancellation/termination;
detail saturation/overflow/cancellation/serializer failure returns false/no-ref
after cleanup. Release a file's byte charge only after unlink succeeds or
returns `NotFound`; other unlink errors keep charge and a tombstone for bounded
retry. Release the entry slot only after all its files are gone. TTL expiry,
explicit removal, and shutdown use the same ordering. Worst case is
`spool_bytes <= quota <= 512 MiB` and `spool_files <= 2 * 1024`, independent of
`max_inflight`.

Under the entry lock, make `OutputStore::read` check expiry and synchronously
open a new independent handle for the selected private pathname. Only after
open succeeds may it create the ref-counted byte/entry lease and release the
lock. Never publish a lease before open, retain a handle on every committed
entry, or use `try_clone`/another handle that shares a seek cursor. TTL/discard
that wins the lock removes and unlinks the entry; a reader that wins finishes
via its independent handle, while ledger bytes and the entry slot stay pinned
until the final reader lease closes.

Retention is best-effort. A storage/admission/cancellation error is consumed by
the renderer, which emits the already preconstructed compact truth with
`detail_retained=false` and no ref/stream. It must not become `-32603`, alter
applied/partial/unknown/completion status, or erase counts. Only successful
retention sets the true/ref/stream trio.

Unit/integration tests in `src/output.rs`, `tests/ssh_transport.rs`, and
`tests/remote_ops.rs` cover exact/+1 serialized-byte boundaries, cancellation
mid-serialization with 64 KiB poll granularity, overflow/serializer/admission
failures, exact-quota and concurrent next-byte saturation, exact 1,024-entry and
next-slot rejection, two-file enforcement, one-job saturation, partial-write
rollback, five simultaneous maximum outputs plus two default retention
reservations on one fresh store (448 MiB used, 64 MiB free), light internal captures, awaited
blocking joins, unlink success/`NotFound`/failure tombstone retry, zero
premature ledger/slot/permit release, both TTL/discard reader lock orders, a
directed former-lease-before-open regression, 1,024 committed entries without
2,048 resident FDs, concurrent different-offset pages with no shared-cursor
interference, last-reader release, explicit removal/shutdown cleanup, and concurrency
saturation. MCP
tests assert every such failure becomes false/no-ref while retaining counts or
mutation truth.

`remote_hosts` has no five-entry ceiling: expected peak five hosts refers to
concurrent execution only. Its full configured list may be large, so it uses
`Aggregate { kind: Hosts, source_count }` without probing; the fallback keeps
host count/cache summary/truncation even when retention fails. List/stat/search/
read use `Remote(RemoteContext)`.

When output-read is shrunk for wire budget, select the inline raw bytes first
(respecting a UTF-8 code-point boundary where applicable), then encode them.
Offsets for both UTF-8 and Base64 are raw stored-byte offsets. Set
`next_offset = requested_offset + actual_inline_raw_bytes` and set `eof` only
when that position reaches the stored stream end; never retain the pre-shrink
next offset or EOF value.

When actual shell is sh, error rendering as well as success rendering adds the
fixed actionable Bashism warning: use POSIX syntax, or request Bash and ensure
it is installed.

- [ ] **Step 7: Run all tool-layer tests**

Run:

```bash
cargo test --test mcp_tools task8_dispatch_ -- --nocapture
cargo test --test mcp_tools task8_single_copy_ -- --nocapture
cargo test --test mcp_tools task8_error_rendering_ -- --nocapture
cargo test --test mcp_tools task8_retention_ -- --nocapture
cargo test --lib output::tests::task8_spool_quota_ -- --nocapture
cargo test --test core task8_spool_limit_config_ -- --nocapture
cargo test --test ssh_transport task8_internal_capture_quota_ -- --nocapture
cargo test --test remote_ops task8_retention_spool_ -- --nocapture
```

Expected: dispatch is bridge-only, every bulk sentinel occurs once, metadata is
complete, error redaction/progress tests pass, and quota/semaphore/temp cleanup
remains exact under concurrent command, internal-capture, and retention writes.

- [ ] **Step 8: Commit dispatch and rendering**

```bash
git add src/mcp/tools.rs src/mcp/render.rs src/mcp/mod.rs src/config.rs config.example.toml src/remote/mod.rs src/output.rs src/ssh/process.rs tests/core.rs tests/mcp_tools.rs tests/ssh_transport.rs tests/remote_ops.rs
git commit -m "feat: dispatch high-level remote MCP tools"
```

---

### Task 8: Wire the MCP Binary and Prove the Complete Surface End to End

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/main.rs`
- Modify: `src/mcp/mod.rs`
- Modify: `tests/mcp_protocol.rs`
- Modify: `tests/mcp_tools.rs`

**Interfaces:**
- Consumes: `Config::load_default`, `RuntimePaths::discover`, `OutputStore`, `SshRunner`, `RemoteBridge`, `RemoteMcpTools`, and `McpServer`.
- Produces: `codex-ssh-bridge mcp` over real stdin/stdout and complete fake-SSH JSON-RPC integration.

- [ ] **Step 1: Add a failing binary lifecycle smoke test**

Spawn `env!("CARGO_BIN_EXE_codex-ssh-bridge")` with argument `mcp`, a secure
temporary TOML config, piped stdin/stdout/stderr, and these frames:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"remote_hosts","arguments":{}}}
```

Close stdin and assert:

- process exit zero;
- stdout has exactly three nonempty lines with IDs 1, 2, and 3;
- the initialize result selected `2025-11-25`;
- tools/list contains exactly nine names;
- remote_hosts succeeds without a fake-SSH command; and
- stderr contains no config contents, host path, ControlPath, or caller frame.

Construct the same `RemoteMcpTools` in memory, compute its exact required frame
from all nine definitions, the synthetic maximum ID, and the real result-only
largest compact-fallback count, and assert
`McpServer::new` accepts that exact maximum-with-compiled-minimum and rejects
one byte less. The accepted server must return the complete nine-tool list.

- [ ] **Step 2: Add one end-to-end call per schema**

Through an in-memory `McpServer<RemoteMcpTools>` and the local fixed fake SSH,
call:

- `remote_hosts` against local config only;
- `remote_list` on a directory with hostile names;
- `remote_stat` with success and per-entry missing;
- `remote_search` with literal `$(touch SHOULD_NOT_EXIST)` query;
- `remote_read` with UTF-8 and binary files;
- `remote_run` producing a public output ref;
- `remote_output_read` for that ref;
- `remote_write` create; and
- `remote_apply_patch` update.

Assert every response ID and remote context. Assert no unintended sentinel
exists. Perform each mutation only in its temporary fake remote root.

- [ ] **Step 3: Add Bash/fallback and read-only end-to-end tests**

Use capability fixtures for:

- Bash available + `shell=auto` → Bash, no fallback;
- Bash unavailable + `shell=auto` → sh, fallback and warning;
- Bash available + `shell=sh` → sh, no fallback and warning;
- Bash unavailable + `shell=bash` → `RemoteCapabilityMissing` and no command
  child; and
- login selection → login metadata and local timeout behavior.

For a read-only profile assert list/stat/search/read/output-read work while
write, patch, and run return `ReadOnlyHost` server-side. Tool annotations are
not consulted by the test or handler for enforcement.

- [ ] **Step 4: Run binary and complete-surface tests and verify RED**

Run:

```bash
cargo test --test mcp_tools task8_binary_ -- --nocapture
cargo test --test mcp_tools task8_complete_surface_ -- --nocapture
cargo test --test mcp_tools task8_shell_surface_ -- --nocapture
```

Expected: binary smoke fails because `main` does not implement `mcp` and Tokio
does not yet expose stdio.

- [ ] **Step 5: Enable only the required Tokio runtime features**

Add `io-std` and `rt-multi-thread` to the existing Tokio feature list. Do not
add an MCP SDK, async-trait, HTTP, SSE, or logging framework.

- [ ] **Step 6: Implement fixed MCP bootstrap**

Implement `src/main.rs` with a Tokio multi-thread entry point. Accept exactly
one mode argument `mcp` in this task. Unknown or missing modes print one fixed
usage line to stderr and exit 2.

The MCP branch uses this exact ownership chain:

```rust
async fn run_mcp() -> BridgeResult<()> {
    let loaded = Config::load_default()?;
    let max_frame_bytes = loaded.config.limits.max_frame_bytes;
    let max_inflight = loaded.config.limits.global_concurrency;
    let global_spool_quota_bytes = loaded.config.limits.global_spool_quota_bytes;
    let retention_serialization_jobs = loaded.config.limits.retention_serialization_jobs;
    let config = Arc::new(loaded.config);
    let runtime = RuntimePaths::discover()?;
    let output_store = Arc::new(OutputStore::with_limits(
        &runtime,
        global_spool_quota_bytes,
        retention_serialization_jobs,
    )?);
    let runner = Arc::new(SshRunner::new(
        Arc::clone(&config),
        runtime,
        output_store,
    )?);
    let bridge = Arc::new(RemoteBridge::new(runner));
    let tools = Arc::new(RemoteMcpTools::new(bridge));
    let server = McpServer::new(tools, max_frame_bytes, max_inflight)?;
    server.serve(tokio::io::stdin(), tokio::io::stdout()).await
}
```

Constructor tests load non-default quotas across the accepted 64--511 MiB
range and serializer-job counts 1--4, then assert the store ledger/semaphore
uses those exact values. A source/ownership test rejects a bootstrap that calls
the default constructor or moves `loaded.config` before extracting both
fields, preventing either setting from becoming dead configuration.

On a fatal error, stderr contains only a fixed prefix and the stable
`ErrorCode` name. Do not print `BridgeError::Debug`, config source/path,
OpenSSH stderr, or any request data. No branch uses `println!`.

- [ ] **Step 7: Run the end-to-end suite**

Run:

```bash
cargo test --test mcp_protocol -- --nocapture
cargo test --test mcp_tools -- --nocapture
```

Expected: binary lifecycle, all nine tools, explicit shell/fallback,
read-only enforcement, cancellation, and single-copy tests pass.

- [ ] **Step 8: Commit the working MCP binary**

```bash
git add Cargo.toml Cargo.lock src/main.rs src/mcp tests/mcp_protocol.rs tests/mcp_tools.rs
git commit -m "feat: expose strict stdio MCP server"
```

---

### Task 9: Close Adversarial, Five-Host, and Resource Acceptance

**Files:**
- Modify: `tests/mcp_protocol.rs`
- Modify: `tests/mcp_tools.rs`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Consumes: complete Tasks 7–8 implementation and existing fake-SSH/performance fixtures.
- Produces: Tasks 7–8 security, resource, dispatch/fake-call p95, five-host,
  release cancellation, and regression evidence; Task 11 still owns the final
  whole-product/real-SSH acceptance and recorded benchmark report.

- [ ] **Step 1: Add a closed hostile-input matrix**

For path, cwd, query, glob, content, command output, and cancellation reason,
cover literal:

```text
spaces ' " newline
leading-hyphen
*
$HOME
$(touch SHOULD_NOT_EXIST)
`touch SHOULD_NOT_EXIST`
Unicode-雪
NUL where the field must reject it
```

Assert data-only fields never create `SHOULD_NOT_EXIST` and never alter local
argv or fixed script source. The command field itself is intentional shell
source; test it with a harmless command that prints the hostile strings from
stdin rather than treating a malicious command as data.

- [ ] **Step 2: Add framing and serializer amplification acceptance**

Generate:

- an exact 8 MiB request frame;
- an 8 MiB + 1 byte frame followed by a valid ping;
- deeply nested JSON within serde's accepted recursion depth and one beyond it;
- duplicate keys in a large nested arguments object;
- wide arrays and objects at and just beyond node/member/key-byte budgets;
- 1 MiB of NUL-heavy valid UTF-8;
- 1 MiB of non-UTF-8 binary data; and
- command output resembling multiple complete JSON-RPC lines.

Assert fixed errors, recovery after the oversized input, exactly one output
line per response, one payload occurrence, and no partial JSON on serializer
overflow. Re-run the private Task 4 retention unit for the direct buffer bound.
Measure maximum-width arrays and objects in separate fresh release child
processes. In each child, sample an idle/warmed baseline before the repeated
parse, sample peak RSS during the parse, and assert `peak - baseline < 48 MiB`.
Print the raw baseline, peak, and delta for each shape. Do not measure both
shapes in one test-binary process, where allocator-retained memory or parallel
tests can contaminate the second sample. The source check must also prove
duplicate detection uses the destination map and does not clone keys into a
`HashSet`.

- [ ] **Step 3: Add five-host concurrent MCP acceptance**

Build five host profiles with distinct fake roots and set:

```rust
config.limits.global_concurrency = 8;
config.limits.per_host_concurrency = 2;
```

After one initialize/initialized pair, pipeline five `remote_run` calls that
each block for one second on its own host. Measure from the first accepted call
until all five result IDs arrive. In release mode assert:

```rust
assert!(elapsed < Duration::from_millis(1_500), "{elapsed:?}");
```

Assert all five contexts name the correct host/root, output lines do not
interleave, and no sixth implicit call occurs. This is concurrency acceptance,
not a multi-host tool.

- [ ] **Step 4: Add MCP-to-process cancellation timing acceptance**

Start a long-running `remote_run`, wait until fake SSH records the command
child, send `notifications/cancelled`, and assert:

- the child process group terminates within 250 ms;
- no response for the cancelled request ID is written;
- a following ping and tool call work;
- no spool file survives bounded cleanup; and
- the remote may-continue truth remains available in direct bridge error tests
  even though the MCP response is suppressed.

- [ ] **Step 5: Run focused adversarial tests and verify RED/GREEN**

Run after writing the new tests:

```bash
cargo test --test mcp_protocol task7_adversarial_ -- --nocapture
cargo test --lib mcp::stdio::tests::task7_frame_retention_ -- --nocapture
cargo test --test mcp_tools task8_hostile_ -- --nocapture
cargo test --test mcp_tools task8_five_hosts_ -- --nocapture
cargo test --test mcp_tools task8_cancel_process_ -- --nocapture
```

Expected: the new tests compile and report their exact assertions. If one is
RED, confirm the failure is the intended missing behavior, make the smallest
production correction, and rerun the same command. If all are already GREEN,
retain them as regression evidence. Never weaken a bound or assertion to
manufacture GREEN.

- [ ] **Step 6: Add and run the Tasks 7–8 release performance gate**

Measure at least 100 warmed calls for each p95. On the approved host assert
bridge-only dispatch below 2 ms, a complete fake-SSH tool call below 10 ms,
five independent one-second hosts below 1.5 seconds, client cancellation to
local process-group termination below 250 ms, 64 MiB-output RSS growth below
16 MiB, and maximum-budget wide-array and wide-object RSS deltas below 48 MiB
in their separate fresh release children. Record raw warmed baseline, peak, and delta samples in failure
messages. These are early Tasks 7–8 gates; Task 11 repeats and records the final
whole-product acceptance rather than treating this slice as a substitute.
The output RSS child also forces bridge retention of large host/list/stat/search
models and proves direct-to-spool serialization stays within the same bounded
growth envelope without a second full-size buffer.

Run:

```bash
cargo test --release --test mcp_tools task78_release_dispatch_p95_ -- --nocapture
cargo test --release --test mcp_tools task78_release_fake_call_p95_ -- --nocapture
cargo test --release --test mcp_tools task8_five_hosts_ -- --nocapture
cargo test --release --test mcp_tools task8_cancel_process_ -- --nocapture
cargo test --release --test mcp_protocol task7_wide_json_rss_ -- --nocapture
cargo test --release --test mcp_tools task8_output_rss_ -- --nocapture
```

Expected: all thresholds pass with measured p50/p95/max or RSS deltas printed
only as test diagnostics, never MCP stdout.

- [ ] **Step 7: Run architecture and Rust-only searches**

Run:

```bash
rg -n "SshRunner|RemotePath|shell_word|build_ssh_argv|guarded_delete|sshfs" src/mcp
rg -n "println!|print!" src/mcp src/main.rs
rg -n "python3|server\\.py|tests/fake_ssh\\.py|ssh_bridge/" src Cargo.toml tests/mcp_protocol.rs tests/mcp_tools.rs
```

Expected:

- the first command prints no matches from `src/mcp/tools.rs`; protocol/module
  files may mention only type names explicitly permitted by the design;
- the second prints no stdout printing path; and
- the third prints no runtime or test-fixture Python dependency.

- [ ] **Step 8: Run the full Tasks 7–8 gate**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo test --release --test mcp_tools task78_release_dispatch_p95_ -- --nocapture
cargo test --release --test mcp_tools task78_release_fake_call_p95_ -- --nocapture
cargo test --release --test mcp_tools task8_five_hosts_ -- --nocapture
cargo test --release --test mcp_tools task8_cancel_process_ -- --nocapture
cargo test --release --test mcp_protocol task7_wide_json_rss_ -- --nocapture
cargo test --release --test mcp_tools task8_output_rss_ -- --nocapture
git diff --check
```

Expected: format and clippy are clean; all Rust tests pass; dispatch/fake-call
p95, five-host, release cancellation, and RSS gates meet their thresholds;
diff check is clean.

- [ ] **Step 9: Commit final Tasks 7–8 evidence**

```bash
git add tests/mcp_protocol.rs tests/mcp_tools.rs tests/ssh_transport.rs tests/remote_ops.rs
git commit -m "test: close MCP security and concurrency acceptance"
```

---

## Plan Self-Review Checklist

Before implementation handoff, verify:

- every design section maps to at least one task and focused test;
- no Task 6 API field is renamed or flattened differently;
- `RunShell`, `RunStdin`, `RemoteRunRequest`, `RemoteRunResult`,
  `CallToolResult`, `WireBudget`, `ToolCallContext`, and `ToolFuture` signatures
  match in every task;
- all nine schema names, order, ranges, annotations, and defaults are repeated
  exactly;
- cancellation suppression is tested at protocol, tool, and process levels;
- payload ownership is tested for read, search, output page, and run preview;
- no implementation task asks MCP to resolve, quote, probe, retry, hash, or
  inspect spool paths;
- every RED command names the test added immediately before it;
- every GREEN command reruns the same focused scope; and
- the final gate includes format, clippy, all Rust tests, release
  dispatch/fake-call p95, five-host, cancellation, wide-JSON/output RSS, and
  diff check; Task 11 remains the final whole-product acceptance.
