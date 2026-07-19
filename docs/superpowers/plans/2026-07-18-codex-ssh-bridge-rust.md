# Codex SSH Bridge Rust Implementation Plan

Status: Ready; Tasks 7–8 strict MCP review incorporated

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the audited Python prototype with a fast, bounded, security-hardened Rust MCP/CLI that uses local OpenSSH to operate allowlisted Linux servers without installing Codex remotely.

**Architecture:** A single Rust binary exposes async stdio MCP and human CLI modes over a shared library. Tokio launches the system OpenSSH client with a dedicated ControlMaster, while focused modules own configuration, quoting, probing, output spooling, high-level remote operations, strict protocol handling, and installation.

**Tech Stack:** Rust 1.91.1, Tokio, Serde/serde_json, TOML, Clap, thiserror, SHA-2, Base64, rand, tempfile, nix, tokio-util, proptest, assert_cmd, predicates, system OpenSSH/SSHFS.

## Global Constraints

- The runtime, installer, benchmarks, and test fixtures must not use Python.
- Only the current Debian ARM64 host runs the bridge; remote hosts are Linux with `sshd` and probed common userland.
- System `/usr/bin/ssh` is the protocol implementation so `Include`, `Match`, `ProxyJump`, ssh-agent, hardware keys, and configured `ProxyCommand` remain supported.
- Remote hosts receive no installed binary, daemon, Codex credential, or persistent helper.
- MCP tools use the `remote_` prefix and always label results as remote with host and physical root.
- SSHFS remains human CLI only and never appears in MCP schemas.
- Default concurrency is eight globally and two per host.
- Default limits are 8 MiB JSON-RPC frame, 256 KiB file chunk, 1 MiB maximum read chunk, 4 MiB patch/write body, 256 KiB in-memory command preview threshold, and 64 MiB aggregate command output.
- Release acceptance on this host is p95 dispatch below 2 ms, fake-SSH call below 10 ms, five one-second commands below 1.5 s, cancellation below 250 ms, and less than 16 MiB RSS growth for 64 MiB output.
- Follow red-green-refactor TDD and commit after every task.

---

## File Map

- `Cargo.toml`: crate metadata, dependencies, release profile, and test/bench targets.
- `src/lib.rs`: public module boundaries and shared `BridgeResult` export.
- `src/main.rs`: Tokio entry point and CLI dispatch only.
- `src/error.rs`: stable error codes, safe details, retryability, and MCP/CLI rendering.
- `src/config.rs`: TOML model, file safety, compiled ceilings, host allowlist, atomic writes.
- `src/path.rs`: lexical remote path normalization beneath a configured root.
- `src/quote.rs`: sole POSIX shell word encoder and fixed-script command builder.
- `src/capability.rs`: fixed probe, parser, shell selection, and in-memory invalidating cache.
- `src/ssh/mod.rs`: transport interfaces and high-level runner.
- `src/ssh/argv.rs`: hardened OpenSSH/SSHFS argument construction and runtime socket paths.
- `src/ssh/process.rs`: Tokio child groups, deadlines, cancellation, and concurrent streams.
- `src/output.rs`: previews, private spool storage, opaque references, paging, expiry.
- `src/remote/mod.rs`: `RemoteBridge` facade and tool request/response types.
- `src/remote/read.rs`: list/stat/read/search fixed remote scripts and parsers.
- `src/remote/write.rs`: no-follow temporary writes, no-clobber create, guarded replace/delete.
- `src/remote/patch.rs`: standard multi-file unified diff parsing and local application.
- `src/mcp/mod.rs`: bounded stdio server, lifecycle, concurrent request registry.
- `src/mcp/protocol.rs`: JSON-RPC/MCP request/response validation and constants.
- `src/mcp/tools.rs`: exact tool schemas, annotations, dispatch, single-copy results.
- `src/cli.rs`: hosts, doctor, run, mount, install, and uninstall commands.
- `tests/support/mod.rs`: temporary config/runtime setup and fake executable helpers.
- `tests/fixtures/fake-ssh.sh`: deterministic non-Python SSH test transport.
- `tests/core.rs`: config, quoting, paths, errors.
- `tests/ssh_transport.rs`: argv, capability, process, concurrency, cancellation, spooling.
- `tests/remote_ops.rs`: remote reads, safe writes, patches, adversarial filesystem cases.
- `tests/mcp_protocol.rs`: lifecycle, schemas, cancellation, size and serialization limits.
- `tests/cli.rs`: configuration, SSHFS, installer transaction behavior.
- `tests/performance_acceptance.rs`: release-only host-specific acceptance harness.
- `config.example.toml`: documented safe configuration.
- `.codex-plugin/plugin.json`, `.mcp.json`: Rust binary plugin wiring.
- `skills/remote-ssh-ops/`: minimal high-level Agent workflow and shell visibility.
- `README.md`, `docs/security.md`, `docs/performance.md`: operator documentation and evidence.
- `legacy/python-prototype/`: Python prototype moved intact only after Rust verification.

---

### Task 1: Rust Skeleton, Errors, Quoting, Paths, and Configuration

**Files:**
- Create: `Cargo.toml`
- Create: `src/lib.rs`
- Create: `src/main.rs`
- Create: `src/error.rs`
- Create: `src/quote.rs`
- Create: `src/path.rs`
- Create: `src/config.rs`
- Create: `tests/core.rs`
- Create: `config.example.toml`

**Interfaces:**
- Produces: `BridgeError { code: ErrorCode, message: String, retryable: bool, details: ErrorDetails }`, optional bounded `ErrorDetails.physical_root`, non-overwriting `attach_available_remote_context`, and `type BridgeResult<T> = Result<T, BridgeError>`.
- Produces: `quote::shell_word(&str) -> BridgeResult<String>` and `quote::fixed_command(script: &str, args: &[&str]) -> BridgeResult<String>`.
- Produces: `RemotePath::resolve(root: &str, requested: &str) -> BridgeResult<RemotePath>` with `absolute()` and `relative()` accessors.
- Produces: `Config::load(path: &Path)`, `Config::save_atomic(path: &Path)`, `Config::host(alias: &str)`, and shared `MAX_REMOTE_CONTEXT_ROOT_BYTES=65_536`.

- [x] **Step 1: Add the failing core tests**

Create tests that prove shell encoding round-trips through `/bin/sh`, NUL is rejected, `..` cannot escape, exact aliases are required, unknown TOML fields fail, limits cannot exceed compiled ceilings, unsafe configuration modes fail, and an environment-overridden config path is explicitly marked as trusted execution-authority input in diagnostics. Configured normalized roots accept exactly 65,536 UTF-8 bytes and reject one more; non-ASCII cases prove byte rather than character counting. Error serialization includes bounded physical root when known and omits it before probe. Include this property test:

```rust
proptest! {
    #[test]
    fn shell_word_round_trips(value in "[^\\x00]{0,256}") {
        let encoded = shell_word(&value).unwrap();
        let script = format!("printf '%s' {}", encoded);
        let output = Command::new("/bin/sh")
            .args(["-c", &script])
            .output().unwrap();
        prop_assert_eq!(output.stdout, value.as_bytes());
    }
}
```

- [x] **Step 2: Run the new test target and verify red**

Run: `cargo test --test core -- --nocapture`

Expected: compilation fails because the crate and required modules do not exist.

- [x] **Step 3: Add the crate and minimal focused implementations**

Use these exact top-level types and ceilings:

```rust
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_READ_BYTES: usize = 1024 * 1024;
pub const MAX_WRITE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_REMOTE_CONTEXT_ROOT_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    HostKeyUnknown, AuthRequired, ConnectTimeout, RemoteCapabilityMissing,
    PathOutsideRoot, ReadOnlyHost, WriteConflict, OutputLimit,
    RequestTooLarge, ProtocolError, Cancelled, RemoteExit, InvalidConfig,
    InvalidArgument, Io,
}

pub fn shell_word(value: &str) -> BridgeResult<String> {
    if value.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument("NUL is not representable in a shell word"));
    }
    Ok(format!("'{}'", value.replace('\'', "'\"'\"'")))
}
```

Define `Config` with `#[serde(deny_unknown_fields)]`, a `BTreeMap<String, HostProfile>`, defaults matching the global constraints, and a host alias regex equivalent to `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. On Unix, validate regular-file type, current UID ownership, and no group/other write bits before loading. Atomic saves use a same-directory `NamedTempFile`, mode `0600`, `sync_all`, then persist.

Validate normalized configured roots against
`MAX_REMOTE_CONTEXT_ROOT_BYTES` using UTF-8 bytes. `ErrorDetails` has optional
`physical_root`; `attach_available_remote_context` fills missing host/root/shell
without overwriting an existing domain code, retryability, or progress.

`RemotePath::resolve` must normalize components lexically without filesystem access, reject NUL and `ParentDir` that would escape root, accept absolute paths only when they begin at the normalized root component boundary, and retain both normalized absolute and root-relative strings.

Configure release as:

```toml
[profile.release]
lto = "thin"
codegen-units = 1
strip = "symbols"
panic = "unwind"
```

- [x] **Step 4: Run formatting, lint, and core tests**

Run: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --test core`

Expected: all commands exit 0; core tests include at least 100,000 generated quote cases across the proptest configuration.

- [x] **Step 5: Commit Task 1**

```bash
git add Cargo.toml Cargo.lock src tests/core.rs config.example.toml
git commit -m "feat: add Rust bridge core primitives"
```

---

### Task 2: Hardened OpenSSH Arguments and Capability Discovery

**Files:**
- Create: `src/ssh/mod.rs`
- Create: `src/ssh/argv.rs`
- Create: `src/capability.rs`
- Create: `tests/ssh_transport.rs`
- Create: `tests/support/mod.rs`
- Create: `tests/fixtures/fake-ssh.sh`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `Config`, `HostProfile`, `RemotePath`, `shell_word`, `BridgeResult`.
- Produces: `SshPolicy::for_host(&Config, ResolvedHost<'_>, &RuntimePaths, resolved_connection_identity: &str) -> BridgeResult<SshPolicy>`. The later runner obtains `resolved_connection_identity` from system `ssh -G`; Task 2 uses a stable fixture string and does not reimplement OpenSSH config parsing.
- Produces: `build_ssh_argv(&SshPolicy, host: &str, remote_command: &str) -> Vec<OsString>`.
- Produces: `Capability { physical_root, shell: ShellKind, bash_version, tools }`
  with shared `MAX_SHELL_VERSION_BYTES=256` enforced before caching.
- Produces: async `CapabilityCache::get_or_probe(host, probe_fn)` backed by a per-host Tokio `OnceCell`, so concurrent callers share one probe future, plus async `invalidate(host)`.
- Produces: `parse_probe_output(output: &[u8], expected_requested_root: &RemotePath) -> BridgeResult<Capability>` for strict NUL-delimited `key=value` records.

- [x] **Step 1: Write failing argv and probe tests**

Assert the generated SSH argv contains, as distinct values, `BatchMode=yes`, `StrictHostKeyChecking=yes`, `ForwardAgent=no`, `ForwardX11=no`, `ClearAllForwardings=yes`, `PermitLocalCommand=no`, `RequestTTY=no`, `ControlMaster=auto`, `ControlPersist=300`, and a ControlPath below an owned mode-`0700` runtime directory. Assert no host text beginning with `-` can enter argv.

Feed the probe parser fixed NUL-delimited output for Bash and sh-only hosts (the notation below uses `\0` for each NUL byte):

```text
CODEX_SSH_PROBE=1\0REQUESTED_ROOT=/srv/project\0ROOT=/srv/project\0SHELL_KIND=bash\0BASH_VERSION=5.2.15\0TOOL_rg=1\0TOOL_dd_nofollow=1\0TOOL_timeout=1\0
```

Assert malformed, duplicated, unknown-version, and root-mismatch output fails closed. Probed physical `ROOT` imports the shared configured-root constant, accepts exactly 65,536 UTF-8 bytes, rejects +1, and has non-ASCII byte-bound cases. Bash-version values accept exactly 256 UTF-8 bytes and reject +1, including non-ASCII boundaries and malicious fake-Bash records, before shell metadata reaches any result or error. Assert a capability failure invalidates exactly one host cache entry.

- [x] **Step 2: Run the focused tests and verify red**

Run: `cargo test --test ssh_transport -- --nocapture`

Expected: compilation fails for missing `ssh` and `capability` modules.

- [x] **Step 3: Implement runtime paths, argv policy, fixed probe, and cache**

Create runtime paths below `XDG_RUNTIME_DIR/codex-ssh-bridge` or `/tmp/codex-ssh-bridge-<uid>`. Refuse symlinks, wrong ownership, or permissions other than `0700`. Hash the alias and resolved connection identity into a short ControlPath filename without exposing it to the Agent.

Build a compile-time probe script that performs `cd -- "$1"`, emits both the exact requested root and `pwd -P`, checks `command -v` for required tools, tests `dd oflag=nofollow` in a private temporary directory, and removes that directory with a trap. Emit strict NUL-delimited `key=value` records so roots containing newlines remain representable. Parse only the versioned keys the bridge defines; do not use `eval`. Require `REQUESTED_ROOT` to equal the expected normalized configured root; require physical `ROOT` to be normalized, absolute, and within the shared UTF-8 byte ceiling, but allow it to differ when the configured root traverses symlinks. Enforce exported `MAX_SHELL_VERSION_BYTES=256` against UTF-8 bytes while parsing `BASH_VERSION`; MCP imports it rather than redeclaring it.

Represent shell selection exactly as:

```rust
pub enum ShellKind { Bash { version: String }, PosixSh, Login }

pub fn select_shell(cap: &Capability, requested: ShellRequest) -> BridgeResult<ShellSelection>;
```

`Auto` chooses Bash without profiles, otherwise sh with `fallback=true`; explicit Bash fails with `RemoteCapabilityMissing`; Login records that the remote account shell will interpret the command.

- [x] **Step 4: Verify the transport policy tests**

Run: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --test ssh_transport`

Expected: all selected tests pass, including runtime-directory permission failures.

- [x] **Step 5: Commit Task 2**

```bash
git add src/ssh src/capability.rs src/lib.rs tests/ssh_transport.rs tests/support tests/fixtures
git commit -m "feat: add hardened OpenSSH policy and probing"
```

---

### Task 3: Async SSH Runner, Cancellation, and Bounded Output Store

**Files:**
- Create: `src/ssh/process.rs`
- Create: `src/output.rs`
- Modify: `src/ssh/mod.rs`
- Modify: `src/lib.rs`
- Modify: `tests/ssh_transport.rs`

**Interfaces:**
- Consumes: hardened argv, `BridgeError`, config limits, `CancellationToken`.
- Produces: `SshRunner::execute(&self, request: RunRequest, cancel: CancellationToken) -> BridgeResult<RunResult>`.
- Produces: `OutputStore::capture(stdout, stderr, cancel) -> CapturedOutput` and `OutputStore::read(reference, stream, offset, max_bytes)`.
- `RunResult` includes status, elapsed, actual shell metadata, stdout/stderr previews, optional opaque reference, bytes seen, and `remote_process_may_continue`.

- [x] **Step 1: Add failing async behavior tests**

Extend the fake SSH fixture with modes selected by environment: echo argv, emit separate streams, emit arbitrary byte counts, sleep, ignore TERM, and exit with chosen status. Add tests that classify strict-host-key, authentication, connect-timeout, remote-exit, and capability failures into stable error codes without returning verbose SSH diagnostics. Test that a local deadline also wraps eligible remote commands with probed GNU `timeout`, and that an unprovably detached process sets `remote_process_may_continue=true`. Add Tokio tests proving:

```rust
#[tokio::test]
async fn five_commands_are_not_head_of_line_blocked() {
    let started = Instant::now();
    join_all((0..5).map(|_| runner.fake_sleep(Duration::from_secs(1)))).await;
    assert!(started.elapsed() < Duration::from_millis(1500));
}

#[tokio::test]
async fn cancellation_kills_the_child_group_quickly() {
    let token = CancellationToken::new();
    let task = tokio::spawn(runner.fake_sleep_with(token.clone()));
    token.cancel();
    assert!(timeout(Duration::from_millis(250), task).await.is_ok());
}
```

Add a 64 MiB output test that proves retained previews stay bounded, output spills to mode-`0600` files, references cannot contain paths, expired/unknown references fail, and stdout/stderr are drained concurrently.

- [x] **Step 2: Run the async tests and verify red**

Run: `cargo test --test ssh_transport -- --nocapture`

Expected: missing runner/output types cause compilation failure.

- [x] **Step 3: Implement process groups and output spooling**

On Unix, set a new child process group in `pre_exec`; on cancellation/timeout/output limit send TERM to the group, wait a bounded grace period, then KILL. Read stdout and stderr in separate Tokio tasks into an `OutputSink` that retains bounded head/tail and begins same-directory private spooling after 256 KiB. Count aggregate bytes and cancel at 64 MiB.

Use random 128-bit reference tokens mapped in memory to owned spool entries. Validate paging offsets and byte limits, expire after ten minutes, and remove files on expiry/drop. Never return a spool path.

Add global and per-host Tokio semaphores. The stdin/protocol task must not hold either semaphore while waiting to acquire another lock.

- [x] **Step 4: Verify async and output behavior**

Run: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --test ssh_transport`

Expected: five-way concurrency, 250 ms cancellation, stream separation, hard limit, and reference expiry tests pass.

- [x] **Step 5: Commit Task 3**

```bash
git add src/ssh src/output.rs src/lib.rs tests/ssh_transport.rs
git commit -m "feat: add cancellable SSH execution and bounded output"
```

---

### Task 4: High-Level Remote Read, List, Stat, and Search

**Files:**
- Create: `src/remote/mod.rs`
- Create: `src/remote/read.rs`
- Create: `tests/remote_ops.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `SshRunner`, capability cache, normalized paths, output limits.
- Produces: `RemoteBridge::hosts`, `list`, `stat`, `read`, `search`, and `output_read` async methods.
- Produces response types containing `remote=true`, alias, physical root, actual paths, hashes, truncation, and shell metadata where relevant.

- [x] **Step 1: Write failing high-level read tests**

Use a temporary local filesystem behind the fake SSH transport. Test batched reads, binary detection/local Base64 encoding, line/byte limits, hashes, hidden/depth entry limits, exact stat types, `rg` selection, grep/find fallback, paths with quotes/newlines/leading hyphens, and root traversal rejection before process launch. Inject exit-zero malformed read/list/stat/search records and assert new domain/protocol errors retain the available host/physical-root/shell through `attach_available_remote_context`.

Assert result serialization includes `remote: true`, `host`, and `physical_root` for every entry.

- [x] **Step 2: Run the remote read tests and verify red**

Run: `cargo test --test remote_ops -- --nocapture`

Expected: missing `RemoteBridge` methods cause compilation failure.

- [x] **Step 3: Implement fixed scripts and parsers**

Each operation uses a compile-time script plus encoded positional arguments. Stream file bytes directly and hash locally when the full requested content is present; obtain a remote SHA-256 for version identity when reads are truncated. Use NUL-delimited internal records for list/stat/search where Linux tools support them, then parse with explicit entry ceilings. Every facade/parser return path attaches available safe remote context to newly created errors without overwriting their classification.

`search` chooses `rg --json` when probed, otherwise a bounded `find -print0` plus `grep` path. Query and glob values remain positional/data inputs. Reject unsupported binary search in the fallback with a typed capability error.

- [x] **Step 4: Verify remote read tools**

Run: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --test remote_ops`

Expected: all focused cases pass without invoking a local shell.

- [x] **Step 5: Commit Task 4**

```bash
git add src/remote src/lib.rs tests/remote_ops.rs
git commit -m "feat: add high-level remote read operations"
```

---

### Task 5: Safe Atomic Remote Writes and Deletes

**Files:**
- Create: `src/remote/write.rs`
- Modify: `src/remote/mod.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Consumes: `RemoteBridge`, capability checks, raw stdin streaming, SHA-256 versions.
- Produces: `RemoteBridge::write(WriteRequest) -> BridgeResult<WriteResult>` and internal guarded delete used by patching.
- `WriteMode` is `Create` or `Replace { expected_sha256: Option<String> }`.

- [x] **Step 1: Add the adversarial failing tests**

Recreate the Python prototype exploit by predicting/replacing candidate temporary names with symlinks to an outside file. Assert the outside content never changes. Also test dangling target symlinks, create-only collision, target created during write, expected-hash mismatch, interrupted transfer cleanup, mode `0600`, same-directory install, read-only profile rejection, and a filename containing all shell metacharacter classes. Write-conflict/snapshot/domain errors created after capability selection must retain host/physical-root/shell without changing conflict or mutation truth.

- [x] **Step 2: Run safe-write tests and verify red**

Run: `cargo test --test remote_ops -- --nocapture`

Expected: missing write implementation fails compilation.

- [x] **Step 3: Implement the fixed safe-write protocol**

Require probed `mktemp`, GNU `dd` with `oflag=nofollow`, `stat`, `sha256sum`, `ln`, and `mv`. The fixed script must:

```bash
umask 077
tmp=$(mktemp --tmpdir="$parent" .codex-ssh-bridge.XXXXXXXXXX) || exit 70
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
dd of="$tmp" status=none conv=notrunc oflag=nofollow || exit 71
test -f "$tmp" && test ! -L "$tmp" || exit 72
```

Pass script/path/mode/hash as encoded arguments rather than interpolating them. Verify ownership/size/hash. For create, `ln -- "$tmp" "$target"` and then unlink the temp, treating `EEXIST` as `WriteConflict`. For replace, recheck expected SHA-256 immediately before `mv -T -- "$tmp" "$target"`. Return exact typed conflicts and cleanup evidence.

The Rust parent computes the content SHA-256 while streaming and checks the remote reported value. It must not retry a mutating write automatically after an ambiguous disconnect. Newly parsed conflict/protocol errors pass through the shared non-overwriting remote-context helper.

- [x] **Step 4: Verify safe writes and the exploit regression**

Run: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --test remote_ops`

Expected: all attacks fail closed; the outside sentinel file is unchanged.

- [x] **Step 5: Commit Task 5**

```bash
git add src/remote tests/remote_ops.rs
git commit -m "feat: add symlink-safe remote writes"
```

---

### Task 6: Unified-Diff Patch Engine and Guarded Multi-File Apply

**Files:**
- Create: `src/remote/patch.rs`
- Modify: `src/remote/mod.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Consumes: batched reads, safe write/delete, path normalization.
- Produces: `parse_patch(&str) -> BridgeResult<Vec<FilePatch>>`, `apply_file_patch(base, patch)`, and `RemoteBridge::apply_patch`.
- Supports standard `--- a/path`, `+++ b/path`, hunks, and `/dev/null` create/delete; rejects rename-only and binary patches.

- [x] **Step 1: Write failing parser and orchestration tests**

Cover multi-hunk updates, multiple files, create/delete, no-newline marker, malformed ranges, overlapping hunks, absolute/traversal paths, binary markers, base mismatch, all-bases-validated-before-write, and accurate partial-change reporting when the second write fails. Patch result/progress parse errors after a fixed child completes retain available host/physical-root/shell and exact changed/not-changed/unknown partitions.

- [x] **Step 2: Run patch tests and verify red**

Run: `cargo test --test remote_ops -- --nocapture`

Expected: missing patch parser and bridge method fail compilation.

- [x] **Step 3: Implement strict parsing and local application**

Parse line-by-line with explicit file/hunk state and checked integer arithmetic. Require every context/deletion line to match the downloaded base byte-for-byte. Preserve final-newline state. Cap file count, hunk count, and total output under configured write ceilings.

`apply_patch` first resolves every path and reads every base/version, then computes every output. Only after all validation succeeds does it call guarded write/delete sequentially. Record `changed_paths` after each confirmed operation; on failure return those paths plus `not_changed_paths` and the underlying typed error. Attach available safe remote context at parser/facade boundaries without overwriting progress.

- [x] **Step 4: Verify all patch behavior**

Run: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --test remote_ops`

Expected: all patch cases pass, and traversal/binary patches launch no SSH process.

- [x] **Step 5: Commit Task 6**

```bash
git add src/remote tests/remote_ops.rs
git commit -m "feat: add guarded remote patch application"
```

---

### Task 7: Strict Bounded JSON-RPC/MCP Protocol Core

**Files:**
- Create: `src/mcp/mod.rs`
- Create: `src/mcp/protocol.rs`
- Create: `tests/mcp_protocol.rs`
- Modify: `src/lib.rs`
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: global config limits, Tokio stdin/stdout, cancellation tokens.
- Produces: `McpServer::serve<R, W>(reader, writer)`, `ProtocolState`, typed `RequestId`, and response constructors.
- Supports initialize, initialized notification, ping, tools/list, tools/call, notifications/cancelled, and orderly EOF/shutdown behavior.

- [x] **Step 1: Write failing protocol state and frame tests**

Test valid initialize flow for both supported versions plus JSON-RPC 1.0 rejection, non-object valid JSON (`-32600`), parse error (`-32700`), invalid/null/overlong IDs, requested-version `clientInfo`, unsupported-version bounded-current-union behavior, open capabilities and `_meta`, ping in AwaitInitialized and Ready, tool calls before initialization, duplicated initialize, unknown methods, notifications without responses, exact `DuplicateKey`/`StructuralBudget`/`Syntax` classification, oversized/over-depth/over-node/member/key-byte input rejection before excess allocation, wide-array/object RSS, exact frame minimum/minimum-minus-one, and cancellation read while another tool future is blocked. Add a two-version project-policy golden matrix based on the official methods for initialize/ping/initialized/list/call/cancelled: 2025-06 accepts bounded extra top-level params and ignores/never reflects them; the project's 2025-11 validator rejects fields outside the known official field set while keeping object `_meta` open; closed tool `arguments` stay closed in both, unnegotiated `task` is rejected, and invalid notifications cause no state/cancellation effect.

Split RED/GREEN groups in this order: constructor budgets; envelope and state;
dispatch/admission; cancellation and buffered races; shutdown and writer. Use
separate synchronous-invocation, future-first-poll, and bridge-operation
counters, durable
predicate/semaphore gates, and timeout-wrap every async wait. Cover request-
only methods without IDs, notification-only methods with IDs, exact duplicate-
ID priority only while a tool task is active, reuse after join with its response
still queued, future-construction/poll panics, continuously ready notifications,
an empty-JoinSet idle server, deterministic block-then-echo out-of-order
completion, clean/partial EOF, serializer-zero-write overflow, partial-write-
then-error, healthy one-byte writes, forever-pending writer, and token-ignoring
futures. No sleep is test synchronization.

The idle regression tests one factored async `next_owner_event` select
iteration directly: with empty JoinSet and pending input/writer it remains
pending, then returns input after input is supplied. Never run an intentionally
unguarded outer owner loop under the same-runtime timeout.

Assert malformed envelope/lifecycle/unknown-name cases are `calls=0, polls=0,
bridge_ops=0`; known-tool invalid arguments are `calls=1, polls=1,
bridge_ops=0`.

- [x] **Step 2: Run protocol tests and verify red**

Run: `cargo test --test mcp_protocol -- --nocapture`

Expected: missing MCP server fails compilation.

- [x] **Step 3: Implement bounded framing and concurrent registry**

Read with `AsyncBufReadExt::fill_buf`, scanning for newline while counting bytes; discard and return `REQUEST_TOO_LARGE` once the configured effective `max_frame_bytes` is exceeded without constructing a larger `String` or `Value`. Eight MiB is the default and compiled maximum, not a hardcoded per-server acceptance bound. Parse only complete UTF-8 JSON lines.

Keep lifecycle state in one owner task. Dispatch valid tool calls into a bounded `JoinSet` and map bounded `RequestId` to cancellation tokens. Control responses remain values serialized by the single writer. Serialize and cap each completed call response exactly once before channel admission, directly from its owned result through a borrowed response wrapper into a private `PreparedJsonLine` bounded to `max_frame_bytes + 1` including newline. The writer performs the final suppression check and writes those prepared bytes without another clone/serialization, so JSON lines cannot interleave and the queue cannot hold a second large result copy. On `notifications/cancelled`, cancel immediately without waiting for the tool task and suppress its response.

The main select monitors input, tool joins, and the writer join. Writer failure,
panic/early return, backpressure, and EOF share one Closing transition; it sets
Closing/rejects dispatch, partial EOF may try-send only `-32700`, then it sets
global call-response suppression and cancels. Tagged queued call messages not
yet committed past the writer's final suppression check are skipped; that
commit is the non-retractable boundary. Task and
writer cleanup use separate MCP-specific 250 ms graces, then abort and drain
through another bounded 250 ms grace. Clean EOF, with or without active calls,
succeeds iff cleanup is healthy; partial EOF returns fixed `PROTOCOL_ERROR` only
after its parse-error response and writer shutdown drain healthily. Any enqueue
or later transport failure wins as fixed `MCP transport failed`.
Call serialization/capacity overflow occurs while preparing the bounded line,
before channel admission and the first transport write, and emits zero bytes. A
`write_all` error or abort may leave the current frame
prefix; close immediately and attempt no next frame. Successful frames on a
healthy transport, including one-byte writes, never interleave.
Invoke `ToolService::call` inside the task and use a
panic-safe task-ID/request-ID association so construction/poll panics produce
fixed `-32603` for the correct active ID (or are suppressed after client
cancellation/Closing). Panic payloads are absent from MCP wire, returned errors,
and bridge-authored diagnostics; Task 5 installs no global panic hook. Acquire
an owned permit before insertion, keep it in owner-held `InFlight`, never the
task, and drop it on join/removal or final clear.

Classify requests and notifications before side effects. Request-only methods
without IDs and malformed notifications do nothing; ID-bearing initialized or
cancelled methods return fixed `-32600` without effect unless their legal ID is
an active tool task, in which case the active-task duplicate rule wins. Any
present illegal ID is invalid with `id=null`, never a notification. A legal ID
matching an active task returns `-32600 Duplicate request id` with `id=null`
after envelope/legal-ID validation but before lifecycle, params, name, and
saturation, never overwriting the active entry. Remove the ID at task join
before response queuing; reuse is allowed while that response remains queued.
Factor one loop iteration into async `next_owner_event` with no internal loop.
Its biased select orders writer result, input, then tool completion and guards
the join branch with `if !join_set.is_empty()`, so buffered cancellation wins
without idle spinning or starving writer faults; after every recoverable input
event, including a drained oversized frame, one guarded
`try_join_next_with_id` prevents a notification flood from starving completions.

Cleanup unit tests use cooperative and token-ignoring-but-yielding tool futures
and injected writer-shutdown failure. Do not inject a non-returning poll into a
current-thread runtime; it freezes deadlines. Keep the defensive production
abort-drain timeout and defer a separately watched non-yielding process case to
adversarial Task 8/11.

Negotiate exactly `2025-11-25` and `2025-06-18` from one constant and return server name/version/capabilities. Supported versions validate their requested shape: name/title/version for 2025-06-18 and those plus icons/description/websiteUrl for 2025-11-25. An unsupported version validates the bounded current 2025-11 union before selecting latest; latest-only fields pass there while fields outside the union fail. Use bounded absolute URIs and fixed non-echoing errors. For the six supported methods, negotiated June shapes collect and discard bounded additional top-level params, while November applies the project's closed validator to official fields; both keep object `_meta` and client capabilities open. Reject unnegotiated `task` and unknown fields in tool arguments at the tools layer.

Absolute URIs use an allocation-free RFC 3986 state machine: ASCII scheme with
nonempty suffix; authority only for immediate post-colon `//`; path; at most
one query transition; and at most one fragment transition, all with component-
specific character sets and exact percent escapes. HTTP(S) comparison is ASCII-
case-insensitive and requires authority. Brackets are IPv6-authority-only;
internal path `//` is not authority; a second `#` fails. Authority rejects
userinfo and accepts parsed bracketed IPv6/IPv4 or bounded DNS labels plus an
optional decimal `u16` port. Test mixed-case HTTPS, `urn`, `data`, path `//`,
query `?` data, IPv4/IPv6/DNS/port, second `#`, brackets in path, relative,
malformed-authority, and exact/+1 byte cases.
Cancellation requires bounded
string/integer `requestId`, admits only optional bounded string reason and
object `_meta` in November, allows/discards other bounded top-level fields in
June, and rejects unnegotiated `task` in both. Validate the complete
cancellation shape before registry lookup.

The strict visitor enforces depth, node, aggregate member, and key-byte budgets, uses one shared failure marker to distinguish duplicate/structural/genuine-syntax errors, and reuses the destination `serde_json::Map` for duplicate detection rather than a second cloned-key set. A malformed tools/call envelope or unknown name is `-32602`; known-tool argument validation returns an actionable normal `isError=true` result and launches no bridge operation.

Define compiled `MIN_MCP_FRAME_BYTES=1024*1024` with a static checked formula covering the shared 65,536-byte root ceiling times conservative combined expansion 13, a maximum 256-byte wire ID, and 64 KiB fixed reserve; known context cannot be truncated. Error rendering derives a context-free `RenderedErrorCore`: Text carries context once and structured top level once, while `structuredContent.error.details` excludes host/root/shell. Safe message/action/warning projection replaces every Unicode `char::is_control()` with one ASCII `?` before or during UTF-8-bound truncation while preserving quotes, backslashes, and ordinary Unicode. An authoritative counting test begins with a real maximum `BridgeError`/`ErrorDetails` containing the maximum control-heavy root and control-heavy shared 256-byte shell version plus maximum bounded message/action/warnings using the worst legal alternating quote/backslash pattern, projects it, proves only those two root contexts remain, and fits the compiled minimum. Task 4 uses an equivalent test-only projection; Task 7 replaces it with the real sanitizer and `RenderedErrorCore`. Server construction also counting-serializes the trusted exact full nine-tool list with a synthetic maximum wire ID and rejects anything below the larger minimum. Test exact effective minimum/minus-one with both the full list and real worst fallback. `max_frame_bytes` and `WireBudget` exclude the newline delimiter. Every tool future receives `ToolCallContext { cancel, wire_budget }`, passing the exact token to the bridge and budget to validation/success/error renderers. Every bulk tool has a compact fallback; completed mutation truth/counts can never become `-32603`. Retention is best-effort and uses a bridge-owned direct-to-spool generic facade with typed remote/aggregate provenance, never direct MCP access to `OutputStore` or another full-size buffer.

For the wire calculators, `compact_fallback_bytes` always means the serialized
fallback `result` value only, excluding JSON-RPC envelope, request ID, and
newline. The compiled 1 MiB constant is a complete-frame floor and must never
be passed as that result-only value. Task 5 passes zero until real tool-result
rendering exists; Task 7 replaces zero with the counting-serialized real
largest fallback result. `McpServer` stores that one result-only value and uses
the identical field for both constructor minimum calculation and every per-ID
`WireBudget::for_response`; Task 5 proves only the stored zero path. Task 7 owns
the real nonzero end-to-end propagation test. Task 4 owns only the calculator, framing, capped writer,
and test-only worst-size projection (including a control-heavy maximum shell
version). Task 5 owns `McpServer::new`, lifecycle/fixed-response fit, and exact
constructor min/minus-one. Task 7 owns the real `RenderedErrorCore`, every
bulk/mutation compact fallback, and repeated constructor exact/minus-one with
the actual fallback count.

- [x] **Step 4: Verify strict MCP behavior**

Run: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --test mcp_protocol && cargo test --release --test mcp_protocol task7_wide_json_rss_ -- --nocapture`

Expected: exact JSON-RPC codes and no pre-initialize tool execution.

- [x] **Step 5: Commit Task 7**

```bash
git add src/mcp src/lib.rs src/main.rs tests/mcp_protocol.rs
git commit -m "feat: add strict asynchronous MCP protocol"
```

---

### Task 8: MCP Tool Schemas, High-Level Dispatch, and Single-Copy Results

**Files:**
- Create: `src/mcp/tools.rs`
- Create: `src/mcp/render.rs`
- Modify: `src/mcp/mod.rs`
- Modify: `src/config.rs`
- Modify: `config.example.toml`
- Modify: `src/remote/mod.rs`
- Modify: `src/output.rs`
- Modify: `src/ssh/process.rs`
- Modify: `tests/mcp_protocol.rs`
- Create: `tests/mcp_tools.rs`
- Modify: `tests/core.rs`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Consumes: every `RemoteBridge` high-level operation and bridge-owned opaque-reference paging; MCP never imports `OutputStore`.
- Produces exact schemas and handlers for `remote_hosts`, `remote_list`, `remote_stat`, `remote_search`, `remote_read`, `remote_output_read`, `remote_apply_patch`, `remote_write`, and `remote_run`.

- [x] **Step 1: Add failing schema and result tests**

Assert the exact nine-tool list, `remote_` names, required host fields, `additionalProperties=false`, size/range constraints, read-only/destructive/open-world annotations, server-side read-only rejection, automatic probe behavior, shell/fallback metadata, actionable sh warnings on success and errors, and remote labels.

Serialize 1 MiB and hostile NUL-heavy output and assert payload appears in only one MCP content representation, the text block's JSON itself contains remote/host/root/shell plus bulk, total wire size remains within response budget, and structured content repeats only small metadata rather than stdout/stderr or other bulk. Bridge-error text is compact JSON with every available remote context plus bounded safe error/warning fields; `RenderedErrorCore` prevents nested structured error details from repeating host/root/shell. Force compact fallbacks for hosts/list/stat/search/read/output-read/run and applied/partial/unknown mutations. Assert truth/counts survive without `-32603`; inject retention success and storage/admission failure for each new read-only ref and mutation detail. Retention tests use actual serialized canonical sizes at exactly `MAX_OUTPUT_BYTES` and +1, cancellation and serializer failure, proving false/no-ref and zero temp residue on failure plus TTL, disk-admission, and concurrency bounds. Use more than five configured hosts without probing. Test aggregate host-list output paging and single-host provenance, plus multi-page UTF-8/Base64 reassembly where shrunk pages use raw-byte offsets with no gaps/overlaps. Release RSS cases for large retained hosts/list/stat/search prove no second full-size vector/JSON clone.

- [x] **Step 2: Run tool tests and verify red**

Run: `cargo test --test mcp_protocol -- --nocapture`

Expected: missing tool registry/handlers fail compilation.

- [x] **Step 3: Implement schemas and dispatch**

Deserialize each argument object into a dedicated `#[serde(deny_unknown_fields)]` struct. Resolve aliases only through `Config::host`. Let `RemoteBridge` own probe, quoting, limits, and errors; handlers only translate typed requests/results.

Render one compact-JSON text content block containing remote/host/root/shell context and the Agent-visible payload, plus `structuredContent` small metadata without payload duplication. Construct typed projections directly; never serialize a complete result/error and then delete or clone fields. Error message/action are bounded to 1,024 UTF-8 bytes, with at most 16 warnings of 1,024 bytes, UTF-8-boundary truncation flags, and no truncation of code/context/truth/counts/progress. Before or during truncation, normalize every Unicode `char::is_control()` to one ASCII `?`, preserving quotes, backslashes, ordinary Unicode, and other non-control characters. Worst-case tests use alternating quote/backslash maximum fields. Large bulk results adapt to `ToolCallContext.wire_budget`. Output-read shrink selects raw bytes before UTF-8/Base64 encoding, then sets `next_offset=offset+actual_inline_raw_bytes` and EOF from the actual stored position. Include actual shell metadata and an actionable Bashism warning in compact-JSON `remote_run` errors as well as successes after sh selection. Compact mutation fallbacks preserve status, progress counts, and `mutation_may_have_applied`.

Define `RetentionProvenance::{Remote(RemoteContext), Aggregate { kind, source_count }}` and carry it through `OutputReadResult`; aggregate pages omit fabricated single-host context. A generic `RemoteBridge::retain_serialized_detail<T: Serialize + Send + 'static>` serializes the owned model directly to bounded private spool storage (offloading blocking work as needed), so MCP never receives store access or creates another large buffer. Enforce crate-root `MAX_OUTPUT_BYTES=64 MiB` on actual serialized canonical bytes with a counting/capped writer: exact succeeds and first +1 byte fails.

Add `Limits.global_spool_quota_bytes` (512 MiB default, compiled `MIN_GLOBAL_SPOOL_QUOTA_BYTES=64 MiB` and maximum 512 MiB), `Limits.retention_serialization_jobs` (two default, four maximum), and compiled `MAX_SPOOL_ENTRIES=1024` pending-plus-committed slots with at most two files per entry. Validate quota config in the inclusive `[64 MiB, 512 MiB]` range. A shared ledger covers command stdout/stderr, fixed-command internal capture, and retained detail. Command/internal writers reserve actual next chunks, release partial tails, and roll back failures; exact quota succeeds and only the next racing byte fails. On a fresh store, five maximum outputs total 320 MiB plus two default retention reservations total 128 MiB, so 448 MiB fits with 64 MiB remaining. Light calls avoid theoretical-max rejection. Test this combined fresh-store case explicitly.

At MCP bootstrap, copy the two validated spool limit values before moving the loaded config and pass them explicitly to `OutputStore::with_limits`. Constructor tests use non-default quota values across 64--511 MiB and job counts across 1--4, proving both configuration fields have real consumers and are not replaced by store defaults.

Generic detail retention first `try_acquire`s its job permit, then an entry slot, then a full crate-root `MAX_OUTPUT_BYTES` quota reservation before `spawn_blocking`; a miss returns false/no-ref without serialization CPU. Its capped writer checks cancel at least every 64 KiB, and the async path always awaits the blocking join and cleanup. Commit shrinks the reservation to actual bytes. Command/internal saturation remains typed `OUTPUT_LIMIT`; detail saturation/overflow/cancellation/serializer failure returns false/no-ref without losing truth/counts. Release byte charge only after unlink succeeds or `NotFound`; other unlink errors retain charge and a retry tombstone. Release the entry slot only after all files are gone; expiry/removal/shutdown use the same order. Tests cover exact quota/next-byte races, exact 1,024/next-slot and two-file limits, job saturation, light internal capture, partial writes, 64 KiB cancellation, awaited joins, unlink failure retry, no premature ledger/slot/permit release, TTL/shutdown, and worst cases `spool_bytes <= 512 MiB`, `spool_files <= 2048` independent of inflight calls.

Under one entry lock, `OutputStore::read` checks expiry and synchronously opens
a new independent handle for the selected private pathname; only after open
succeeds does it create the ref-counted byte/entry lease and release the lock.
It never publishes a lease before open, keeps no FD per committed entry, and
never clones a shared cursor. TTL/discard that wins removes and unlinks the
entry, while a reader that wins finishes from its own handle and pins
charge/slot until final close. Test both lock orders, the former
lease-before-open window, 1,024 entries without resident-FD amplification,
concurrent different-offset pages, and last-reader release.

- [x] **Step 4: Verify the complete MCP surface**

Run: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --test mcp_protocol && cargo test --test mcp_tools && cargo test --release --test mcp_tools task78_release_dispatch_p95_ -- --nocapture && cargo test --release --test mcp_tools task78_release_fake_call_p95_ -- --nocapture && cargo test --release --test mcp_tools task8_five_hosts_ -- --nocapture && cargo test --release --test mcp_tools task8_cancel_process_ -- --nocapture && cargo test --release --test mcp_tools task8_output_rss_ -- --nocapture`

Expected: lifecycle, schema, cancellation, readonly, amplification, dispatch/fake-call p95, five-host, release cancellation, and RSS gates pass. Task 11 still repeats and records the final whole-product/real-SSH acceptance.

- [x] **Step 5: Commit Task 8**

```bash
git add src/mcp src/config.rs config.example.toml src/remote/mod.rs src/output.rs src/ssh/process.rs tests/core.rs tests/mcp_protocol.rs tests/mcp_tools.rs tests/ssh_transport.rs tests/remote_ops.rs
git commit -m "feat: expose high-level remote MCP tools"
```

---

### Task 9: Human CLI, SSHFS Safety, and Transactional Installation

**Files:**
- Create: `src/cli.rs`
- Create: `tests/cli.rs`
- Modify: `src/main.rs`
- Modify: `src/ssh/argv.rs`

**Interfaces:**
- Consumes: config atomic save, transport policy, capability probe, shared remote run.
- Produces Clap commands `hosts list/add/remove/show`, `doctor`, `run`, `mount`, `unmount`, `mount-status`, `install --user`, and `uninstall --user`.

- [x] **Step 1: Add failing CLI tests**

Use `assert_cmd` to test dry-run defaults, explicit `--apply`, host addition validation, config mode `0600`, doctor root/shell reporting, direct run shell reporting, mountpoint validation, no overwrite of unrelated Codex entries, differentiated `codex mcp get` failures, subprocess timeout, rollback after Skill failure, and identity-checked uninstall. Feed verbose doctor output containing agent socket paths, identity paths, command data, and credential-like tokens, then assert the displayed diagnostic is redacted.

Assert SSHFS argv includes BatchMode, strict host keys, disabled agent/X11/forwarding/local command, connect timeout, keepalives, reconnect, and `ro` for read-only profiles. Assert no MCP source file contains an SSHFS tool.

- [x] **Step 2: Run CLI tests and verify red**

Run: `cargo test --test cli -- --nocapture`

Expected: CLI subcommands and SSHFS builder are missing.

- [x] **Step 3: Implement the CLI and installer transaction**

Keep `main.rs` limited to argument parsing, config loading, Tokio runtime entry, and exit-code rendering. Human commands call shared library APIs.

Installer preflight resolves the release binary, plugin/Skill sources, existing Codex MCP entry, target paths, and permissions before changing anything. `install`/`uninstall` are dry-run unless `--apply` is present. Record every successful mutation and roll it back in reverse order on later failure. Use timeouts for Codex subprocesses and distinguish not-found from other nonzero results. Never remove an entry or symlink whose resolved target/installation identity differs.

Mount refuses a relative or nonempty mountpoint without an explicit human override, forces read-only mode from the profile, and prints that commands remain remote and FUSE is not an Agent workspace.

- [x] **Step 4: Verify all CLI behavior**

Run: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --test cli`

Expected: all dry-run, rollback, identity, SSHFS, and host-config tests pass.

- [x] **Step 5: Commit Task 9**

```bash
git add src/cli.rs src/main.rs src/ssh/argv.rs tests/cli.rs
git commit -m "feat: add safe CLI and local installation"
```

---

### Task 10: Plugin, Skill, Documentation, and Verified Legacy Move

**Files:**
- Modify: `.codex-plugin/plugin.json`
- Modify: `.mcp.json`
- Modify: `skills/remote-ssh-ops/SKILL.md`
- Modify: `skills/remote-ssh-ops/agents/openai.yaml`
- Modify: `skills/remote-ssh-ops/references/operations.md`
- Modify: `README.md`
- Create: `docs/security.md`
- Create: `docs/performance.md`
- Move after verification: `mcp/`, `scripts/`, `ssh_bridge/`, `tests/fake_ssh.py`, `tests/test_bridge.py`, `config.example.json` into `legacy/python-prototype/`

**Interfaces:**
- Consumes: final binary CLI/MCP names and exact schemas.
- Produces: installable Rust-only plugin chain and minimal Agent workflow.

- [x] **Step 1: Add failing packaging checks**

Add a Rust integration check or shell validation command that parses both JSON manifests, asserts `.mcp.json` launches `./bin/codex-ssh-bridge mcp`, asserts no installed manifest/Skill references Python, asserts SSHFS is absent from MCP tools, and checks the Skill names all nine tools exactly.

- [x] **Step 2: Run packaging checks and verify red**

Run: `cargo test packaging -- --nocapture`

Expected: current manifests fail because they launch `python3` and use old tool names.

- [x] **Step 3: Update plugin, Skill, and documentation**

The Skill must teach one default workflow: `remote_search/read -> remote_apply_patch -> remote_run`. It must say that every path/result is remote, output is untrusted, the actual Bash/sh/login shell is in results, POSIX commands are preferred, explicit Bash is required for Bash-only syntax, and SSHFS is human-only.

README must cover build, configuration, adding future SSH aliases, dry-run installation, approvals, tool examples, SSHFS limitations, and no-remote-Codex guarantee. `docs/security.md` records trust boundaries and every hardened SSH flag. `docs/performance.md` records benchmark commands and measured values rather than claims without evidence.

Build `target/release/codex-ssh-bridge`, copy it to `bin/codex-ssh-bridge`, and verify the copied binary hash. Only after all Rust tests in Tasks 1-9 pass, move the Python prototype intact into `legacy/python-prototype/`; do not delete it.

- [x] **Step 4: Run format, tests, validators, and Rust-only search**

Run:

```bash
cargo test --all-targets
rg -n "python3|server.py|ssh_bridge" .codex-plugin .mcp.json skills README.md
python3 /home/wkj/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
python3 /home/wkj/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/remote-ssh-ops
```

Expected: tests and validators pass; the Rust-only search prints no installed-chain references. The two Python commands are development-time validators supplied by Codex and are not part of the bridge runtime, installer, benchmark, or test fixture.

- [x] **Step 5: Commit Task 10**

```bash
git add .codex-plugin .mcp.json skills README.md docs bin legacy Cargo.toml Cargo.lock src tests config.example.toml
git commit -m "feat: package Rust SSH bridge plugin"
```

---

### Task 11: Security, Real-SSH, Performance, and End-to-End Acceptance

**Files:**
- Create: `tests/performance_acceptance.rs`
- Create: `tests/real_ssh.rs`
- Modify: `docs/performance.md`
- Modify: `docs/security.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: complete release binary and plugin.
- Produces: requirement-by-requirement evidence and installed local toolchain.

- [x] **Step 1: Add acceptance tests before recording results**

The release-only performance test must measure at least 100 dispatches/fake calls for p95, five concurrent one-second commands, cancellation latency, 64 MiB output RSS delta, maximum-budget wide JSON array/object RSS deltas below 48 MiB, and maximum MCP wire bytes. Run the wide array and wide object in separate fresh release child processes. Each child records an idle/warmed baseline, samples peak during repeated parsing, prints raw baseline/peak/delta, and asserts `peak-baseline < 48 MiB`; never reuse one test-binary process where allocator-retained memory or parallel tests can contaminate the second shape. Task 11 deliberately repeats the Tasks 7–8 wide-JSON gate as final whole-product acceptance. The real-SSH test creates an isolated local `sshd` fixture when facilities permit and otherwise prints one explicit skip reason; it tests host keys, ControlMaster reuse, Bash/sh metadata, raw command, read/search/patch/write, timeout, and cleanup.

- [x] **Step 2: Run acceptance tests to expose remaining failures**

Run:

```bash
cargo test --release --test performance_acceptance -- --nocapture
cargo test --release --test real_ssh -- --nocapture
```

Expected before final tuning: any unmet threshold or unavailable fixture is visible and not summarized as a pass.

- [x] **Step 3: Fix measured regressions without weakening thresholds**

Use profiling evidence to remove avoidable allocations, clone-free payload paths, blocking locks, duplicate serialization, or excess process setup. Do not replace actual acceptance with mocks. Record host/kernel/Rust/OpenSSH versions, raw samples, p50/p95/max, RSS delta, and real-SSH status in `docs/performance.md`.

Re-run the original predictable-temp symlink exploit, 16 MiB stdout+stderr serializer case, oversized-frame case, cancellation case, and SSHFS policy test; record the passing commands in `docs/security.md`.

- [x] **Step 4: Run the full completion audit**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo test --release --test performance_acceptance -- --nocapture
cargo test --release --test real_ssh -- --nocapture
python3 /home/wkj/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
python3 /home/wkj/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/remote-ssh-ops
./bin/codex-ssh-bridge --help
./bin/codex-ssh-bridge install --user
```

Expected: all mandatory checks pass, any real-SSH skip is explicitly reported for user judgment, help lists no Python dependency, and install dry-run reports only expected Rust MCP/Skill changes.

- [x] **Step 5: Install with approval and smoke-test Codex MCP**

Request approval for writes under the user's Codex/config directories, then run:

```bash
./bin/codex-ssh-bridge install --user --apply
codex mcp get ssh-bridge
```

Start the MCP binary directly, send initialize/initialized/tools-list frames, and confirm all nine tools. If an allowlisted real host exists, run `remote_hosts` and one bounded `remote_list`; do not mutate a real server without separate explicit authorization.

- [x] **Step 6: Commit final evidence**

```bash
git add tests/performance_acceptance.rs tests/real_ssh.rs docs/performance.md docs/security.md README.md
git commit -m "test: verify SSH bridge security and performance"
```

---

## Completion Evidence Matrix

- No remote Codex/helper and full OpenSSH compatibility: `src/ssh/argv.rs`, README architecture, real-SSH fixture.
- Minimal Agent burden and shell visibility: exact MCP schemas, Skill workflow, shell metadata tests.
- No Agent SSHFS confusion: MCP tool-list assertion and CLI-only mount tests.
- Quoting/injection resistance: 100,000-case property suite and hostile-path integration cases.
- Symlink/race defense: preserved exploit regression and safe-write tests.
- Async/cancellation: lifecycle cancellation test and 250 ms release acceptance.
- Bounded memory/wire output: 64 MiB RSS and serializer acceptance.
- Strict MCP: lifecycle/frame/schema suite.
- Rust-only runtime: manifest search, binary help, legacy move, plugin validators.
- Complete local toolchain: dry-run, transactional apply, Codex MCP registration, direct stdio smoke test.

## Final Review Evidence — 2026-07-19

- All 56 implementation-plan steps above are complete; final hardening preserved every compiled security, memory, wire, latency, and cancellation threshold.
- RED evidence reproduced identity resolution caching, resolved-identity drift acceptance, absent ordinary-SSH keepalives, unsupported configuration versions, and unconditional real-SSH setup skipping before their fixes.
- Focused GREEN evidence covers two `ssh -G` calls across two operations, rejection of changed resolved configuration before `P`/`R`/`C`, exact-once keepalives in bootstrap/operational/SSHFS argv, rejection of config versions 0 and 2 on load/save, and required-mode setup failure with its original reason.
- `cargo fmt --all -- --check`, warning-free Clippy, and `cargo test --all-targets --all-features -- --test-threads=1` passed after the final changes.
- `cargo test --release --test performance_acceptance -- --nocapture` passed all five tests with unchanged gates; `docs/performance.md` records the final samples.
- `CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH=1 cargo test --release --test real_ssh -- --nocapture` failed closed in the managed sandbox with `cannot reserve a localhost port: Operation not permitted (os error 1)` and no integration skip. This exact command requires an outside-sandbox rerun before release sign-off.
- `cargo build --release` succeeded; `bin/codex-ssh-bridge` is mode `0755`, and it matched the release artifact at SHA-256 `92e47acbe4ea9738ed9c660e204e9901ffb6d773c641308ee7746408878d5749`.
