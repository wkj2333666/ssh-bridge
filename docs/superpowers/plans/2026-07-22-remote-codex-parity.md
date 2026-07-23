# Remote Codex Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace per-operation SSH execution with a bounded persistent SSH session and request multiplexer whose observable command behavior matches the local Codex execution model, while making the public shell contract explicit and safe.

**Architecture:** The local Rust bridge owns one `HostSession` per configured host alias. A session contains one long-lived OpenSSH child running a temporary POSIX `sh` dispatcher; request-scoped frames start independent remote process groups and return bounded stdout/stderr, exit status, timeout, and cancellation state. The dispatcher is only a transport/runtime component: the user command still runs in the requested shell (omitted shell means Bash, explicit `sh` or `login`), and all existing root/capability guards remain in the bridge.

**Tech Stack:** Rust 2024, Tokio process/IO/tasks, serde JSON for MCP, bounded length-prefixed frames with binary payloads, POSIX `sh`/`dd`/`mkfifo`/`setsid` on the remote host, existing OpenSSH configuration and capability probes.

## Implementation status

Tasks 1–8 are implemented. The integration and performance fixtures now speak
the framed persistent-session protocol, including session lifecycle, cancellation,
bounded output, and remote capability differences. Environment overrides remain
deferred from the v0 public contract rather than silently ignored.

## Global Constraints

- Do not install or authenticate Codex on a remote host.
- Do not use Python; implementation and test helpers are Rust, POSIX `sh`, or existing project tooling.
- Public `remote_run.shell` accepts only `bash`, `sh`, and `login`; omission means `bash`; `auto` is removed and never silently falls back.
- The dispatcher itself is POSIX `sh`; it must never interpret the user command as its own shell language.
- Requests on one host are independent and concurrent up to existing configured global/per-host capacity; there is no mutation-specific serialization.
- Persistent-session startup failure is a hard error; never silently fall back to one-shot SSH.
- Every remote operation remains bounded by configured frame, input, output, timeout, root, and capability limits.
- Host selection is restricted to configured aliases; no raw hostnames or raw SSH argv are accepted from MCP.
- `remote_run` is account-scoped remote execution; configured roots guard bridge-managed paths and working-directory validation, not a complete remote filesystem sandbox.
- v0 keeps the public MCP surface buffered and high-level; process handles, appended stdin, and PTY controls remain internal to the bridge.
- A transport loss must report whether the remote process was known to stop; otherwise return an explicit unknown-outcome error and do not retry mutations.
- The bridge remains a local MCP server; no remote bridge binary, Codex binary, API key, plugin, or helper installation is permitted.

## File Map

- Create `src/ssh/frame.rs`: bounded frame header, frame kinds, encode/decode, and malformed/oversize handling.
- Create `src/ssh/dispatcher.rs`: handshake constants, frame-to-script control metadata, and remote capability requirements.
- Create `src/ssh/dispatcher.sh`: the audited POSIX dispatcher source embedded with `include_str!` by `src/ssh/dispatcher.rs`.
- Create `src/ssh/session.rs`: `HostSession`, one persistent SSH child, request registry, writer task, reader task, cancellation, and shutdown.
- Modify `src/ssh/mod.rs`: register the new modules and expose session types to `SshRunner`.
- Modify `src/ssh/process.rs`: route operational requests through `HostSession`, retain one-shot execution only for explicitly local diagnostics if still needed, and map session outcomes into existing `RunResult`/`FixedRunResult` types.
- Modify `src/capability.rs`: split dispatcher prerequisites from user-shell selection; retain capability probing but make Bash selection explicit.
- Modify `src/remote/mod.rs`, `src/remote/run.rs`, `src/remote/read.rs`, `src/remote/write.rs`, `src/remote/patch.rs`, `src/remote/search.rs`, and `src/remote/metadata.rs`: use the session-backed runner without changing the high-level root/hash contracts.
- Modify `src/mcp/tools.rs`, `src/mcp/render.rs`, and `src/cli.rs`: remove public `auto`, default omitted shell to Bash, and preserve structured shell/transport metadata. Per-request environment overrides remain deferred until the dispatcher metadata contract is extended.
- Modify `skills/remote-ssh-ops/SKILL.md`, `skills/remote-ssh-ops/references/operations.md`, `README.md`, `docs/performance.md`, and `docs/security.md`: document persistence, concurrency, cancellation, shell fallback, unknown outcomes, and the fact that SSHFS is not an agent workspace.
- Modify `tests/ssh_transport.rs`, `tests/remote_ops.rs`, `tests/mcp_tools.rs`, `tests/mcp_protocol.rs`, `tests/performance_acceptance.rs`, and `tests/fixtures/fake-ssh.sh`; create `tests/session.rs` for deterministic persistent-session tests.

---

### Task 1: Make the public shell contract explicit

**Files:**
- Modify `src/mcp/tools.rs:180-190,350-365,520-530`.
- Modify `src/remote/mod.rs:675-690`.
- Modify `src/remote/run.rs:118-130`.
- Modify `src/cli.rs:105-120,240-255`.
- Modify `src/capability.rs:760-820`.
- Test in `tests/mcp_tools.rs` and `tests/ssh_transport.rs`.

**Interfaces:**
- `RunShell` becomes `Bash | Sh | Login`.
- `RemoteRunRequest.shell` remains a concrete `RunShell`; the MCP deserializer supplies `RunShell::Bash` when the field is absent.
- `RunRequest.shell` remains `ShellRequest`, but the public remote-run path maps omitted input to `ShellRequest::Bash`; fixed POSIX bridge scripts use `ShellRequest::Sh` explicitly.
- `select_shell(&Capability, ShellRequest::Bash)` returns an error when Bash is absent; it never selects `sh` implicitly.

- [ ] **Step 1: Write failing API/schema tests.**

  Add assertions that `remote_run` advertises `enum: ["bash", "sh", "login"]`, has `default: "bash"`, rejects `"auto"`, and deserializes `{host, command}` to `RunShell::Bash`.

- [ ] **Step 2: Run the focused tests and verify failure.**

  Run `cargo test --test mcp_tools remote_run -- --nocapture`.
  Expected: failures mention the old `auto` enum/default and `RunShell::Auto`.

- [ ] **Step 3: Implement the smallest contract change.**

  Remove `Auto` from the public MCP/CLI enums, set the serde/clap default to `bash`, and make the mapper return:

  ```rust
  fn map_run_shell(shell: ToolRunShell) -> RunShell {
      match shell {
          ToolRunShell::Bash => RunShell::Bash,
          ToolRunShell::Sh => RunShell::Sh,
          ToolRunShell::Login => RunShell::Login,
      }
  }
  ```

  Keep the internal capability probe shell as POSIX `sh`; do not call it fallback behavior. Update errors to say “request `shell: \"sh\"` explicitly”.

- [ ] **Step 4: Run the focused tests and update all old test fixtures.**

  Run `cargo test --test mcp_tools --test ssh_transport -- --nocapture` and replace only public `auto` fixtures; retain internal probe cases only where they test the internal enum.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/mcp/tools.rs src/remote/mod.rs src/remote/run.rs src/cli.rs src/capability.rs tests/mcp_tools.rs tests/ssh_transport.rs
  git commit -m "fix: make remote shell selection explicit"
  ```

### Task 2: Add bounded request frames

**Files:**
- Create `src/ssh/frame.rs`.
- Modify `src/ssh/mod.rs`.
- Test in `tests/session.rs` and inline `#[cfg(test)]` module in `src/ssh/frame.rs`.

**Interfaces:**

  ```rust
  pub(crate) const FRAME_VERSION: u8 = 1;

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub(crate) enum FrameKind { Hello, HelloAck, Open, Data, Cancel, Close, Ready, Stdout, Stderr, Exit, Error }

  #[derive(Debug, Clone, PartialEq, Eq)]
  pub(crate) struct Frame { pub kind: FrameKind, pub request_id: u64, pub payload: Vec<u8> }

  pub(crate) async fn read_frame<R: AsyncBufRead + Unpin>(reader: &mut R, max_payload: usize) -> io::Result<Frame>;
  pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame, max_payload: usize) -> io::Result<()>;
  ```

  The wire format is an ASCII bounded header followed by an exact raw payload: `CXSB1 <kind> <request_id> <payload_bytes>\n<payload>`. The header is deliberately ASCII so a POSIX dispatcher can parse it without non-portable shell features; command/stdin/stdout/stderr payloads remain binary and are never placed in shell variables.

- [ ] **Step 1: Write failing frame tests.**

  Cover round trips for empty and binary payloads, fragmented reads, multiple frames in one read, zero-length payloads, request-id overflow, unknown kinds, header length overflow, payload length over `max_payload`, missing newline, and truncated payload EOF.

- [ ] **Step 2: Run `cargo test --lib ssh::frame` and verify failure.**

- [ ] **Step 3: Implement bounded parsing/writing.**

  Parse only ASCII decimal fields, reject leading signs, reject unknown frame kinds, enforce `max_payload` before allocation, and use `write_all` for header and payload. A malformed frame is a session-fatal protocol error, not a request-local error.

- [ ] **Step 4: Run the frame tests and a sanitizer-like bounded fuzz loop.**

  Run `cargo test --lib ssh::frame -- --nocapture` and `cargo test --test session frame_`.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/ssh/frame.rs src/ssh/mod.rs tests/session.rs
  git commit -m "feat: add bounded ssh session frames"
  ```

### Task 3: Implement and probe the POSIX dispatcher

**Files:**
- Create `src/ssh/dispatcher.rs`.
- Create `src/ssh/dispatcher.sh`.
- Modify `src/capability.rs`.
- Modify `tests/fixtures/fake-ssh.sh`.
- Create `tests/fixtures/fake-dispatcher.sh`.
- Test in `tests/session.rs`.

**Interfaces:**

  ```rust
  pub(crate) const DISPATCHER_PROTOCOL_VERSION: &str = "codex-ssh-dispatcher/1";
  pub(crate) const DISPATCHER_SCRIPT: &str = include_str!("dispatcher.sh");

  pub(crate) struct DispatcherHello { pub protocol: String, pub shell: String, pub root: String }
  pub(crate) fn dispatcher_command() -> &'static str;
  ```

  The dispatcher starts with `exec sh -s -- codex-ssh-dispatcher-1`, sends `HelloAck`, accepts independent `Open/Data/Cancel/Close` frames, and starts each user command in its own process group. It writes stdout/stderr to bounded per-request spool files, drains after the cap, and emits `Ready`, `Stdout`, `Stderr`, then `Exit` under an atomic `mkdir` output lock so concurrent completions cannot interleave.

- [ ] **Step 1: Write the dispatcher protocol tests.**

  Test handshake success, missing prerequisite reporting, two concurrent `printf` requests, binary stdout/stderr, stdin close, timeout cancellation, duplicate request IDs, and dispatcher EOF cleanup. The fixture must run under `/bin/sh` and must not require Bash for the dispatcher itself.

- [ ] **Step 2: Run `cargo test --test session dispatcher_` and verify failure.**

- [ ] **Step 3: Implement the script and capability probe.**

  Require and probe `sh`, `dd`, `mkdir`, `cat`, `wc`, `mkfifo`, `setsid`, and the existing safe `stat` path. Use temp files below the configured runtime directory, never interpolate command/stdin/output bytes into shell variables, and remove every request directory on exit. The script must distinguish `Bash unavailable` from transport failure.

- [ ] **Step 4: Run shell syntax and protocol tests.**

  Run `dash -n src/ssh/dispatcher.sh` (or `/bin/sh -n` when `dash` is absent), then `cargo test --test session dispatcher_ -- --nocapture`.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/ssh/dispatcher.rs src/ssh/dispatcher.sh src/capability.rs tests/fixtures/fake-ssh.sh tests/fixtures/fake-dispatcher.sh tests/session.rs
  git commit -m "feat: add bounded posix ssh dispatcher"
  ```

### Task 4: Add one persistent `HostSession` per alias

**Files:**
- Create `src/ssh/session.rs`.
- Modify `src/ssh/mod.rs` and `src/ssh/process.rs`.
- Test in `tests/session.rs` and `tests/ssh_transport.rs`.

**Interfaces:**

  ```rust
  pub(crate) struct SessionRequest {
      pub command: String,
      pub cwd: String,
      pub shell: ShellSelection,
      pub env: BTreeMap<String, Option<String>>,
      pub stdin: Option<Vec<u8>>,
      pub timeout: Duration,
      pub stdout_limit: u64,
      pub stderr_limit: u64,
  }

  pub(crate) struct SessionResult {
      pub request_id: u64,
      pub status: i32,
      pub stdout: Vec<u8>,
      pub stderr: Vec<u8>,
      pub stdout_truncated: bool,
      pub stderr_truncated: bool,
      pub elapsed_ms: u64,
      pub remote_process_may_continue: bool,
  }

  pub(crate) struct HostSession { /* private child, reader/writer tasks, registry */ }
  impl HostSession {
      pub(crate) async fn connect(policy: SshPolicy, host: String, limits: EffectiveLimits, cancel: CancellationToken) -> BridgeResult<Self>;
      pub(crate) async fn execute(&self, request: SessionRequest, cancel: CancellationToken) -> BridgeResult<SessionResult>;
      pub(crate) async fn close(&self) -> BridgeResult<()>;
  }
  ```

- [ ] **Step 1: Write failing session tests.**

  Verify one SSH child is spawned for three requests, request IDs are unique and connection-scoped, two long commands do not block each other, output remains associated with its ID, cancellation only stops the selected request, and a dispatcher startup error is returned without a one-shot retry.

- [ ] **Step 2: Run `cargo test --test session host_session_` and verify failure.**

- [ ] **Step 3: Implement session lifecycle.**

  `HostSession::connect` performs `ssh -T <alias> sh -s -- codex-ssh-dispatcher-1`, completes the handshake once, and starts one reader task plus one serialized writer task. The request registry maps `u64` IDs to oneshot completion channels and cancellation guards. A reader EOF marks every pending request as transport-unknown and removes the session from `SshRunner`; no request is silently retried.

- [ ] **Step 4: Implement bounded concurrency and cleanup.**

  Reuse the existing global/per-host semaphores only as capacity limits. Do not add a mutation lock. On request timeout/cancellation send `Cancel`, wait the configured grace period, then close the session if the dispatcher does not acknowledge termination. On `HostSession::close`, cancel all active requests and wait for the SSH child to exit.

- [ ] **Step 5: Run focused and existing transport tests.**

  Run `cargo test --test session --test ssh_transport -- --nocapture`.

- [ ] **Step 6: Commit.**

  ```bash
  git add src/ssh/session.rs src/ssh/process.rs src/ssh/mod.rs tests/session.rs tests/ssh_transport.rs
  git commit -m "feat: multiplex remote requests over persistent ssh"
  ```

### Task 5: Route all remote operations through the session

**Files:**
- Modify `src/ssh/process.rs:execute,execute_fixed,initialize_host,run_child`.
- Modify `src/remote/*.rs` only where a request needs the new session result fields.
- Test in `tests/remote_ops.rs`, `tests/real_ssh.rs`, and `tests/performance_acceptance.rs`.

**Interfaces:**

  `SshRunner` keeps its current public `execute` and fixed-operation methods. Internally it owns `Mutex<HashMap<String, Arc<HostSession>>>` and exposes no raw session handle to MCP. `initialize_host` performs capability initialization once per alias; later business commands use the cached policy and the same session without root-observation frames.

- [ ] **Step 1: Write failing integration tests.**

  Assert that a sequence of `remote_stat -> remote_read -> remote_run` uses one fake SSH process, that concurrent fixed operations complete independently, and that a changed OpenSSH identity or trusted root still fails before the business command.

- [ ] **Step 2: Run `cargo test --test remote_ops --test performance_acceptance -- --nocapture` and verify failure.**

- [ ] **Step 3: Replace per-call `build_ssh_argv` execution.**

  Keep capability probing as an explicit connection-time diagnostic, but submit business commands directly as `SessionRequest`s. The configured root remains a lexical routing boundary rather than a per-request physical-root trust guard. Preserve `OutputStore` provenance and all existing fixed-operation capability requirements.

- [ ] **Step 4: Handle session invalidation.**

  Remove a session after protocol error, SSH EOF, identity mismatch, or dispatcher capability failure. The next request may establish a fresh session only after returning the original error; never retry the failed mutation in the same call.

- [ ] **Step 5: Run the complete Rust test suite.**

  Run `cargo test --all-targets --all-features -- --nocapture`.

- [ ] **Step 6: Commit.**

  ```bash
  git add src/ssh/process.rs src/remote tests/remote_ops.rs tests/real_ssh.rs tests/performance_acceptance.rs
  git commit -m "refactor: run remote operations through host sessions"
  ```

### Task 6: Match MCP cancellation and result semantics

**Files:**
- Modify `src/mcp/tools.rs:RunArguments, tool schema, validation`.
- Modify `src/remote/mod.rs:RemoteRunRequest` and `src/remote/run.rs`.
- Modify `src/mcp/render.rs`.
- Test in `tests/mcp_tools.rs` and `tests/mcp_protocol.rs`.

**Interfaces:**

  Keep the public v0 request buffered and closed. Preserve per-stream cap flags, exit status, elapsed time, actual shell, and `remote_process_may_continue`. Per-request environment overrides are explicitly deferred: the current session request rejects non-empty environment metadata rather than silently dropping it.

- [ ] **Step 1: Write failing MCP tests.**

  Test omitted shell => Bash, explicit `sh` => POSIX warning with no silent fallback, Bash-missing => structured capability error, cancellation propagation, and binary output preview/base64 retention.

- [ ] **Step 2: Run `cargo test --test mcp_tools --test mcp_protocol -- --nocapture` and verify failure.**

- [ ] **Step 3: Implement request mapping and rendering.**

  Preserve current host/root/shell provenance fields. Add a warning only when the actual selected shell is explicitly `sh`; never set `fallback: true` for a user-requested `sh`. Render transport loss as an unknown-outcome error rather than a normal nonzero exit.

- [ ] **Step 4: Verify MCP framing and cancellation.**

  Run `cargo test --test mcp_tools --test mcp_protocol -- --nocapture` and then `cargo test --all-targets --all-features`.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/mcp/tools.rs src/mcp/render.rs src/remote/mod.rs src/remote/run.rs tests/mcp_tools.rs tests/mcp_protocol.rs
  git commit -m "feat: align remote run semantics with codex"
  ```

### Task 7: Update skill, security, performance, and acceptance documentation

**Files:**
- Modify `skills/remote-ssh-ops/SKILL.md` and `skills/remote-ssh-ops/references/operations.md`.
- Modify `README.md`, `docs/security.md`, and `docs/performance.md`.
- Test documentation snippets in `tests/packaging.rs` and `tests/cli.rs` where applicable.

- [ ] **Step 1: Write documentation assertions/checklist.**

  The skill must say: use configured aliases only; omitted `shell` means Bash; Bash errors require an explicit retry with `sh`; requests are concurrent; no mutation serialization is promised; cancellation/timeout may produce unknown remote state; persistent-session startup errors are fatal; SSHFS is human-only and never an Agent workspace.

- [ ] **Step 2: Update the documentation.**

  Document the one-session-per-host model, the dispatcher prerequisites, the five-host expected peak without a hard host limit, the first-connection versus steady-state latency, and the absence of remote Codex installation.

- [ ] **Step 3: Run packaging and documentation-related tests.**

  Run `cargo test --test packaging --test cli -- --nocapture` and `cargo fmt --check`.

- [ ] **Step 4: Commit.**

  ```bash
  git add README.md docs/security.md docs/performance.md skills/remote-ssh-ops tests/packaging.rs tests/cli.rs
  git commit -m "docs: describe persistent remote execution boundaries"
  ```

### Task 8: Final verification and performance comparison

**Files:**
- Modify `tests/performance_acceptance.rs` only if the measured assertions need the new session baseline.
- No production-file changes unless a verification failure identifies a concrete defect.

- [ ] **Step 1: Run formatting, lint, unit, integration, and release checks.**

  ```bash
  cargo fmt --check
  cargo test --all-targets --all-features -- --nocapture
  cargo clippy --all-targets --all-features -- -D warnings
  cargo build --release
  ```

- [ ] **Step 2: Run the deterministic latency acceptance test.**

  Verify the fake SSH transport spawns exactly one connection per host, the second and later requests do not perform SSH handshake/probe work, five hosts can each run independent requests, and one long request does not delay four short requests on the same host beyond the configured dispatcher/CPU capacity.

- [ ] **Step 3: Run a real configured-host smoke test when an alias is available.**

  Use `codex-ssh-bridge doctor <alias>` followed by bounded `remote_run` commands; record first-call and steady-state elapsed times, shell metadata, exit status, and cancellation behavior. Do not run destructive commands or retry a timed-out mutation.

- [ ] **Step 4: Apply the verification-before-completion checklist.**

  Confirm that the final report includes exact commands and outputs for formatting, tests, clippy, release build, dispatcher syntax, and the persistent-session acceptance test. Do not claim parity if any of these checks are missing.
