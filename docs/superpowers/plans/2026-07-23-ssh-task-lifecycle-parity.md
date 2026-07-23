# SSH Task Lifecycle Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. This plan is executed inline in the current session; do not dispatch subagents.

**Goal:** Make the external SSH backend expose local-Codex-like MCP task lifecycle semantics: normal runner contention waits, cancellation propagates, and one stale task cannot make unrelated calls fail with `Server busy`.

**Architecture:** Keep `SshRunner` as the sole remote execution limiter. Remove the MCP operation semaphore's fail-fast admission behavior and replace it with a bounded task-admission window derived from the existing global concurrency setting. Accepted MCP calls remain individually tracked while their service futures either execute or wait cancellably inside `SshRunner`; `remote_hosts` uses a separate control lane that is not blocked by remote work.

**Tech Stack:** Rust 2024, Tokio `JoinSet`, `CancellationToken`, existing MCP stdio framing, existing persistent SSH dispatcher, Rust integration tests and the fake SSH fixture. No Python, no remote helper installation, and no new runtime dependency.

## Global Constraints

- The MCP server remains local-only; no Codex binary, MCP server, API key, or helper is installed remotely.
- `limits.global_concurrency` and `limits.per_host_concurrency` remain the only remote execution capacity limits.
- Runner contention waits cancellably; it is not surfaced as `Server busy`.
- MCP task admission remains bounded. The default pending window is `max_inflight + 8`, where `max_inflight` is the existing constructor/configuration value; `remote_hosts` is exempt from this remote-task window.
- `Server busy` means only that the local MCP task window is full. Its message must say `MCP task queue full`.
- Every accepted call owns one cancellation token and one task-registry entry until its service future has completed or has been forcibly reaped during transport shutdown.
- A cancelled mutation keeps the existing unknown-outcome semantics and is never automatically retried.
- Persistent SSH request IDs, remote process groups, and session restarts remain invisible to the MCP caller.
- Existing frame-size, output-quota, path, expected-hash, shell, capability, and host-allowlist rules remain unchanged.

## File Map

- Modify `src/mcp/mod.rs`: replace fail-fast semaphore admission with bounded task admission, add the control-lane classifier, and preserve completion/cancellation cleanup.
- Modify `src/mcp/protocol.rs`: change the capacity error message to `MCP task queue full` and keep the stable `-32000` code.
- Modify `src/main.rs`: keep passing configured global concurrency to `McpServer`; add a comment documenting that the constructor derives the pending window.
- Modify `tests/mcp_protocol.rs`: replace old permit-saturation expectations with queue admission, queue-full, control-lane, cancellation, completion-race, and EOF cleanup assertions.
- Modify `tests/mcp_tools.rs` only if constructor or public error-shape fixtures require synchronized updates.
- Modify `tests/ssh_transport.rs`: retain and extend the existing cancellable runner-wait test so an MCP task waiting inside `SshRunner` cannot claim a remote process continued.
- Modify `README.md`, `docs/performance.md`, `docs/security.md`, `skills/remote-ssh-ops/SKILL.md`, and `skills/remote-ssh-ops/references/operations.md`: document that runner contention queues, only a full local task window returns `MCP task queue full`, and native client cancellation is required when a client abandons an open MCP connection.

---

### Task 1: Define the new MCP lifecycle with failing tests

**Files:**
- Modify: `tests/mcp_protocol.rs:1537-1610` (old saturation tests).
- Modify: `tests/mcp_protocol.rs` near `StubTools` and lifecycle helpers.
- Modify: `tests/mcp_protocol.rs` response-constructor assertions.

**Interfaces:**
- The existing `McpServer::new(service, frame_bytes, max_inflight)` signature remains; its third argument still represents configured remote concurrency and now derives the MCP pending window as `max_inflight + 8`.
- A normal `tools/call` beyond remote runner capacity is accepted and remains cancellable while the service waits inside the runner.
- `remote_hosts` is represented by a test service definition named exactly `remote_hosts` and is accepted even when the remote-task window is occupied.

- [ ] **Step 1: Write the failing queue-admission test.** Replace the old bound-one busy assertion with a test that starts one blocked call, sends a second blocked call, waits for two service polls, and asserts that no `-32000` response is produced. Release both gates and assert both responses arrive.

  ```rust
  #[tokio::test]
  async fn task8_runner_contention_is_not_mcp_server_busy() {
      let tools = Arc::new(StubTools::new());
      let mut session = Session::start(
          McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES, 1).unwrap(),
      ).await;
      session.ready().await;
      for id in ["first", "second"] {
          session.send(&json!({
              "jsonrpc":"2.0", "id":id, "method":"tools/call",
              "params":{"name":"block","arguments":{}}
          })).await;
      }
      tools.wait_for_polls(2).await;
      assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 2);
      tools.release.add_permits(2);
      let mut ids = [session.recv().await["id"].clone(), session.recv().await["id"].clone()];
      ids.sort_by_key(|id| id.to_string());
      assert_eq!(ids, [json!("first"), json!("second")]);
      assert!(session.close().await.is_ok());
  }
  ```

- [ ] **Step 2: Run the focused test and verify the intended RED failure.**

  Run: `cargo test --test mcp_protocol task8_runner_contention_is_not_mcp_server_busy -- --nocapture`

  Expected: FAIL because the current semaphore has one permit and the second call returns `-32000` before `StubTools::call` is entered.

- [ ] **Step 3: Add the bounded-window failure test.** With `max_inflight = 1`, send nine blocked calls (the new window is nine) and a tenth known call. Assert the tenth response is `{"code":-32000,"message":"MCP task queue full"}` and exactly nine service calls were admitted. This preserves a finite local memory bound while distinguishing queue saturation from runner contention.

- [ ] **Step 4: Add the control-lane failure test.** Add a small `ControlStubTools` service with `block` and `remote_hosts` definitions. Occupy the remote window with a blocked call, send `remote_hosts`, and assert the control result arrives without waiting for the blocked call.

- [ ] **Step 5: Add cancellation and completion-race assertions.** Extend the existing cancellation matrix so a call admitted while the runner is full receives a cancellation notification, observes a cancelled context, and never increments the fake backend-start counter. Keep the existing late-cancellation test and assert a completion already removed from the registry still returns its response.

- [ ] **Step 6: Run the focused tests again and record the expected failures.**

  Run: `cargo test --test mcp_protocol task8_ -- --nocapture`

  Expected: all newly added tests fail only at the old semaphore admission or old error message, not during protocol setup.

- [ ] **Step 7: Commit the RED tests.**

  ```bash
  git add tests/mcp_protocol.rs
  git commit -m "test: define MCP task lifecycle parity"
  ```

### Task 2: Replace fail-fast MCP permits with bounded task admission

**Files:**
- Modify: `src/mcp/mod.rs:18-132,168-260,300-498`.
- Modify: `src/mcp/protocol.rs:251-253`.
- Modify: `src/main.rs:46-63`.
- Test: `tests/mcp_protocol.rs` from Task 1.

**Interfaces:**
- `InFlight` stores only `cancel` and `cancelled_by_client`; remove `OwnedSemaphorePermit`.
- `McpServer` stores `max_pending: usize` and derives it in `new` as `max_inflight.checked_add(8)`, rejecting overflow with the existing invalid-bound error.
- `process_control_frame` receives `max_pending` instead of an `Arc<Semaphore>`.
- The existing `server_busy_response(id)` function keeps code `-32000` but serializes message `MCP task queue full`.
- Add a private classifier:

  ```rust
  const CONTROL_TOOL_REMOTE_HOSTS: &str = "remote_hosts";

  fn is_control_tool(name: &str) -> bool {
      name == CONTROL_TOOL_REMOTE_HOSTS
  }
  ```

- [ ] **Step 1: Implement the smallest admission change.** Remove `OwnedSemaphorePermit` and the MCP `Semaphore` allocation. In the `tools/call` branch, after tool-name validation and before creating the task:

  ```rust
  if !is_control_tool(name) && active.len() >= self.max_pending {
      return Some(server_busy_response(id));
  }
  ```

  Keep duplicate-ID validation before this capacity check. Create and insert `InFlight` exactly once, then spawn the service future as before. The service future is allowed to wait cancellably inside `SshRunner::acquire_operation`.

- [ ] **Step 2: Preserve completion-before-response ordering.** Keep `process_completion` removing `active` and `task_ids` before serializing/enqueuing the response. Add a short comment that removal is the task-capacity release point; do not release capacity from the writer loop.

- [ ] **Step 3: Make the control lane exempt from remote-task admission.** Apply the classifier only to the capacity check. Control calls still get an `InFlight` entry and a cancellation token, so EOF cleanup and late-cancellation behavior remain uniform. Do not add a second SSH or process semaphore.

- [ ] **Step 4: Update server channel sizing and constructor validation.** Use `self.max_pending + 8` for the writer channel capacity. Keep the configured `max_inflight` validation at `1..=32`; validate the derived `max_pending` for overflow before constructing the server.

- [ ] **Step 5: Change the stable error message and update the main wiring comment.** `server_busy_response` must return:

  ```json
  {"jsonrpc":"2.0","id":<id>,"error":{"code":-32000,"message":"MCP task queue full"}}
  ```

  `run_mcp` continues passing `loaded.config.limits.global_concurrency`; the constructor owns the `+8` pending-window policy so CLI/config behavior remains backward compatible.

- [ ] **Step 6: Run the focused tests and verify GREEN.**

  Run: `cargo fmt --all && cargo test --test mcp_protocol task8_ -- --nocapture`

  Expected: queue admission, bounded saturation, control-lane, cancellation, and completion-race tests pass. Existing protocol tests that assert the old message or permit saturation must be updated in Task 3, not weakened.

- [ ] **Step 7: Commit the MCP scheduler change.**

  ```bash
  git add src/mcp/mod.rs src/mcp/protocol.rs src/main.rs tests/mcp_protocol.rs
  git commit -m "fix: queue MCP tasks instead of failing on runner contention"
  ```

### Task 3: Migrate the existing MCP lifecycle matrix

**Files:**
- Modify: `tests/mcp_protocol.rs` all tests whose names or comments refer to permits, in-flight saturation, or the old `Server busy` message.
- Modify: `tests/mcp_tools.rs` constructor/error-shape fixtures if the changed response message affects frame-budget assertions.

**Interfaces:**
- Duplicate request IDs remain rejected before capacity admission.
- Invalid request shapes remain side-effect-free even when the task window is full.
- A completion frees a task slot before a later request with the same ID is accepted.
- EOF, writer failure, panic, partial EOF, and cancellation notification behavior remain unchanged except for removal of permit-specific assertions.

- [ ] **Step 1: Update saturation names and expectations.** Rename `task7_inflight_rejects_duplicate_before_shape_and_saturation` to describe duplicate validation plus queue admission. Keep the duplicate-ID and invalid-ID assertions; replace the second known call's immediate busy assertion with a successful admission and a gate release.

- [ ] **Step 2: Update the bound-two test.** Replace `task7_inflight_third_unique_known_call_is_busy_at_bound_two` with a test that sends three calls at `max_inflight = 2`, observes all three service calls, and releases all three. Add a separate queue-full test at the derived pending limit so the fail-safe is still covered.

- [ ] **Step 3: Update response-budget fixtures.** Keep `server_busy_response` in the fixed-response budget matrix, update its expected message, and confirm `required_mcp_frame_bytes` still accepts the minimum frame budget. If the assertion fails, add a dedicated serialized queue-full response size to the required-frame calculation rather than increasing the global minimum.

- [ ] **Step 4: Remove permit-specific source assertions.** Delete tests that inspect `_permit` or infer cleanup solely from semaphore state. Replace them with task-registry behavior: a completed call can reuse its request ID, a cancelled call is absent after its future completes, and a queued runner wait observes cancellation before fake SSH dispatch.

- [ ] **Step 5: Run the complete MCP test targets.**

  Run: `cargo test --test mcp_protocol --test mcp_tools -- --nocapture`

  Expected: all protocol and tool-schema tests pass with no remaining references to an MCP operation permit or the old `Server busy` message.

- [ ] **Step 6: Commit the lifecycle-matrix migration.**

  ```bash
  git add tests/mcp_protocol.rs tests/mcp_tools.rs
  git commit -m "test: migrate MCP lifecycle assertions to task semantics"
  ```

### Task 4: Verify the runner and persistent-session cancellation boundary

**Files:**
- Modify: `tests/ssh_transport.rs:3065-3120`.
- Modify: `src/ssh/process.rs` only if a failing integration test reveals a runner cleanup defect.
- Test: existing `src/ssh/session.rs` and `tests/ssh_transport.rs` cancellation suites.

**Interfaces:**
- `SshRunner::acquire_operation` remains the sole execution limiter and continues to wait with `CancellationToken`.
- A task cancelled while waiting for a per-host slot returns `ErrorCode::Cancelled` with `remote_process_may_continue == Some(false)` and does not spawn a second SSH request.
- A running task cancellation still sends a dispatcher cancel frame and closes the host session when termination is not confirmed.

- [ ] **Step 1: Extend the existing queued-cancellation fixture.** Add a fake SSH invocation counter and assert that after the first request owns the single per-host slot, cancelling the second request leaves the counter at one. Keep the existing assertion that the queued cancellation cannot claim a remote process continued.

- [ ] **Step 2: Add the running-cancellation release test.** Start a first sleep request, start a second request that waits for the slot, cancel the first, and assert the second either starts after the session cleanup or returns a definite transport/cancellation error; it must never receive MCP `Server busy` because MCP is no longer the execution limiter.

- [ ] **Step 3: Run focused transport tests.**

  Run: `cargo test --test ssh_transport queued_cancellation -- --nocapture && cargo test --lib ssh::session -- --nocapture`

  Expected: queued cancellation stays definite, session cancellation remains within the existing grace bound, and no extra SSH request appears after cancellation.

- [ ] **Step 4: Commit the transport-boundary verification.**

  ```bash
  git add tests/ssh_transport.rs src/ssh/process.rs
  git commit -m "test: verify runner cancellation releases remote capacity"
  ```

### Task 5: Document the new observable contract

**Files:**
- Modify: `README.md:150-160`.
- Modify: `docs/performance.md` concurrency and cancellation sections.
- Modify: `docs/security.md` cancellation/transport sections.
- Modify: `skills/remote-ssh-ops/SKILL.md:38-50`.
- Modify: `skills/remote-ssh-ops/references/operations.md:65-75`.

**Interfaces:**
- Documentation says remote calls may wait in the local bridge while `SshRunner` capacity is occupied.
- Documentation says `MCP task queue full` is a local admission failure, distinct from SSH/remote errors.
- Documentation says an MCP client must send cancellation when abandoning an open call; if cancellation cannot be confirmed, the existing mutation-unknown rules apply.
- Documentation keeps the one-session-per-alias, independent request, output bound, shell, path, and mutation guarantees.

- [ ] **Step 1: Update the README behavior paragraph.** Replace wording that suggests the MCP server rejects work at configured execution capacity with wording that distinguishes local task admission from runner execution capacity.

- [ ] **Step 2: Update performance notes.** State that queue bookkeeping is local Rust work, warm requests still use one persistent request frame, and benchmark results must distinguish queue wait, SSH/session transport, and remote command execution.

- [ ] **Step 3: Update security/skill references.** Preserve cancellation uncertainty and no-blind-retry rules; add that queue saturation is not evidence of remote host failure and that `remote_hosts` remains available for local cached context.

- [ ] **Step 4: Run documentation consistency checks.**

  Run: `rg -n "Server busy|in-flight permit|fail-fast|queue full|runner contention" README.md docs skills src tests`

  Expected: only the new `MCP task queue full` contract and intentional protocol-test references remain.

- [ ] **Step 5: Commit the documentation update.**

  ```bash
  git add README.md docs/performance.md docs/security.md skills/remote-ssh-ops/SKILL.md skills/remote-ssh-ops/references/operations.md
  git commit -m "docs: describe MCP task queue and runner contention"
  ```

### Task 6: Full verification and native-app smoke test

**Files:**
- No production files; update `docs/performance.md` only if measured values need a factual correction.

- [ ] **Step 1: Run formatting, unit, integration, and lint checks.**

  ```bash
  cargo fmt --all -- --check
  cargo test --workspace --all-targets
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  ```

  Expected: all existing tests and the new task-lifecycle tests pass without warnings.

- [ ] **Step 2: Run release and SSH transport verification.**

  ```bash
  cargo test --release --test mcp_protocol --test mcp_tools --test ssh_transport -- --nocapture
  cargo build --release
  ```

  Expected: the release bridge builds and the persistent-session, output, timeout, cancellation, and queue tests pass.

- [ ] **Step 3: Exercise the native Codex-app MCP path manually.** Start a bounded long-running `remote_run` on a disposable command, cancel it from the Codex app (not by terminating an outer shell wait), then call `remote_hosts` and a harmless short `remote_run`. Record whether cancellation reaches the bridge and whether the second call avoids `MCP task queue full`.

- [ ] **Step 4: Inspect the final diff and status.**

  Run: `git diff HEAD~6..HEAD --stat && git status --short`

  Expected: only the lifecycle implementation, tests, and documentation are present; no generated binaries, Python helpers, credentials, or remote artifacts are committed.

- [ ] **Step 5: Report verification evidence.** Include exact test commands, pass/fail counts, release-build result, native-app cancellation observation, and any remaining limitation: an MCP server cannot detect an abandoned open connection unless the client sends cancellation or closes the transport.
