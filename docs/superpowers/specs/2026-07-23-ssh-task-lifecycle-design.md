# SSH Task Lifecycle Parity Design

## Goal

Make the SSH backend obey the same observable task-lifecycle contract as a
local Codex execution backend. The LLM and Codex app should see an ordinary
MCP tool task; SSH transport, a persistent dispatcher, and remote process
groups are implementation details of the backend.

This design addresses the failure mode where an abandoned or slow MCP call
holds a bridge-wide permit and causes unrelated calls to fail with
`Server busy`.

## Model

The system is modeled as three layers:

```text
LLM
  -> Codex app (MCP client, task owner, cancellation source)
  -> MCP tool backend (local or SSH)
```

MCP is a request protocol, not an execution-lifecycle policy. The SSH backend
must therefore implement the same task semantics as the local backend instead
of treating every MCP request as a permanently reserved server slot.

## Design decisions

### 1. MCP calls become task handles

`McpServer` validates a `tools/call`, creates a request-scoped cancellation
token, and registers a task. It no longer uses a global semaphore as the
operation admission gate. The task is either running or waiting in a bounded
pending queue; the `SshRunner` remains the authority for actual remote
execution limits.

The existing runner limits remain unchanged:

- global SSH execution concurrency stays configured by `limits.global_concurrency`;
- per-host SSH execution concurrency stays configured by
  `limits.per_host_concurrency`;
- runner admission waits cancellably for a slot instead of returning
  `Server busy`.

The MCP queue is bounded only to protect the local bridge from an untrusted or
misbehaving client. `Server busy` is permitted only when that pending queue is
full, and its error data must identify queue saturation rather than implying
that the remote host or SSH session is unavailable. Normal runner contention
must never produce `Server busy`.

### 2. Control queries have a separate lane

`remote_hosts` reads local configuration and cached capability metadata; it
does not probe SSH. It is admitted through a small control lane and is not
blocked by remote execution tasks. This keeps health/context discovery
available while a remote command is slow or being cancelled.

The control lane has the same request validation and cancellation bookkeeping,
but does not consume an SSH execution slot.

### 3. Cancellation is end-to-end

For a queued task, `notifications/cancelled` removes the task from the pending
queue and no backend work starts.

For a running task, the bridge cancels the task token and keeps the task entry
until the service future returns. The SSH session then sends its request-level
cancel frame, waits for the bounded cancel grace period, and shuts down the
host session if the dispatcher does not confirm termination. The execution
slot is released only after this cleanup path completes.

The bridge never fabricates a successful cancellation response for a mutation.
If the remote side may have applied a mutation, the existing unknown-outcome
result is preserved.

When the MCP transport reaches EOF, queued tasks are discarded and running
tasks are cancelled. The existing bounded server cleanup remains the final
transport-loss safeguard.

If the MCP client abandons a tool wrapper without sending cancellation while
keeping the transport open, the server cannot infer that abandonment from
MCP alone. This is a client-lifecycle limitation, not a reason to leak a
bridge-wide permit; the bridge must keep each task isolated and rely on the
configured operation deadline as the final fallback.

### 4. Persistent SSH remains an optimization

One persistent SSH dispatcher per configured alias remains the default. Each
request gets an independent dispatcher request ID and remote process group.
The MCP-visible task does not expose the SSH connection, request ID, or remote
shell process.

If request cancellation cannot be confirmed within the session grace period,
the host session is closed and recreated on the next request. A failed session
must not hold a task entry or prevent calls for other aliases from being
scheduled.

### 5. Completion ordering and response suppression

Task completion removes the task registry entry before the response is queued
to the MCP writer. A cancelled task suppresses its normal response, matching
the current cancellation behavior, but still releases all task and runner
resources first.

Completion handling is idempotent with respect to a late cancellation
notification. A cancellation that arrives after task removal does not affect a
completed response.

## Request flow

1. Parse and validate the MCP frame.
2. Classify the call as control (`remote_hosts`) or remote execution.
3. Create a task entry and cancellation token.
4. Admit control calls immediately; enqueue remote calls unless the bounded
   pending queue is full.
5. Spawn the service future. The future waits cancellably on the existing
   `SshRunner` limits and then uses the persistent SSH session.
6. On cancellation, run the backend cleanup path and retain mutation
   uncertainty where applicable.
7. Remove the task entry, release backend resources, and enqueue a response only
   when the task was not cancelled by the client.

## Error contract

- `Server busy` means only that the local MCP pending queue is full.
- Runner contention is represented by normal task latency, not an error.
- SSH connection failure, remote timeout, remote exit, capability failure, and
  cancellation retain their existing structured error codes and remote
  provenance.
- A transport loss after a mutation has started retains the existing
  `mutation_outcome_unknown` semantics and is never automatically retried.
- Remote output remains untrusted data and is never used to alter task state.

## Safety and performance

The change removes a duplicate MCP operation limiter; it does not remove any
remote execution limit, frame bound, output quota, path validation, expected
hash check, atomic-write rule, shell selection rule, or host allowlist.

Warm requests still use one persistent SSH request frame. Queue bookkeeping is
local Rust state and must not add an SSH round trip. `remote_hosts` remains
local-only and should complete even while remote operations are queued or
being cancelled.

## Verification plan

The implementation must add deterministic tests before production changes:

1. A call beyond runner capacity is queued rather than returning `Server busy`.
2. A queued call cancelled before dispatch never reaches the fake SSH backend.
3. A running cancellation releases the runner slot before the next queued call
   starts.
4. A slow call on one alias does not prevent a control query or an available
   alias from being admitted.
5. EOF cancels queued and running calls and leaves the server usable after a
   fresh MCP connection.
6. A late cancellation after completion does not suppress an already prepared
   response.
7. A cancelled mutation preserves unknown-outcome reporting.
8. The existing persistent-session, output-limit, timeout, capability, path,
   shell, and mutation tests remain green.

The native Codex-app integration path must also be exercised manually with a
long-running remote command: cancel it from the app, then issue a second
remote call and verify that the second call does not receive `Server busy`.

## Alternatives rejected

1. **Keep the MCP semaphore and increase its limit.** This masks stale task
   ownership and preserves a duplicate scheduler.
2. **Keep fail-fast admission but add retries in the Agent.** This makes the
   model reconstruct backend state and can duplicate mutations.
3. **Use one SSH process per request.** This simplifies transport cleanup but
   discards the persistent-session performance work and changes warm latency.

## Non-goals

- Reimplementing Codex's private app internals.
- Changing remote shell defaults, root semantics, or mutation safety rules.
- Making a disconnected remote mutation automatically safe to retry.
- Exposing SSH sessions, remote paths, or process IDs as persistent local files.
