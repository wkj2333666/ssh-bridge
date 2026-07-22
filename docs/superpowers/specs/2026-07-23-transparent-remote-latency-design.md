# Transparent Remote Execution Latency Design

## Goal

Make the default SSH bridge behave like local Codex for trusted remote servers:
keep the persistent SSH dispatcher and structured remote tools, but do not pay a
per-request round trip to defend against rare remote mount or symlink retargeting.

## Decision

The configured remote root is a trusted working-directory boundary, not a
per-request physical-identity pin. A bridge process performs the normal
capability probe when a host session is first initialized, then submits later
requests through the persistent dispatcher without a separate `root observation`
request and without an in-command physical-root guard in the default mode.

This matches the local Codex trust model: the local process and filesystem are
trusted execution authority, while ordinary file conflicts are handled by
path-safe operations, expected hashes, and atomic replacement where applicable.

## Behavior boundaries

### Remote root and paths

- `host.profile.root` remains the configured remote working-directory boundary.
- Relative paths are still normalized and rejected when they are lexically
  outside that configured root.
- Remote symlink, bind-mount, overlay, and directory replacement behavior follows
  normal remote filesystem semantics, just as local Codex follows local
  filesystem semantics.
- The bridge does not synthesize a root-drift error merely because the physical
  target behind the configured path changed.
- The connection-time capability probe may continue to report physical-root
  metadata for diagnostics, but that metadata is not a per-request authorization
  condition.

### Requests and mutations

- `remote_run`, `remote_write`, `remote_apply_patch`, and guarded delete keep
  their existing command, path, expected-hash, atomicity, and partial-progress
  semantics.
- Mutation results are not automatically retried. A timeout, cancellation, or
  transport loss after dispatch still reports the existing outcome-unknown
  state.
- A changed remote root is not treated as a special preflight mutation conflict;
  the remote command may succeed or fail according to the resulting filesystem
  state.
- Read operations keep their current bounded output, pagination, and untrusted
  remote-data treatment. They no longer need to perform a separate physical-root
  observation before the business request.

### Transport and shell behavior

- One persistent SSH dispatcher remains the default per configured alias.
- Capability initialization remains cached per configured host and is retried
  only through the existing capability/session invalidation paths.
- Bash/sh/login selection, request concurrency, cancellation, output quotas,
  retained output, and MCP framing are unchanged.
- The local OpenSSH alias and credential policy remain local execution authority;
  this change does not permit arbitrary SSH options or hostnames.

### Timing contract

- Existing `elapsed_ms` compatibility is preserved while its meaning is
  documented as bridge operation time, not remote CPU or disk time.
- In a warm persistent session, bridge work is expected to approach the cost of
  one request-frame encode/decode and local bookkeeping; it must not add a
  second SSH round trip or a per-request root probe. The dominant steady-state
  terms should therefore be network propagation and remote command execution.
- Rust-side timing instrumentation must report enough phase data to distinguish
  local bridge bookkeeping, SSH/session transport, and remote command timing in
  benchmarks. It must not require a Python helper or make the Agent assemble
  these phases itself.
- Implementation timing instrumentation may expose phase data for diagnostics,
  but it must not change command output or make the Agent reconstruct transport
  behavior.

## Alternatives rejected

1. **Mutation-only root-observation removal.** This saves one request for writes
   but keeps a remote-only physical-root policy for reads, so the default still
   diverges from local Codex and keeps avoidable latency on every read.
2. **Strict root pinning as the default.** This preserves the strongest remote
   deployment defense but protects against rare administrator/container changes
   that are not in scope for the trusted-server product model.
3. **SSHFS or a long-lived remote shell exposed to the Agent.** These obscure the
   remote/local boundary or weaken per-request cancellation and output limits.

## Error and security consequences

- Removing physical-root pinning does not remove lexical path validation,
  expected-content hashes, atomic writes, output bounds, shell selection, host
  allowlisting, or cancellation uncertainty.
- A remote server remains trusted execution authority for its own filesystem;
  remote command output remains untrusted prompt data.
- If a future deployment needs physical-root pinning, it should be an explicit
  strict-host policy with its own latency and error contract rather than an
  implicit default.

## Verification

- Add deterministic persistent-fixture assertions that normal warm requests do
  not submit `CODEX_SSH_ROOT_OBSERVE` or root-guard wrappers.
- Update root-retarget tests to assert ordinary filesystem semantics rather than
  synthetic root-drift failures.
- Preserve tests for expected-hash conflicts, path traversal rejection,
  cancellation uncertainty, capability invalidation, and session transport loss.
- Run the full library, remote operation, MCP, packaging, real-SSH, clippy,
  release-build, and performance acceptance suites.
- Compare first-request and warm-request timings before and after the change;
  report bridge bookkeeping, SSH/session transport, and remote command inner
  timing separately. The warm-request acceptance check must show no extra
  `CODEX_SSH_ROOT_OBSERVE` frame and no material bridge-only work beyond frame
  handling and local bookkeeping.
