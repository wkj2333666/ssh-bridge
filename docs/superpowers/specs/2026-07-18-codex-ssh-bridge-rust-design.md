# Codex SSH Bridge Rust Redesign

Date: 2026-07-18

Status: Approved; strict MCP security/performance review incorporated

## 1. Purpose

Build a production-ready local Codex plugin that lets Codex operate allowlisted SSH servers without installing or authenticating Codex on those servers. Only the current Debian ARM64 machine runs the bridge. Remote machines are Linux servers with `sshd` and common userland tools.

The installed runtime must not depend on Python. It is a single optimized Rust binary plus plugin metadata, a Skill, configuration, and documentation. System OpenSSH remains the transport so all present and future `~/.ssh/config` behavior continues to work, including `Include`, `Match`, `ProxyJump`, ssh-agent, hardware-backed keys, and `ProxyCommand` where the user has configured it.

## 2. Success Criteria

The finished system must:

1. Keep Codex, the MCP process, SSH credentials, agent sockets, and output caches on the local host.
2. Install no executable or persistent helper on a remote server.
3. Expose high-level remote read, search, patch, write, and command tools so the Agent expresses intent rather than SSH mechanics.
4. Reuse system OpenSSH configuration exactly while overriding only explicit safety properties.
5. Detect remote Bash and utility capabilities automatically. It must tell the Agent which shell interprets `remote_run` commands because Bash and POSIX sh have different semantics.
6. Make SSHFS an explicit human CLI feature only. It must not be registered as an MCP tool or presented as a local Agent workspace.
7. Bound concurrency, request frames, retained output, wire responses, memory use, and execution time.
8. Process MCP cancellation while SSH work is active and terminate the associated local process group promptly.
9. Prevent the predictable-temporary-file symlink overwrite demonstrated against the Python prototype.
10. Use strict JSON-RPC/MCP lifecycle validation and never duplicate large payloads in both textual and structured response fields.
11. Pass the security, protocol, concurrency, shell-escaping, and performance acceptance tests in this document.

## 3. Scope and Trust Boundary

### 3.1 In scope

- A local stdio MCP server.
- A local human CLI for configuration, diagnosis, direct commands, installation, and SSHFS lifecycle.
- Exact allowlisting of SSH aliases with per-alias remote root, read-only mode, and resource limits.
- Remote file discovery, reads, searches, patches, safe creates/replacements, and arbitrary shell commands.
- Local connection multiplexing through a dedicated OpenSSH ControlMaster namespace.
- A Codex Skill and plugin manifest.

### 3.2 Out of scope

- Installing Codex, Rust, an agent, or a daemon remotely.
- Treating a lexical remote root as a security sandbox.
- Inferring that an arbitrary shell command is read-only.
- Guaranteeing termination of a command that deliberately daemonizes and detaches on the remote server.
- Making multi-file patch replacement transactionally atomic across files.
- Windows or macOS as the local bridge host.

Remote account permissions are the hard security boundary. File roots constrain normal tool operation, but symlinks and arbitrary `remote_run` commands can reach anything accessible to that SSH account. High-value servers should use a dedicated least-privilege account.

## 4. Architecture

The project builds one binary, `codex-ssh-bridge`, backed by a library crate. It has these entry modes:

- `mcp`: asynchronous JSON-RPC/MCP server over stdin/stdout.
- `hosts`: list, add, remove, and inspect allowlisted profiles.
- `doctor`: human-oriented SSH/config/capability diagnostics.
- `run`: human direct execution through the same core transport.
- `mount`, `unmount`, `mount-status`: explicit SSHFS operations unavailable to MCP.
- `install --user` and `uninstall --user`: preflight and transactionally add or remove the MCP entry and Skill for local Codex. Both default to dry-run mode.

The library uses focused modules:

- `config`: TOML parsing, safe-default validation, permissions, limits, exact
  alias lookup, and the shared 65,536-byte configured/physical-root ceiling.
- `quote`: the only POSIX remote-shell word encoder.
- `capability`: automatic Bash/Linux utility probing and per-process caching.
- `ssh`: hardened OpenSSH argv construction, ControlMaster lifecycle, Tokio child handling, cancellation, and error classification.
- `output`: bounded in-memory previews, private spool files, pagination tokens, and TTL cleanup.
- `remote`: path resolution, list/stat/read/search/write, and patch orchestration.
- `patch`: parse and apply the supported patch format locally before a guarded remote write.
- `mcp`: strict protocol state machine, schemas, annotations, and result rendering.
- `cli`: human commands and dry-run/apply installation behavior.

No local operation is invoked through a shell. Rust starts `/usr/bin/ssh`, `/usr/bin/sshfs`, and unmount helpers with `std::process::Command`/`tokio::process::Command` argument arrays.

## 5. Configuration

The default configuration is `${XDG_CONFIG_HOME:-~/.config}/codex-ssh-bridge/config.toml`, required to be a regular file owned by the current user and not writable by group or others. Environment overrides are accepted only as explicit trusted local execution-authority input and are called out in diagnostics.

Each host profile contains:

- `alias`: an exact, non-option-looking OpenSSH Host alias.
- `root`: an absolute Linux path.
- `description`: optional human context.
- `read_only`: whether all arbitrary command and write tools are disabled.
- optional overrides for timeout, response, file, spool, and concurrency limits within compiled hard ceilings.

The file stores no password, private-key path, agent socket, hostname, username, ProxyJump route, or host key. These remain in OpenSSH configuration. Adding a server requires configuring and manually verifying its SSH alias, then running `codex-ssh-bridge hosts add <alias> --root <path>`.

## 6. OpenSSH Transport and Hardening

Every connection uses system OpenSSH and therefore consumes normal user configuration. The bridge adds command-line safety settings that cannot be relaxed per host:

- `BatchMode=yes`
- `StrictHostKeyChecking=yes`
- `ForwardAgent=no`
- `ForwardX11=no`
- `ClearAllForwardings=yes`
- `PermitLocalCommand=no`
- `RequestTTY=no`
- bounded connect timeout and server-alive settings

Disabling agent forwarding does not disable using the local agent for authentication. `ProxyJump`, `ProxyCommand`, `IdentityFile`, `IdentityAgent`, certificates, and hardware keys continue to work. The user's SSH config is trusted local authority; a configured `ProxyCommand` can execute local programs by design.

The bridge owns a directory below `${XDG_RUNTIME_DIR}` with mode `0700` and a dedicated hashed ControlPath. When `XDG_RUNTIME_DIR` is unavailable, it creates and validates `/tmp/codex-ssh-bridge-<uid>` as a non-symlink directory owned by the current user with mode `0700`. Its master sessions use `ControlMaster=auto` and `ControlPersist=300`. This prevents reuse of an externally created permissive master while amortizing handshake and authentication cost. The first capability probe establishes the reusable session.

Global concurrency defaults to eight tasks and per-host concurrency to two tasks. Both are hard-bounded. The expected peak is five hosts.

## 7. Capability and Shell Model

The first operation on a host runs a fixed, noninteractive probe. It verifies the configured root with `cd` and records the physical working directory. It detects at least:

- Bash and its version.
- POSIX sh.
- `mktemp`, `dd` with no-follow support, `sha256sum`, `stat`, `find`, `grep`, `rg`, `timeout`, `ln`, and `mv` behaviors needed by the bridge.

Probe output uses a fixed, versioned key/value format and is never evaluated. Results are cached in memory for the MCP process. A capability-related execution failure invalidates the entry and triggers one reprobe before returning a final error.

`config` exports `MAX_REMOTE_CONTEXT_ROOT_BYTES=65_536`. Configured normalized
roots and probed physical `ROOT` values are both rejected above that UTF-8 byte
length; exact/+1 and non-ASCII byte-bound tests cover both admission points.
MCP imports this bridge constant rather than redeclaring it.

`capability` likewise exports and enforces
`MAX_SHELL_VERSION_BYTES=256` on probed Bash versions before caching or
constructing result/error context. Exact/+1, non-ASCII UTF-8 byte boundaries,
and malicious fake-Bash records are tested. MCP imports this shared bound for
its real maximum-response counting fixture.

Internal scripts prefer `bash --noprofile --norc` and use a strict POSIX sh implementation only where the probed operations remain safe. Unsafe functionality, especially file replacement, must return `REMOTE_CAPABILITY_MISSING` rather than silently downgrade.

`remote_run` defaults to `shell=auto`, selecting non-profile Bash when present and POSIX sh otherwise. It supports explicit `bash`, `sh`, and `login` modes. Every command result identifies the actual shell, version when available, and whether fallback occurred. When sh is selected, successes and later errors carry an actionable warning against Bash-only arrays, `[[ ]]`, `source`, `pipefail`, and Bash substitutions: use POSIX syntax, or request Bash and ensure it is installed. An explicit Bash request fails before execution if Bash is missing.

## 8. MCP Tool Interface

All tools use a `remote_` prefix. Every result labels the SSH host and remote physical root so remote data cannot be mistaken for local workspace state.

### 8.1 Read-only tools

- `remote_hosts()`: configured hosts, roots, permission mode, and cached shell status without forcing network access.
- `remote_list(host, path=".", depth, include_hidden, max_entries)`: bounded directory listing.
- `remote_stat(host, paths[])`: batched metadata.
- `remote_search(host, query, path=".", globs[], max_results)`: bridge-selected `rg` or safe fallback.
- `remote_read(host, paths[], start_line, max_lines, max_bytes)`: batched text/binary reads with version hashes and truncation metadata.
- `remote_output_read(output_ref, stream, offset, max_bytes)`: page a short-lived locally spooled command result.

### 8.2 Mutating tools

- `remote_apply_patch(host, patch)`: parse standard multi-file unified diff locally, read and validate all bases, apply in memory, then perform per-file guarded atomic replacement. Paths use `--- a/<relative-path>` and `+++ b/<relative-path>`; `/dev/null` denotes create/delete. Text create, update, and delete hunks are supported; rename-only and binary patches are rejected. All files are validated before the first write. If a later write fails, the response lists exactly which files changed; it never claims cross-file atomicity.
- `remote_write(host, path, content, encoding, mode)`: create or replace a complete file with optional expected version.
- `remote_run(host, command, cwd=".", shell="auto", timeout_ms, stdin)`: arbitrary remote shell execution.

Read-only profiles expose read tools but reject all mutating tools server-side. `remote_run` is always mutating/destructive because the bridge cannot infer shell effects. MCP annotations describe read-only/destructive and open-world behavior, but enforcement is in the bridge rather than annotations.

The normal Skill workflow is `remote_search/read -> remote_apply_patch -> remote_run`. Capability probing, path quoting, hashing, chunking, conflict checks, temporary files, timeouts, and error interpretation are bridge responsibilities rather than Agent steps.

## 9. Quoting and Data Transfer Invariants

OpenSSH does not provide a true remote argv transport: remote command arguments are joined into a command string and parsed by the remote login shell. The bridge therefore treats the remote boundary as a shell protocol.

There is one audited POSIX word encoder. It single-quotes every word and encodes embedded single quotes with the standard close/quoted-quote/reopen sequence. It supports empty strings, spaces, newlines, Unicode, backslashes, glob characters, dollar signs, backticks, command-substitution text, and leading hyphens. NUL is rejected.

Internal command text is a compile-time fixed script. Untrusted paths, hashes, modes, queries, and other values are passed as encoded positional parameters. Commands use `--` before operands where supported. No untrusted value is interpolated into script source.

File bytes and command stdin are streamed through SSH stdin and never embedded into shell source. Raw file bytes return through SSH stdout and are encoded locally only when required by MCP. The only intentional shell program is `remote_run.command`; `cwd`, shell selection, environment, and stdin remain separate validated fields.

## 10. Remote Paths and Safe Writes

Relative paths resolve lexically beneath the configured root; absolute tool paths must remain beneath that root. The bridge rejects `..` traversal and invalid NUL data. Probe results provide the physical root used in responses. This is an operational guard, not confinement against filesystem symlinks or `remote_run`.

Safe writes use a fixed remote script:

1. Verify and enter the target parent beneath the configured root.
2. Set `umask 077` and create an unpredictable same-directory temporary regular file with `mktemp`.
3. Stream bytes with a probed no-follow open so replacement of the temporary pathname by a symlink cannot redirect the write.
4. Verify type, owner, size, and optional SHA-256.
5. For create-only mode, use a same-filesystem hard link to install the target atomically without replacing an existing directory entry, then unlink the temporary name.
6. For replace mode, perform a same-directory atomic rename. If an expected version was supplied, check it immediately before replacement and return `WRITE_CONFLICT` on mismatch.
7. Clean the temporary file on all normal error and signal paths.

The Bridge does not claim that shell utilities can provide a perfect compare-and-swap against a malicious same-account process. A same-account attacker already shares the SSH security boundary. Tests must prove that a different user able to create names in a shared directory cannot use a temporary symlink to overwrite an arbitrary file through the bridge.

## 11. Asynchrony, Cancellation, Timeouts, and Output

The MCP stdin loop validates and dispatches requests without waiting for tool completion. Each request ID owns a Tokio task, cancellation token, and local SSH process group. A valid client `notifications/cancelled` kills that process group and suppresses the request's MCP response; direct Rust/CLI callers and non-client cancellation may still observe a typed cancelled error. Initialize instructions warn that a cancelled mutation may have partially or unknowably applied and must be inspected rather than blindly retried. A bounded worker/semaphore model prevents unbounded task creation.

Timeouts use both a local deadline and probed GNU `timeout` where command semantics permit. Closing an SSH channel normally terminates the remote foreground command, but a deliberately daemonized process may survive. Results expose `remote_process_may_continue=true` whenever termination cannot be proven.

Output policy:

- Keep small stdout/stderr in memory.
- Above 256 KiB, spool concurrently into private mode-`0600` files below a mode-`0700` runtime directory.
- Return bounded head/tail previews, byte counts, truncation flags, and an opaque short-lived `output_ref`.
- Default hard aggregate command-output limit is 64 MiB; crossing it cancels the command.
- Spool tokens are random, scoped to the running process, expire after ten minutes, and never accept a caller-provided path.
- A response carries payload bytes only once. The single text block is compact JSON containing remote/host/root/shell context plus bulk; structured content repeats only small metadata, never bulk.
- Every bulk tool (hosts/list/stat/search/read/output-read/run) degrades to a compact wire-budget fallback. Hosts/list/stat/search/read retain omitted canonical detail behind an opaque pageable reference; output-read keeps its reference but recomputes raw-byte offsets from the page actually returned; run keeps or creates a reference. A completed mutation can never be rewritten as an internal error because its full rendering overflowed: compact fallbacks preserve applied/partial/unknown truth, counts, and an opaque detail reference owned by the bridge.

Retained output has typed provenance: either `Remote(RemoteContext)` or
`Aggregate { kind, source_count }`. `remote_hosts` uses aggregate provenance
and may contain any configured host count; five is a concurrency expectation,
not a list cap. Aggregate output pages omit rather than fabricate a single
host/root/shell. The bridge's generic `retain_serialized_detail<T: Serialize +
Send + 'static>` facade serializes an owned value directly into a bounded
private spool, offloading blocking work as needed, without first materializing
a second large byte vector or JSON value. Retention remains best-effort:
failure preserves context/count/truncation or mutation truth with
`detail_retained=false` and no new reference.

The direct spool imports crate-root `MAX_OUTPUT_BYTES=64 MiB` as a hard ceiling
on serialized canonical bytes. Its counting/capped writer accepts exact limit
and rejects the first +1 byte. Overflow, cancellation, serialization failure,
or admission failure produces no reference and removes the temporary spool.
`Limits` exposes `global_spool_quota_bytes` (default 512 MiB, compiled maximum
512 MiB) and `retention_serialization_jobs` (default two, compiled maximum
four). Its compiled minimum is 64 MiB; configuration must remain in the
inclusive `[64 MiB, 512 MiB]` range. The global quota covers committed plus temporary bytes for command,
fixed-command internal capture, and retention spools. Command/internal writers
reserve only each actual next chunk; partial/failed writes release or roll it
back, and both streams share the ledger. This makes exact quota succeed, the
next racing byte fail, and light calls avoid theoretical-max rejection. On a
fresh store, five maximum outputs (320 MiB) plus two default retention
reservations (128 MiB) consume 448 MiB and leave 64 MiB of the default quota.
MCP bootstrap reads both validated values before moving the loaded config and
passes them explicitly to `OutputStore::with_limits`; neither field may fall
back to an internal default or remain an unconsumed configuration value.

Detail retention first `try_acquire`s its two/four job semaphore, then a spool
entry slot, then a full 64 MiB quota reservation before `spawn_blocking`; a miss
returns false/no-ref without serialization CPU. The capped serializer checks
cancel at least every 64 KiB, is always joined rather than detached, and commit
shrinks its reservation to actual bytes. Compiled `MAX_SPOOL_ENTRIES=1024`
bounds pending plus committed entries, each to at most two files, so empty files
cannot evade the byte quota. Command/internal saturation is typed
`OUTPUT_LIMIT`; retention saturation is false/no-ref.

Cleanup releases byte charges and the slot only after unlink succeeds or
returns `NotFound`. Other unlink errors retain charge plus a retry tombstone;
expiry/removal/shutdown follow the same rule and never release first. Thus disk
is bounded by 512 MiB default/hard and files by 2,048, independently of
inflight calls. Tests cover quota/slot/job exact saturation, two-file limits,
partial writes, the fresh-store 5-command-plus-2-retention combination,
exact/+1 payload, 64 KiB cancellation, awaited joins,
unlink-failure retry, TTL/shutdown, and zero premature ledger/slot release.

Under the entry lock, output paging checks expiry and synchronously opens a new
independent handle for the selected private pathname; only after open succeeds
does it create the ref-counted byte/entry lease and release the lock. There is
no lease-before-open window, no committed-entry FD, and no cloned shared file
cursor. TTL/discard that wins the lock removes and unlinks the entry so a later
read returns expired; a reader that wins can finish from its independent handle
while charge and slot remain pinned until its final lease closes. Tests force
both lock orders, the former lease-before-open window, 1,024 committed entries
without 2,048 resident FDs, concurrent different-offset pages, and last-reader
release.

Default protocol limits are an 8 MiB JSON-RPC frame, 256 KiB file chunk, 1 MiB maximum file-read chunk, and 4 MiB patch/write body. Compiled ceilings prevent configuration from making limits unbounded.

## 12. Protocol and Error Model

The MCP server implements a strict JSON-RPC 2.0 state machine for versions `2025-11-25` and `2025-06-18`, initialization, initialized notification, ping, tool listing, tool calls, cancellation, and orderly shutdown. Ping is valid after initialize while awaiting initialized and in Ready. Supported versions validate their requested `clientInfo` schema (`name/title/version` for 2025-06-18; those plus `icons/description/websiteUrl` for 2025-11-25). An unsupported version validates the bounded current 2025-11 union before the server selects the latest version; latest-only fields are accepted there, but fields outside the union are rejected. For initialize/ping/initialized/list/call/cancelled, negotiated 2025-06 accepts bounded additional top-level params, discards them, and never reflects them; negotiated 2025-11 uses the official closed method fields while retaining open object `_meta`. Tool `arguments` and nested tagged inputs remain closed in both versions, and an unnegotiated `task` field is rejected. A two-version golden matrix covers all six methods and proves invalid notifications have no state/cancellation effect. URI/string bounds, request/notification shape, ID type/size, lifecycle state, and tool schemas are validated. Client capabilities remain open objects.

Malformed `tools/call` envelopes and unknown tool names return JSON-RPC `-32602`. Once a known tool is selected, argument-schema failures return a normal `CallToolResult` with `isError=true` and actionable compact-JSON text, without invoking the bridge. Bridge errors also use compact-JSON text containing every available remote/host/root/shell and safe warning/error field; structured content repeats only small metadata. Strict parsing rejects duplicate keys and enforces depth, node/member, and aggregate-key-byte budgets before allocation; a shared marker distinguishes `DuplicateKey`, `StructuralBudget`, and genuine `Syntax`, while duplicate checks reuse the destination JSON map rather than cloning keys into a second set. Bounded newline framing rejects an oversized message before JSON parsing.

Every accepted tool future receives `ToolCallContext { cancel, wire_budget }`; the exact token goes to the bridge and the exact budget goes to validation/success/error rendering. `max_frame_bytes` excludes the newline delimiter. A compiled 1 MiB `MIN_MCP_FRAME_BYTES` is statically checked against the shared 65,536-byte root ceiling times a conservative thirteen-byte combined expansion: root occurs in inner Text JSON which is escaped again by outer MCP JSON, and once directly in structured context. The reserve also covers a maximum 256-byte wire ID and 64 KiB fixed response overhead. Error rendering derives a context-free `RenderedErrorCore` from `BridgeError`; Text carries context once and the structured top level carries it once, while nested `structuredContent.error.details` excludes host/root/shell. The authoritative counting test starts from a real maximum `ErrorDetails` with maximum root/shell and bounded safe strings, projects it, and proves only those two root contexts exist and fit. Server construction also counts the trusted full nine-tool list and uses the largest requirement. Exact minimum succeeds and minimum-minus-one is rejected without root truncation. Response renderers reserve envelope/ID/fallback but not newline. The writer is only a capped final serializer. It never replaces a completed mutation result with `-32603`.

`required_mcp_frame_bytes` and `WireBudget::for_response` take fallback bytes
for the serialized `result` value only, excluding JSON-RPC envelope, request ID,
and newline. The 1 MiB constant is a complete-frame floor and is never supplied
as that argument. Task 5 passes zero until real tool-result rendering exists;
Task 7 replaces it with the counting-serialized real largest fallback result.
`McpServer` stores this one result-only count; construction and every per-ID
`WireBudget::for_response` consume the same field, with an equality/propagation
test preventing budget drift.
Task 4 owns only the generic counting and test-only worst-size projection;
Task 5 owns server/lifecycle exact-min tests, and Task 7 owns real renderer and
all bulk/mutation fallback assertions. The worst projection uses an absolute
control-heavy maximum root, control-heavy maximum shell version, and the worst
legal alternating quote/backslash safe strings.

All bulk tools—not only read/run—have compact fallbacks. Hosts/list/stat/search/read retain omitted canonical detail behind a bridge-owned logical-stdout ref, and run preserves or creates a ref. Output-read preserves its reference, but after wire shrink sets `next_offset = offset + actual_inline_raw_bytes` and derives EOF from that actual raw position; UTF-8 and Base64 offsets are always stored raw bytes. Multi-page reassembly tests prove no gap or overlap. `remote_hosts` has no five-entry hard limit; five is only expected concurrent peak. Retention is best-effort: read-only failure preserves context/count/truncation with `detail_retained=false`, mutation failure preserves truth/counts, and neither becomes `-32603`. Successful retention returns the true/ref pair. MCP never accesses output-store internals.

Stable bridge error codes include:

- `HOST_KEY_UNKNOWN`
- `AUTH_REQUIRED`
- `CONNECT_TIMEOUT`
- `REMOTE_CAPABILITY_MISSING`
- `PATH_OUTSIDE_ROOT`
- `READ_ONLY_HOST`
- `WRITE_CONFLICT`
- `OUTPUT_LIMIT`
- `REQUEST_TOO_LARGE`
- `PROTOCOL_ERROR`
- `CANCELLED`
- `REMOTE_EXIT`

Errors include a safe summary, retryability, host, operation, elapsed time, remote exit status when available, and a concise suggested action. Normal MCP results do not expose verbose SSH diagnostics. Human `doctor` may run SSH diagnostics with an explicit flag and must redact obvious credentials, agent socket paths, and sensitive command data before display.

`ErrorDetails.physical_root: Option<String>` carries the bounded safe root once
capability discovery has supplied it; pre-probe errors omit it. A shared
non-overwriting `attach_available_remote_context` helper is used by transport
errors and by remote facade/parser boundaries that create domain/protocol errors
after an exit-zero fixed child (including read/snapshot/write conflict/patch).
Bridge-error Text JSON and structured metadata expose the root when available
without changing the original code, retryability, or mutation progress.

The safe wire projection bounds message and suggested action to 1,024 UTF-8
bytes each and warnings to at most 16 entries of 1,024 bytes. Truncation occurs
only at UTF-8 boundaries. Before or during truncation, every Unicode
`char::is_control()` is normalized to one ASCII `?`; quotes, backslashes,
ordinary Unicode, and other non-control characters are preserved. The
projection sets `message_truncated` or `warnings_truncated`; code, context,
shell, truth, counts, and progress are never truncated. Authoritative worst-case
tests use alternating quote/backslash bytes for every maximum safe field;
Task 4's test-only projection is replaced by the real sanitizer/projection in
Task 7.
Renderers construct `RenderedErrorCore`, Text, and structured metadata directly
rather than serializing a complete `BridgeError` and deleting or cloning
fields.

## 13. SSHFS Policy

SSHFS is optional and human-only. `mount`, `unmount`, and `mount-status` require explicit local paths and never appear in MCP schemas or Skill workflows. The mount command applies relevant SSH hardening, connection keepalives, and reconnect behavior. Read-only host profiles force `-o ro`. It refuses a nonempty mountpoint unless the human supplies an explicit override and clearly reports the semantic and disconnect limitations of FUSE/SFTP.

## 14. Testing Strategy

Implementation follows red-green-refactor TDD. No Python is used by the runtime, installer, benchmarks, or test fixtures.

Unit and property tests cover:

- Shell word encoding across at least 100,000 generated hostile cases.
- Configuration, ownership/mode checks, limits, alias validation, and path normalization.
- Probe parsing, Bash/sh selection, cache invalidation, and warning metadata.
- Patch parsing/application and expected-version conflicts.
- Output budgeting, spooling, token validation/expiry, and single-copy serialization.
- Strict JSON-RPC/MCP lifecycle, version-specific client shapes, open `_meta`,
  structural JSON budgets, known-tool validation-result semantics, and error codes.

Integration tests use a controllable fake SSH executable and, when available, a real local OpenSSH `sshd` fixture. They cover:

- Exact SSH argv and ControlMaster safety policy.
- ProxyJump-compatible delegation to system OpenSSH.
- Read-only enforcement including forced read-only SSHFS.
- Timeout, cancellation, process-group cleanup, disconnects, and five-way concurrency.
- Bash availability and POSIX sh fallback.
- Paths containing quotes, newlines, wildcard text, leading hyphens, and command-substitution syntax.
- Temporary symlink attacks, dangling target symlinks, no-clobber creates, overwrite conflicts, and cleanup.
- Malformed requests, pre-initialize calls, oversized frames, serializer amplification, and hostile output.

The real-SSH suite is skipped only with a visible reason when local privileges or facilities genuinely cannot provide an `sshd`; its absence cannot be reported as a pass.

## 15. Performance Acceptance

Release builds use thin LTO, one codegen unit, symbol stripping, and unwind-on-panic so process and spool cleanup guards still run. On the current Debian ARM64 host:

- Bridge dispatch overhead excluding SSH/network has p95 below 2 ms.
- A complete fake-SSH tool call has p95 below 10 ms.
- Five concurrent one-second commands complete within 1.5 seconds.
- Cancellation terminates the local SSH process within 250 ms.
- Processing 64 MiB hostile output increases RSS by less than 16 MiB above idle.
- Parsing maximum-budget wide JSON arrays and objects in separate fresh release
  child processes increases peak RSS by less than 48 MiB over each child's
  idle/warmed baseline; Task 11 repeats the final measurements and records raw
  baseline, peak, and delta so allocator retention and parallel-test noise
  cannot contaminate the result.
- Any MCP response remains within configured response bounds and never exhibits multiplicative payload duplication.

Benchmarks report raw values and fail the acceptance harness when these host-specific targets regress.

## 16. Packaging and Installation

The release artifact contains:

- The stripped ARM64 `codex-ssh-bridge` binary.
- `.codex-plugin/plugin.json` and `.mcp.json` launching that binary in `mcp` mode.
- `skills/remote-ssh-ops/SKILL.md`, minimal agent metadata, and concise operational reference.
- A TOML example, installation/uninstallation instructions, security model, troubleshooting, and benchmark report.

`install --user` and `uninstall --user` default to a dry run. Apply mode preflights every destination, refuses to overwrite unrelated MCP or Skill entries, uses atomic local file replacement, invokes Codex registration with timeouts, and rolls back changes it made if a later step fails. It must not silently treat every nonzero Codex CLI result as “not installed.” Uninstall removes only entries whose resolved target and recorded installation identity match this bridge.

The Python prototype is excluded from the installed chain. After the Rust implementation and acceptance suite pass, it moves intact beneath `legacy/python-prototype/` for audit reference.

## 17. Delivery Sequence

1. Commit this approved specification.
2. Produce a task-by-task implementation plan with explicit tests before code changes.
3. Build quoting/config/path primitives with TDD.
4. Build async OpenSSH transport, capability probing, cancellation, and output spooling with TDD.
5. Build high-level remote file/patch/run operations with adversarial write tests.
6. Build strict MCP and human CLI.
7. Update plugin, Skill, documentation, and installer.
8. Run unit, property, integration, security, and performance acceptance.
9. Move the Python prototype to `legacy/` only after the Rust chain is verified.
10. Install locally with explicit approval for writes outside the workspace and run an end-to-end Codex/MCP smoke test.
