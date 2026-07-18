# Codex SSH Bridge Rust Redesign

Date: 2026-07-18

Status: Approved in conversation; written-spec review pending

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

- `config`: TOML parsing, safe-default validation, permissions, limits, and exact alias lookup.
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

Internal scripts prefer `bash --noprofile --norc` and use a strict POSIX sh implementation only where the probed operations remain safe. Unsafe functionality, especially file replacement, must return `REMOTE_CAPABILITY_MISSING` rather than silently downgrade.

`remote_run` defaults to `shell=auto`, selecting non-profile Bash when present and POSIX sh otherwise. It supports explicit `bash`, `sh`, and `login` modes. Every command result identifies the actual shell, version when available, and whether fallback occurred. When sh is selected, results warn against Bash-only arrays, `[[ ]]`, `source`, `pipefail`, and Bash substitutions. An explicit Bash request fails before execution if Bash is missing.

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

The MCP stdin loop validates and dispatches requests without waiting for tool completion. Each request ID owns a Tokio task, cancellation token, and local SSH process group. MCP cancellation kills that process group and returns a typed cancelled result. A bounded worker/semaphore model prevents unbounded task creation.

Timeouts use both a local deadline and probed GNU `timeout` where command semantics permit. Closing an SSH channel normally terminates the remote foreground command, but a deliberately daemonized process may survive. Results expose `remote_process_may_continue=true` whenever termination cannot be proven.

Output policy:

- Keep small stdout/stderr in memory.
- Above 256 KiB, spool concurrently into private mode-`0600` files below a mode-`0700` runtime directory.
- Return bounded head/tail previews, byte counts, truncation flags, and an opaque short-lived `output_ref`.
- Default hard aggregate command-output limit is 64 MiB; crossing it cancels the command.
- Spool tokens are random, scoped to the running process, expire after ten minutes, and never accept a caller-provided path.
- A response carries payload bytes only once. Structured content contains metadata, not a duplicate of textual output.

Default protocol limits are an 8 MiB JSON-RPC frame, 256 KiB file chunk, 1 MiB maximum file-read chunk, and 4 MiB patch/write body. Compiled ceilings prevent configuration from making limits unbounded.

## 12. Protocol and Error Model

The MCP server implements a strict JSON-RPC 2.0 state machine for initialization, initialized notification, ping, tool listing, tool calls, cancellation, and orderly shutdown. It validates protocol version, request/notification shape, ID type, method parameters, lifecycle state, tool schemas, and unknown fields. Bounded newline framing rejects an oversized message before JSON parsing.

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
- Strict JSON-RPC/MCP lifecycle and error codes.

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
