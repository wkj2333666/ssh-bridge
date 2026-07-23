# Persistent Remote Helper Design

## Goal

Keep the Rust helper binary on each supported remote host so that the bridge
does not upload it on every new SSH session, while preserving the current
per-host session reuse and shell fallback behavior. The optimization must add
no work to a warm request.

## Confirmed behavior boundaries

- A bridge/MCP process owns one reusable `HostSession` per host.
- A `HostSession` contains one SSH child process and one remote dispatcher or
  helper process. Individual commands are logical request IDs multiplexed over
  that stream.
- The SSH/helper process ends when the bridge exits, the SSH transport closes,
  the protocol becomes invalid, or the session is explicitly shut down. A
  command completing does not close the session.
- The helper executable is persistent on the remote filesystem, but its
  process is not a daemon. It is started only for the current SSH session and
  exits with that session.
- Installation, validation, and fallback decisions happen only while creating
  a cold `HostSession`.
- Once a `HostSession` is established, `HostSession::execute` and its framed
  request path are unchanged. No warm request performs a remote `stat`, hash,
  lock operation, upload, or extra SSH call.
- The MCP tool schemas and model-visible shell semantics remain unchanged.

## Non-goals

- Do not install a system service, daemon, port listener, shell startup hook,
  or `PATH` entry on the remote host.
- Do not install Codex, Rust, Python, or a package manager on the remote host.
- Do not compile the helper remotely.
- Do not delete remote helper versions automatically.
- Do not silently retry a request after a helper has accepted it.
- Do not add a per-request capability probe or remote filesystem check.

## Architecture

The local bridge remains the SSH policy owner. During cold connection setup it
selects a release helper artifact from the existing architecture mapping and
starts one SSH command containing an installation-aware bootstrap. The
bootstrap uses a versioned, architecture-specific path under the authenticated
remote user's home directory. It reports whether a matching executable is
already present. If it is missing or invalid, the bridge sends the helper bytes
over the same SSH stdin, the bootstrap validates and atomically installs them,
and then `exec`s the fixed path. If the file is already valid, no helper bytes
are sent and the bootstrap immediately `exec`s it. In both cases the first
post-install output is the normal helper handshake.

The local session reader consumes the bootstrap status line before parsing the
binary helper handshake. This status is part of cold setup only and never
appears on a warm request stream. A pre-request installation or handshake
failure closes the attempt and may fall back to the existing shell dispatcher.
After the first request frame has been accepted, transport failures retain the
existing unknown-outcome behavior and are not retried through another shell.

## Remote layout and identity

The installation root is resolved with remote shell tilde expansion and must
resolve to an absolute directory owned by the authenticated account:

`VERSION` and `TARGET` below are literal path components derived from the
running bridge package and selected release target:

```text
~/.local/share/codex-ssh-bridge/helpers/VERSION/TARGET/helper
```

For example, the x86_64 helper for bridge version `0.2.5` is stored at:

```text
~/.local/share/codex-ssh-bridge/helpers/0.2.5/x86_64-unknown-linux-musl/helper
```

The bridge version is the package version embedded in the running bridge, not
the MCP protocol version. The helper target is the exact release target chosen
from `uname -m`. Each version/target directory is immutable from the bridge's
point of view: an upgrade creates a new directory instead of replacing a
helper used by another session.

The root and helper directories use mode `0700`; the executable uses mode
`0700`. The bootstrap never adds the directory to `PATH` and never edits shell
startup files. A temporary upload uses a unique name inside the target
directory and is committed with an atomic rename. A failed transfer can leave
only an untrusted temporary file; it can never make a partial file the active
helper.

## Cold installation negotiation

The SSH command starts a fixed, shell-quoted bootstrap with the following
arguments: protocol tag, maximum frame size, bridge version, target name,
expected helper length, expected SHA-256, and the quoted destination path.
Uploaded bytes are never interpolated into shell text.

The bootstrap performs these steps:

1. Validate numeric arguments, the protocol tag, the absolute destination,
   and the destination's parent ownership/mode.
2. Create the version/target directory if needed with mode `0700`.
3. Acquire an advisory installation lock with atomic `mkdir`. A second cold
   connector waits for a bounded interval for a valid target; if the lock is
   stale or the wait expires, it uses its own temporary path and the same
   atomic-rename rule rather than blocking a host indefinitely.
4. If the destination is a regular executable with mode `0700`, the expected
   byte length, and the expected SHA-256, print exactly:

   ```text
   CXSB-INSTALL-1 HIT\n
   ```

   and `exec` the destination.
5. Otherwise print exactly:

   ```text
   CXSB-INSTALL-1 NEED\n
   ```

   Read exactly the advertised number of bytes from stdin, write them to a
   mode-`0700` temporary file, verify length and SHA-256, atomically rename the
   file to the destination, release the lock, and `exec` the destination.
6. On any installation error, emit a bounded diagnostic on stderr and exit
   before the helper can accept a request. The local bridge may then try the
   existing temporary helper path once and finally the shell dispatcher.

The local bridge writes helper bytes only after receiving `NEED`. It writes no
bytes after `HIT`, so an already-installed helper produces no binary upload.
The bootstrap status line is read with a bounded line parser and must match
the expected tag exactly; any other output is a cold startup failure.

## Fallback and capability behavior

The existing architecture mapping remains the fast-path selector:

| Remote `uname -m` | Helper target |
|---|---|
| `x86_64` | `x86_64-unknown-linux-musl` |
| `aarch64` | `aarch64-unknown-linux-musl` |
| `armv7l`, `armv7` | `armv7-unknown-linux-musleabihf` |
| `riscv64` | `riscv64gc-unknown-linux-gnu` |
| `ppc64le` | `powerpc64le-unknown-linux-gnu` |
| `s390x` | `s390x-unknown-linux-gnu` |

Unsupported architecture, non-Linux, missing local artifact, unsafe local
artifact permissions, missing remote home, missing remote install
capabilities, installation failure, `Exec format error`, EOF before helper
handshake, or helper protocol mismatch all occur before a request is accepted
and therefore may select a fallback.

Fallback order is explicit and observable:

1. Persistent helper (`helper_mode=persistent`);
2. Existing per-session temporary helper (`helper_mode=temporary`);
3. Existing POSIX shell dispatcher (`helper_mode=shell`).

If the temporary path or shell path is selected, the tool result includes the
selected mode and a bounded reason. A successful Bash request still reports
`shell.kind=bash`; helper mode is transport metadata, not a change to the
requested shell. If a helper has already accepted a request, its failure is a
transport failure and is not retried through a different mode.

## Concurrency and lifecycle

The existing local `session_initializers` map serializes cold connection setup
for a host inside one bridge process. Thus concurrent first requests share the
same installation result. Across separate bridge processes, the remote
installation `mkdir` lock prevents two processes from committing partial data;
all committed candidates are content-addressed by the expected version,
target, length, and hash. Lock waiting is bounded and never blocks warm
requests because warm requests do not enter installation code.

The installed executable remains after SSH and bridge shutdown. The running
helper receives `CLOSE` during normal session shutdown and is terminated with
the SSH process group on abnormal transport failure. A new bridge process
revalidates the persistent file during its cold connection and reuses it when
the identity matches. Old version directories remain available for explicit
future cleanup and are never removed as part of normal connection handling.

## Security boundaries

- All remote installation happens under the configured SSH account; no
  privilege escalation is attempted.
- Destination and temporary paths are constructed by the fixed bootstrap and
  shell-quoted arguments. Helper bytes are read as exact-length binary data,
  never evaluated as shell code.
- The bridge accepts only its own regular, executable local artifact and
  computes the expected length and SHA-256 before connecting.
- Remote destination directories and files must be private (`0700`) and under
  the account's home. A symlink or group/other-writable destination is not
  accepted as a persistent helper.
- A failed or interrupted upload cannot replace the active helper because the
  final rename is atomic and occurs only after validation.
- The helper receives only the request data already authorized for that host;
  it receives no local credentials or environment secrets.
- Diagnostics expose mode and phase, not helper bytes, credentials, command
  contents, or local filesystem secrets.

## Observability and performance

Cold profile events distinguish `session_connect`, `helper_install_probe`,
`helper_install_upload`, and `helper_handshake`. The existing helper request
events (`helper_frame_write`, `helper_command_spawn`, `helper_output_drain`,
and `helper_exit`) remain unchanged. The profile is opt-in and diagnostic;
its file writes must not be used as a latency gate.

Acceptance measurements report separately:

- cold connection with a first-time installation;
- cold connection reusing an installed helper;
- warm helper request on an existing session;
- warm shell fallback request on the same fixture.

The warm helper request must have the same frame construction, queueing,
remote process launch, output drain, and result parsing path as before. Any
regression in warm request latency is a release blocker even if cold setup is
faster.

## Testing and acceptance

Unit and integration tests must cover:

- bootstrap status parsing for `HIT` and `NEED`;
- exact binary upload with NUL/newline/invalid UTF-8 bytes;
- persistent path construction, mode/owner checks, and hash/length mismatch;
- atomic install after interrupted or short uploads;
- reuse of an installed helper without a second upload;
- bridge restart reusing the same remote file;
- concurrent cold connectors with one committed result;
- architecture mapping and unsupported-host fallback;
- temporary-helper and shell fallback diagnostics;
- unchanged multiplexed warm-request behavior and request IDs;
- helper handshake, streams, output limits, cancellation, and process-group
  cleanup from the existing helper suite.

Release CI must package the helper matrix already defined by the release
workflow. A local test fixture should emulate the persistent directory and
record whether the second connection received zero helper bytes. Real-host
verification on `nkai` should report the installed path, mode, target, hash,
and selected `helper_mode` without printing the binary contents.

## Migration

The first bridge version containing this design finds no persistent file and
performs one cold installation. Existing temporary helper sessions continue to
work during upgrade because the shell fallback and temporary upload paths are
retained. No remote cleanup is required for correctness. The README and
operator documentation must explain the persistent location, the explicit
cleanup command, and how to inspect the selected helper mode.
