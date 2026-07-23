# Remote Binary Helper and Fast Dispatcher Design

## Goal

Use a small precompiled Rust helper on supported remote Linux machines to
remove the per-request POSIX-shell dispatcher overhead, while preserving the
existing shell dispatcher as a complete compatibility fallback.

## Non-goals

- Do not install Codex, Rust, Python, or a persistent package on the remote
  machine.
- Do not compile Rust or C/C++ source on a remote machine automatically.
- Do not change the MCP tool schemas or the Agent-visible shell semantics.
- Do not silently retry a request after a helper has accepted it.

## Architecture

The local bridge remains the MCP server and SSH policy owner. During
connection initialization, the existing capability probe also reports the
remote kernel architecture (`uname -m`). The bridge maps that value to a
known helper artifact. If the artifact is available, it starts one SSH command
that receives an exact-length helper upload, writes it into a private
per-session directory, and `exec`s the helper while preserving stdin/stdout.
The helper then speaks the existing `CXSB1` framed protocol for the lifetime of
the SSH session. If architecture detection, helper lookup, upload, execution,
or the startup handshake fails before any request is accepted, the bridge
closes that attempt and starts the existing shell dispatcher. The fallback is
reported in connection diagnostics and never hidden from the model.

The helper is a separate Rust binary with a minimal standard-library runtime.
It does not depend on Tokio or the local bridge executable. It reads framed
requests from stdin, launches the selected remote command shell directly with
`Command`, puts each child into its own process group, drains stdout/stderr
concurrently through pipes, applies the configured byte limits while draining,
and serializes output/exit frames through one writer. Request workers are
independent so one long command does not block other hosts or requests within
the configured capacity.

The helper keeps the existing request and result frame meanings, but omits the
unused `READY` success frame on the new path. The local reader remains
backward-compatible with `READY` from the shell dispatcher during migration.
`OPEN` metadata and `DATA` payloads are still length-delimited; the helper may
retain those bounded request bytes in memory rather than staging them through
remote files. No request output is written to a remote spool file on the
normal helper path.

## Artifact and compatibility matrix

The release package contains one main bridge binary for each published Linux
target plus a `remote-helpers/` directory containing the complete helper
matrix. The x86_64, aarch64, and armv7 helpers are statically linked with
musl. The riscv64, ppc64le, and s390x helpers use the cross toolchain's GNU
targets because the pinned cross release does not provide the corresponding
musl images; if a remote loader or libc cannot run one of those helpers, the
bridge falls back to the shell dispatcher before accepting a request. All
artifacts are compiled without `target-cpu=native`.

The published main targets are:

| Main package target |
|---|
| `x86_64-unknown-linux-gnu` |
| `aarch64-unknown-linux-gnu` |
| `armv7-unknown-linux-gnueabihf` |
| `x86_64-unknown-linux-musl` |
| `aarch64-unknown-linux-musl` |
| `riscv64gc-unknown-linux-gnu` |
| `powerpc64le-unknown-linux-gnu` |
| `s390x-unknown-linux-gnu` |

The helper matrix is:

| Remote `uname -m` | Helper target |
|---|---|
| `x86_64` | `x86_64-unknown-linux-musl` |
| `aarch64` | `aarch64-unknown-linux-musl` |
| `armv7l`, `armv7` | `armv7-unknown-linux-musleabihf` |
| `riscv64` | `riscv64gc-unknown-linux-gnu` |
| `ppc64le` | `powerpc64le-unknown-linux-gnu` |
| `s390x` | `s390x-unknown-linux-gnu` |

The helper directory is discovered relative to the configured bridge
executable, with an explicit environment override reserved for development
and packaging tests. A missing artifact, unsupported architecture, non-Linux
remote, `noexec` temporary directory, permission failure, or incompatible
helper handshake selects the shell fallback. This means adding a new server
never requires a bridge release before it remains usable; only the fast path
waits for a matching artifact.

The bridge verifies the helper startup fields: protocol version, helper
version, reported architecture, and a bounded capability set. It treats an
`Exec format error`, handshake EOF, or helper protocol mismatch before the
first request as a startup fallback. After a request has been accepted, a
helper transport failure follows the existing unknown-outcome rules and is not
blindly retried through sh.

## Bootstrap and cleanup

The SSH command used for helper startup is a fixed, shell-quoted bootstrap
script. It creates a mode-0700 directory, reads exactly the advertised helper
byte count from stdin, verifies the count, applies mode 0700, and executes the
file. The remote helper removes its executable path after opening it where the
platform permits; the bootstrap trap removes the private directory on normal
session exit. Upload bytes are never interpreted as shell text.

The bridge uploads only once per host session. Reconnects create a new private
directory and perform a new startup handshake. The shell fallback uses the
existing dispatcher bootstrap and cleanup path unchanged. Its `READY` frame
remains accepted for compatibility; only the new helper path omits that frame.

## Fast-path reductions

The helper path removes the following per-request work from the shell
dispatcher:

- remote input-frame temp files and `mv` staging;
- request directories used only to pass cwd/command/stdin;
- stdout/stderr FIFOs and collector shell processes;
- `dd`, `wc`, `cat`, and chunk temp files for small output;
- the wrapper `setsid sh -c` process (the helper sets the process group before
  executing the selected shell);
- the unused success `READY` frame.

The shell fallback remains available for hosts where these reductions cannot
be used. Its output limits, cancellation, mutation uncertainty, and security
behavior remain covered by the existing tests.

## Testing and acceptance

- Unit-test helper frame parsing, bounded metadata, architecture mapping,
  startup handshake validation, output-limit accounting, cancellation, and
  process-group cleanup.
- Add an integration fixture that runs the helper as a local child without
  SSH, then exercises concurrent requests, binary output, stderr, timeout,
  cancellation, and an unknown architecture fallback.
- Keep the existing shell dispatcher integration suite unchanged and run it
  explicitly as the compatibility path.
- Extend release CI to build and package every helper target, verify static
  linkage where the toolchain permits, and test that the release archive
  contains the main binary plus all helper artifacts.
- Extend the profile with `helper_bootstrap`, `helper_frame_write`,
  `helper_command_spawn`, `helper_output_drain`, and `helper_exit` phases.
  The profile remains opt-in and is not used as a latency gate because its
  JSONL writes perturb short requests.
- Acceptance measurements must report cold helper startup separately from
  warm helper requests and compare warm helper requests with warm shell
  fallback requests on the same fixture.

## Security boundaries

The helper is untrusted remote code only in the same sense as the current
dispatcher: it runs under the configured SSH account and remote Unix
permissions. The local bridge still owns host-key verification, SSH options,
configured roots, shell selection, quotas, cancellation uncertainty, and MCP
approvals. The helper receives no credentials, API keys, or local filesystem
paths outside the request data already authorized for that host.
