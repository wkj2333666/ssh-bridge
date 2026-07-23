# Codex SSH Bridge

Use Codex on this local machine to inspect, edit, and run commands on allowlisted SSH servers without installing or signing in to Codex on those servers.

```text
local Codex
    │ local stdio MCP
    ▼
native Rust bridge
    │ local OpenSSH + local keys/agent/known_hosts
    ▼
remote sshd ── files, compilers, tests, services

optional, human-only: local SSHFS mount over SFTP
```

The bridge keeps one local-owned SSH session per alias. On supported Linux architectures it uploads a precompiled Rust helper once for that session; unsupported hosts use the complete transient POSIX dispatcher fallback. Neither path installs a persistent package: the server receives no Codex binary, API key, plugin, or bridge installation.

## Why this design

| Approach | Strength | Problem for this use case | Role |
|---|---|---|---|
| Raw `ssh` | Universal and minimal | Leaves target selection, quoting, limits, shell detection, cancellation, and output handling to the Agent | Transport below the bridge |
| SSHFS | Convenient human browsing | Makes remote files look local while commands still run locally; adds FUSE/SFTP latency and reconnect semantics | Explicit optional CLI only |
| Native local MCP | Closed schemas, allowlisted hosts, bounded I/O, shared policy, explicit Bash/sh choice | Non-interactive by design | Default Agent interface |

The bridge is Rust rather than a Bash program because strict MCP framing, bounded parsing, async concurrency, process-group cancellation, and spool quotas need one auditable state machine. Bash and POSIX sh remain supported as the *remote command shells*; the result always reports which shell actually ran.

SSHFS is intentionally absent from the MCP tool list. This prevents an Agent from silently treating a FUSE path as a local workspace.

## Requirements

- Local Linux host with Rust 1.91.1 or newer to build the bridge.
- Local OpenSSH client at `/usr/bin/ssh`.
- Key-based or local-agent authentication and verified host keys.
- Remote `sshd`, a POSIX sh, a GNU- or BSD-compatible `stat`, and the ordinary utilities checked by `doctor`; Bash is optional. `shell=login` additionally needs an account shell that can be resolved through `getent passwd` or, when `getent` is absent, one unique readable `/etc/passwd` record.
- Optional local `sshfs` and `fusermount3` for the human mount commands.
- Common Linux remote architectures use the bundled helper; new or unsupported hosts remain usable through the shell fallback. The local bridge binary must match the local host.

## Build and package locally

```bash
cargo build --release
./target/release/codex-ssh-bridge --help
```

There is no Python runtime or remote build step.

## CI and release builds

GitHub Actions runs formatting, Clippy, the full test suite, release builds,
and source-package checks. Release archives are published from version tags.

The release tag must match the version in `Cargo.toml`; for example:

```bash
git tag v<version>
git push origin v<version>
```

The release workflow publishes Linux binaries and SHA-256 files for:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `armv7-unknown-linux-gnueabihf`
- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `riscv64gc-unknown-linux-gnu`
- `powerpc64le-unknown-linux-gnu`
- `s390x-unknown-linux-gnu`

Each archive also contains `remote-helpers/` with helpers for all six
supported Linux architectures: static musl helpers for `x86_64`, `aarch64`,
and `armv7l`, plus GNU-target helpers for `riscv64`, `ppc64le`, and `s390x`.
When a GNU helper cannot run because the remote loader or libc is incompatible,
the bridge reports the startup fallback and uses the POSIX dispatcher.
Keep that directory beside the bridge binary. The bridge probes `uname -s` and
`uname -m`, uploads the matching helper once per SSH session, and automatically
uses the POSIX dispatcher when the host or artifact is unsupported. For local
development or a custom package, set `CODEX_SSH_BRIDGE_HELPERS_DIR` to a
private directory containing files named by their Rust target triple.

Download the archive matching the local Codex host, extract the binary to a
private path, and put that absolute path in `.mcp.json.example` before
registering the MCP server. Windows and macOS assets are not produced because
the bridge currently requires Linux OpenSSH and Linux SSHFS tooling.

## Configure hosts

Define and manually verify a concrete alias in local `~/.ssh/config`:

```sshconfig
Host devbox
  HostName devbox.example.com
  User deploy
  IdentityFile ~/.ssh/id_ed25519
  ForwardAgent no
```

```bash
ssh devbox
./target/release/codex-ssh-bridge hosts add devbox \
  --root /srv/my-project \
  --description "development server"
./target/release/codex-ssh-bridge doctor devbox
```

Add future servers with another concrete alias and `hosts add`; there is no five-host ceiling. Use `--read-only` for inspection-only profiles. The default local config is `~/.config/codex-ssh-bridge/config.toml`; [config.example.toml](config.example.toml) documents limits. It accepts exactly configuration `version = 1` and contains aliases, roots, descriptions, and limits—never credentials.

On first use, the bridge validates the local SSH configuration and probes the
remote shell and utility capabilities. It reuses the connection for later
requests. Writes and patches use expected hashes, no-follow checks, atomic
replacement, and explicit conflict or unknown-outcome reporting.

## Configure MCP for local Codex

The public package contains the Skill and a configuration template, not a machine-specific MCP entry. Build the bridge locally, copy the template, and replace its command with the absolute path to your release binary:

```bash
cargo build --release
cp .mcp.json.example .mcp.json
$EDITOR .mcp.json
```

The template must contain a command like:

```json
"command": "/absolute/path/to/target/release/codex-ssh-bridge",
"args": ["mcp"]
```

For the Codex CLI, register the same command explicitly:

```bash
codex mcp add ssh-bridge -- /absolute/path/to/target/release/codex-ssh-bridge mcp
codex mcp get ssh-bridge --json
```

The user-owned `.mcp.json` is ignored by Git so local absolute paths are not published. Start a new Codex task after registering or updating the server so the Skill and MCP surface are reloaded.

For a direct MCP entry, Codex can prompt only for tools not marked read-only:

```toml
[mcp_servers.ssh-bridge]
default_tools_approval_mode = "writes"
```

## Agent workflow

Invoke the Skill explicitly when useful:

```text
Use $remote-ssh-ops to inspect the devbox repository, patch the timeout bug, and run its focused tests.
Use $remote-ssh-ops to search devbox logs without downloading unbounded output.
```

The nine MCP tools are:

| Read-oriented | Mutation/command |
|---|---|
| `remote_hosts`, `remote_list`, `remote_stat`, `remote_search`, `remote_read`, `remote_output_read` | `remote_apply_patch`, `remote_write`, `remote_run` |

The default flow is bounded search/read → unified patch → remote verification. Calls are synchronous. Oversized detail is retained under an opaque `output_ref` and paged with `remote_output_read`, so the Agent never needs to reconstruct transport logic.

`remote_run` accepts one command string plus `shell: bash|sh|login`; omission means `bash`. Prefer POSIX syntax. Bash is never silently changed to sh: if Bash is unavailable, the model receives a capability error and may explicitly retry with `shell:"sh"`. `login` resolves the account shell from NSS or `/etc/passwd`, never from `$SHELL`, and fails closed when it cannot do so safely. Always inspect the returned actual shell, fallback flag, warnings, exit status, truncation, and process-continuation uncertainty.

Operational requests use one persistent SSH session per alias and are bounded
by the configured concurrency and output limits. Requests are cancellable;
mutations report conflicts or unknown outcomes and are never blindly retried.

## Human direct CLI

The direct CLI accepts argv and handles shell-word encoding inside the bridge:

```bash
./target/release/codex-ssh-bridge hosts list
./target/release/codex-ssh-bridge run devbox --cwd . --shell bash -- git status --short
```

This is convenient for a person or a diagnostic. Model-driven work should use MCP so results remain structured and approvals follow tool annotations.

## Optional SSHFS

Mount only when a person explicitly wants local browsing:

```bash
mkdir -p /absolute/local/mountpoint
./target/release/codex-ssh-bridge mount devbox /absolute/local/mountpoint --remote-path .
./target/release/codex-ssh-bridge mount-status /absolute/local/mountpoint
./target/release/codex-ssh-bridge unmount /absolute/local/mountpoint
```

The CLI requires a real absolute current-user-owned mountpoint, refuses nonempty directories without `--allow-nonempty`, forces `ro` for read-only profiles, and never enables `allow_other`. It prints that the mount is remote and not an Agent workspace.

Use SSHFS for browsing or narrow human editing. Keep builds, Git, tests, containers, and services on the server through `remote_run`. SFTP/FUSE workloads add a round trip to many metadata operations; caching, permissions, hardlinks, rename behavior, and broken-connection recovery also differ from a native filesystem. See the [SSHFS documentation](https://github.com/libfuse/sshfs).

## Security and performance

The bridge forces non-interactive authentication, strict host keys, no agent/X11/port forwarding, no local command, no TTY, bounded connection time, `ServerAliveInterval=15`, `ServerAliveCountMax=3`, and a private hashed ControlMaster socket for ordinary SSH and SSHFS. It never accepts arbitrary SSH options from MCP. Remote output remains untrusted and remote Unix permissions are the hard isolation boundary.

Read [docs/security.md](docs/security.md) for the complete trust model and flags. Read [docs/performance.md](docs/performance.md) for performance notes.
