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

The server receives fixed POSIX scripts and user commands through ordinary SSH. The bridge keeps one local-owned SSH session per alias and streams a bounded POSIX dispatcher over it; the dispatcher is transient and is never installed on the server. The server receives no Codex binary, API key, plugin, or persistent bridge installation.

## Why this design

| Approach | Strength | Problem for this use case | Role |
|---|---|---|---|
| Raw `ssh` | Universal and minimal | Leaves target selection, quoting, limits, shell detection, cancellation, and output handling to the Agent | Transport below the bridge |
| SSHFS | Convenient human browsing | Makes remote files look local while commands still run locally; adds FUSE/SFTP latency and reconnect semantics | Explicit optional CLI only |
| Native local MCP | Closed schemas, allowlisted hosts, bounded I/O, shared policy, explicit Bash/sh choice | Non-interactive by design | Default Agent interface |
| Official Codex SSH Remote | Native remote project experience | Currently starts Codex remotely and requires remote installation/authentication | Deliberately not used |

The bridge is Rust rather than a Bash program because strict MCP framing, bounded parsing, async concurrency, process-group cancellation, and spool quotas need one auditable state machine. Bash and POSIX sh remain supported as the *remote command shells*; the result always reports which shell actually ran.

SSHFS is intentionally absent from the MCP tool list. This prevents an Agent from silently treating a FUSE path as a local workspace.

## Requirements

- Local Linux host with Rust 1.91.1 or newer to build the bridge.
- Local OpenSSH client at `/usr/bin/ssh`.
- Key-based or local-agent authentication and verified host keys.
- Remote `sshd`, a POSIX sh, a GNU- or BSD-compatible `stat`, and the ordinary utilities checked by `doctor`; Bash is optional. `shell=login` additionally needs an account shell that can be resolved through `getent passwd` or, when `getent` is absent, one unique readable `/etc/passwd` record.
- Optional local `sshfs` and `fusermount3` for the human mount commands.
- The remote server architecture is irrelevant; only the local build must match the local host.

## Build and package locally

```bash
cargo build --release
./target/release/codex-ssh-bridge --help
```

There is no Python runtime or remote build step.

## CI and release builds

GitHub Actions runs formatting, Clippy, the full test suite, a release build,
and source-package checks for pull requests and pushes to `main`.

The diagnostics job also runs the opt-in cold/warm profile and release RSS
acceptance tests. Its JSONL profile and RSS logs are uploaded as a short-lived
workflow artifact; they are not part of the published binary.

Release builds are created only from version tags. The tag must match the
version in `Cargo.toml`; for example:

```bash
git tag v0.2.1
git push origin v0.2.1
```

The release workflow publishes Linux binaries and SHA-256 files for:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `armv7-unknown-linux-gnueabihf`
- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`

Download the archive matching the local Codex host, extract the binary to a
private path, and put that absolute path in `.mcp.json.example` before
registering the MCP server. Windows and macOS assets are not produced because
the bridge currently requires Linux OpenSSH and Linux SSHFS tooling.

For isolated local development, keep worktrees in the repository's ignored
`.worktrees/` directory so the checkout, branch, and generated target files
stay together:

```bash
git worktree add .worktrees/<task-name> -b codex/<task-name> main
```

Remove a finished worktree with `git worktree remove .worktrees/<task-name>`
after its branch has been merged or otherwise retained.

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

On the first operation for an alias, the bridge resolves the local OpenSSH policy with bounded `ssh -G`, records its immutable connection identity, and probes shell/utility capabilities. The policy and capability result are cached for the lifetime of the bridge; later operations use one framed request on the already-open SSH session without another `ssh -G`, root observation, or physical-root guard. The local Unix user and that user's OpenSSH configuration remain trusted execution authority.

`doctor` reports the configured root's connection-time physical path and device/inode identity as diagnostics. The configured root remains a lexical routing boundary, and ordinary remote filesystem behavior—including symlink retargeting—matches a command run directly on that server. Individual writes and patches still use expected hashes, no-follow identity checks, atomic replacement, and explicit unknown-outcome reporting.

`doctor devbox --verbose-ssh` also runs a bounded local OpenSSH diagnostic and redacts identity paths, agent sockets, commands, and credential-like fields.

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

Operational requests are multiplexed over one persistent SSH session per alias. Remote execution runs concurrently up to the configured global/per-host capacity; additional accepted calls wait cancellably inside the runner instead of becoming MCP errors. The local MCP task window is bounded at `global_concurrency + 8`; only a full window returns `MCP task queue full`, while `remote_hosts` remains available as a control lane. Each request has an independent process group and cancellation; mutations are not implicitly serialized, so concurrent same-path calls have no ordering guarantee. If cancellation cannot be confirmed, the session is closed and the result is explicitly marked unknown rather than retried.

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

Read [docs/security.md](docs/security.md) for the complete trust model and flags. Read [docs/performance.md](docs/performance.md) for reproducible commands and raw measurements.

OpenAI's official SSH Remote workflow currently requires installing and authenticating Codex on the remote host ([Remote connections](https://learn.chatgpt.com/docs/remote-connections#connect-to-an-ssh-host)). This bridge deliberately keeps that identity and runtime local.
