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

The server receives fixed POSIX scripts and user commands through ordinary SSH. It receives no Codex binary, session, API key, plugin, or persistent helper.

## Why this design

| Approach | Strength | Problem for this use case | Role |
|---|---|---|---|
| Raw `ssh` | Universal and minimal | Leaves target selection, quoting, limits, shell detection, cancellation, and output handling to the Agent | Transport below the bridge |
| SSHFS | Convenient human browsing | Makes remote files look local while commands still run locally; adds FUSE/SFTP latency and reconnect semantics | Explicit optional CLI only |
| Native local MCP | Closed schemas, allowlisted hosts, bounded I/O, shared policy, visible Bash/sh fallback | Non-interactive by design | Default Agent interface |
| Official Codex SSH Remote | Native remote project experience | Currently starts Codex remotely and requires remote installation/authentication | Deliberately not used |

The bridge is Rust rather than a Bash program because strict MCP framing, bounded parsing, async concurrency, process-group cancellation, spool quotas, and transactional installation need one auditable state machine. Bash and POSIX sh remain supported as the *remote command shells*; the result always reports which shell actually ran.

SSHFS is intentionally absent from the MCP tool list. This prevents an Agent from silently treating a FUSE path as a local workspace.

## Requirements

- Local Linux host with the packaged `codex-ssh-bridge` binary.
- Local OpenSSH client at `/usr/bin/ssh`.
- Key-based or local-agent authentication and verified host keys.
- Remote `sshd`, a POSIX sh, a GNU- or BSD-compatible `stat`, and the ordinary utilities checked by `doctor`; Bash is optional. `shell=login` additionally needs an account shell that can be resolved through `getent passwd` or, when `getent` is absent, one unique readable `/etc/passwd` record.
- Optional local `sshfs` and `fusermount3` for the human mount commands.
- Rust 1.91.1 or newer only when rebuilding.

The bundled binary is native to the machine/architecture on which it was built. Rebuild and replace `bin/codex-ssh-bridge` when moving the plugin to a different local architecture. Remote server architecture is irrelevant.

## Build and package locally

```bash
cargo build --release
mkdir -p bin
cp target/release/codex-ssh-bridge bin/codex-ssh-bridge
chmod 0755 bin/codex-ssh-bridge
sha256sum target/release/codex-ssh-bridge bin/codex-ssh-bridge
./bin/codex-ssh-bridge --help
```

There is no Python runtime or remote build step.

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
./bin/codex-ssh-bridge hosts add devbox \
  --root /srv/my-project \
  --description "development server"
./bin/codex-ssh-bridge doctor devbox
```

Add future servers with another concrete alias and `hosts add`; there is no five-host ceiling. Use `--read-only` for inspection-only profiles. The default local config is `~/.config/codex-ssh-bridge/config.toml`; [config.example.toml](config.example.toml) documents limits. It accepts exactly configuration `version = 1` and contains aliases, roots, descriptions, and limits—never credentials.

Before every operation, the bridge reruns bounded system `ssh -G`, hashes the resolved OpenSSH configuration, and compares it with the first immutable connection identity for that alias. A mismatch fails with `INVALID_CONFIG` before capability probing, root observation, or the business command; verify the alias and restart the bridge to accept an intentional change. The local Unix user and that user's OpenSSH configuration remain trusted execution authority.

`doctor` probes the configured root's physical path and device/inode identity as well as shell and utility capabilities. Every later operation revalidates that root identity through the reused SSH connection and pins the checked directory as its working directory before the business script. Reads may follow a newly observed physical root and report it; writes, patches, and `remote_run` compare against the bridge process's immutable first root trust and fail closed if it changed. Refreshing tool capabilities never refreshes root trust: intentionally accepting a replacement root requires a bridge restart and fresh probe.

`doctor devbox --verbose-ssh` also runs a bounded local OpenSSH diagnostic and redacts identity paths, agent sockets, commands, and credential-like fields.

## Install for local Codex

The package contains a normal Codex plugin manifest, Skill, and local stdio MCP manifest. Codex documents that desktop, CLI, and IDE clients on one host share MCP configuration, and that a plugin can bundle both Skills and `.mcp.json` servers ([MCP](https://learn.chatgpt.com/docs/extend/mcp), [plugins](https://learn.chatgpt.com/docs/build-plugins)).

For a direct user installation, review the dry run first:

```bash
./bin/codex-ssh-bridge install --user
./bin/codex-ssh-bridge install --user --apply
codex mcp get ssh-bridge --json
```

The installer:

- accepts only this canonical Rust package layout;
- refuses an unrelated MCP entry or Skill target;
- validates trusted source ancestors and the complete Skill tree;
- serializes bridge-managed install/uninstall transactions with a private user lock;
- journals mutations and compensates a partially successful Codex CLI call;
- stores a private content-hashed installation identity;
- is dry-run unless `--apply` is explicit.

Uninstall follows the same rule:

```bash
./bin/codex-ssh-bridge uninstall --user
./bin/codex-ssh-bridge uninstall --user --apply
```

Start a new Codex task after installing or updating so the Skill and MCP surface are reloaded. The user running the bridge is the local installation trust boundary: another process running as that same Unix user can bypass the bridge and edit Codex configuration directly because the Codex CLI does not expose compare-and-swap removal.

Keep an installed bundle at a durable, versioned, private path such as `~/.local/share/codex-ssh-bridge/0.1.0`; the MCP entry and Skill symlink intentionally point back to that reviewed bundle. For an update, do not overwrite the active bundle in place: run its recorded `uninstall --user --apply`, stage the new version in a new directory, review the new dry run, then apply it. The content-hashed identity deliberately rejects an overwritten or unrelated bundle instead of guessing that it is a safe upgrade.

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

`remote_run` accepts one command string plus `shell: auto|bash|sh|login`. Prefer POSIX syntax. `auto` may fall back to sh; request Bash explicitly for Bash-only syntax. `login` resolves the account shell from NSS or `/etc/passwd`, never from `$SHELL`, and fails closed when it cannot do so safely. Always inspect the returned actual shell, fallback flag, warnings, exit status, truncation, and process-continuation uncertainty.

## Human direct CLI

The direct CLI accepts argv and handles shell-word encoding inside the bridge:

```bash
./bin/codex-ssh-bridge hosts list
./bin/codex-ssh-bridge run devbox --cwd . --shell auto -- git status --short
```

This is convenient for a person or a diagnostic. Model-driven work should use MCP so results remain structured and approvals follow tool annotations.

## Optional SSHFS

Mount only when a person explicitly wants local browsing:

```bash
mkdir -p /absolute/local/mountpoint
./bin/codex-ssh-bridge mount devbox /absolute/local/mountpoint --remote-path .
./bin/codex-ssh-bridge mount-status /absolute/local/mountpoint
./bin/codex-ssh-bridge unmount /absolute/local/mountpoint
```

The CLI requires a real absolute current-user-owned mountpoint, refuses nonempty directories without `--allow-nonempty`, forces `ro` for read-only profiles, and never enables `allow_other`. It prints that the mount is remote and not an Agent workspace.

Use SSHFS for browsing or narrow human editing. Keep builds, Git, tests, containers, and services on the server through `remote_run`. SFTP/FUSE workloads add a round trip to many metadata operations; caching, permissions, hardlinks, rename behavior, and broken-connection recovery also differ from a native filesystem. See the [SSHFS documentation](https://github.com/libfuse/sshfs).

## Security and performance

The bridge forces non-interactive authentication, strict host keys, no agent/X11/port forwarding, no local command, no TTY, bounded connection time, `ServerAliveInterval=15`, `ServerAliveCountMax=3`, and a private hashed ControlMaster socket for ordinary SSH and SSHFS. It never accepts arbitrary SSH options from MCP. Remote output remains untrusted and remote Unix permissions are the hard isolation boundary.

Read [docs/security.md](docs/security.md) for the complete trust model and flags. Read [docs/performance.md](docs/performance.md) for reproducible commands and raw measurements.

OpenAI's official SSH Remote workflow currently requires installing and authenticating Codex on the remote host ([Remote connections](https://learn.chatgpt.com/docs/remote-connections#connect-to-an-ssh-host)). This bridge deliberately keeps that identity and runtime local.
