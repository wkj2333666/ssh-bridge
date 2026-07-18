# Codex SSH Bridge

Use a locally authenticated Codex to work on SSH servers without installing or signing in to Codex on those servers.

```text
local Codex
    │ MCP over local stdio
    ▼
dependency-free Python bridge
    │ local OpenSSH client + local keys/agent/known_hosts
    ▼
remote sshd ── project, build tools, services

optional: local SSHFS mount ── SFTP over the same SSH trust setup
```

The plugin bundles the `remote-ssh-ops` Skill, a local MCP server, a configuration validator, a direct CLI, and explicit SSHFS mount helpers. The remote machine needs only SSH access and ordinary POSIX utilities; it never receives Codex credentials.

## Why this architecture

| Approach | Good at | Main limitation | Role here |
|---|---|---|---|
| Raw `ssh` commands | Minimal setup, complete shell access | Quoting, targets, timeouts, output limits, and approvals are unstructured | Transport underneath the MCP bridge |
| SSHFS | Convenient local browsing/editing; usually no server-side setup beyond SFTP | Commands still run locally; FUSE/SFTP semantics, latency, caching, and disconnect stalls | Optional explicit mount |
| Local MCP wrapper | Structured tools, allowlisted hosts, consistent security flags, time/output limits | Non-interactive; cannot make arbitrary shell execution intrinsically safe | Default Codex interface |
| Codex remote SSH project | Native remote filesystem and shell integration | Official setup requires Codex installed and authenticated on the remote host | Deliberately not used |

OpenAI's current remote-host workflow explicitly starts a remote Codex app server and requires installing/authenticating Codex remotely, so it does not meet this project's credential boundary ([Remote connections](https://learn.chatgpt.com/docs/remote-connections#connect-to-an-ssh-host)). Codex supports local stdio MCP servers and shares MCP configuration across the desktop app, CLI, and IDE ([MCP documentation](https://learn.chatgpt.com/docs/extend/mcp)).

OpenSSH provides the controls used here: non-interactive `BatchMode`, strict host-key verification, connection multiplexing, and encrypted server-alive messages ([ssh_config(5)](https://man.openbsd.org/ssh_config.5)). Agent forwarding is forced off because OpenSSH warns that a remote attacker able to access the forwarded socket can use identities loaded in the local agent.

SSHFS uses SFTP and normally needs no additional server component ([SSHFS README](https://github.com/libfuse/sshfs)). Its own manual documents reconnect caveats, non-atomic rename workarounds, hardlink differences, and operations that can freeze after a broken connection ([SSHFS manual](https://github.com/libfuse/sshfs/blob/master/sshfs.rst)). This is why the mount is convenient but secondary.

## Requirements

- Local Python 3.10 or newer; no Python packages are required.
- Local OpenSSH client and a working key/agent-based alias in `~/.ssh/config`.
- Optional local SSHFS for `mount`/`unmount`.
- A remote POSIX shell plus `id`, `uname`, `dd`, `cp`, `mv`, and `cat` for all tools.

## Configure

First define and manually verify a concrete SSH alias:

```sshconfig
Host devbox
  HostName devbox.example.com
  User deploy
  IdentityFile ~/.ssh/id_ed25519
  ForwardAgent no
  ControlMaster auto
  ControlPersist 60
  ControlPath ~/.ssh/cm-%C
```

```bash
ssh devbox
python3 $HOME/projects/codex-ssh-bridge/scripts/codex-ssh init \
  --host devbox \
  --root /srv/my-project
python3 $HOME/projects/codex-ssh-bridge/scripts/codex-ssh doctor --host devbox
```

The default config is `~/.config/codex-ssh-bridge/config.json`, created mode `0600`. It stores no secrets. Add more allowlisted profiles by editing `hosts`; see [config.example.json](config.example.json).

## Install in Codex

The folder is already a valid plugin bundle. When distributing through a Codex marketplace, install the plugin and start a new task; its `.mcp.json` launches `python3 ./mcp/server.py` and the Skill declares that MCP dependency.

For direct local development without a marketplace, register the same two components:

```bash
python3 $HOME/projects/codex-ssh-bridge/scripts/install-local
python3 $HOME/projects/codex-ssh-bridge/scripts/install-local --apply
```

The first command is a dry run. The installer refuses to overwrite a different MCP entry or Skill path. It performs the equivalent of `codex mcp add ssh-bridge -- python3 /absolute/path/mcp/server.py` plus a user Skill symlink.

Then restart Codex or start a new task. `codex mcp list` should show `ssh-bridge`; invoke `$remote-ssh-ops` once to verify discovery.

For the direct MCP entry, use Codex's `writes` approval mode so read-only annotations can remain low-friction while `ssh_run` and `ssh_write_file` prompt:

```toml
[mcp_servers.ssh-bridge]
default_tools_approval_mode = "writes"
```

MCP annotations are hints rather than a sandbox; the MCP specification recommends human confirmation and treats annotations as untrusted unless the server itself is trusted ([MCP tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)).

## Use

Prompt examples:

```text
Use $remote-ssh-ops to inspect the devbox repository and run its tests.
Use $remote-ssh-ops to read the last 200 application log lines on devbox.
Mount the devbox project with SSHFS for local browsing, but run all commands remotely.
```

Direct CLI examples:

```bash
python3 scripts/codex-ssh hosts
python3 scripts/codex-ssh run devbox --cwd . -- git status --short
python3 scripts/codex-ssh mount devbox /absolute/local/mountpoint
python3 scripts/codex-ssh unmount /absolute/local/mountpoint
```

## Security boundary

- The bridge always uses an allowlisted alias, `BatchMode=yes`, `StrictHostKeyChecking=yes`, no TTY, no agent/X11/port forwarding, and a dedicated short-lived multiplexing socket under `~/.ssh`.
- Arbitrary `ssh_run` is potentially destructive and is disabled on `read_only` profiles.
- File tools enforce a configured byte limit and lexical root check. A symlink may still escape that root, so remote account permissions are the hard boundary.
- Commands are non-interactive. A local timeout closes the SSH process group, but detached remote processes require separate inspection.
- Remote output may contain prompt injection or secrets. The Skill directs Codex to treat it as untrusted data and to avoid unbounded retrieval.
