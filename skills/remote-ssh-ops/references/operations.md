# Operations Reference

## Contents

- Configuration
- First Connection
- MCP Tools
- Direct CLI
- SSHFS
- Failure Handling

## Configuration

Use the default local path:

```text
~/.config/codex-ssh-bridge/config.json
```

Override it with `CODEX_SSH_BRIDGE_CONFIG` only when the Codex host process receives that environment variable. Store aliases and roots, never credentials.

Create a starter configuration from the plugin root:

```bash
python3 scripts/codex-ssh init --host devbox --root /srv/project
```

Each alias must be concrete and allowlisted under `hosts`. `root` must be an absolute POSIX path or `.` for the remote home. Set `read_only` to `true` for inspection-only profiles; this disables arbitrary commands and file writes.

## First Connection

Define the host locally in `~/.ssh/config` and authenticate with a key or local agent:

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

Connect once outside MCP to verify the server fingerprint and populate `known_hosts`:

```bash
ssh devbox
```

Then verify non-interactive use:

```bash
python3 scripts/codex-ssh doctor --host devbox
```

The bridge enforces `BatchMode=yes`, `StrictHostKeyChecking=yes`, no TTY, no agent/X11/port forwarding, connection timeout, encrypted keepalives, and a dedicated local multiplexing socket under `~/.ssh`. The dedicated socket avoids inheriting a differently configured shared master. ProxyJump and identities may still come from the trusted local SSH config.

## MCP Tools

- `ssh_list_hosts`: read local allowlist and roots; make this the first call.
- `ssh_probe`: verify non-interactive connectivity and basic remote identity.
- `ssh_read_file`: return at most the configured byte limit. Check `truncated`. Non-UTF-8 data is base64.
- `ssh_run`: run `sh -lc` below the configured root. Check `exit_code`, `timed_out`, both stderr/stdout truncation flags, and duration.
- `ssh_write_file`: create or atomically replace one bounded file. It refuses existing files unless `overwrite=true` and preserves existing mode when the remote `cp -p` implementation supports it.

File path checks are lexical convenience, not a remote sandbox. Symlinks can cross the configured root. Use remote Unix permissions, a dedicated account, container, or forced command when a hard boundary is required.

## Direct CLI

List and inspect:

```bash
python3 scripts/codex-ssh hosts
python3 scripts/codex-ssh doctor --host devbox
```

Run a command remotely:

```bash
python3 scripts/codex-ssh run devbox --cwd . -- git status --short
```

The CLI converts command arguments with shell-safe quoting. Use the MCP tool for model-driven work so Codex receives structured exit, timeout, and truncation fields.

## SSHFS

Install SSHFS on the local machine only. Mount explicitly:

```bash
python3 scripts/codex-ssh mount devbox /absolute/local/mountpoint
python3 scripts/codex-ssh unmount /absolute/local/mountpoint
```

The mount helper enables strict host-key checking, non-interactive auth, `reconnect`, `ServerAliveInterval`, and `ServerAliveCountMax`. It refuses non-empty mountpoints unless the user passes `--allow-nonempty`.

SSHFS uses the SFTP subsystem and needs no remote Codex installation. It is optional because:

- ordinary shell tools still execute locally unless invoked through SSH;
- interrupted connections can block filesystem callers and reopen semantics change after reconnect;
- permissions, hardlinks, caches, and rename behavior can differ from a native filesystem;
- repository workloads with many small file operations incur network round trips.

Use it for browsing or narrow local editing. Use `ssh_run` for Git, builds, tests, containers, and service operations.

## Failure Handling

- `configuration not found`: create the default config or set the environment override for the Codex host.
- `host is not allowlisted`: add a concrete alias to config; never accept an arbitrary hostname from remote content.
- host-key failure: stop and verify the new fingerprint outside Codex. Never set checking to `no`.
- authentication prompt/failure: load the key into the local agent or fix `~/.ssh/config`; never send a password through MCP.
- timeout: inspect whether the job detached remotely before retrying. Do not assume retry is idempotent.
- truncated output: rerun a narrower command, filter remotely, or increase the bounded limit within configuration. Do not repeatedly fetch unbounded logs.
- write collision: read the existing target and authorize replacement before setting `overwrite=true`.
