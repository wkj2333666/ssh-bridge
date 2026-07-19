from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import posixpath
import shlex
import shutil
from pathlib import Path
from typing import Any

from .config import BridgeConfig, HostProfile
from .runner import ProcessResult, run_process


class BridgeError(RuntimeError):
    pass


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


class Bridge:
    def __init__(self, config: BridgeConfig) -> None:
        self.config = config

    def list_hosts(self) -> dict[str, Any]:
        return {
            "config_path": str(self.config.path),
            "hosts": [
                {
                    "alias": host.alias,
                    "root": host.root,
                    "read_only": host.read_only,
                    "description": host.description,
                }
                for host in self.config.hosts.values()
            ],
        }

    def _host(self, alias: str) -> HostProfile:
        host = self.config.hosts.get(alias)
        if host is None:
            configured = ", ".join(sorted(self.config.hosts)) or "none"
            raise BridgeError(f"host {alias!r} is not allowlisted; configured hosts: {configured}")
        return host

    def _ssh_binary(self) -> str:
        binary = self.config.ssh.binary
        if "/" in binary:
            if not Path(binary).expanduser().is_file():
                raise BridgeError(f"SSH binary does not exist: {binary}")
            return str(Path(binary).expanduser())
        resolved = shutil.which(binary)
        if resolved is None:
            raise BridgeError(f"SSH binary not found on PATH: {binary}")
        return resolved

    def _ssh_argv(self, host: HostProfile, remote_command: str) -> list[str]:
        ssh = self.config.ssh
        argv = [self._ssh_binary()]
        if ssh.config_file is not None:
            if not ssh.config_file.is_file():
                raise BridgeError(f"SSH config file does not exist: {ssh.config_file}")
            argv.extend(["-F", str(ssh.config_file)])
        argv.extend(
            [
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ForwardAgent=no",
                "-o",
                "ForwardX11=no",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "PermitLocalCommand=no",
                "-o",
                "RequestTTY=no",
                "-o",
                "ControlMaster=auto",
                "-o",
                "ControlPersist=60",
                "-o",
                "ControlPath=~/.ssh/cm-codex-ssh-%C",
                "-o",
                f"ConnectTimeout={ssh.connect_timeout_sec}",
                "-o",
                f"ServerAliveInterval={ssh.server_alive_interval_sec}",
                "-o",
                f"ServerAliveCountMax={ssh.server_alive_count_max}",
                host.alias,
                remote_command,
            ]
        )
        return argv

    def _timeout(self, requested: int | None) -> int:
        limits = self.config.limits
        timeout = limits.command_timeout_sec if requested is None else requested
        if isinstance(timeout, bool) or not isinstance(timeout, int):
            raise BridgeError("timeout_sec must be an integer")
        if not 1 <= timeout <= limits.max_command_timeout_sec:
            raise BridgeError(
                f"timeout_sec must be between 1 and {limits.max_command_timeout_sec}"
            )
        return timeout

    def _output_limit(self, requested: int | None) -> int:
        maximum = self.config.limits.max_output_bytes
        limit = maximum if requested is None else requested
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise BridgeError("max_output_bytes must be an integer")
        if not 1024 <= limit <= maximum:
            raise BridgeError(f"max_output_bytes must be between 1024 and {maximum}")
        return limit

    def _remote_path(self, host: HostProfile, path: str) -> str:
        if not isinstance(path, str) or not path:
            raise BridgeError("path must be a non-empty string")
        if "\x00" in path or "\n" in path or "\r" in path:
            raise BridgeError("path must not contain NUL or newlines")
        normalized = posixpath.normpath(path)
        root = posixpath.normpath(host.root)
        if posixpath.isabs(normalized):
            if root == ".":
                raise BridgeError("absolute paths are disabled when the host root is '.'")
            candidate = normalized
        else:
            candidate = posixpath.normpath(posixpath.join(root, normalized))
        if root != ".":
            try:
                common = posixpath.commonpath([root, candidate])
            except ValueError as exc:
                raise BridgeError("path is outside the configured host root") from exc
            if common != root:
                raise BridgeError("path is outside the configured host root")
        elif candidate == ".." or candidate.startswith("../"):
            raise BridgeError("path is outside the configured host root")
        return candidate

    def _cwd(self, host: HostProfile, cwd: str | None) -> str:
        return self._remote_path(host, cwd or ".")

    def _execute(
        self,
        host: HostProfile,
        remote_command: str,
        *,
        timeout_sec: int | None = None,
        max_output_bytes: int | None = None,
        input_bytes: bytes | None = None,
    ) -> ProcessResult:
        return run_process(
            self._ssh_argv(host, remote_command),
            timeout_sec=self._timeout(timeout_sec),
            max_output_bytes=self._output_limit(max_output_bytes),
            input_bytes=input_bytes,
        )

    def _result(self, host: HostProfile, cwd: str, result: ProcessResult) -> dict[str, Any]:
        return {
            "host": host.alias,
            "cwd": cwd,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "duration_ms": result.duration_ms,
            "stdout": _decode(result.stdout),
            "stderr": _decode(result.stderr),
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
        }

    def probe(self, alias: str, timeout_sec: int | None = None) -> dict[str, Any]:
        host = self._host(alias)
        remote = (
            "printf 'codex-ssh-bridge-ok\\n'; "
            "printf 'user='; id -un 2>/dev/null || printf 'unknown\\n'; "
            "printf 'cwd='; pwd -P; "
            "printf 'os='; uname -s 2>/dev/null || printf 'unknown\\n'"
        )
        result = self._execute(host, remote, timeout_sec=timeout_sec, max_output_bytes=65_536)
        return self._result(host, host.root, result)

    def run(
        self,
        alias: str,
        command: str,
        *,
        cwd: str | None = None,
        timeout_sec: int | None = None,
        max_output_bytes: int | None = None,
    ) -> dict[str, Any]:
        host = self._host(alias)
        if host.read_only:
            raise BridgeError(f"host {alias!r} is read-only; arbitrary commands are disabled")
        if not isinstance(command, str) or not command.strip():
            raise BridgeError("command must be a non-empty string")
        if "\x00" in command:
            raise BridgeError("command must not contain NUL")
        resolved_cwd = self._cwd(host, cwd)
        remote = f"cd -- {shlex.quote(resolved_cwd)} && exec sh -lc {shlex.quote(command)}"
        result = self._execute(
            host,
            remote,
            timeout_sec=timeout_sec,
            max_output_bytes=max_output_bytes,
        )
        return self._result(host, resolved_cwd, result)

    def read_file(
        self,
        alias: str,
        path: str,
        *,
        max_bytes: int | None = None,
        timeout_sec: int | None = None,
    ) -> dict[str, Any]:
        host = self._host(alias)
        limit = self.config.limits.max_file_bytes if max_bytes is None else max_bytes
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise BridgeError("max_bytes must be an integer")
        if not 1 <= limit <= self.config.limits.max_file_bytes:
            raise BridgeError(
                f"max_bytes must be between 1 and {self.config.limits.max_file_bytes}"
            )
        remote_path = self._remote_path(host, path)
        block_size = 32_768
        blocks = math.ceil((limit + 1) / block_size)
        remote = (
            f"test -f {shlex.quote(remote_path)} && "
            f"dd if={shlex.quote(remote_path)} bs={block_size} count={blocks} 2>/dev/null"
        )
        result = self._execute(
            host,
            remote,
            timeout_sec=timeout_sec,
            max_output_bytes=limit,
        )
        if result.exit_code != 0:
            payload = self._result(host, host.root, result)
            raise BridgeError(
                f"could not read {remote_path!r} (exit {result.exit_code}): {payload['stderr'].strip()}"
            )
        raw = result.stdout
        try:
            content = raw.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            content = base64.b64encode(raw).decode("ascii")
            encoding = "base64"
        return {
            "host": host.alias,
            "path": remote_path,
            "encoding": encoding,
            "content": content,
            "bytes_returned": len(raw),
            "truncated": result.stdout_truncated,
            "sha256_returned": hashlib.sha256(raw).hexdigest(),
            "duration_ms": result.duration_ms,
        }

    def write_file(
        self,
        alias: str,
        path: str,
        content: str,
        *,
        encoding: str = "utf-8",
        overwrite: bool = False,
        create_parents: bool = False,
        timeout_sec: int | None = None,
    ) -> dict[str, Any]:
        host = self._host(alias)
        if host.read_only:
            raise BridgeError(f"host {alias!r} is read-only; file writes are disabled")
        if not isinstance(content, str):
            raise BridgeError("content must be a string")
        if not isinstance(overwrite, bool):
            raise BridgeError("overwrite must be a boolean")
        if not isinstance(create_parents, bool):
            raise BridgeError("create_parents must be a boolean")
        if encoding == "utf-8":
            raw = content.encode("utf-8")
        elif encoding == "base64":
            try:
                raw = base64.b64decode(content, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise BridgeError("content is not valid base64") from exc
        else:
            raise BridgeError("encoding must be 'utf-8' or 'base64'")
        if len(raw) > self.config.limits.max_file_bytes:
            raise BridgeError(
                f"content exceeds max_file_bytes ({self.config.limits.max_file_bytes})"
            )
        remote_path = self._remote_path(host, path)
        parent = posixpath.dirname(remote_path) or "."
        base = posixpath.basename(remote_path)
        prepare_parent = f"mkdir -p -- {shlex.quote(parent)}" if create_parents else f"test -d {shlex.quote(parent)}"
        existence = ":" if overwrite else f"test ! -e {shlex.quote(remote_path)}"
        remote = "\n".join(
            [
                "set -eu",
                prepare_parent,
                existence,
                f"target={shlex.quote(remote_path)}",
                f"tmp={shlex.quote(posixpath.join(parent, '.' + base + '.codex-ssh-tmp'))}.$$",
                "trap 'rm -f -- \"$tmp\"' EXIT HUP INT TERM",
                "if [ -e \"$target\" ]; then cp -p -- \"$target\" \"$tmp\"; : > \"$tmp\"; else (umask 077; : > \"$tmp\"); fi",
                "cat > \"$tmp\"",
                "mv -f -- \"$tmp\" \"$target\"",
                "trap - EXIT HUP INT TERM",
            ]
        )
        result = self._execute(
            host,
            remote,
            timeout_sec=timeout_sec,
            max_output_bytes=65_536,
            input_bytes=raw,
        )
        if result.exit_code != 0:
            details = _decode(result.stderr).strip()
            if not overwrite:
                details = details or "target may already exist; set overwrite=true only after inspection"
            raise BridgeError(
                f"could not write {remote_path!r} (exit {result.exit_code}): {details}"
            )
        return {
            "host": host.alias,
            "path": remote_path,
            "bytes_written": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "atomic_replace": True,
            "duration_ms": result.duration_ms,
        }

    def resolved_ssh_config(self, alias: str) -> dict[str, Any]:
        host = self._host(alias)
        argv = [self._ssh_binary()]
        if self.config.ssh.config_file is not None:
            argv.extend(["-F", str(self.config.ssh.config_file)])
        argv.extend(["-G", host.alias])
        result = run_process(
            argv,
            timeout_sec=self.config.ssh.connect_timeout_sec,
            max_output_bytes=262_144,
        )
        if result.exit_code != 0:
            raise BridgeError(f"ssh -G failed: {_decode(result.stderr).strip()}")
        visible_keys = {"hostname", "user", "port", "proxyjump", "identityfile"}
        resolved: dict[str, Any] = {}
        for line in _decode(result.stdout).splitlines():
            key, _, value = line.partition(" ")
            if key in visible_keys:
                if key == "identityfile":
                    resolved.setdefault(key, []).append(value)
                else:
                    resolved[key] = value
        return {"host": alias, "resolved": resolved}

    def json(self, value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
