from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class SSHConfig:
    binary: str = "ssh"
    config_file: Path | None = None
    connect_timeout_sec: int = 10
    server_alive_interval_sec: int = 15
    server_alive_count_max: int = 3


@dataclass(frozen=True)
class Limits:
    command_timeout_sec: int = 120
    max_command_timeout_sec: int = 1800
    max_output_bytes: int = 1_048_576
    max_file_bytes: int = 1_048_576


@dataclass(frozen=True)
class HostProfile:
    alias: str
    root: str
    read_only: bool = False
    description: str = ""


@dataclass(frozen=True)
class BridgeConfig:
    path: Path
    ssh: SSHConfig
    limits: Limits
    hosts: Mapping[str, HostProfile]


def default_config_path() -> Path:
    override = os.environ.get("CODEX_SSH_BRIDGE_CONFIG")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "codex-ssh-bridge" / "config.json"


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a JSON object")
    return value


def _only_keys(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigError(f"{label} has unsupported keys: {', '.join(unknown)}")


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ConfigError(f"{label} must be between {minimum} and {maximum}")
    return value


def _clean_text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{label} must be a string")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ConfigError(f"{label} must not contain NUL or newlines")
    if not allow_empty and not value:
        raise ConfigError(f"{label} must not be empty")
    return value


def _parse_ssh(raw: Any) -> SSHConfig:
    data = _object(raw, "ssh")
    _only_keys(
        data,
        {
            "binary",
            "config_file",
            "connect_timeout_sec",
            "server_alive_interval_sec",
            "server_alive_count_max",
        },
        "ssh",
    )
    config_file: Path | None = None
    if data.get("config_file") is not None:
        config_file = Path(_clean_text(data["config_file"], "ssh.config_file")).expanduser()
    return SSHConfig(
        binary=_clean_text(data.get("binary", "ssh"), "ssh.binary"),
        config_file=config_file,
        connect_timeout_sec=_bounded_int(
            data.get("connect_timeout_sec", 10), "ssh.connect_timeout_sec", 1, 300
        ),
        server_alive_interval_sec=_bounded_int(
            data.get("server_alive_interval_sec", 15),
            "ssh.server_alive_interval_sec",
            1,
            3600,
        ),
        server_alive_count_max=_bounded_int(
            data.get("server_alive_count_max", 3),
            "ssh.server_alive_count_max",
            1,
            100,
        ),
    )


def _parse_limits(raw: Any) -> Limits:
    data = _object(raw, "limits")
    _only_keys(
        data,
        {
            "command_timeout_sec",
            "max_command_timeout_sec",
            "max_output_bytes",
            "max_file_bytes",
        },
        "limits",
    )
    command_timeout = _bounded_int(
        data.get("command_timeout_sec", 120), "limits.command_timeout_sec", 1, 86_400
    )
    maximum_timeout = _bounded_int(
        data.get("max_command_timeout_sec", 1800),
        "limits.max_command_timeout_sec",
        1,
        86_400,
    )
    if command_timeout > maximum_timeout:
        raise ConfigError("limits.command_timeout_sec cannot exceed max_command_timeout_sec")
    return Limits(
        command_timeout_sec=command_timeout,
        max_command_timeout_sec=maximum_timeout,
        max_output_bytes=_bounded_int(
            data.get("max_output_bytes", 1_048_576),
            "limits.max_output_bytes",
            1024,
            16_777_216,
        ),
        max_file_bytes=_bounded_int(
            data.get("max_file_bytes", 1_048_576),
            "limits.max_file_bytes",
            1024,
            16_777_216,
        ),
    )


def _parse_hosts(raw: Any) -> Mapping[str, HostProfile]:
    data = _object(raw, "hosts")
    hosts: dict[str, HostProfile] = {}
    for alias, host_raw in data.items():
        if not isinstance(alias, str) or not HOST_RE.fullmatch(alias):
            raise ConfigError(f"invalid SSH host alias: {alias!r}")
        host = _object(host_raw, f"hosts.{alias}")
        _only_keys(host, {"root", "read_only", "description"}, f"hosts.{alias}")
        root = _clean_text(host.get("root", "."), f"hosts.{alias}.root")
        if root != "." and not root.startswith("/"):
            raise ConfigError(f"hosts.{alias}.root must be an absolute POSIX path or '.'")
        read_only = host.get("read_only", False)
        if not isinstance(read_only, bool):
            raise ConfigError(f"hosts.{alias}.read_only must be a boolean")
        description = _clean_text(
            host.get("description", ""), f"hosts.{alias}.description", allow_empty=True
        )
        hosts[alias] = HostProfile(alias, root, read_only, description)
    return hosts


def load_config(path: Path | None = None) -> BridgeConfig:
    resolved = (path or default_config_path()).expanduser().resolve()
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(
            f"configuration not found at {resolved}; run scripts/codex-ssh init --host ALIAS --root /path"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in {resolved}: {exc}") from exc
    root = _object(raw, "configuration")
    _only_keys(root, {"version", "ssh", "limits", "hosts"}, "configuration")
    if root.get("version") != 1:
        raise ConfigError("configuration.version must be 1")
    return BridgeConfig(
        path=resolved,
        ssh=_parse_ssh(root.get("ssh", {})),
        limits=_parse_limits(root.get("limits", {})),
        hosts=_parse_hosts(root.get("hosts", {})),
    )
