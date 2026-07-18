from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ssh_bridge import Bridge, BridgeError, ConfigError, load_config  # noqa: E402


FAKE_SSH = PROJECT_ROOT / "tests" / "fake_ssh.py"


class BridgeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remote = self.root / "remote"
        self.remote.mkdir()
        self.config_path = self.root / "config.json"
        payload = {
            "version": 1,
            "ssh": {
                "binary": str(FAKE_SSH),
                "connect_timeout_sec": 2,
                "server_alive_interval_sec": 2,
                "server_alive_count_max": 1,
            },
            "limits": {
                "command_timeout_sec": 3,
                "max_command_timeout_sec": 10,
                "max_output_bytes": 65_536,
                "max_file_bytes": 65_536,
            },
            "hosts": {
                "devbox": {"root": str(self.remote), "read_only": False},
                "prod-ro": {"root": str(self.remote), "read_only": True},
            },
        }
        self.config_path.write_text(json.dumps(payload), encoding="utf-8")
        self.bridge = Bridge(load_config(self.config_path))

    def test_list_probe_and_run(self) -> None:
        self.assertEqual(["devbox", "prod-ro"], [h["alias"] for h in self.bridge.list_hosts()["hosts"]])
        probe = self.bridge.probe("devbox")
        self.assertEqual(0, probe["exit_code"])
        self.assertIn("codex-ssh-bridge-ok", probe["stdout"])
        result = self.bridge.run("devbox", "printf 'remote-ok'", cwd=".")
        self.assertEqual(0, result["exit_code"])
        self.assertEqual("remote-ok", result["stdout"])
        self.assertEqual(str(self.remote), result["cwd"])

    def test_bounded_file_round_trip_and_overwrite_guard(self) -> None:
        written = self.bridge.write_file(
            "devbox", "nested/hello.txt", "你好\n", create_parents=True
        )
        self.assertEqual(len("你好\n".encode()), written["bytes_written"])
        read = self.bridge.read_file("devbox", "nested/hello.txt")
        self.assertEqual("utf-8", read["encoding"])
        self.assertEqual("你好\n", read["content"])
        with self.assertRaisesRegex(BridgeError, "could not write"):
            self.bridge.write_file("devbox", "nested/hello.txt", "replacement")
        replaced = self.bridge.write_file(
            "devbox", "nested/hello.txt", "replacement", overwrite=True
        )
        self.assertEqual(11, replaced["bytes_written"])
        empty = self.bridge.write_file("devbox", "nested/empty.txt", "")
        self.assertEqual(0, empty["bytes_written"])
        self.assertEqual("", self.bridge.read_file("devbox", "nested/empty.txt")["content"])
        with self.assertRaisesRegex(BridgeError, "valid base64"):
            self.bridge.write_file("devbox", "nested/bad.bin", "%%%", encoding="base64")

    def test_output_truncation_and_path_escape(self) -> None:
        result = self.bridge.run(
            "devbox", "yes x | head -c 4096", max_output_bytes=1024
        )
        self.assertTrue(result["stdout_truncated"])
        self.assertEqual(1024, len(result["stdout"]))
        with self.assertRaisesRegex(BridgeError, "outside"):
            self.bridge.read_file("devbox", "../secret")

    def test_read_only_profile_blocks_mutation_surfaces(self) -> None:
        with self.assertRaisesRegex(BridgeError, "read-only"):
            self.bridge.run("prod-ro", "true")
        with self.assertRaisesRegex(BridgeError, "read-only"):
            self.bridge.write_file("prod-ro", "x", "x")
        (self.remote / "visible.txt").write_text("visible", encoding="utf-8")
        self.assertEqual(
            "visible", self.bridge.read_file("prod-ro", "visible.txt")["content"]
        )

    def test_unknown_host_and_config_validation(self) -> None:
        with self.assertRaisesRegex(BridgeError, "not allowlisted"):
            self.bridge.probe("other")
        bad = self.root / "bad.json"
        bad.write_text('{"version":1,"hosts":{"-bad":{"root":"."}}}', encoding="utf-8")
        with self.assertRaises(ConfigError):
            load_config(bad)

    def test_resolved_ssh_config_redacts_unrelated_options(self) -> None:
        resolved = self.bridge.resolved_ssh_config("devbox")["resolved"]
        self.assertEqual("127.0.0.1", resolved["hostname"])
        self.assertEqual("test-user", resolved["user"])
        self.assertNotIn("proxycommand", resolved)


class MCPServerTestCase(unittest.TestCase):
    def test_initialize_list_and_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote"
            remote.mkdir()
            config = root / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "ssh": {"binary": str(FAKE_SSH)},
                        "hosts": {"devbox": {"root": str(remote)}},
                    }
                ),
                encoding="utf-8",
            )
            requests = [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "ssh_list_hosts", "arguments": {}},
                },
            ]
            wire = "".join(json.dumps(item) + "\n" for item in requests)
            environment = os.environ.copy()
            environment["CODEX_SSH_BRIDGE_CONFIG"] = str(config)
            completed = subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "mcp" / "server.py")],
                input=wire,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
                env=environment,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            responses = [json.loads(line) for line in completed.stdout.splitlines()]
            self.assertEqual([1, 2, 3], [item["id"] for item in responses])
            self.assertEqual("codex-ssh-bridge", responses[0]["result"]["serverInfo"]["name"])
            names = [tool["name"] for tool in responses[1]["result"]["tools"]]
            self.assertEqual(
                [
                    "ssh_list_hosts",
                    "ssh_probe",
                    "ssh_run",
                    "ssh_read_file",
                    "ssh_write_file",
                ],
                names,
            )
            call_result = responses[2]["result"]
            self.assertFalse(call_result["isError"])
            self.assertEqual("devbox", call_result["structuredContent"]["hosts"][0]["alias"])


class CLITestCase(unittest.TestCase):
    def test_run_argument_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote"
            remote.mkdir()
            config = root / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "ssh": {"binary": str(FAKE_SSH)},
                        "hosts": {"devbox": {"root": str(remote)}},
                    }
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "scripts" / "codex-ssh"),
                    "--config",
                    str(config),
                    "run",
                    "devbox",
                    "--cwd",
                    ".",
                    "--",
                    "printf",
                    "%s",
                    "cli-ok",
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual("cli-ok", payload["stdout"])


if __name__ == "__main__":
    unittest.main()
