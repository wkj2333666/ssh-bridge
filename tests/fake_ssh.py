#!/usr/bin/env python3
"""Test-only OpenSSH stand-in that executes the remote command locally."""

from __future__ import annotations

import os
import sys


def main() -> int:
    args = sys.argv[1:]
    if "-G" in args:
        alias = args[-1]
        print(f"host {alias}")
        print("hostname 127.0.0.1")
        print("user test-user")
        print("port 22")
        print("identityfile ~/.ssh/id_test")
        return 0
    if not args:
        return 2
    remote_command = args[-1]
    os.execvp("sh", ["sh", "-c", remote_command])
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
