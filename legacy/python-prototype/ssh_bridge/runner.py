from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import BinaryIO, Sequence


@dataclass(frozen=True)
class ProcessResult:
    argv: Sequence[str]
    exit_code: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    duration_ms: int


class _Capture:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.total = 0

    def read_from(self, stream: BinaryIO) -> None:
        while True:
            chunk = stream.read(65_536)
            if not chunk:
                return
            self.total += len(chunk)
            room = self.limit - len(self.data)
            if room > 0:
                self.data.extend(chunk[:room])

    @property
    def truncated(self) -> bool:
        return self.total > len(self.data)


def run_process(
    argv: Sequence[str],
    *,
    timeout_sec: int,
    max_output_bytes: int,
    input_bytes: bytes | None = None,
) -> ProcessResult:
    started = time.monotonic()
    process = subprocess.Popen(
        list(argv),
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_capture = _Capture(max_output_bytes)
    stderr_capture = _Capture(max_output_bytes)
    readers = [
        threading.Thread(target=stdout_capture.read_from, args=(process.stdout,), daemon=True),
        threading.Thread(target=stderr_capture.read_from, args=(process.stderr,), daemon=True),
    ]
    for reader in readers:
        reader.start()

    writer: threading.Thread | None = None
    if input_bytes is not None:
        assert process.stdin is not None

        def write_input() -> None:
            try:
                process.stdin.write(input_bytes)
                process.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            finally:
                process.stdin.close()

        writer = threading.Thread(target=write_input, daemon=True)
        writer.start()

    timed_out = False
    try:
        exit_code = process.wait(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            exit_code = process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            exit_code = process.wait()

    if writer is not None:
        writer.join(timeout=1)
    for reader in readers:
        reader.join(timeout=2)
    process.stdout.close()
    process.stderr.close()
    duration_ms = round((time.monotonic() - started) * 1000)
    return ProcessResult(
        argv=tuple(argv),
        exit_code=exit_code,
        stdout=bytes(stdout_capture.data),
        stderr=bytes(stderr_capture.data),
        stdout_truncated=stdout_capture.truncated,
        stderr_truncated=stderr_capture.truncated,
        timed_out=timed_out,
        duration_ms=duration_ms,
    )
