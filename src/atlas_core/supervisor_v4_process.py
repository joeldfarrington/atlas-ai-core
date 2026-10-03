"""Bounded process supervision for inactive Supervisor v4 qualification."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True, slots=True)
class SupervisedCompletedProcess:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    process_id: int
    process_group_id: int
    process_group_reaped: bool


class ProcessSupervisionError(RuntimeError):
    """A privacy-safe stop with proof that the launched process group was reaped."""

    def __init__(
        self,
        code: str,
        *,
        process_id: int | None = None,
        process_group_id: int | None = None,
        process_group_reaped: bool = False,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.process_id = process_id
        self.process_group_id = process_group_id
        self.process_group_reaped = process_group_reaped


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> bool:
    """Terminate the dedicated session, escalate once, and reap its leader."""

    def group_exists() -> bool:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    if group_exists():
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=0.75)
    except subprocess.TimeoutExpired:
        pass
    end = time.monotonic() + 0.75
    while group_exists() and time.monotonic() < end:
        time.sleep(0.025)
    if group_exists():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        return False
    end = time.monotonic() + 2
    while group_exists() and time.monotonic() < end:
        time.sleep(0.025)
    return process.poll() is not None and not group_exists()


def run_supervised(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    env: Mapping[str, str],
    pause_file: Path | None = None,
    max_output_bytes: int = 1_048_576,
    max_stderr_bytes: int | None = None,
    process_fork_denied: bool = False,
) -> SupervisedCompletedProcess:
    """Run one bounded child in a dedicated process group.

    Output is drained incrementally, and every stop path terminates and reaps
    the complete process group before returning control to Atlas.
    """

    arguments = tuple(str(item) for item in argv)
    if (
        not arguments
        or timeout <= 0
        or max_output_bytes <= 0
        or (max_stderr_bytes is not None and max_stderr_bytes <= 0)
        or not isinstance(process_fork_denied, bool)
    ):
        raise ValueError("Supervisor v4 process bounds are invalid")
    if pause_file is not None and pause_file.exists():
        raise ProcessSupervisionError(
            "pause_requested",
            process_group_reaped=True,
        )

    process = subprocess.Popen(
        list(arguments),
        cwd=str(cwd),
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    selector: selectors.BaseSelector | None = None
    cleanup_complete = False
    try:
        if process.stdout is None or process.stderr is None:
            reaped = _terminate_and_reap(process)
            cleanup_complete = True
            raise ProcessSupervisionError(
                "process_pipe_unavailable",
                process_id=process.pid,
                process_group_id=process.pid,
                process_group_reaped=reaped,
            )

        selector = selectors.DefaultSelector()
        stdout = bytearray()
        stderr = bytearray()
        streams = {process.stdout.fileno(): stdout, process.stderr.fileno(): stderr}
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream.fileno(), selectors.EVENT_READ)

        deadline = time.monotonic() + timeout
        stop_code: str | None = None
        while selector.get_map() or process.poll() is None:
            if pause_file is not None and pause_file.exists():
                stop_code = "pause_requested"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_code = "deadline_exceeded"
                break
            for key, _mask in selector.select(timeout=min(0.1, remaining)):
                try:
                    chunk = os.read(key.fd, 65_536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                streams[key.fd].extend(chunk)
                if (
                    max_stderr_bytes is not None
                    and streams[key.fd] is stderr
                    and len(stderr) > max_stderr_bytes
                ):
                    stop_code = "stderr_limit_exceeded"
                    break
                if len(stdout) + len(stderr) > max_output_bytes:
                    stop_code = "output_limit_exceeded"
                    break
            if stop_code is not None:
                break

        if stop_code is not None:
            reaped = _terminate_and_reap(process)
            cleanup_complete = True
            raise ProcessSupervisionError(
                stop_code,
                process_id=process.pid,
                process_group_id=process.pid,
                process_group_reaped=reaped,
            )

        process.wait(timeout=2)
        if process_fork_denied:
            # A bound sandbox has made descendants impossible. Reaping the
            # leader is therefore complete cleanup, and avoids probing or
            # signalling a numeric process-group ID after the PID can be reused.
            reaped = True
            cleanup_complete = True
        else:
            reaped = _terminate_and_reap(process)
            cleanup_complete = True
            if not reaped:
                raise ProcessSupervisionError(
                    "process_group_not_reaped",
                    process_id=process.pid,
                    process_group_id=process.pid,
                    process_group_reaped=False,
                )
        return SupervisedCompletedProcess(
            args=arguments,
            returncode=int(process.returncode),
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            process_id=process.pid,
            process_group_id=process.pid,
            process_group_reaped=True,
        )
    except BaseException:
        if not cleanup_complete:
            if process_fork_denied and process.returncode is not None:
                cleanup_complete = True
            else:
                _terminate_and_reap(process)
                cleanup_complete = True
        raise
    finally:
        if selector is not None:
            selector.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


__all__ = [
    "ProcessSupervisionError",
    "SupervisedCompletedProcess",
    "run_supervised",
]
