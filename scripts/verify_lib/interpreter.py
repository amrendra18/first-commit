# This module runs before the Python version is known, so it uses only what
# Python 3.7 has, and the future import keeps its annotations unevaluated. The
# harness code it guards may use anything Python 3.11 has.
from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from pathlib import Path
from types import FrameType
from typing import NoReturn

PROJECT = Path(__file__).resolve().parents[2]
MINIMUM = (3, 11)
VARIABLE = "FIRST_COMMIT_VERIFY_PYTHON"
PROBE_TIMEOUT_SECONDS = 60
NOT_READY = 3
FORWARDED_SIGNALS = (signal.SIGTERM, signal.SIGHUP)


def _running() -> tuple[int, ...]:
    return tuple(sys.version_info[:3])


def _supported(python: str) -> bool:
    if not Path(python).is_file() or not os.access(python, os.X_OK):
        return False
    try:
        result = subprocess.run(
            [python, "-c", f"import sys; sys.exit(sys.version_info < {MINIMUM})"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


@contextlib.contextmanager
def handling_signals(
    numbers: Iterable[int],
    handler: Callable[[int, FrameType | None], object] | signal.Handlers,
) -> Iterator[None]:
    previous = {number: signal.signal(number, handler) for number in numbers}
    try:
        yield
    finally:
        for number, restored in previous.items():
            signal.signal(number, restored)


# The first Ctrl-C lets the child clean up; each later one sends it SIGTERM.
# SIGTERM and SIGHUP are passed on, so the child stops and removes its work folder.
def run_under(python: str, script: Path, arguments: Sequence[str]) -> int:
    interrupts = 0
    with subprocess.Popen([python, str(script), *arguments]) as child:

        def forward(number: int, _frame: object) -> None:
            child.send_signal(number)

        with handling_signals(FORWARDED_SIGNALS, forward):
            while True:
                try:
                    code = child.wait()
                    break
                except KeyboardInterrupt:
                    interrupts += 1
                    if interrupts > 1:
                        child.send_signal(signal.SIGTERM)
    return 128 - code if code < 0 else code


def _refuse(script: Path, why: str) -> NoReturn:
    minimum = ".".join(map(str, MINIMUM))
    running = ".".join(map(str, _running()))
    print(
        f"error: {script.as_posix()} needs Python {minimum} or newer; this is Python "
        f"{running} ({sys.executable}).\n"
        f"why: {why}.\n"
        "fix: create the project environment with `python3.13 -m venv .venv` and "
        "`.venv/bin/python -m pip install -e '.[test]'`, or set "
        f"{VARIABLE} to a Python {minimum} or newer that has pre-commit and PyYAML.",
        file=sys.stderr,
    )
    raise SystemExit(NOT_READY)


def harness_python() -> str:
    return os.environ.get(VARIABLE) or str(PROJECT / ".venv/bin/python")


def require_supported(script: Path, arguments: Sequence[str]) -> None:
    if _running() >= MINIMUM:
        return
    named = os.environ.get(VARIABLE)
    python = harness_python()
    if not _supported(python):
        minimum = ".".join(map(str, MINIMUM))
        _refuse(
            script,
            f"{VARIABLE} names {python}, which is not Python {minimum} or newer"
            if named
            else f"{python} is missing or is not Python {minimum} or newer",
        )
    raise SystemExit(run_under(python, script, arguments))
