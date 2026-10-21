import os
import shlex
import subprocess
import sys
import threading
from collections.abc import Callable, Sequence
from pathlib import Path

from first_commit.git import sanitized_git_environment
from first_commit.gitleaks_scanner import DependencyError
from first_commit.models import SetupError
from first_commit.setup_command import HOOK_CONFIG

SETUP_TIMEOUT_SECONDS = 300
PROGRESS_INTERVAL_SECONDS = 30
SCHEMA_VALIDATION = (
    "import json,sys,cfgv; from pre_commit.clientlib import CONFIG_SCHEMA; "
    "cfgv.validate(json.load(sys.stdin),CONFIG_SCHEMA)"
)
PRE_COMMIT_STEPS = {
    "install-hooks": ("Hook environment install failed", "Installing hook environment"),
    "install": ("Hook script install failed", "Installing hook scripts"),
}
OTHER_STEP = ("Hook setup failed", "Running hook setup")


def validate_schema(content: bytes) -> None:
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", SCHEMA_VALIDATION],
            input=content,
            env=sanitized_git_environment(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=SETUP_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DependencyError(
            "Pre-commit schema validation could not run; check the setup "
            "environment and retry."
        ) from error
    if result.returncode:
        command = f"{_python_command()} -m pre_commit validate-config {HOOK_CONFIG}"
        raise SetupError(
            "Pre-commit configuration failed validation; correct it before setup.\n"
            f"fix: run `{command}` to see the error, correct the file, then rerun "
            "setup."
        )


def _python_command() -> str:
    return shlex.quote(sys.executable)


def progress_heartbeat(
    progress: Callable[[str], None],
    label: str,
    detail: str,
    done: threading.Event,
) -> None:
    elapsed = PROGRESS_INTERVAL_SECONDS
    while not done.wait(PROGRESS_INTERVAL_SECONDS):
        suffix = f"; {detail}" if detail else ""
        progress(f"{label}... {elapsed}s elapsed{suffix}")
        elapsed += PROGRESS_INTERVAL_SECONDS


# The rule pre-commit uses for the folder of its store, which holds the log.
def _pre_commit_log() -> Path:
    home = os.environ.get("PRE_COMMIT_HOME")
    cache = os.environ.get("XDG_CACHE_HOME")
    store = (
        Path(home)
        if home
        else (Path(cache) if cache else Path("~/.cache").expanduser()) / "pre-commit"
    )
    return store / "pre-commit.log"


# pre-commit makes its store folder before any other work and writes its log there,
# so a file in the way leaves no log to read.
def _cannot_be_folder(path: Path) -> bool:
    existing = next(item for item in (path, *path.parents) if os.path.lexists(item))
    return not existing.is_dir()


# pre-commit rewrites its log on every error, so the log comes before any rerun. A
# rerun shows the error only while the project's config and .git stay after rollback.
def _install_hooks_failure(error_label: str, code: int, *, offer_rerun: bool) -> str:
    store = _pre_commit_log().parent
    if _cannot_be_folder(store):
        return (
            f"{error_label}: pre-commit exited {code}; it cannot use its cache folder "
            f"{store}.\nfix: make {store} a folder you can write, or set "
            "PRE_COMMIT_HOME to one, then rerun setup."
        )
    rerun = f"{_python_command()} -m pre_commit install-hooks"
    again = (
        f" To see the error again, run `{rerun}` in the project folder."
        if offer_rerun
        else ""
    )
    return (
        f"{error_label}: pre-commit exited {code}; check Git access "
        "(HTTPS credentials or SSH authentication and host trust) and "
        "Python package index access for pinned build dependencies, "
        "then retry setup.\n"
        f"fix: read `{_pre_commit_log()}` before you rerun anything: it holds "
        "pre-commit's own error, and the next pre-commit error replaces it."
        f"{again}"
    )


def _pre_commit_failure(
    command: str, error_label: str, code: int, *, offer_rerun: bool
) -> Exception:
    if command == "install-hooks":
        return DependencyError(
            _install_hooks_failure(error_label, code, offer_rerun=offer_rerun)
        )
    return DependencyError(
        f"{error_label}: pre-commit exited {code}; review the trusted "
        "hook configuration and dependencies, then retry."
    )


def run_pre_commit(
    root: Path,
    arguments: Sequence[str],
    progress: Callable[[str], None] | None = None,
    *,
    offer_rerun: bool = False,
) -> None:
    error_label, label = PRE_COMMIT_STEPS.get(arguments[0], OTHER_STEP)
    detail = "dependency work or cache lock" if arguments[0] == "install-hooks" else ""
    done = threading.Event()
    heartbeat = None
    if progress is not None:
        progress(f"{label}...")
        heartbeat = threading.Thread(
            target=progress_heartbeat,
            args=(progress, label, detail, done),
            daemon=True,
        )
        heartbeat.start()
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-m", "pre_commit", *arguments],
            cwd=root,
            env=sanitized_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=SETUP_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DependencyError(
            f"{error_label}: pre-commit could not run; check tool availability and "
            "network access, then retry."
        ) from error
    finally:
        done.set()
        if heartbeat is not None:
            heartbeat.join(timeout=1)
    if result.returncode:
        raise _pre_commit_failure(
            arguments[0], error_label, result.returncode, offer_rerun=offer_rerun
        )
    if progress is not None:
        progress(f"{label}: done")
