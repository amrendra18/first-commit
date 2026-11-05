import re
import subprocess
from pathlib import Path

from first_commit.executables import find_executable
from first_commit.git import sanitized_git_environment
from first_commit.hooks import (
    INSTALLED_COMMAND,
    hook_entries,
    installed_command_problem,
    load_hook_config,
    runs_installed_command,
)
from first_commit.models import SetupFailedError
from first_commit.setup_command import HOOK_CONFIG
from first_commit.setup_files import read_if_present
from first_commit.setup_files_plan import INSTALLED_COMMAND_FIX

VERSION_TIMEOUT_SECONDS = 60
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\S*")
NO_VERSION = (
    "The first-commit on PATH did not print its version, so the hooks that run it "
    "may not run first-commit's checks.\n"
    "fix: put a working first-commit on PATH (see Install in the first-commit "
    "README), then rerun setup."
)


def verify_installed_command(root: Path) -> None:
    raw = read_if_present(root / HOOK_CONFIG)
    if raw is None or not runs_installed_command(hook_entries(load_hook_config(raw))):
        return
    problem = installed_command_problem(root)
    if problem is not None:
        raise SetupFailedError(
            f"Setup verification failed: {problem}\n{INSTALLED_COMMAND_FIX}."
        )
    program = find_executable(INSTALLED_COMMAND) or INSTALLED_COMMAND
    try:
        result = subprocess.run(
            [program, "version"],
            cwd=root,
            env=sanitized_git_environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=VERSION_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SetupFailedError(NO_VERSION) from error
    if result.returncode or not VERSION.fullmatch(result.stdout.strip()):
        raise SetupFailedError(NO_VERSION)
