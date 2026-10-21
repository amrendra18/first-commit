import os
import subprocess
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest import mock


def run_git(root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
    )


def initialize_repository(root: Path) -> None:
    run_git(root, "init", "-q", "-b", "main")


def commit_message(subject: str) -> str:
    return (
        subject + "\n\nWhy:\n- Explain the reason.\n\n"
        "Changes:\n- Describe the change.\n\n"
        "Test Plan:\n- Run the focused tests.\n\n"
        "Risks:\n- Low: isolated fixture change.\n"
    )


class TemporaryRootTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)


@contextmanager
def global_excludes(directory: Path, pattern: str) -> Iterator[None]:
    global_ignore = directory / "global-ignore"
    global_ignore.write_text(pattern + "\n", encoding="utf-8")
    global_config = directory / "global-config"
    global_config.write_text(
        f"[core]\n\texcludesFile = {global_ignore}\n", encoding="utf-8"
    )
    with mock.patch.dict(
        os.environ,
        {"GIT_CONFIG_GLOBAL": str(global_config), "GIT_CONFIG_NOSYSTEM": "1"},
    ):
        yield
