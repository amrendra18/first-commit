import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import cli
from tests.setup_support import synthetic_key
from tests.support import initialize_repository

PROJECT = Path(__file__).resolve().parents[1]
GIT_CONFIG = ".git/config"
HOOK = ".git/hooks/pre-commit"
RECORD = ".local/first-commit/contributor.json"
# Public-key files the test identities name, relative to the repository root.
KEY_FILES = ("key.pub", "file.pub", "var.pub", "record.pub", "typed.pub", "other.pub")


def write_keys(root: Path) -> None:
    for name in KEY_FILES:
        (root / name).write_text(synthetic_key() + " test\n", encoding="ascii")


class CliFixture(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        (self.root / ".repo-policy.json").write_text(
            '{"schema_version":1}\n', encoding="utf-8"
        )
        write_keys(self.root)
        machine = tempfile.TemporaryDirectory()
        self.addCleanup(machine.cleanup)
        self.identity = Path(machine.name) / "identity.json"
        self.enterContext(
            patch.dict(os.environ, {"FIRST_COMMIT_IDENTITY_FILE": str(self.identity)})
        )

    def run_cli(self, *arguments: str) -> tuple[int, str, str]:
        output = io.StringIO()
        error = io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = cli.main((*arguments, "--root", str(self.root)))
        return code, output.getvalue(), error.getvalue()

    def typed_setup(self, *answers: str) -> tuple[int, str]:
        with (
            patch(
                "first_commit.setup_cli.setup_repository",
                return_value=("Verification: passed",),
            ),
            patch("first_commit.setup_cli.load_contributor", return_value=None),
            patch("first_commit.cli.sys.stdin") as stream,
            patch("builtins.input", side_effect=answers),
        ):
            stream.isatty.return_value = True
            code, _, error = self.run_cli("setup")
        return code, error


class PatchedSetupFixture(CliFixture):
    def setUp(self) -> None:
        super().setUp()
        self.setup = self.enterContext(
            patch(
                "first_commit.setup_cli.setup_repository",
                return_value=("Verification: passed",),
            )
        )
        self.stdin = self.enterContext(patch("first_commit.cli.sys.stdin"))
        self.stdin.isatty.return_value = False
