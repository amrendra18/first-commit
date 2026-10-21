import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import cli
from first_commit.git import GIT_STATUS_FIX, GitError, run_git
from tests.support import initialize_repository
from tests.support import run_git as fixture_git

GIT_FAILURE = (
    r"^error: Git command `git [a-z-]+` failed with exit code 128\.\n"
    r"fix: run `git status` in this repository to see Git's own error, then "
    r"rerun\.\n$"
)


class GitFailureMessageTest(unittest.TestCase):
    def test_a_failed_call_names_the_subcommand_exit_code_and_a_fix(self) -> None:
        canary = b"private-git-error-canary"
        completed = subprocess.CompletedProcess(
            args=["git"], returncode=128, stdout=canary, stderr=canary
        )
        arguments = ("--literal-pathspecs", "ls-files", "-z", "--", canary.decode())
        with patch("first_commit.git.subprocess.run", return_value=completed):
            with self.assertRaises(GitError) as context:
                run_git(Path(), arguments)
        self.assertEqual(
            "Git command `git ls-files` failed with exit code 128.\n"
            "fix: run `git status` in this repository to see Git's own error, "
            "then rerun.",
            str(context.exception),
        )

    def test_a_timeout_names_the_subcommand_and_the_limit(self) -> None:
        timeout = subprocess.TimeoutExpired(["git"], 120)
        with patch("first_commit.git.subprocess.run", side_effect=timeout):
            with self.assertRaises(GitError) as context:
                run_git(Path(), ("status",))
        self.assertEqual(
            "Git command `git status` timed out after 120 seconds.\n" + GIT_STATUS_FIX,
            str(context.exception),
        )


def run_check(root: Path) -> tuple[int, str, str]:
    output, error = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(error):
        code = cli.main(("check", "--root", str(root)))
    return code, output.getvalue(), error.getvalue()


class CheckGitErrorTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_outside_a_repository_the_error_names_the_folder_once(self) -> None:
        expected = (
            f"error: {self.root} is not inside a Git repository, or Git cannot read "
            "it.\n"
            "fix: run first-commit in a Git checkout, or run `first-commit setup` to "
            "create one; `git status` in that folder shows Git's own error.\n"
        )
        self.assertEqual((4, "", expected), run_check(self.root))

    def test_a_corrupt_index_names_the_git_subcommand_and_a_fix(self) -> None:
        initialize_repository(self.root)
        (self.root / ".repo-policy.json").write_text(
            '{"schema_version":1}\n', encoding="utf-8"
        )
        (self.root / "README.md").write_text("Readme.\n", encoding="utf-8")
        fixture_git(self.root, "add", "--", "README.md")
        (self.root / ".git/index").write_bytes(b"DIRC corrupt")
        code, output, error = run_check(self.root)
        self.assertEqual((4, ""), (code, output))
        self.assertRegex(error, GIT_FAILURE)


if __name__ == "__main__":
    unittest.main()
