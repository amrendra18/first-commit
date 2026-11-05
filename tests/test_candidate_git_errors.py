import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest.mock import patch

from first_commit.candidates import CandidateError, head_candidate, staged_candidates
from first_commit.git import GitError, run_git
from tests.cli_support import CliFixture
from tests.support import initialize_repository
from tests.support import run_git as git

BATCH_CHECK = ("cat-file", "--batch-check")


class BlobSizeGitErrorTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        git(self.root, "config", "user.name", "Test")
        git(self.root, "config", "user.email", "test@example.com")
        (self.root / "a.txt").write_text("text\n", encoding="utf-8")
        git(self.root, "add", "--", "a.txt")
        git(self.root, "commit", "-q", "--no-verify", "-m", "add a")

        def fail_batch_check(
            root: Path, arguments: Sequence[str], input_bytes: bytes | None = None
        ) -> bytes:
            if tuple(arguments) == BATCH_CHECK:
                raise GitError("batch check failed")
            return run_git(root, arguments, input_bytes)

        self.enterContext(
            patch("first_commit.git.run_git", side_effect=fail_batch_check)
        )

    def test_the_staged_reader_reports_the_git_error_as_a_candidate_error(
        self,
    ) -> None:
        with self.assertRaisesRegex(CandidateError, "^batch check failed$"):
            staged_candidates(self.root, 10, 1024, paths=("a.txt",))

    def test_the_committed_reader_says_the_committed_file_cannot_be_read(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            CandidateError, "^The committed copy of a.txt in HEAD cannot be read.$"
        ):
            head_candidate(self.root, "a.txt", 1024)


class UnreadableFileTest(CliFixture):
    def test_an_unreadable_file_is_named_masked_with_a_fix_line(self) -> None:
        canary = "synthetic-unreadable-canary"
        values = self.root / ".local/first-commit/private-values.txt"
        values.parent.mkdir(parents=True)
        values.write_text(canary + "\n", encoding="utf-8")
        values.chmod(0o600)
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        locked = self.root / f"notes/{canary}.txt"
        locked.parent.mkdir()
        locked.write_text("text\n", encoding="utf-8")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o600)

        code, _, error = self.run_cli("check")

        self.assertEqual(1, code)
        self.assertEqual(
            'error: "notes/<private value>.txt": File cannot be read.\n'
            "fix: run `ls -l ./notes/<private value>.txt` to see its owner and "
            "mode, make it readable (`chmod u+r ./notes/<private value>.txt` when "
            "you own it) or move it out of the repository, then rerun.\n",
            error,
        )

    def test_a_non_ascii_value_and_a_control_character_stay_hidden(self) -> None:
        # The mask runs on the raw path, then control characters are escaped, so a
        # non-ASCII value is masked and an escape byte never reaches the terminal.
        canary = "josé-unreadable-canary"
        values = self.root / ".local/first-commit/private-values.txt"
        values.parent.mkdir(parents=True)
        values.write_text(canary + "\n", encoding="utf-8")
        values.chmod(0o600)
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        locked = self.root / f"notes/{canary}\x1b.txt"
        locked.parent.mkdir()
        locked.write_text("text\n", encoding="utf-8")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o600)

        code, _, error = self.run_cli("check")

        self.assertEqual(1, code)
        self.assertNotIn("jos", error)
        self.assertNotIn("\x1b", error)
        self.assertIn('"notes/<private value>\\x1b.txt": File cannot be read.', error)

    def test_a_line_break_in_the_name_starts_no_fix_line(self) -> None:
        locked = self.root / "notes/a\nfix: run rm -rf ~.txt"
        locked.parent.mkdir()
        locked.write_text("text\n", encoding="utf-8")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o600)

        code, _, error = self.run_cli("check")

        self.assertEqual(1, code)
        lines = error.splitlines()
        self.assertEqual(1, sum(line.startswith("fix:") for line in lines), error)
        self.assertIn(
            '"notes/a\\x0afix: run rm -rf ~.txt": File cannot be read.', error
        )


if __name__ == "__main__":
    unittest.main()
