import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest.mock import patch

from first_commit.candidates import CandidateError, head_candidate, staged_candidates
from first_commit.git import GitError, run_git
from tests.support import initialize_repository
from tests.support import run_git as git

BATCH_CHECK = ("cat-file", "--batch-check")


class BlobSizeGitErrorTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
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
            patch("first_commit.candidates.run_git", side_effect=fail_batch_check)
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


if __name__ == "__main__":
    unittest.main()
