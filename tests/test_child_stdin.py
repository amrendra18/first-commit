import os
import unittest
from collections.abc import Iterator
from contextlib import contextmanager

from first_commit.git import run_git
from first_commit.gitleaks_scanner import run_scanner
from tests.support import TemporaryRootTest, initialize_repository

CALLER_INPUT = b"input meant for the hook\n"
# The id `git hash-object --stdin` prints for empty input.
EMPTY_BLOB = b"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391\n"


# Puts a pipe that holds data on file descriptor 0, the stdin a child inherits.
@contextmanager
def caller_stdin(data: bytes) -> Iterator[None]:
    read, write = os.pipe()
    os.write(write, data)
    os.close(write)
    saved = os.dup(0)
    os.dup2(read, 0)
    os.close(read)
    try:
        yield
    finally:
        os.dup2(saved, 0)
        os.close(saved)


class ChildStdinTest(TemporaryRootTest):
    def test_git_reads_end_of_file_without_input(self) -> None:
        initialize_repository(self.root)
        with caller_stdin(CALLER_INPUT):
            output = run_git(self.root, ("hash-object", "--stdin"))
        self.assertEqual(EMPTY_BLOB, output)

    def test_gitleaks_reads_end_of_file_without_input(self) -> None:
        with caller_stdin(CALLER_INPUT):
            result = run_scanner(["/bin/cat"], self.root, None)
        self.assertEqual(b"", result.stdout)


if __name__ == "__main__":
    unittest.main()
