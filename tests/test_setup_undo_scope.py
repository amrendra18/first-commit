import hashlib
import os
import signal
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit.contributor import CONTRIBUTOR_PATH
from first_commit.git import GitError
from first_commit.git import run_git as real_run_git
from first_commit.gitleaks_scanner import LOCAL_SCANNER_PATH, scanner_platform
from first_commit.models import SetupFailedError, SetupTerminatedError
from first_commit.setup import SetupRequest, setup_repository
from tests.setup_support import REVISION, SetupFixture

REQUEST = SetupRequest(revision=REVISION, trust_self=True, confirmed=True)
UNDONE = "Setup stopped on Ctrl-C; its changes were undone."
SCANNER = b"synthetic scanner"
# The Git call that fails: the second setting setup writes.
FAILED_CALL = 2


class ConcurrentConfigTest(SetupFixture):
    # Another process writes a setting and holds .git/config.lock, so setup's own
    # second git config fails without writing anything.
    def test_a_failed_git_config_keeps_another_writers_setting(self) -> None:
        self.initialized_with_hooks()
        calls = []

        def run_git(root: Path, arguments: tuple[str, ...]) -> bytes:
            calls.append(arguments)
            if len(calls) == FAILED_CALL:
                real_run_git(root, ("config", "--local", "other.writer", "kept"))
                raise GitError("Git command `git config` failed with exit code 255.")
            return real_run_git(root, arguments)

        with (
            patch("first_commit.setup_apply.run_git", side_effect=run_git),
            patch("first_commit.setup_apply.run_pre_commit"),
            self.assertRaises(SetupFailedError) as failed,
        ):
            setup_repository(self.root, REQUEST, contributor=self.person)
        message = str(failed.exception)
        self.assertIn("left the Git settings as they are", message)
        self.assertIn("fix: run `git config --local --list`", message)
        self.assertNotIn("undone", message)
        self.assertIn("kept", (self.root / ".git/config").read_text("utf-8"))
        self.assertFalse((self.root / CONTRIBUTOR_PATH).exists())
        self.assertFalse((self.root / ".repo-policy.json").exists())


class ScannerSignalTest(SetupFixture):
    # The real install_scanner links .local/bin/gitleaks, unlinks its temporary
    # file, and returns; a Ctrl-C after the link and before setup records the
    # scanner lands here.
    def install_scanner(self, root: Path) -> bool:
        super().install_scanner(root)
        os.kill(os.getpid(), signal.SIGINT)
        return True

    def stopped(self, pinned: bytes) -> str:
        self.initialized_with_hooks()
        digests = {scanner_platform(): hashlib.sha256(pinned).hexdigest()}
        with (
            patch("first_commit.setup_apply.BINARY_DIGESTS", digests),
            patch("first_commit.setup_apply.run_pre_commit"),
            self.assertRaises(SetupTerminatedError) as stopped,
        ):
            setup_repository(self.root, REQUEST, contributor=self.person)
        return str(stopped.exception)

    def test_ctrl_c_after_the_scanner_is_linked_removes_it(self) -> None:
        self.assertEqual(UNDONE, self.stopped(SCANNER))
        self.assertEqual([".pre-commit-config.yaml"], sorted(self.files()))
        self.assertFalse((self.root / ".local").exists())

    def test_a_scanner_that_is_not_the_pinned_one_is_kept(self) -> None:
        self.stopped(b"another binary")
        self.assertEqual(SCANNER, (self.root / LOCAL_SCANNER_PATH).read_bytes())


class ScannerAppearedFirstTest(SetupFixture):
    # Another process puts the pinned binary there after setup found the path free;
    # install_scanner then keeps it and returns False, and a later failure undoes.
    def install_scanner(self, root: Path) -> bool:
        super().install_scanner(root)
        return False

    def test_a_scanner_setup_did_not_write_is_kept(self) -> None:
        self.initialized_with_hooks()
        digests = {scanner_platform(): hashlib.sha256(SCANNER).hexdigest()}
        with (
            patch("first_commit.setup_apply.BINARY_DIGESTS", digests),
            patch(
                "first_commit.setup_apply.run_pre_commit",
                side_effect=SetupFailedError("pre-commit failed"),
            ),
            self.assertRaises(SetupFailedError),
        ):
            setup_repository(self.root, REQUEST, contributor=self.person)
        self.assertEqual(SCANNER, (self.root / LOCAL_SCANNER_PATH).read_bytes())


if __name__ == "__main__":
    unittest.main()
