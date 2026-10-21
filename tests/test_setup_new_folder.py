import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit.contributor import Contributor
from first_commit.git import GitError
from first_commit.models import SetupError
from first_commit.setup import SetupRequest, setup_repository
from first_commit.setup_apply import SETUP_LOCK_NAME
from first_commit.setup_files_plan import SetupOptions
from first_commit.setup_plan import RepositoryState, SetupPlan, plan_setup
from tests.setup_support import REVISION, SetupFixture
from tests.support import run_git

HOLD_LOCK = (
    "import fcntl, os, sys\n"
    "descriptor = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n"
    "fcntl.flock(descriptor, fcntl.LOCK_EX)\n"
    "print('held', flush=True)\n"
    "sys.stdin.read()\n"
)


class NewFolderSetupTest(SetupFixture):
    def hold_lock_in_another_process(self) -> None:
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                HOLD_LOCK,
                str(self.root / ".git" / SETUP_LOCK_NAME),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(holder.wait, 10)
        if holder.stdin is None or holder.stdout is None:
            self.fail("the lock holder has no pipes")
        self.addCleanup(holder.stdin.close)
        self.assertEqual("held\n", holder.stdout.readline())
        holder.stdout.close()

    def test_a_setup_that_loses_a_new_folder_keeps_the_other_setups_git(self) -> None:
        self.local_hooks()

        # The other setup runs git init and takes the lock after this one planned.
        def plan_then_lose(
            root: Path,
            options: SetupOptions,
            contributor: Contributor | None,
            repository: RepositoryState,
            *,
            check_scanner: bool = True,
        ) -> SetupPlan:
            plan = plan_setup(
                root, options, contributor, repository, check_scanner=check_scanner
            )
            if repository is RepositoryState.WOULD_INITIALIZE:
                run_git(self.root, "init", "-q")
                self.hold_lock_in_another_process()
            return plan

        with (
            patch("first_commit.setup.plan_setup", side_effect=plan_then_lose),
            self.assertRaisesRegex(SetupError, "Another process created .git"),
        ):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, confirmed=True),
                contributor=self.person,
            )
        self.assertTrue((self.root / ".git/HEAD").is_file())

    def test_a_failed_git_init_leaves_no_git_folder(self) -> None:
        self.local_hooks()
        with (
            patch("first_commit.setup.run_git", side_effect=GitError("init failed")),
            self.assertRaisesRegex(GitError, "init failed"),
        ):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, confirmed=True),
                contributor=self.person,
            )
        self.assertFalse((self.root / ".git").exists())

    def test_a_git_init_that_writes_then_fails_leaves_no_git_folder(self) -> None:
        self.local_hooks()

        def write_then_fail(root: Path, arguments: tuple[str, ...]) -> bytes:
            if arguments[0] == "init":
                (root / ".git/objects").mkdir(parents=True)
                (root / ".git/HEAD").write_text("ref: refs/heads/main\n", "ascii")
            raise GitError("init failed")

        with (
            patch("first_commit.setup.run_git", side_effect=write_then_fail),
            self.assertRaisesRegex(GitError, "init failed"),
        ):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, confirmed=True),
                contributor=self.person,
            )
        self.assertFalse((self.root / ".git").exists())


if __name__ == "__main__":
    unittest.main()
