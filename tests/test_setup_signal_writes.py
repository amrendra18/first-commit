import os
import signal
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

from first_commit import paths, setup_files
from first_commit.contributor import create_contributor
from first_commit.git import GitError
from first_commit.git import run_git as real_run_git
from first_commit.models import SetupTerminatedError
from first_commit.setup import SetupRequest, setup_repository
from tests.setup_support import REVISION, SetupFixture

WRITES: dict[str, tuple[Callable[..., object], int]] = {
    "create_exclusive": (paths.create_exclusive, 7),
    "create_contributor": (create_contributor, 1),
    "create_local_file": (setup_files.create_local_file, 2),
    "run_git": (real_run_git, 9),
}
NAMES = {signal.SIGINT: "Ctrl-C", signal.SIGTERM: "SIGTERM"}
REQUEST = SetupRequest(revision=REVISION, trust_self=True, confirmed=True)


def _signal_after(
    real: Callable[..., object], call: int, number: int
) -> Callable[..., object]:
    calls: list[int] = []

    def write(*arguments: object, **options: object) -> object:
        result = real(*arguments, **options)
        calls.append(1)
        if len(calls) == call:
            os.kill(os.getpid(), number)
        return result

    return write


class SetupSignalWriteTest(SetupFixture):
    def new_repository(self) -> tuple[bytes, dict[str, bytes]]:
        temporary = tempfile.TemporaryDirectory(prefix="first-commit setup ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.initialized_with_hooks()
        return (self.root / ".git/config").read_bytes(), self.files()

    def assert_undone_after_each(self, name: str) -> None:
        real, count = WRITES[name]
        for call in sorted({1, count}):
            for number, label in NAMES.items():
                with self.subTest(call=call, signal=label):
                    before = self.new_repository()
                    with (
                        patch(
                            f"first_commit.setup_apply.{name}",
                            side_effect=_signal_after(real, call, number),
                        ),
                        patch("first_commit.setup_apply.run_pre_commit"),
                        self.assertRaises(SetupTerminatedError) as stopped,
                    ):
                        setup_repository(self.root, REQUEST, contributor=self.person)
                    self.assertEqual(
                        f"Setup stopped on {label}; its changes were undone.",
                        str(stopped.exception),
                    )
                    after = ((self.root / ".git/config").read_bytes(), self.files())
                    self.assertEqual(before, after)
                    self.assertFalse((self.root / ".local").exists())

    def test_a_signal_after_a_generated_file_is_written_leaves_none(self) -> None:
        self.assert_undone_after_each("create_exclusive")

    def test_a_signal_after_the_contributor_record_is_written_leaves_none(
        self,
    ) -> None:
        self.assert_undone_after_each("create_contributor")

    def test_a_signal_after_a_local_file_is_written_leaves_none(self) -> None:
        self.assert_undone_after_each("create_local_file")

    def test_a_signal_after_a_git_setting_is_written_leaves_none(self) -> None:
        self.assert_undone_after_each("run_git")

    def test_ctrl_c_that_stops_git_after_it_wrote_still_undoes_it(self) -> None:
        before = self.new_repository()

        def run_git(root: Path, arguments: tuple[str, ...]) -> bytes:
            real_run_git(root, arguments)
            os.kill(os.getpid(), signal.SIGINT)
            raise GitError("Git command `git config` failed with exit code 130.")

        with (
            patch("first_commit.setup_apply.run_git", side_effect=run_git),
            patch("first_commit.setup_apply.run_pre_commit"),
            self.assertRaises(SetupTerminatedError) as stopped,
        ):
            setup_repository(self.root, REQUEST, contributor=self.person)
        self.assertEqual(
            "Setup stopped on Ctrl-C; its changes were undone.", str(stopped.exception)
        )
        after = ((self.root / ".git/config").read_bytes(), self.files())
        self.assertEqual(before, after)

    def test_the_fixture_reaches_every_counted_write(self) -> None:
        self.new_repository()
        seen = dict.fromkeys(WRITES, 0)

        def counted(name: str) -> Callable[..., object]:
            def write(*arguments: object, **options: object) -> object:
                seen[name] += 1
                return WRITES[name][0](*arguments, **options)

            return write

        for name in WRITES:
            self.enterContext(patch(f"first_commit.setup_apply.{name}", counted(name)))
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            setup_repository(self.root, REQUEST, contributor=self.person)
        self.assertEqual({name: count for name, (_, count) in WRITES.items()}, seen)


if __name__ == "__main__":
    unittest.main()
