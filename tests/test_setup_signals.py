import io
import os
import signal
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import cli, git, setup_apply
from first_commit.contributor import CONTRIBUTOR_PATH, Contributor
from first_commit.gitleaks_scanner import DependencyError
from first_commit.machine_identity import (
    EMAIL_VARIABLE,
    KEY_VARIABLE,
    NAME_VARIABLE,
    PATH_VARIABLE,
)
from first_commit.setup import SetupRequest, setup_repository
from first_commit.setup_apply import (
    TERMINATING_SIGNALS,
    SetupTerminatedError,
    setup_lock,
)
from first_commit.setup_files_plan import SetupOptions
from first_commit.setup_plan import RepositoryState, SetupPlan, plan_setup
from tests.setup_support import REVISION, SetupFixture

HOOK_CONFIG = ".pre-commit-config.yaml"
CTRL_C_UNDONE = "Setup stopped on Ctrl-C; its changes were undone."


def _signal_on_install_hooks(number: int) -> Callable[..., None]:

    def run(_root: Path, arguments: tuple[str, ...], **_options: object) -> None:
        if arguments[0] == "install-hooks":
            os.kill(os.getpid(), number)

    return run


def _held_after_ctrl_c(send: Callable[[], bool]) -> Callable[[], object]:
    real_held = setup_apply.signals_held

    @contextmanager
    def held() -> Iterator[list[int]]:
        if send():
            os.kill(os.getpid(), signal.SIGINT)
        with real_held() as received:
            yield received

    return held


class SetupSignalTest(SetupFixture):
    def stopped_setup(self) -> str:
        self.local_hooks()
        before = (self.root / HOOK_CONFIG).read_bytes()
        with self.assertRaises(SetupTerminatedError) as stopped:
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, confirmed=True),
                contributor=self.person,
            )
        left = [
            path
            for path in (self.root / ".git", self.root / CONTRIBUTOR_PATH)
            if path.exists()
        ]
        self.assertEqual(([], before), (left, (self.root / HOOK_CONFIG).read_bytes()))
        return str(stopped.exception)

    def test_each_terminating_signal_stops_setup_and_rolls_it_back(self) -> None:
        for number in TERMINATING_SIGNALS:
            name = signal.Signals(number).name
            with (
                self.subTest(signal=name),
                patch(
                    "first_commit.setup_apply.run_pre_commit",
                    side_effect=_signal_on_install_hooks(number),
                ),
            ):
                self.assertIn(name, self.stopped_setup())
                handlers = {signal.getsignal(item) for item in TERMINATING_SIGNALS}
                self.assertEqual({signal.SIG_DFL}, handlers)

    def test_ctrl_c_stops_setup_and_rolls_it_back(self) -> None:
        with patch(
            "first_commit.setup_apply.run_pre_commit", side_effect=KeyboardInterrupt
        ):
            self.assertEqual(CTRL_C_UNDONE, self.stopped_setup())

    def test_ctrl_c_during_rollback_is_ignored(self) -> None:
        real_roll_back = setup_apply.roll_back_applied

        def roll_back(applied: setup_apply._Applied) -> None:
            os.kill(os.getpid(), signal.SIGINT)
            real_roll_back(applied)

        with (
            patch(
                "first_commit.setup_apply.run_pre_commit",
                side_effect=KeyboardInterrupt,
            ),
            patch("first_commit.setup_apply.roll_back_applied", side_effect=roll_back),
        ):
            self.assertEqual(CTRL_C_UNDONE, self.stopped_setup())

    def test_ctrl_c_in_the_setup_command_prints_one_line_and_exits_two(self) -> None:
        self.local_hooks()
        machine = tempfile.TemporaryDirectory()
        self.addCleanup(machine.cleanup)
        variables = {
            NAME_VARIABLE: self.person.name,
            EMAIL_VARIABLE: self.person.email,
            KEY_VARIABLE: self.person.signing_key,
            PATH_VARIABLE: str(Path(machine.name) / "identity.json"),
        }
        output, error = io.StringIO(), io.StringIO()
        with (
            patch.dict(os.environ, variables),
            patch(
                "first_commit.setup_apply.run_pre_commit",
                side_effect=KeyboardInterrupt,
            ),
            redirect_stdout(output),
            redirect_stderr(error),
        ):
            code = cli.main(
                ("setup", "--yes", "--revision", REVISION, "--root", str(self.root))
            )

        self.assertEqual((2, f"error: {CTRL_C_UNDONE}\n"), (code, error.getvalue()))
        self.assertNotIn("Traceback", output.getvalue())
        self.assertFalse((self.root / ".git").exists())

    def test_a_second_ctrl_c_before_the_rollback_starts_is_ignored(self) -> None:
        with (
            patch(
                "first_commit.setup_apply.run_pre_commit",
                side_effect=_signal_on_install_hooks(signal.SIGINT),
            ),
            patch(
                "first_commit.setup_apply.signals_held",
                side_effect=_held_after_ctrl_c(lambda: True),
            ),
        ):
            self.assertEqual(CTRL_C_UNDONE, self.stopped_setup())

    def test_a_first_ctrl_c_before_the_rollback_of_another_failure_rolls_back(
        self,
    ) -> None:
        with (
            patch(
                "first_commit.setup_apply.run_pre_commit",
                side_effect=DependencyError("synthetic install failure"),
            ),
            patch(
                "first_commit.setup_apply.signals_held",
                side_effect=_held_after_ctrl_c(lambda: True),
            ),
        ):
            self.assertEqual(CTRL_C_UNDONE, self.stopped_setup())

    def test_a_first_ctrl_c_after_the_rollback_still_removes_new_git(self) -> None:
        sent: list[bool] = []

        def send() -> bool:
            ready = (self.root / ".git").exists() and not (
                self.root / CONTRIBUTOR_PATH
            ).exists()
            if ready and not sent:
                sent.append(True)
                return True
            return False

        held = _held_after_ctrl_c(send)
        with (
            patch(
                "first_commit.setup_apply.run_pre_commit",
                side_effect=DependencyError("synthetic install failure"),
            ),
            patch("first_commit.setup.signals_held", side_effect=held),
            patch("first_commit.setup_apply.signals_held", side_effect=held),
        ):
            self.assertEqual(CTRL_C_UNDONE, self.stopped_setup())
        self.assertEqual([True], sent)

    def test_ctrl_c_after_git_init_outside_the_plan_says_git_was_removed(
        self,
    ) -> None:
        def plan(
            root: Path,
            options: SetupOptions,
            contributor: Contributor | None,
            repository: RepositoryState,
            *,
            check_scanner: bool = True,
        ) -> SetupPlan:
            if repository is RepositoryState.INITIALIZED:
                os.kill(os.getpid(), signal.SIGINT)
            return plan_setup(
                root, options, contributor, repository, check_scanner=check_scanner
            )

        with patch("first_commit.setup.plan_setup", side_effect=plan):
            self.assertEqual(CTRL_C_UNDONE, self.stopped_setup())

    def test_a_second_signal_during_rollback_is_ignored(self) -> None:
        real_roll_back = setup_apply.roll_back_applied

        def roll_back(applied: setup_apply._Applied) -> None:
            os.kill(os.getpid(), signal.SIGHUP)
            real_roll_back(applied)

        with (
            patch(
                "first_commit.setup_apply.run_pre_commit",
                side_effect=_signal_on_install_hooks(signal.SIGTERM),
            ),
            patch("first_commit.setup_apply.roll_back_applied", side_effect=roll_back),
        ):
            self.assertIn("SIGTERM", self.stopped_setup())

    def test_a_signal_during_rollback_after_another_failure_is_ignored(self) -> None:
        real_roll_back = setup_apply.roll_back_applied

        def roll_back(applied: setup_apply._Applied) -> None:
            os.kill(os.getpid(), signal.SIGTERM)
            real_roll_back(applied)

        self.local_hooks()
        with (
            patch(
                "first_commit.setup_apply.run_pre_commit",
                side_effect=DependencyError("synthetic install failure"),
            ),
            patch("first_commit.setup_apply.roll_back_applied", side_effect=roll_back),
            self.assertRaisesRegex(DependencyError, "synthetic install failure"),
        ):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, confirmed=True),
                contributor=self.person,
            )
        self.assertFalse((self.root / ".git").exists())
        self.assertFalse((self.root / CONTRIBUTOR_PATH).exists())

    def test_a_signal_between_git_init_and_the_lock_removes_git(self) -> None:
        def stopped(*_arguments: object) -> None:
            raise AssertionError("the test handler ran; setup installed none")

        for number in TERMINATING_SIGNALS:
            self.addCleanup(signal.signal, number, signal.signal(number, stopped))

        def run_git(root: Path, arguments: tuple[str, ...]) -> bytes:
            output = git.run_git(root, arguments)
            if tuple(arguments) == ("init", "-q"):
                os.kill(os.getpid(), signal.SIGTERM)
            return output

        with patch("first_commit.setup.run_git", side_effect=run_git):
            self.assertIn("SIGTERM", self.stopped_setup())
        self.assertEqual(
            {stopped}, {signal.getsignal(item) for item in TERMINATING_SIGNALS}
        )

    def test_previous_handlers_return_and_other_threads_are_unchanged(self) -> None:
        (self.root / ".git").mkdir()
        previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
        self.addCleanup(signal.signal, signal.SIGHUP, previous)
        with setup_lock(self.root):
            self.assertIsNot(signal.SIG_IGN, signal.getsignal(signal.SIGHUP))
        self.assertIs(signal.SIG_IGN, signal.getsignal(signal.SIGHUP))

        seen = []

        def run() -> None:
            with setup_lock(self.root):
                seen.append(signal.getsignal(signal.SIGTERM))

        worker = threading.Thread(target=run)
        worker.start()
        worker.join()
        self.assertEqual([signal.getsignal(signal.SIGTERM)], seen)
