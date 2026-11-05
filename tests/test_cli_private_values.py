import io
import json
import os
import shutil
import signal
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from types import FrameType
from unittest.mock import patch

from first_commit import cli
from first_commit.models import Result
from first_commit.policy import REQUIRED_DOCUMENTS
from first_commit.private_values import MAX_PRIVATE_VALUES_BYTES
from tests.cli_support import CliFixture
from tests.support import run_git

CANARY = "synthetic-cli-private-canary"
RULE = "privacy.private-literal"


def _timed_out(_number: int, _frame: FrameType | None) -> None:
    raise TimeoutError("reading the user list did not finish")


class PrivateValuesFixture(CliFixture):
    def setUp(self) -> None:
        super().setUp()
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        for name in REQUIRED_DOCUMENTS:
            (self.root / name).write_text("# Reviewed\n", encoding="utf-8")
        self.private = self.root / ".local/first-commit/private-values.txt"
        self.private.parent.mkdir(parents=True)
        self.private.write_text(CANARY + "\n", encoding="utf-8")
        self.private.chmod(0o600)
        (self.root / "notes.txt").write_text(f"written by {CANARY}\n", "utf-8")
        run_git(self.root, "add", "--", ".gitignore", *REQUIRED_DOCUMENTS, "notes.txt")

    def run_without_scanner(self, *arguments: str) -> tuple[int, str, str]:
        passed = Result("test", ())
        with (
            patch("first_commit.validation.doctor", return_value=passed),
            patch("first_commit.validation.history", return_value=passed),
            patch("first_commit.validation.scan_staged", return_value=[]),
        ):
            return self.run_cli(*arguments)


class PrivateValuesCliTest(PrivateValuesFixture):
    def test_each_command_blocks_a_private_value_in_every_scope_it_checks(
        self,
    ) -> None:
        for arguments, scopes in (
            (("check",), {"working", "staged"}),
            (("hook", "pre-commit"), {"staged"}),
            (("hook", "pre-push"), {"working", "staged"}),
        ):
            with self.subTest(command=" ".join(arguments)):
                code, output, error = self.run_without_scanner(*arguments)
                self.assertEqual(1, code, output + error)
                self.assertIn(RULE, output)
                self.assertNotIn(CANARY, output + error)
                code, output, error = self.run_without_scanner(
                    *arguments, "--format", "json"
                )
                self.assertEqual((1, ""), (code, error))
                self.assertNotIn(CANARY, output)
                found = {
                    check["name"]
                    for check in json.loads(output)["checks"]
                    if any(item["rule_id"] == RULE for item in check["findings"])
                }
                self.assertEqual(scopes, found)

    def check_from_a_subfolder(self, *arguments: str) -> tuple[int, str]:
        subfolder = self.root / "docs"
        subfolder.mkdir(exist_ok=True)
        previous = Path.cwd()
        os.chdir(subfolder)
        self.addCleanup(os.chdir, previous)
        output = io.StringIO()
        passed = Result("test", ())
        with (
            redirect_stdout(output),
            patch("first_commit.validation.doctor", return_value=passed),
            patch("first_commit.validation.history", return_value=passed),
            patch("first_commit.validation.scan_staged", return_value=[]),
        ):
            code = cli.main(("check", *arguments))
        return code, output.getvalue()

    def test_the_repository_path_hides_a_private_value(self) -> None:
        folder = self.root.name
        self.private.write_text(f"{CANARY}\n{folder}\n", encoding="utf-8")
        code, output = self.check_from_a_subfolder()
        self.assertEqual(1, code)
        self.assertTrue(output.startswith("Repository: "), output)
        self.assertIn("<private value>", output.splitlines()[0])
        self.assertNotIn(folder.casefold(), output.casefold())
        code, output = self.check_from_a_subfolder("--format", "json")
        self.assertEqual(1, code)
        repository = json.loads(output)["repository"]
        self.assertIn("<private value>", repository)
        self.assertNotIn(folder.casefold(), repository.casefold())

    def test_a_refused_program_is_named_inside_the_repository(self) -> None:
        program = self.root / "bin/git"
        program.parent.mkdir()
        program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        program.chmod(0o755)
        search = os.pathsep.join((str(program.parent), os.environ["PATH"]))
        with patch.dict(os.environ, {"PATH": search}):
            code, _, error = self.run_cli("check")
        self.assertEqual(4, code)
        self.assertIn("Git on PATH is bin/git inside this repository", error)
        self.assertNotIn(self.root.name.casefold(), error.casefold())

    def test_a_refused_scanner_error_hides_a_private_value(self) -> None:
        program = self.root / f"tools-{CANARY}/gitleaks"
        program.parent.mkdir()
        program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        program.chmod(0o755)
        search = os.pathsep.join((str(program.parent), os.environ["PATH"]))
        for arguments in (
            ("check",),
            ("check", "--format", "json"),
            ("hook", "pre-commit"),
        ):
            with (
                self.subTest(command=" ".join(arguments)),
                patch.dict(os.environ, {"PATH": search}),
            ):
                code, output, error = self.run_cli(*arguments)
                self.assertEqual(3, code, output + error)
                self.assertIn(
                    "Gitleaks on PATH is tools-<private value>/gitleaks", error
                )
                self.assertNotIn(CANARY, output + error)


class UserPrivateValuesCliTest(PrivateValuesFixture):
    def setUp(self) -> None:
        super().setUp()
        self.private.write_text("# No project values.\n", encoding="utf-8")
        config = tempfile.TemporaryDirectory()
        self.addCleanup(config.cleanup)
        self.config = Path(config.name)
        self.user_list = self.config / "first-commit/private-values.txt"
        self.user_list.parent.mkdir()
        self.enterContext(patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.config)}))

    def write_user_list(
        self, path: Path, mode: int = 0o600, text: str = CANARY + "\n"
    ) -> None:
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)

    def input_error(self, root: Path | None = None) -> str:
        with patch.object(self, "root", root or self.root):
            code, output, error = self.run_without_scanner("check")
        self.assertEqual(2, code, output + error)
        return error

    def assert_blocked(self, root: Path | None = None) -> str:
        with patch.object(self, "root", root or self.root):
            code, output, error = self.run_without_scanner("check")
        self.assertEqual(1, code, output + error)
        self.assertIn(RULE, output)
        self.assertNotIn(CANARY, output + error)
        return error

    def test_the_user_list_blocks_a_value(self) -> None:
        self.write_user_list(self.user_list)
        self.assertEqual("", self.assert_blocked())
        home = Path(os.environ["HOME"])
        default = home / ".config/first-commit/private-values.txt"
        default.parent.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, home / ".config")
        self.write_user_list(default)
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": ""}):
            self.user_list.unlink()
            self.assert_blocked()

    def test_both_lists_apply_and_a_shared_value_is_reported_once(self) -> None:
        second = "synthetic-second-canary"
        self.write_user_list(self.user_list, text=f"{CANARY}\n{second}\n")
        self.private.write_text(CANARY + "\n", "utf-8")
        (self.root / "other.txt").write_text(second + "\n", "utf-8")
        code, output, _ = self.run_without_scanner("check", "--format", "json")
        self.assertEqual(1, code)
        self.assertNotIn(second, output)
        paths = sorted(
            item["path"]
            for check in json.loads(output)["checks"]
            if check["name"] == "working"
            for item in check["findings"]
            if item["rule_id"] == RULE
        )
        self.assertEqual(["notes.txt", "other.txt"], paths)

    def test_an_error_names_the_list_it_comes_from(self) -> None:
        user = "$XDG_CONFIG_HOME/first-commit/private-values.txt: "
        for content, problem in (
            (b"\xff\n", "Private-values file is not valid UTF-8 text."),
            (b"Same\nsame\n", "Private-values file contains a duplicate value."),
        ):
            with self.subTest(problem=problem):
                self.user_list.write_bytes(content)
                self.user_list.chmod(0o600)
                self.assertIn(user + problem, self.input_error())
        self.user_list.unlink()
        self.private.write_text("Same\nsame\n", "utf-8")
        self.assertIn(
            ".local/first-commit/private-values.txt: "
            "Private-values file contains a duplicate value.",
            self.input_error(),
        )

    # One comment line too long: an unlimited read would skip it and go on.
    def test_an_oversize_user_list_stops_the_run(self) -> None:
        self.write_user_list(self.user_list, text="#" * MAX_PRIVATE_VALUES_BYTES + "\n")
        self.assertIn(
            "$XDG_CONFIG_HOME/first-commit/private-values.txt: "
            "Private-values file is unreadable or exceeds the size limit.",
            self.input_error(),
        )

    # Without a nonblocking open, a pipe with no writer would wait forever.
    def test_a_pipe_or_an_unreadable_user_list_stops_the_run(self) -> None:
        os.mkfifo(self.user_list, 0o600)
        previous = signal.signal(signal.SIGALRM, _timed_out)
        self.addCleanup(signal.signal, signal.SIGALRM, previous)
        signal.alarm(10)
        try:
            error = self.input_error()
        finally:
            signal.alarm(0)
        self.assertIn(
            "fix: replace $XDG_CONFIG_HOME/first-commit/private-values.txt with a file",
            error,
        )
        self.user_list.unlink()
        if os.geteuid() == 0:
            self.skipTest("root can read a file with mode 000")
        self.write_user_list(self.user_list, 0o000)
        self.assertIn(
            "$XDG_CONFIG_HOME/first-commit/private-values.txt: "
            "Private-values file is unreadable or exceeds the size limit.",
            self.input_error(),
        )

    def test_only_the_user_list_may_be_a_link_to_a_regular_file(self) -> None:
        target = self.config / "master-list.txt"
        self.write_user_list(target)
        self.user_list.symlink_to(target)
        self.assert_blocked()
        self.private.unlink()
        self.private.symlink_to(target)
        code, _, error = self.run_without_scanner("check")
        self.assertEqual(2, code)
        self.assertIn("Private-values file must be a regular file.", error)
        self.private.unlink()
        for broken in (self.config, self.config / "missing.txt"):
            with self.subTest(target=broken.name):
                self.user_list.unlink()
                self.user_list.symlink_to(broken)
                code, _, error = self.run_without_scanner("check")
                self.assertEqual(2, code)
                self.assertIn(
                    "User private-values file must be a regular file or a link to one.",
                    error,
                )

    def test_a_broad_user_list_is_set_to_600_and_the_check_continues(self) -> None:
        target = self.config / "master-list.txt"
        self.write_user_list(target, 0o644)
        self.user_list.symlink_to(target)
        error = self.assert_blocked()
        self.assertEqual(0o600, target.stat().st_mode & 0o777)
        self.assertEqual(
            "Private values: set $XDG_CONFIG_HOME/first-commit/private-values.txt "
            "to mode 600.\n",
            error,
        )
        self.assertEqual("", self.assert_blocked())

    # The mode is read and changed through the one open file, never by its path.
    def test_the_user_list_mode_changes_through_the_open_file(self) -> None:
        target = self.config / "master-list.txt"
        self.write_user_list(target, 0o744)
        self.user_list.symlink_to(target)
        with patch("os.chmod", side_effect=AssertionError("changed by path")):
            error = self.assert_blocked()
        self.assertEqual(0o700, target.stat().st_mode & 0o777)
        self.assertEqual(
            "Private values: set $XDG_CONFIG_HOME/first-commit/private-values.txt "
            "to mode 700.\n",
            error,
        )

    def test_a_broad_user_list_it_cannot_change_warns_and_the_check_continues(
        self,
    ) -> None:
        self.write_user_list(self.user_list, 0o640)
        for name, change in (
            ("another owner", patch("os.getuid", return_value=os.getuid() + 1)),
            ("refused", patch("os.fchmod", side_effect=PermissionError)),
        ):
            with self.subTest(name), change:
                error = self.assert_blocked()
                self.assertEqual(0o640, self.user_list.stat().st_mode & 0o777)
                self.assertEqual(
                    "warning: $XDG_CONFIG_HOME/first-commit/private-values.txt is "
                    "open to other users; first-commit cannot set it to mode "
                    "600, so its owner should run `chmod 600` on it.\n",
                    error,
                )

    def linked_worktree(self) -> Path:
        run_git(self.root, "add", "--", ".repo-policy.json")
        run_git(
            self.root,
            "-c",
            "user.name=Example",
            "-c",
            "user.email=example@example.com",
            "commit",
            "-q",
            "--no-verify",
            "--no-gpg-sign",
            "-m",
            "start",
        )
        linked = self.root.parent / (self.root.name + "-linked")
        run_git(self.root, "worktree", "add", "-q", str(linked))
        self.addCleanup(shutil.rmtree, linked, ignore_errors=True)
        return linked

    def test_a_linked_worktree_adds_the_main_list_to_its_own(self) -> None:
        self.private.write_text(CANARY + "\n", encoding="utf-8")
        linked = self.linked_worktree()
        (linked / "notes.txt").write_text(f"written by {CANARY}\n", "utf-8")
        self.assert_blocked(linked)
        own = linked / ".local/first-commit/private-values.txt"
        own.parent.mkdir(parents=True)
        own.write_text("# The main list still applies.\n", encoding="utf-8")
        own.chmod(0o600)
        self.assert_blocked(linked)
        self.private.write_text("Same\nsame\n", "utf-8")
        self.assertIn(
            ".local/first-commit/private-values.txt in the main worktree: "
            "Private-values file contains a duplicate value.",
            self.input_error(linked),
        )

    def test_an_error_in_the_main_list_names_it(self) -> None:
        linked = self.linked_worktree()
        main = ".local/first-commit/private-values.txt in the main worktree: "
        (self.root / ".gitignore").write_text("", "utf-8")
        self.assertIn(
            main + "Private-values file must be protected by repository .gitignore.",
            self.input_error(linked),
        )
        (self.root / ".gitignore").write_text(".local/\n", "utf-8")
        target = self.config / "master-list.txt"
        self.write_user_list(target, text="# No values.\n")
        self.private.unlink()
        self.private.symlink_to(target)
        self.assertIn(
            main + "Private-values file must be a regular file.",
            self.input_error(linked),
        )
        shutil.rmtree(self.private.parent)
        self.private.parent.symlink_to(self.config)
        self.assertIn(
            main + "Private-values path is invalid.", self.input_error(linked)
        )
