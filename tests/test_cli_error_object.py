import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import cli
from first_commit.candidates import CandidateError
from first_commit.contributor import ContributorError
from first_commit.git import GitError
from first_commit.gitleaks_scanner import DependencyError
from first_commit.models import (
    FileAccessError,
    LimitExceededError,
    RepositoryContentError,
    SetupBlockedError,
    SetupCancelledError,
    SetupError,
    SetupFailedError,
    SetupTerminatedError,
)
from first_commit.paths import PathError
from first_commit.policy_fields import PolicyError
from first_commit.private_values import PrivateValuesError
from tests.cli_support import CliFixture

COMMAND = "/opt/first-commit/bin/first-commit"
PRE_COMMIT = "/opt/tools/pre-commit"
CHECK_HOOK = " run first-commit-check --hook-stage manual --all-files"
NO_COMMAND = "No single command fixes this"
# Each error a run can stop on, with its error code and exit code.
ERROR_ROWS = (
    (SetupError("Setup input ended.\nfix: run setup in a terminal."), "setup-input", 2),
    (SetupCancelledError("Setup was cancelled."), "cancelled", 1),
    (SetupBlockedError("Another setup is running."), "setup-blocked", 1),
    (SetupFailedError("Setup failed verification."), "setup-failed", 1),
    (SetupTerminatedError("Setup stopped on SIGTERM."), "interrupted", 1),
    (KeyboardInterrupt(), "interrupted", 1),
    (PolicyError("The policy has unknown fields."), "policy-invalid", 2),
    (ContributorError("The record is invalid.", "delete it."), "contributor-record", 2),
    (PrivateValuesError("The list is a link."), "private-values", 2),
    (DependencyError("Gitleaks is unavailable."), "dependency-missing", 1),
    (GitError("Git returned an invalid commit."), "git-access", 1),
    (CandidateError("Git returned invalid index metadata."), "git-access", 1),
    (FileAccessError('"locked.txt": File cannot be read.'), "file-access", 1),
    (RepositoryContentError(".gitleaks.toml is refused."), "repository-content", 1),
    (LimitExceededError("File count exceeds the limit."), "limit-exceeded", 1),
    (PathError("The file changed."), "file-access", 1),
    (OSError("The disk failed."), "file-access", 1),
)


class ErrorObjectTest(CliFixture):
    def setUp(self) -> None:
        super().setUp()
        self.enterContext(patch.dict(os.environ, {cli.EXECUTABLE_VARIABLE: COMMAND}))

    def error_object(self, *arguments: str) -> tuple[int, dict[str, object]]:
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = cli.main(arguments)
        self.assertEqual("", error.getvalue())
        value = json.loads(output.getvalue())
        self.assertEqual(["error"], list(value))
        self.assertEqual(["code", "message", "next"], sorted(value["error"]))
        return code, value["error"]

    def checked(self, *arguments: str) -> tuple[int, dict[str, object]]:
        return self.error_object(
            *arguments, "--format", "json", "--root", str(self.root)
        )

    def test_each_error_class_has_its_code_exit_code_and_no_command(self) -> None:
        for raised, error_code, exit_code in ERROR_ROWS:
            with (
                self.subTest(error=type(raised).__name__),
                patch("first_commit.validation.doctor", side_effect=raised),
            ):
                code, value = self.checked("check")
                self.assertEqual(
                    (exit_code, error_code, []), (code, value["code"], value["next"])
                )
                self.assertIn(NO_COMMAND, str(value["message"]))
                self.assertNotIn("fix:", str(value["message"]))

    def test_the_message_drops_the_fix_line_and_says_why_next_is_empty(self) -> None:
        with patch("first_commit.validation.doctor", side_effect=ERROR_ROWS[0][0]):
            _, value = self.checked("check")
        self.assertEqual(
            "Setup input ended. No single command fixes this; run setup in a terminal.",
            value["message"],
        )

    def test_a_message_that_names_its_command_never_denies_one(self) -> None:
        text = (
            "Gitleaks 8.30.0 is unavailable; run 'first-commit setup' in this "
            "checkout, or install Gitleaks 8.30.0 on PATH."
        )
        with patch("first_commit.validation.doctor", side_effect=DependencyError(text)):
            code, value = self.checked("check")
        self.assertEqual(
            (1, "dependency-missing", text, []),
            (code, value["code"], value["message"], value["next"]),
        )

    def test_text_mode_keeps_the_error_and_fix_lines_on_stderr(self) -> None:
        with patch("first_commit.validation.doctor", side_effect=ERROR_ROWS[0][0]):
            code, output, error = self.run_cli("check")
        self.assertEqual(
            (2, "", "error: Setup input ended.\nfix: run setup in a terminal.\n"),
            (code, output, error),
        )

    def test_a_locked_git_config_blocks_a_dry_run_with_exit_one(self) -> None:
        (self.root / ".git" / "config.lock").touch()
        code, value = self.checked("setup", "--dry-run", "--revision", "1" * 40)
        self.assertEqual((1, "setup-blocked", []), (code, value["code"], value["next"]))
        self.assertEqual(
            "Git configuration is locked; retry later. No single command fixes this.",
            value["message"],
        )

    def test_a_missing_policy_file_has_its_own_code(self) -> None:
        (self.root / ".repo-policy.json").unlink()
        code, value = self.checked("check")
        self.assertEqual(
            (2, "policy-missing", []), (code, value["code"], value["next"])
        )
        self.assertIn(".repo-policy.json does not exist", str(value["message"]))
        (self.root / ".repo-policy.json").write_text("{", encoding="utf-8")
        code, value = self.checked("check")
        self.assertEqual((2, "policy-invalid"), (code, value["code"]))

    def test_a_folder_outside_git_is_a_git_access_error(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            code, value = self.error_object(
                "check", "--format", "json", "--root", folder
            )
        self.assertEqual((1, "git-access", []), (code, value["code"], value["next"]))
        self.assertIn("not inside a Git repository", str(value["message"]))

    def test_an_unknown_flag_names_the_verbs_help_as_next(self) -> None:
        for verb in ("check", "doctor"):
            with (
                self.subTest(verb=verb),
                patch.dict(os.environ, {cli.EXECUTABLE_VARIABLE: COMMAND}),
            ):
                code, value = self.checked(verb, "--no-such-flag")
                self.assertEqual((2, "invalid-arguments"), (code, value["code"]))
                self.assertEqual([f"{COMMAND} {verb} --help"], value["next"])
                message = str(value["message"])
                self.assertIn(
                    f"`first-commit {verb}` does not accept argument 2", message
                )
                self.assertIn("it accepts -h, --help, --root, --format", message)

    def test_an_unknown_verb_names_the_top_level_help_as_next(self) -> None:
        code, value = self.error_object("no-such-verb", "--format", "json")
        self.assertEqual((2, "invalid-arguments"), (code, value["code"]))
        self.assertEqual([COMMAND + " --help"], value["next"])

    def test_an_unsupported_platform_exits_one_in_both_modes(self) -> None:
        with patch.object(sys, "platform", "win32"):
            code, value = self.error_object("check", "--format", "json")
            self.assertEqual((1, "unsupported-platform"), (code, value["code"]))
            self.assertIn("this system reports win32", str(value["message"]))
            code, output, error = self.run_cli("check")
        self.assertEqual((1, ""), (code, output))
        self.assertIn("error: first-commit runs on macOS and Linux only", error)

    def test_a_hook_stage_names_the_check_hook_with_pre_commits_path(self) -> None:
        with (
            patch("first_commit.cli.find_executable", return_value=PRE_COMMIT),
            patch(
                "first_commit.validation.staged",
                side_effect=DependencyError("Gitleaks is unavailable."),
            ),
        ):
            code, value = self.checked("hook", "pre-commit")
            self.assertEqual(1, code)
            self.assertEqual(
                "Gitleaks is unavailable. Run the next command inside the repository.",
                value["message"],
            )
            self.assertEqual([PRE_COMMIT + CHECK_HOOK], value["next"])
            _, value = self.checked("hook", "pre-commit", "--no-such-flag")
            self.assertEqual([PRE_COMMIT + CHECK_HOOK], value["next"])

    def test_a_hook_stage_without_pre_commit_says_it_is_not_on_path(self) -> None:
        with (
            patch("first_commit.cli.find_executable", return_value=None),
            patch(
                "first_commit.validation.staged",
                side_effect=DependencyError("Gitleaks is unavailable."),
            ),
        ):
            _, value = self.checked("hook", "pre-commit")
        self.assertEqual([], value["next"])
        self.assertEqual(
            "Gitleaks is unavailable. pre-commit is not on PATH, so no command can "
            "rerun this check.",
            value["message"],
        )

    def test_a_hook_stage_without_a_readable_repository_names_no_command(self) -> None:
        with (
            patch("first_commit.cli.find_executable", return_value=PRE_COMMIT),
            tempfile.TemporaryDirectory() as folder,
        ):
            code, value = self.error_object(
                "hook", "pre-commit", "--format", "json", "--root", folder
            )
        self.assertEqual((1, "git-access", []), (code, value["code"], value["next"]))
        self.assertIn(
            "The check hook command runs only inside a repository Git can read, so "
            "no command can rerun this check.",
            str(value["message"]),
        )

    def test_the_command_path_variable_is_read_once_and_not_passed_on(self) -> None:
        self.checked("check", "--no-such-flag")
        self.assertNotIn(cli.EXECUTABLE_VARIABLE, os.environ)

    def program_file(self, mode: int) -> Path:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        program = Path(folder.name) / "first-commit"
        program.write_text("#!/bin/sh\n", encoding="utf-8")
        program.chmod(mode)
        return program

    def test_without_the_variable_the_program_file_that_ran_is_named(self) -> None:
        os.environ.pop(cli.EXECUTABLE_VARIABLE)
        program = self.program_file(0o755)
        with patch.object(sys, "argv", [str(program)]):
            _, value = self.checked("check", "--no-such-flag")
        self.assertEqual([f"{program.resolve()} check --help"], value["next"])

    def test_a_start_from_a_module_names_first_commit_from_path(self) -> None:
        os.environ.pop(cli.EXECUTABLE_VARIABLE)
        installed = {"first-commit": COMMAND}
        for start in (str(self.program_file(0o644)), "-c"):
            with (
                self.subTest(start=start),
                patch.object(sys, "argv", [start]),
                patch("first_commit.cli.find_executable", side_effect=installed.get),
            ):
                _, value = self.checked("check", "--no-such-flag")
                self.assertEqual([COMMAND + " check --help"], value["next"])

    def test_with_no_program_to_name_next_is_empty_and_says_why(self) -> None:
        os.environ.pop(cli.EXECUTABLE_VARIABLE)
        with (
            patch.object(sys, "argv", ["-c"]),
            patch("first_commit.cli.find_executable", return_value=None),
        ):
            code, value = self.checked("check", "--no-such-flag")
        self.assertEqual((2, []), (code, value["next"]))
        self.assertIn(
            "The command that fixes this cannot be named: first-commit did not start "
            "from a program file, and PATH holds no first-commit.",
            str(value["message"]),
        )


if __name__ == "__main__":
    unittest.main()
