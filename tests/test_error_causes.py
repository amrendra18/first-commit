import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from first_commit import cli
from first_commit.candidates import working_candidates
from first_commit.git import GitTimeoutError
from first_commit.gitleaks_scanner import CAPTURE, DependencyError, run_scanner
from first_commit.models import FileAccessError, LimitExceededError
from first_commit.paths import PathError, PathSizeError
from first_commit.policy import parse_policy
from first_commit.validation import message
from tests.cli_support import CliFixture
from tests.support import initialize_repository
from tests.support import run_git as fixture_git

PRE_COMMIT = "/opt/tools/pre-commit"
CHECK_HOOK = " run first-commit-check --hook-stage manual --all-files"


class ErrorCauseTest(CliFixture):
    def error_object(self, *arguments: str) -> tuple[int, dict[str, object]]:
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = cli.main((*arguments, "--format", "json", "--root", str(self.root)))
        return code, json.loads(output.getvalue())["error"]

    def unreadable(self, name: str) -> None:
        path = self.root / name
        path.write_text("# Reviewed\n", encoding="utf-8")
        path.chmod(0o200)
        self.addCleanup(path.chmod, 0o600)

    def test_an_unreadable_working_file_is_a_file_access_error(self) -> None:
        self.unreadable("locked.txt")
        code, value = self.error_object("check")
        self.assertEqual((1, "file-access", []), (code, value["code"], value["next"]))
        self.assertIn('"locked.txt": File cannot be read.', str(value["message"]))
        self.assertIn("`chmod u+r ./locked.txt`", str(value["message"]))

    def test_an_unreadable_document_in_a_hook_names_the_check_hook(self) -> None:
        self.unreadable("README.md")
        fixture_git(self.root, "add", "--", ".repo-policy.json")
        with (
            patch("first_commit.cli.find_executable", return_value=PRE_COMMIT),
            patch("first_commit.validation.scan_staged", return_value=()),
            patch("first_commit.validation.scan_hidden_staged", return_value=()),
        ):
            code, value = self.error_object("hook", "pre-commit")
        self.assertEqual((1, "file-access"), (code, value["code"]))
        self.assertEqual([PRE_COMMIT + CHECK_HOOK], value["next"])
        self.assertIn('"README.md": File cannot be read.', str(value["message"]))

    def test_a_file_under_a_link_out_of_the_repository_is_a_file_access_error(
        self,
    ) -> None:
        folder = self.root / "folder"
        folder.mkdir()
        (folder / "file.txt").write_text("text\n", encoding="utf-8")
        fixture_git(self.root, "add", "--", "folder/file.txt")
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        (Path(outside.name) / "file.txt").write_text("text\n", encoding="utf-8")
        (folder / "file.txt").unlink()
        folder.rmdir()
        folder.symlink_to(outside.name)
        code, value = self.error_object("check")
        self.assertEqual((1, "file-access", []), (code, value["code"], value["next"]))
        text = str(value["message"])
        self.assertIn('"folder/file.txt": File path escapes the repository.', text)
        self.assertIn("replace the link with a real folder", text)

    def stop(self, raised: object) -> tuple[int, dict[str, object]]:
        with patch("first_commit.validation.doctor", side_effect=raised):
            return self.error_object("check")

    def test_real_limit_stops_are_limit_exceeded_errors(self) -> None:
        def count(root: Path, _policy: object) -> None:
            list(working_candidates(root, 1, 10, paths=("one", "two")))

        def scanner_timeout(root: Path, _policy: object) -> None:
            timeout = subprocess.TimeoutExpired(["gitleaks"], 120)
            with patch(
                "first_commit.gitleaks_scanner.subprocess.run", side_effect=timeout
            ):
                run_scanner(["gitleaks"], root, {}, CAPTURE)

        for stop in (count, scanner_timeout):
            with self.subTest(stop=stop.__name__):
                code, value = self.stop(stop)
                self.assertEqual((1, "limit-exceeded"), (code, value["code"]))

    def test_a_git_command_over_its_time_limit_is_a_limit_exceeded_error(
        self,
    ) -> None:
        with patch("first_commit.git.GIT_TIMEOUT_SECONDS", 0.000001):
            code, value = self.error_object("check")
        self.assertEqual((1, "limit-exceeded"), (code, value["code"]))
        self.assertIn("timed out after 1e-06 seconds", str(value["message"]))
        self.assertIn("`git status` answers", str(value["message"]))

    def test_a_git_timeout_under_a_wrapper_is_a_limit_exceeded_error(self) -> None:
        timeout = GitTimeoutError(("ls-files", "--stage"))
        with patch("first_commit.candidates.run_git", side_effect=timeout):
            code, value = self.error_object("check")
        self.assertEqual((1, "limit-exceeded"), (code, value["code"]))
        self.assertIn("`git ls-files` timed out", str(value["message"]))

    def test_a_gitleaks_rule_file_is_refused_repository_content(self) -> None:
        (self.root / ".gitleaks.toml").write_text("[extend]\n", encoding="utf-8")
        code, value = self.error_object("check")
        self.assertEqual(
            (1, "repository-content", []), (code, value["code"], value["next"])
        )
        self.assertIn(".gitleaks.toml", str(value["message"]).split("No single")[0])
        self.assertIn("No single command fixes this; remove", str(value["message"]))


class LimitErrorTest(unittest.TestCase):
    def test_a_path_count_over_the_limit_is_a_limit_error(self) -> None:
        with self.assertRaisesRegex(LimitExceededError, "File count exceeds"):
            working_candidates(Path(), 1, 10, paths=("one", "two"))

    def test_a_file_that_grows_past_the_limit_is_a_limit_error(self) -> None:
        with (
            patch("first_commit.candidates.os.path.lexists", return_value=True),
            patch(
                "first_commit.candidates.read_worktree_bytes",
                side_effect=PathSizeError("File exceeds the size limit."),
            ),
            self.assertRaisesRegex(LimitExceededError, "exceeds the size limit"),
        ):
            list(working_candidates(Path("/repository"), 1, 10, paths=("one",)))

    def test_an_unreadable_file_is_a_file_access_error(self) -> None:
        with (
            patch("first_commit.candidates.os.path.lexists", return_value=True),
            patch(
                "first_commit.candidates.read_worktree_bytes",
                side_effect=PathError("File cannot be read."),
            ),
            self.assertRaisesRegex(FileAccessError, '^"one": File cannot be read.$'),
        ):
            list(working_candidates(Path("/repository"), 1, 10, paths=("one",)))

    def test_a_gitleaks_timeout_is_a_limit_error_and_a_dependency_error(self) -> None:
        timeout = subprocess.TimeoutExpired(["gitleaks"], 120)
        with (
            patch("first_commit.gitleaks_scanner.subprocess.run", side_effect=timeout),
            self.assertRaisesRegex(LimitExceededError, "timed out") as context,
        ):
            run_scanner(["gitleaks"], Path("/repository"), {}, CAPTURE)
        self.assertIsInstance(context.exception, DependencyError)

    def test_a_commit_message_over_the_limit_is_a_limit_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            policy = parse_policy(b'{"schema_version":1}', root)
            path = root / ".git" / "COMMIT_EDITMSG"
            path.write_text("fix: too long\n", encoding="utf-8")
            with self.assertRaisesRegex(
                LimitExceededError, "^Commit message exceeds the size limit.$"
            ):
                message(root, replace(policy, max_message_bytes=4), path)


if __name__ == "__main__":
    unittest.main()
