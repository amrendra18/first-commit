import io
import json
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from first_commit import cli
from first_commit.git import GitError
from first_commit.gitleaks_scanner import DependencyError
from first_commit.models import SetupError
from first_commit.setup import SetupRequest, setup_repository
from first_commit.setup_files_plan import SetupOptions, files_plan
from first_commit.setup_trust import trust_plan
from tests.setup_support import REVISION, SetupFixture
from tests.support import commit_message, run_git


def _exit_code(error: Exception) -> int:
    return next(code for kind, _, code in cli.ERRORS if isinstance(error, kind))


class SetupErrorCodeTest(SetupFixture):
    def assert_not_a_bad_call(self, error: Exception, kind: type[Exception]) -> None:
        self.assertIsInstance(error, kind)
        self.assertNotIsInstance(error, SetupError)
        self.assertEqual(1, _exit_code(error))

    def test_an_invalid_root_from_git_is_a_git_error(self) -> None:
        run_git(self.root, "init", "-q")
        with (
            patch("first_commit.setup.git_path", side_effect=GitError("bad path")),
            self.assertRaises(Exception) as raised,
        ):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
        self.assert_not_a_bad_call(raised.exception, GitError)

    def test_unknown_git_state_of_the_trust_file_is_a_git_error(self) -> None:
        signers = self.root / ".local/first-commit/allowed-signers"
        signers.parent.mkdir(parents=True)
        signers.write_bytes(b"public@example.net ssh-ed25519 AAAA\n")
        with (
            patch("first_commit.setup_trust.is_tracked", side_effect=GitError("no")),
            self.assertRaises(Exception) as raised,
        ):
            trust_plan(self.root, None, trust_self=True, settings={})
        self.assert_not_a_bad_call(raised.exception, GitError)

    def test_a_damaged_packaged_license_is_a_dependency_error(self) -> None:
        with (
            patch(
                "first_commit.setup_files_plan.importlib.metadata.distribution"
            ) as distribution,
            self.assertRaises(Exception) as raised,
        ):
            distribution.return_value.read_text.return_value = "wrong license"
            files_plan(
                self.root, SetupOptions(revision=REVISION, license_choice="apache-2.0")
            )
        self.assert_not_a_bad_call(raised.exception, DependencyError)


class LinkedWorktreeSetupTest(SetupFixture):
    def setUp(self) -> None:
        super().setUp()
        self.main = self.root / "main"
        self.main.mkdir()
        run_git(self.main, "init", "-q", "-b", "main")
        run_git(self.main, "config", "user.name", "Example")
        run_git(self.main, "config", "user.email", "public@example.net")
        run_git(self.main, "commit", "-q", "--allow-empty", "-m", commit_message("a"))
        self.linked = self.root / "linked"
        run_git(self.main, "worktree", "add", "-q", str(self.linked))

    def test_setup_in_a_linked_worktree_names_the_main_worktree(self) -> None:
        with self.assertRaises(SetupError) as refused:
            setup_repository(
                self.linked,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
        message = str(refused.exception)
        self.assertIn("linked worktree", message)
        self.assertIn("does not support linked worktrees", message)
        self.assertIn(
            f"fix: commit from the main worktree at {self.main.resolve()}", message
        )

    def test_the_json_refusal_names_no_command_and_says_why(self) -> None:
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = cli.main(
                [
                    "setup",
                    "--dry-run",
                    "--revision",
                    REVISION,
                    "--format",
                    "json",
                    "--root",
                    str(self.linked),
                ]
            )
        value = json.loads(output.getvalue())["error"]
        self.assertEqual((2, "setup-input", []), (code, value["code"], value["next"]))
        self.assertIn("does not support linked worktrees", value["message"])
        self.assertIn(
            f"No single command fixes this; commit from the main worktree at "
            f"{self.main.resolve()}",
            value["message"],
        )
