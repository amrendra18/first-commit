import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import cli
from first_commit.fixes import SETUP_NAMING_RULES, UNNAMED_MAIN_WORKTREE, WORKTREE_FIX
from first_commit.models import Result
from tests.support import commit_message, run_git

CANARY = "synthetic-worktree-canary"


class LinkedWorktreeFixTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name).resolve()
        self.main = folder / f"main-{CANARY}"
        self.main.mkdir()
        run_git(self.main, "init", "-q", "-b", "main")
        run_git(self.main, "config", "user.name", "Example")
        run_git(self.main, "config", "user.email", "public@example.net")
        (self.main / ".repo-policy.json").write_text('{"schema_version":1}\n', "utf-8")
        (self.main / ".gitignore").write_text(".local/\n", "utf-8")
        run_git(self.main, "add", ".repo-policy.json", ".gitignore")
        run_git(self.main, "commit", "-q", "-m", commit_message("feat: start"))
        self.linked = folder / "linked"
        run_git(self.main, "worktree", "add", "-q", str(self.linked))
        private = self.linked / ".local/first-commit/private-values.txt"
        private.parent.mkdir(parents=True)
        private.write_text(CANARY + "\n", "utf-8")
        private.chmod(0o600)

    def run_cli(self, *arguments: str) -> tuple[int, str]:
        output = io.StringIO()
        passed = Result("test", ())
        with (
            redirect_stdout(output),
            redirect_stderr(io.StringIO()),
            patch("first_commit.validation.history", return_value=passed),
            patch("first_commit.validation.scan_staged", return_value=[]),
        ):
            code = cli.main((*arguments, "--root", str(self.linked)))
        return code, output.getvalue()

    def test_doctor_fix_lines_name_the_main_worktree(self) -> None:
        code, output = self.run_cli("doctor")
        self.assertEqual(1, code)
        expected = WORKTREE_FIX.format(main=UNNAMED_MAIN_WORKTREE)
        self.assertIn(f"  fix: {expected}", output)
        self.assertNotIn("Run first-commit setup", output)
        self.assertIn(
            f"Next action: commit from the main worktree at {UNNAMED_MAIN_WORKTREE}",
            output,
        )
        self.assertNotIn(str(self.main), output)

    def test_check_masks_a_private_value_in_the_main_worktree_path(self) -> None:
        code, output = self.run_cli("check", "--format", "json")
        self.assertEqual(1, code)
        self.assertNotIn(CANARY, output)
        masked = str(self.main).replace(CANARY, "<private value>")
        fixes = [
            finding["fix"]
            for check in json.loads(output)["checks"]
            for finding in check["findings"]
            if finding["rule_id"] in SETUP_NAMING_RULES
        ]
        self.assertTrue(fixes)
        self.assertEqual({WORKTREE_FIX.format(main=masked)}, set(fixes))


if __name__ == "__main__":
    unittest.main()
