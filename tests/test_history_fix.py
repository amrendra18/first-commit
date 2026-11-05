import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from first_commit.fixes import HOOK_FIXES, fix_for
from first_commit.gitleaks import RULE_ID, scan_history, scan_pushed, scan_staged
from first_commit.models import Finding
from first_commit.pushed import PushedScope
from tests.gitleaks_support import (
    SCANNER_PATH,
    SLACK_LINE,
    TOKEN,
    commit_fixture,
    needs_real_scanner,
    write_reporting_scanner,
)
from tests.support import initialize_repository, run_git

COMMIT = "0123456789abcdef" * 2 + "01234567"
SHORT = COMMIT[:12]


def _head(root: Path) -> str:
    return run_git(root, "rev-parse", "HEAD").stdout.decode().strip()


class HistoryFixTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def reported(self, commit: object) -> dict[str, str]:
        report = self.root / "fixture-report.json"
        entry = {"RuleID": "rule", "File": "cfg.txt", "StartLine": 1, "Commit": commit}
        report.write_text(json.dumps([entry]), encoding="utf-8")
        return {"PATH": SCANNER_PATH, "FIRST_COMMIT_TEST_REPORT": str(report)}

    def history_finding(self, commit: object) -> Finding:
        executable = str(write_reporting_scanner(self.root))
        (finding,) = scan_history(
            self.root,
            max_findings=10,
            executable=executable,
            environment=self.reported(commit),
        )
        return finding

    def test_a_history_finding_names_its_commit_and_the_history_fix(self) -> None:
        finding = self.history_finding(COMMIT)

        self.assertEqual(SHORT, finding.commit)
        self.assertIn(f"commit {SHORT}", finding.summary)
        fix = fix_for(finding) or ""
        self.assertIn(f"git rebase -i {SHORT}^", fix)
        self.assertIn("force push", fix)
        self.assertNotEqual(HOOK_FIXES[RULE_ID], fix)

    def test_the_root_commit_fix_runs_where_the_parent_form_fails(self) -> None:
        self.assertIn(
            "git rebase -i --root", fix_for(self.history_finding(COMMIT)) or ""
        )
        root = self.root / "root-commit"
        root.mkdir()
        initialize_repository(root)
        (root / "config.txt").write_text("one\n", encoding="utf-8")
        commit_fixture(root, "config.txt")
        head = _head(root)
        environment = {**os.environ, "GIT_SEQUENCE_EDITOR": "true"}

        def rebase(*arguments: str) -> int:
            return subprocess.run(
                ["git", "-C", str(root), "rebase", "-i", *arguments],
                env=environment,
                capture_output=True,
                check=False,
            ).returncode

        self.assertNotEqual(0, rebase(f"{head[:12]}^"))
        self.assertEqual(0, rebase("--root"))

    def test_a_commit_field_that_is_no_object_id_is_dropped(self) -> None:
        for commit in ("", "private-commit-canary", COMMIT[:39], 7):
            with self.subTest(commit=commit):
                finding = self.history_finding(commit)
                self.assertIsNone(finding.commit)
                self.assertNotIn("private-commit-canary", finding.summary)
                self.assertEqual(HOOK_FIXES[RULE_ID], fix_for(finding))

    @needs_real_scanner
    def test_a_removed_secret_names_the_commit_that_added_it(self) -> None:
        initialize_repository(self.root)
        (self.root / "cfg.txt").write_text(SLACK_LINE, encoding="utf-8")
        commit_fixture(self.root, "cfg.txt")
        added = _head(self.root)
        run_git(self.root, "rm", "-q", "--", "cfg.txt")
        run_git(self.root, "commit", "-q", "--no-verify", "-m", "chore: remove")
        head = _head(self.root)

        for findings in (
            scan_history(self.root, max_findings=10),
            scan_pushed(self.root, PushedScope(head, None), max_findings=10),
        ):
            (finding,) = findings
            self.assertEqual(added[:12], finding.commit)
            self.assertIn(f"git rebase -i {added[:12]}^", fix_for(finding) or "")
            self.assertNotIn(SLACK_LINE.split('"')[1], repr(finding))

    @needs_real_scanner
    def test_a_staged_finding_keeps_the_staged_fix(self) -> None:
        initialize_repository(self.root)
        (self.root / "value.txt").write_text(f'token = "{TOKEN}"\n', encoding="utf-8")
        run_git(self.root, "add", "--", "value.txt")

        (finding,) = scan_staged(self.root, max_findings=10)

        self.assertIsNone(finding.commit)
        self.assertEqual(HOOK_FIXES[RULE_ID], fix_for(finding))


if __name__ == "__main__":
    unittest.main()
