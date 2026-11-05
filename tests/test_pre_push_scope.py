import io
import json
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from unittest import mock

from first_commit import cli
from first_commit.gitleaks_scanner import CALIBRATION_INPUT
from first_commit.models import Result
from first_commit.policy import parse_policy
from first_commit.pushed import pushed_scope
from first_commit.pushed_privacy import pushed_privacy_findings, pushed_versions
from tests.gitleaks_support import (
    commit_fixture,
    needs_real_scanner,
    pushed_base_commit,
)
from tests.support import TemporaryRootTest, run_git

TOO_MANY_FILES = "File count exceeds the limit of 10,000 paths."
CANARY = "synthetic-first-push-canary"


class PrePushScopeTest(TemporaryRootTest):
    @needs_real_scanner
    def setUp(self) -> None:
        super().setUp()
        unsigned = mock.patch(
            "first_commit.validation.unsigned_commit_findings", return_value=[]
        )
        unsigned.start()
        self.addCleanup(unsigned.stop)
        pushed_base_commit(self.root)
        (self.root / "new.txt").write_text("clean\n", encoding="utf-8")
        commit_fixture(self.root, "new.txt")

    def run_cli(self, *arguments: str) -> tuple[int, str]:
        head = run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()
        environment = {"PRE_COMMIT_TO_REF": head, "PRE_COMMIT_REMOTE_NAME": "origin"}
        output = io.StringIO()
        with (
            mock.patch.dict("os.environ", environment),
            mock.patch(
                "first_commit.validation.doctor", return_value=Result("doctor", ())
            ),
            redirect_stdout(output),
            redirect_stderr(output),
        ):
            code = cli.main((*arguments, "--root", str(self.root)))
        return code, output.getvalue()

    def test_an_untracked_draft_does_not_block_a_push(self) -> None:
        (self.root / "notes.txt").write_text("draft   \n", encoding="utf-8")

        code, output = self.run_cli("hook", "pre-push")

        self.assertEqual(0, code, output)
        self.assertNotIn("notes.txt", output)

        code, output = self.run_cli("check")

        self.assertEqual(1, code)
        self.assertIn("FAIL working", output)
        self.assertIn('"notes.txt"', output)

    def test_a_large_working_tree_does_not_block_a_small_push(self) -> None:
        drafts = self.root / "drafts"
        drafts.mkdir()
        for number in range(10_001):
            (drafts / f"{number}.txt").touch()

        code, output = self.run_cli("hook", "pre-push")

        self.assertEqual(0, code, output)
        self.assertNotIn(TOO_MANY_FILES, output)

        code, output = self.run_cli("check")

        self.assertEqual(1, code)
        self.assertIn(TOO_MANY_FILES, output)

    def test_a_pushed_secret_still_blocks_the_push(self) -> None:
        (self.root / "key.txt").write_bytes(CALIBRATION_INPUT)
        commit_fixture(self.root, "key.txt")
        (self.root / "notes.txt").write_text("draft   \n", encoding="utf-8")

        code, output = self.run_cli("hook", "pre-push")

        self.assertEqual(1, code)
        self.assertIn('secrets.gitleaks "key.txt"', output)
        self.assertNotIn("notes.txt", output)

    def test_pre_push_reports_list_doctor_and_history_only(self) -> None:
        (self.root / "staged.txt").write_text("staged   \n", encoding="utf-8")
        run_git(self.root, "add", "--", "staged.txt")

        code, text = self.run_cli("hook", "pre-push", "--format", "json")

        self.assertEqual(0, code, text)
        names = [check["name"] for check in json.loads(text)["checks"]]
        self.assertEqual(["doctor", "history"], names)

        code, output = self.run_cli("hook", "pre-push")

        self.assertEqual(0, code, output)
        statuses = [line for line in output.splitlines() if line.startswith("PASS ")]
        self.assertEqual(["PASS doctor", "PASS history"], statuses)
        self.assertNotIn("staged", output)
        self.assertNotIn("working", output)


class FirstPushLimitTest(TemporaryRootTest):
    def test_a_first_push_past_the_limit_reads_the_pushed_branch(self) -> None:
        pushed_base_commit(self.root)
        (self.root / "new.txt").write_text(f"x {CANARY}\n", encoding="utf-8")
        commit_fixture(self.root, "new.txt")
        run_git(self.root, "switch", "-q", "-c", "side")
        for name in ("one.txt", "two.txt"):
            (self.root / name).write_text(name + "\n", encoding="utf-8")
            commit_fixture(self.root, name)
        run_git(self.root, "switch", "-q", "main")
        run_git(self.root, "remote", "add", "mirror", "https://example.invalid/m.git")
        policy = replace(parse_policy(b'{"schema_version":1}', self.root), max_files=3)
        scope = pushed_scope(
            {
                "PRE_COMMIT_LOCAL_BRANCH": "refs/heads/main",
                "PRE_COMMIT_REMOTE_NAME": "mirror",
            }
        )

        found = pushed_privacy_findings(
            self.root,
            policy,
            pushed_versions(self.root, scope, policy.max_files),
            (CANARY,),
            max_findings=10,
        )

        self.assertEqual(
            [("privacy.private-literal", "new.txt")],
            [(item.rule_id, item.path) for item in found],
        )
