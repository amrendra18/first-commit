import json
import os
import unittest
from pathlib import Path
from unittest import mock

from first_commit.contributor import (
    CONTRIBUTOR_PATH,
    Contributor,
    record_bytes,
    setup_time,
)
from first_commit.pushed_signatures import (
    made_before,
    unsigned_commit_findings,
    unsigned_since_setup_findings,
)
from tests.gitleaks_support import history_cli, needs_real_scanner
from tests.support import (
    TemporaryRootTest,
    commit_message,
    initialize_repository,
    run_git,
)

SETUP = 1_700_000_000
RULE = "git.unsigned-commit"
HEADER = (
    b"tree 1\nauthor A <a@example.com> 1 +0000\ncommitter A <a@example.com> %s\n\nm\n"
)


class SetupTimeTest(TemporaryRootTest):
    def setUp(self) -> None:
        super().setUp()
        initialize_repository(self.root)
        run_git(self.root, "config", "user.name", "Test")
        run_git(self.root, "config", "user.email", "test@example.com")

    def record(self) -> Path:
        record = self.root / CONTRIBUTOR_PATH
        record.parent.mkdir(parents=True)
        record.write_bytes(
            record_bytes(Contributor("Test", "test@example.com", "key.pub"))
        )
        record.chmod(0o600)
        os.utime(record, (SETUP, SETUP))
        return record

    def commit(self, committed: int, authored: int | None = None) -> str:
        with mock.patch.dict(
            os.environ,
            {
                "GIT_COMMITTER_DATE": f"{committed} +0000",
                "GIT_AUTHOR_DATE": f"{committed if authored is None else authored} +0000",
            },
        ):
            run_git(
                self.root,
                *("commit", "-q", "--allow-empty", "--no-verify", "--no-gpg-sign"),
                *("-m", commit_message("feat: a commit")),
            )
        return run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()

    def pushed(self) -> list[str]:
        findings = unsigned_commit_findings(
            self.root, None, max_bytes=100_000, max_findings=100
        )
        self.assertTrue(all(item.rule_id == RULE for item in findings))
        return [str(item.commit) for item in findings]

    def checked(self) -> list[str]:
        findings = unsigned_since_setup_findings(
            self.root, max_bytes=100_000, max_findings=100
        )
        self.assertFalse(any(item.pushed for item in findings))
        return [str(item.commit) for item in findings]

    def test_the_setup_time_is_the_record_time(self) -> None:
        self.assertIsNone(setup_time(self.root))
        self.record()
        self.assertEqual(SETUP, setup_time(self.root))

    def test_a_linked_record_gives_no_setup_time(self) -> None:
        target = self.root / "elsewhere"
        target.write_text("{}\n", "utf-8")
        record = self.root / CONTRIBUTOR_PATH
        record.parent.mkdir(parents=True)
        record.symlink_to(target)
        self.assertIsNone(setup_time(self.root))

    def test_push_skips_only_commits_older_than_the_setup(self) -> None:
        self.record()
        self.commit(SETUP - 1)
        at_setup = self.commit(SETUP)
        after = self.commit(SETUP + 1)
        self.assertEqual([at_setup[:12], after[:12]], self.pushed())

    def test_push_with_no_record_checks_every_commit(self) -> None:
        old = self.commit(SETUP - 1)
        self.assertEqual([old[:12]], self.pushed())

    def test_a_commit_rewritten_after_the_setup_counts_as_new(self) -> None:
        self.record()
        rewritten = self.commit(SETUP + 1, authored=SETUP - 100)
        self.assertEqual([rewritten[:12]], self.pushed())

    def test_check_reports_only_unsigned_commits_since_the_setup(self) -> None:
        self.record()
        self.commit(SETUP - 1)
        after = self.commit(SETUP + 1)
        self.assertEqual([after[:12]], self.checked())

    @needs_real_scanner
    def test_the_check_command_reports_an_unsigned_commit_since_the_setup(self) -> None:
        (self.root / ".repo-policy.json").write_text('{"schema_version":1}\n', "utf-8")
        (self.root / ".gitignore").write_text(".local/\n", "utf-8")
        self.record()
        old = self.commit(SETUP - 1)
        new = self.commit(SETUP + 1)

        code, text = history_cli(self.root, ("check", "--format", "json"), {})

        history = json.loads(text)["checks"][-1]
        reported = [
            item["commit"] for item in history["findings"] if item["rule_id"] == RULE
        ]
        self.assertEqual(1, code)
        self.assertEqual([new[:12]], reported)
        self.assertNotIn(old[:12], reported)

    def test_check_with_no_record_reports_no_commit(self) -> None:
        self.commit(SETUP + 1)
        self.assertEqual([], self.checked())

    def test_check_leaves_out_a_commit_a_remote_holds(self) -> None:
        self.record()
        held = self.commit(SETUP + 1)
        run_git(self.root, "remote", "add", "origin", "https://example.invalid/x")
        run_git(self.root, "update-ref", "refs/remotes/origin/main", held)
        self.assertEqual([], self.checked())

    def test_an_empty_repository_reports_no_commit(self) -> None:
        self.record()
        self.assertEqual([], self.checked())

    def test_a_committer_time_that_cannot_be_read_counts_as_new(self) -> None:
        for broken in (b"soon +0000", b"", b"9" * 19 + b" +0000", b"1 0000"):
            with self.subTest(broken=broken):
                self.assertFalse(made_before(HEADER % broken, SETUP))
        self.assertFalse(made_before(b"tree 1\n\nm\n", SETUP))

    def test_made_before_compares_the_committer_time(self) -> None:
        self.assertTrue(made_before(HEADER % b"1699999999 +0000", SETUP))
        self.assertFalse(made_before(HEADER % b"1700000000 +0000", SETUP))
        self.assertFalse(made_before(HEADER % b"1699999999 +0000", None))
        message_line = HEADER % b"1700000000 +0000" + b"committer A <a> 1 +0000\n"
        self.assertFalse(made_before(message_line, SETUP))


if __name__ == "__main__":
    unittest.main()
