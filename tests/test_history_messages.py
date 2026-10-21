import os
import subprocess
import unittest
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path
from unittest import mock

from first_commit.candidates import CandidateError
from first_commit.git import GitError
from first_commit.gitleaks_blobs import MESSAGE_PATH
from first_commit.history_messages import MessageScope, history_message_findings
from first_commit.models import Candidate, Result, Severity
from first_commit.policy import parse_policy
from first_commit.pushed import PushedScope
from first_commit.validation import history, message
from tests.gitleaks_support import (
    SLACK_LINE,
    SLACK_TOKEN,
    history_cli,
    needs_real_scanner,
    pushed_base_commit,
    stage_allowed_slack_token,
)
from tests.support import (
    TemporaryRootTest,
    commit_message,
    run_git,
)

HOME_LINE = b"- Built in /Users/" + b"someone/work.\n"
COMMIT = "c" * 40
SCISSORS = "# ------------------------ >8 ------------------------\n"
GITLEAKS_SUMMARY = "Gitleaks reported a commit-message finding."
PASSED = Result("test", ())


class CommittedMessageTest(TemporaryRootTest):
    @needs_real_scanner
    def setUp(self) -> None:
        super().setUp()
        pushed_base_commit(self.root)
        self.policy = parse_policy(b'{"schema_version":1}', self.root)
        self.changes = 0

    def head(self) -> str:
        return run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()

    def message_file(self, text: str) -> Path:
        path = self.root / ".git/test-message"
        path.write_text(text, encoding="utf-8")
        return path

    def commit(self, text: str) -> str:
        self.changes += 1
        change = self.root / "change.txt"
        change.write_text(f"change {self.changes}\n", encoding="utf-8")
        run_git(self.root, "add", "--", "change.txt")
        path = self.message_file(text)
        run_git(self.root, "commit", "-q", "--no-verify", "-F", str(path))
        return self.head()

    def pushed(self) -> PushedScope:
        return PushedScope(self.head(), "origin")

    def run_cli(self, *arguments: str) -> tuple[int, str]:
        environment = {
            "PRE_COMMIT_TO_REF": self.head(),
            "PRE_COMMIT_REMOTE_NAME": "origin",
        }
        return history_cli(self.root, arguments, environment)

    def test_a_hand_written_scissors_line_hides_nothing_from_push_and_check(
        self,
    ) -> None:
        above = commit_message("feat: add change")
        text = above + SCISSORS + SLACK_LINE
        commit = self.commit(text)
        committed = run_git(self.root, "log", "-1", "--format=%B").stdout.decode()
        self.assertIn(SLACK_TOKEN, committed)
        # The commit-msg check only warns below the scissors line, as for `-v`.
        cut = message(self.root, self.policy, self.message_file(text))
        self.assertIn(
            ("secrets.gitleaks", Severity.WARNING),
            [(item.rule_id, item.severity) for item in cut.findings],
        )
        expected = (
            "secrets.gitleaks",
            MESSAGE_PATH,
            above.count("\n") + 2,
            f"Commit {commit[:12]}: {GITLEAKS_SUMMARY}",
        )

        for scope in (None, self.pushed()):
            with self.subTest(scope=scope):
                result = history(self.root, self.policy, scope)
                self.assertIn(
                    expected,
                    [
                        (item.rule_id, item.path, item.line, item.summary)
                        for item in result.findings
                    ],
                )

    def test_the_pre_push_hook_blocks_and_check_reports_without_the_secret(
        self,
    ) -> None:
        above = commit_message("feat: add change")
        commit = self.commit(above + SCISSORS + SLACK_LINE)
        location = f'secrets.gitleaks "{MESSAGE_PATH}":{above.count(chr(10)) + 2}'

        for arguments in (("hook", "pre-push"), ("check",)):
            with self.subTest(arguments=arguments):
                code, output = self.run_cli(*arguments)
                self.assertEqual(1, code)
                self.assertIn(
                    f"{location}: Commit {commit[:12]}: {GITLEAKS_SUMMARY}", output
                )
                self.assertIn(
                    "  fix: Revoke the secret and delete it from the commit message",
                    output,
                )
                self.assertNotIn(SLACK_TOKEN, output)

    def test_a_verbose_commit_with_an_allowed_staged_secret_pushes_cleanly(
        self,
    ) -> None:
        stage_allowed_slack_token(self.root)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "commit",
                "-q",
                "--no-verify",
                "-v",
                "-e",
                "-m",
                commit_message("feat: add config"),
            ],
            env={**os.environ, "GIT_EDITOR": "true"},
            capture_output=True,
            check=True,
        )
        committed = run_git(self.root, "log", "-1", "--format=%B").stdout.decode()
        self.assertNotIn(SLACK_TOKEN, committed)

        self.assertEqual((), history(self.root, self.policy, self.pushed()).findings)
        self.assertEqual(0, self.run_cli("hook", "pre-push")[0])

    def test_privacy_rules_and_private_values_read_committed_messages(self) -> None:
        above = commit_message("feat: add change")
        commit = self.commit(
            above + "- Built in /Users/" + "someone/work by private-name.\n"
        )
        line = above.count("\n") + 1

        result = history(self.root, self.policy, self.pushed(), ("private-name",))

        self.assertEqual(
            [
                (
                    "privacy.private-literal",
                    line,
                    f"Commit {commit[:12]}: Detected a configured private literal.",
                ),
                (
                    "privacy.user-home-path",
                    line,
                    f"Commit {commit[:12]}: Detected a literal user-home path.",
                ),
            ],
            [
                (item.rule_id, item.line, item.summary)
                for item in result.findings
                if item.path == MESSAGE_PATH
            ],
        )

    def test_only_commits_the_remote_lacks_are_scanned_on_push(self) -> None:
        old = self.commit(commit_message("feat: add change") + "- " + SLACK_LINE)
        run_git(self.root, "update-ref", "refs/remotes/origin/main", old)
        self.commit(commit_message("feat: change again"))

        self.assertEqual((), history(self.root, self.policy, self.pushed()).findings)
        everything = history(self.root, self.policy).findings
        self.assertEqual([MESSAGE_PATH], [item.path for item in everything])
        self.assertIn(old[:12], everything[0].summary)

    def test_a_message_that_is_not_utf8_is_still_scanned(self) -> None:
        path = self.root / ".git/test-message"
        path.write_bytes(b"feat: add change\n\n\xff\xfe " + SLACK_LINE.encode())
        tree = run_git(self.root, "write-tree").stdout.decode().strip()
        commit = run_git(
            self.root, "commit-tree", "-p", self.head(), "-F", str(path), tree
        )
        run_git(
            self.root, "update-ref", "refs/heads/main", commit.stdout.decode().strip()
        )

        findings = history(self.root, self.policy, self.pushed()).findings

        self.assertEqual(
            [("secrets.gitleaks", 3)], [(f.rule_id, f.line) for f in findings]
        )

    def test_the_finding_limit_and_the_message_size_limit_apply(self) -> None:
        self.commit(commit_message("feat: add change") + "- " + SLACK_LINE)
        large = self.commit(commit_message("feat: change again") + "- " + SLACK_LINE)

        one = replace(self.policy, max_findings=1)
        self.assertEqual(1, len(history(self.root, one, self.pushed()).findings))
        small = replace(self.policy, max_message_bytes=64)
        with self.assertRaisesRegex(
            CandidateError, f"Commit message of {large[:12]} exceeds the size limit"
        ):
            history(self.root, small, self.pushed())


def _consume(
    _root: Path, messages: Iterable[Candidate]
) -> list[tuple[str | None, int | None]]:
    for _ in messages:
        continue
    return []


class CommittedMessageParsingTest(TemporaryRootTest):
    def setUp(self) -> None:
        super().setUp()
        self.policy = parse_policy(b'{"schema_version":1}', self.root)

    def findings(self, max_findings: int = 10) -> list[tuple[str, int | None, str]]:
        found = history_message_findings(
            self.root, self.policy, (), MessageScope(None), max_findings=max_findings
        )
        return [(item.rule_id, item.line, item.summary) for item in found]

    def test_git_answers_that_are_not_commits_are_refused(self) -> None:
        for answers, error in (
            ((b"HEAD\n",), "invalid commit"),
            ((COMMIT.encode() + b"\n", COMMIT.encode() + b" blob 3\n"), "inconsistent"),
            (
                (COMMIT.encode() + b"\n", COMMIT.encode() + b" missing\n"),
                "inconsistent",
            ),
        ):
            with (
                self.subTest(answers=answers),
                mock.patch(
                    "first_commit.history_messages.run_git", side_effect=answers
                ),
                self.assertRaisesRegex(GitError, error),
            ):
                self.findings()

    def test_the_message_is_the_text_after_the_commit_headers(self) -> None:
        objects = [(COMMIT, b"tree x\nauthor y\n\nfeat: x\n\n" + HOME_LINE)]
        with (
            mock.patch(
                "first_commit.history_messages.run_git",
                side_effect=(
                    COMMIT.encode() + b"\n",
                    COMMIT.encode() + b" commit 9\n",
                    b"",
                ),
            ),
            mock.patch(
                "first_commit.history_messages.cat_file_objects", return_value=objects
            ),
            mock.patch(
                "first_commit.history_messages.message_locations", side_effect=_consume
            ),
        ):
            found = self.findings()

        self.assertEqual(
            [
                (
                    "privacy.user-home-path",
                    3,
                    f"Commit {COMMIT[:12]}: Detected a literal user-home path.",
                )
            ],
            found,
        )

    def test_privacy_findings_stop_at_the_limit(self) -> None:
        messages = [("a" * 12, HOME_LINE), ("b" * 12, HOME_LINE)]
        with (
            mock.patch("first_commit.history_messages._commit_ids", return_value=[]),
            mock.patch(
                "first_commit.history_messages._commit_messages",
                return_value=iter(messages),
            ),
            mock.patch(
                "first_commit.history_messages.message_locations", side_effect=_consume
            ),
        ):
            self.assertEqual(1, len(self.findings(max_findings=1)))

    def test_a_scanner_finding_without_a_line_names_no_commit(self) -> None:
        with (
            mock.patch("first_commit.history_messages._commit_ids", return_value=[]),
            mock.patch(
                "first_commit.history_messages._commit_messages", return_value=iter(())
            ),
            mock.patch(
                "first_commit.history_messages.message_locations",
                return_value=iter([(None, None), ("a" * 12, 2)]),
            ),
        ):
            found = self.findings(max_findings=1)

        self.assertEqual([("secrets.gitleaks", None, GITLEAKS_SUMMARY)], found)


if __name__ == "__main__":
    unittest.main()
