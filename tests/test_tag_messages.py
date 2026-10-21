import io
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from unittest import mock

from first_commit import cli
from first_commit.candidates import CandidateError
from first_commit.git import GitError
from first_commit.history_messages import (
    TAG_MESSAGE_PATH,
    MessageScope,
    history_message_findings,
)
from first_commit.models import Result
from first_commit.policy import parse_policy
from first_commit.pushed import PushedScope
from first_commit.validation import history
from tests.gitleaks_support import (
    SLACK_LINE,
    SLACK_TOKEN,
    commit_fixture,
    needs_real_scanner,
    pushed_base_commit,
)
from tests.support import TemporaryRootTest, run_git

GITLEAKS_SUMMARY = "Gitleaks reported a tag-message finding."
HOME_LINE = "Built in /Users/" + "someone/work.\n"
PASSED = Result("test", ())
TAG = "d" * 40


class TagMessageTest(TemporaryRootTest):
    @needs_real_scanner
    def setUp(self) -> None:
        super().setUp()
        self.head = pushed_base_commit(self.root)
        self.policy = parse_policy(b'{"schema_version":1}', self.root)
        run_git(self.root, "config", "tag.gpgSign", "false")

    def tag(self, name: str, text: str, target: str = "HEAD") -> str:
        path = self.root / ".git/test-tag-message"
        path.write_text(text, encoding="utf-8")
        run_git(self.root, "tag", "-a", name, "-F", str(path), target)
        return run_git(self.root, "rev-parse", f"refs/tags/{name}").stdout.decode()[:12]

    def new_commit(self) -> str:
        (self.root / "change.txt").write_text("change\n", encoding="utf-8")
        commit_fixture(self.root, "change.txt")
        return run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()

    def scopes(self) -> tuple[PushedScope | None, ...]:
        return (None, PushedScope(self.new_commit(), "origin"))

    def findings(
        self, scope: PushedScope | None, private_values: tuple[str, ...] = ()
    ) -> list[tuple[str, str, int | None, str]]:
        result = history(self.root, self.policy, scope, private_values)
        return [
            (item.rule_id, item.path, item.line, item.summary)
            for item in result.findings
        ]

    def test_a_secret_in_a_tag_of_a_pushed_commit_is_reported_on_push_and_check(
        self,
    ) -> None:
        scopes = self.scopes()
        tag = self.tag("v1", "Release v1\n\n" + SLACK_LINE)
        expected = [
            ("secrets.gitleaks", TAG_MESSAGE_PATH, 3, f"Tag {tag}: {GITLEAKS_SUMMARY}")
        ]

        for scope in scopes:
            with self.subTest(scope=scope):
                self.assertEqual(expected, self.findings(scope))

    def test_an_old_tag_on_a_commit_the_remote_has_does_not_block_a_push(
        self,
    ) -> None:
        old = self.tag("v0", "Release v0\n\n" + SLACK_LINE, target=self.head)
        scope = PushedScope(self.new_commit(), "origin")

        self.assertEqual([], self.findings(scope))
        self.assertIn(f"Tag {old}: ", self.findings(None)[0][3])

    def test_privacy_rules_and_private_values_read_tag_messages(self) -> None:
        tag = self.tag("v1", "Release v1\n\n" + HOME_LINE + "By private-name.\n")

        self.assertEqual(
            [
                (
                    "privacy.user-home-path",
                    TAG_MESSAGE_PATH,
                    3,
                    f"Tag {tag}: Detected a literal user-home path.",
                ),
                (
                    "privacy.private-literal",
                    TAG_MESSAGE_PATH,
                    4,
                    f"Tag {tag}: Detected a configured private literal.",
                ),
            ],
            sorted(self.findings(None, ("private-name",)), key=lambda row: row[2]),
        )

    def test_a_tag_of_a_tag_has_both_messages_scanned(self) -> None:
        inner = self.tag("inner", "Inner\n\n" + SLACK_LINE)
        outer = self.tag("outer", "Outer\n\n" + HOME_LINE, target="inner")
        run_git(self.root, "tag", "-d", "inner")

        self.assertEqual(
            [
                ("privacy.user-home-path", f"Tag {outer}: "),
                ("secrets.gitleaks", f"Tag {inner}: "),
            ],
            sorted(
                (rule, summary[: len("Tag ") + 14])
                for rule, _, _, summary in self.findings(None)
            ),
        )

    def test_a_lightweight_tag_adds_no_message(self) -> None:
        run_git(self.root, "tag", "light")

        self.assertEqual([], self.findings(None))

    def test_the_finding_limit_and_the_message_size_limit_apply(self) -> None:
        self.tag("v1", "Release v1\n\n" + SLACK_LINE)
        large = self.tag("v2", "Release v2\n\n" + SLACK_LINE + "x" * 200 + "\n")

        one = replace(self.policy, max_findings=1)
        self.assertEqual(1, len(history(self.root, one, None).findings))
        small = replace(self.policy, max_message_bytes=300)
        with self.assertRaisesRegex(
            CandidateError, f"Tag message of {large} exceeds the size limit"
        ):
            history(self.root, small, None)

    def test_check_prints_the_tag_fix_line_and_never_the_secret(self) -> None:
        tag = self.tag("v1", "Release v1\n\n" + SLACK_LINE)
        output = io.StringIO()
        with (
            mock.patch("first_commit.validation.doctor", return_value=PASSED),
            mock.patch("first_commit.validation.working", return_value=PASSED),
            mock.patch("first_commit.validation.staged", return_value=PASSED),
            redirect_stdout(output),
        ):
            code = cli.main(("check", "--root", str(self.root)))

        self.assertEqual(1, code)
        self.assertIn(
            f'secrets.gitleaks "{TAG_MESSAGE_PATH}":3: Tag {tag}: {GITLEAKS_SUMMARY}',
            output.getvalue(),
        )
        self.assertIn(
            "  fix: Revoke any secret with its provider. Delete the tag with git tag -d",
            output.getvalue(),
        )
        self.assertNotIn(SLACK_TOKEN, output.getvalue())


class TagMessageParsingTest(TemporaryRootTest):
    def test_git_answers_that_are_not_objects_are_refused(self) -> None:
        policy = parse_policy(b'{"schema_version":1}', self.root)
        tag_ref = TAG.encode() + b" tag\n"
        for remotes, answers, error in (
            (["origin"], (b"HEAD\n",), "invalid remote commit"),
            ([], (b"", b"HEAD tag\n"), "invalid tag"),
            ([], (b"", tag_ref, TAG.encode() + b" blob 3\n"), "inconsistent"),
            ([], (b"", tag_ref, TAG.encode() + b" missing\n"), "inconsistent"),
        ):
            with (
                self.subTest(answers=answers),
                mock.patch(
                    "first_commit.history_messages.configured_remotes",
                    return_value=remotes,
                ),
                mock.patch(
                    "first_commit.history_messages.run_git", side_effect=answers
                ),
                self.assertRaisesRegex(GitError, error),
            ):
                history_message_findings(
                    self.root,
                    policy,
                    (),
                    MessageScope(None, warn_on_remote=True),
                    max_findings=9,
                )


if __name__ == "__main__":
    unittest.main()
