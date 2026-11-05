from dataclasses import replace
from unittest import mock

from first_commit import validation
from first_commit.candidates import CandidateError
from first_commit.policy import parse_policy
from first_commit.pushed import PushedScope
from first_commit.pushed_privacy import pushed_versions
from tests.gitleaks_support import commit_fixture, pushed_base_commit
from tests.support import TemporaryRootTest, run_git

PARTIAL_PUSH = "git push <remote> <full commit id>:refs/heads/<branch>"


class PushLimitTest(TemporaryRootTest):
    def setUp(self) -> None:
        super().setUp()
        pushed_base_commit(self.root)
        for name in ("one.txt", "two.txt"):
            (self.root / name).write_text(name + "\n", encoding="utf-8")
            commit_fixture(self.root, name)
        self.head = run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()
        self.policy = replace(
            parse_policy(b'{"schema_version":1}', self.root), max_files=1
        )

    def test_a_push_past_the_version_limit_stops_before_any_scan(self) -> None:
        with (
            mock.patch("first_commit.validation.history") as history,
            mock.patch("first_commit.pushed_privacy.cat_file_blobs") as blobs,
            mock.patch("first_commit.validation.unsigned_commit_findings") as signed,
            self.assertRaisesRegex(CandidateError, "more than 1 file versions"),
        ):
            validation.pushed_history(
                self.root, self.policy, PushedScope(self.head, "origin")
            )

        history.assert_not_called()
        blobs.assert_not_called()
        signed.assert_not_called()

    def test_each_fix_line_names_a_refspec_git_accepts_for_a_new_branch(self) -> None:
        for scope in (PushedScope(self.head, "origin"), None):
            with (
                self.subTest(scope=scope),
                self.assertRaises(CandidateError) as error,
            ):
                pushed_versions(self.root, scope, self.policy.max_files)
            self.assertIn(PARTIAL_PUSH, str(error.exception))
            self.assertNotIn(":<branch>", str(error.exception))
