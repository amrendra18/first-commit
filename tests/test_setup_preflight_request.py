from pathlib import Path
from unittest.mock import patch

from first_commit.hooks import HTTPS_REPOSITORY
from first_commit.setup import SetupRequest, setup_repository
from tests.setup_support import REVISION, SetupFixture
from tests.support import run_git


class PreflightRequestTest(SetupFixture):
    def preflight_calls(self, root: Path, *, preflight: bool) -> list[tuple[object]]:
        with (
            patch("first_commit.setup._preflight_source") as check,
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            actions = setup_repository(
                root,
                SetupRequest(revision=REVISION, confirmed=True, preflight=preflight),
                contributor=self.person,
            )
        self.assertIn("Verification: passed", actions)
        return [call.args for call in check.call_args_list]

    def test_the_request_decides_whether_setup_checks_the_hook_source(self) -> None:
        for repository in (False, True):
            for preflight in (True, False):
                with self.subTest(repository=repository, preflight=preflight):
                    root = self.root / f"project-{repository}-{preflight}"
                    root.mkdir()
                    if repository:
                        run_git(root, "init", "-q")
                    expected = [(root.resolve(), HTTPS_REPOSITORY)] if preflight else []
                    self.assertEqual(
                        expected, self.preflight_calls(root, preflight=preflight)
                    )
