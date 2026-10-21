import os
import shlex
import sys
from pathlib import Path
from unittest.mock import patch

from first_commit.gitleaks_scanner import DependencyError
from first_commit.models import SetupError
from first_commit.setup import SetupRequest, setup_repository
from first_commit.setup_hooks import hook_bytes
from tests.setup_support import REVISION, SetupFixture
from tests.support import run_git


class PreCommitFailureTest(SetupFixture):
    def apply(self) -> tuple[str, ...]:
        return setup_repository(
            self.root,
            SetupRequest(revision=REVISION, confirmed=True),
            contributor=self.person,
        )

    def test_a_schema_error_stops_setup_before_pre_commit_runs(self) -> None:
        run_git(self.root, "init", "-q")
        hook_file = self.root / ".pre-commit-config.yaml"
        hook_file.write_bytes(hook_bytes(REVISION) + b"fail_fast: maybe\n")
        with (
            patch("first_commit.setup_apply.run_pre_commit") as pre_commit,
            self.assertRaises(SetupError) as refused,
        ):
            self.apply()
        pre_commit.assert_not_called()
        self.assertEqual(
            "Pre-commit configuration failed validation; correct it before setup.\n"
            f"fix: run `{shlex.quote(sys.executable)} -m pre_commit validate-config "
            ".pre-commit-config.yaml` to see the error, correct the file, then rerun "
            "setup.",
            str(refused.exception),
        )

    def test_a_cache_path_under_a_file_names_the_cache_folder(self) -> None:
        self.initialized_with_hooks()
        blocker = self.root / "not-a-folder"
        blocker.write_bytes(b"")
        store = blocker / "pre-commit"
        with (
            patch.dict(os.environ, {"PRE_COMMIT_HOME": str(store)}),
            self.assertRaises(DependencyError) as refused,
        ):
            self.apply()
        self.assertEqual(
            "Hook environment install failed: pre-commit exited 1; it cannot use its "
            f"cache folder {store}.\n"
            f"fix: make {store} a folder you can write, or set PRE_COMMIT_HOME to "
            "one, then rerun setup.",
            str(refused.exception),
        )
        self.assertFalse(Path(self.root / ".local/first-commit").exists())
