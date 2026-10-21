import importlib.metadata
from unittest.mock import patch

from first_commit.generated_files import proposal_name
from first_commit.models import SetupError
from first_commit.setup_files_plan import (
    REVISION_REQUIRED,
    SetupOptions,
    files_plan,
)
from first_commit.setup_hooks import HooksMissingError
from tests.setup_support import REVISION
from tests.support import TemporaryRootTest


class FilesPlanTest(TemporaryRootTest):
    def test_a_new_hook_file_needs_a_revision(self) -> None:
        with self.assertRaises(SetupError) as refused:
            files_plan(self.root, SetupOptions(revision=None))
        self.assertEqual(REVISION_REQUIRED, str(refused.exception))

    def test_an_existing_document_proposal_stops_the_plan(self) -> None:
        (self.root / "README.md").write_text("# Project\n", encoding="utf-8")
        (self.root / proposal_name("README.md")).write_text("old\n", encoding="utf-8")
        with self.assertRaisesRegex(SetupError, "proposal already exists"):
            files_plan(self.root, SetupOptions(revision=REVISION))

    def test_a_source_checkout_reads_the_repository_license(self) -> None:
        with patch(
            "first_commit.setup_files_plan.importlib.metadata.distribution",
            side_effect=importlib.metadata.PackageNotFoundError,
        ):
            plan = files_plan(
                self.root, SetupOptions(revision=REVISION, license_choice="apache-2.0")
            )
        self.assertIn(b"Apache License", plan.pending[self.root / "LICENSE"])

    def test_a_hook_file_without_first_commit_hooks_gets_no_proposal_unpinned(
        self,
    ) -> None:
        (self.root / ".pre-commit-config.yaml").write_text("repos: []\n", "utf-8")
        with self.assertRaises(HooksMissingError) as missing:
            files_plan(self.root, SetupOptions(revision=None))
        self.assertIsNone(missing.exception.proposal)
