import importlib.metadata
from pathlib import Path
from unittest.mock import patch

from first_commit.generated_files import proposal_name
from first_commit.models import SetupError
from first_commit.setup_files_plan import (
    REVISION_REQUIRED,
    SetupOptions,
    files_plan,
)
from first_commit.setup_hooks import HooksMissingError, hook_bytes
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

    def test_a_launcher_hook_conflicts_outside_this_checkout(self) -> None:
        project = Path(__file__).resolve().parents[1]
        push_hook = (
            b"  - repo: local\n    hooks:\n      - id: project-push\n"
            b"        name: push\n        entry: bin/first-commit hook pre-push\n"
            b"        language: system\n        always_run: true\n"
            b"        pass_filenames: false\n        stages: [pre-push]\n"
        )
        for label, raw in (
            (
                "this checkout's hook file",
                (project / ".pre-commit-config.yaml").read_bytes(),
            ),
            (
                "a project push hook",
                hook_bytes(REVISION).replace(b"      - id: first-commit-push\n", b"")
                + push_hook,
            ),
        ):
            with self.subTest(label):
                (self.root / ".pre-commit-config.yaml").write_bytes(raw)
                with self.assertRaisesRegex(SetupError, "declaration conflicts"):
                    files_plan(self.root, SetupOptions(revision=REVISION))
