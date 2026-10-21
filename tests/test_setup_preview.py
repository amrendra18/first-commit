import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit.contributor import (
    CONTRIBUTOR_PATH,
    Contributor,
    ContributorError,
    create_contributor,
)
from first_commit.hooks import HTTPS_REPOSITORY, SSH_REPOSITORY
from first_commit.models import SetupError
from first_commit.setup import SetupRequest, setup_repository
from first_commit.setup_apply import setup_lock
from first_commit.setup_files import restore_git_config
from first_commit.setup_hooks import check_hook_config, configured_source, hook_bytes
from tests.setup_support import (
    REVISION,
    SetupFixture,
    create_allowed_signers,
    synthetic_key,
)
from tests.support import run_git


class SetupPreviewTest(SetupFixture):
    ACTIONS = (
        "Files",
        "Local contributor",
        "Private values",
        "Git identity/signing",
        "Commit template",
        "Hook source",
        "Hook cache",
        "Signature verification",
        "Gitleaks",
        "Hook scripts",
        "Hook environments",
        "Verification",
        "Next action",
    )

    def setUp(self) -> None:
        super().setUp()
        keys = tempfile.TemporaryDirectory(prefix="first-commit keys ")
        self.addCleanup(keys.cleanup)
        key = Path(keys.name) / "id_ed25519.pub"
        key.write_text(synthetic_key() + "\n", "utf-8")
        self.keyed = Contributor(self.person.name, self.person.email, str(key))

    def labels(self, lines: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(line.split(":", 1)[0] for line in lines)

    def expected(self, *, initialized: bool, trust_self: bool) -> tuple[str, ...]:
        labels = list(self.ACTIONS)
        if trust_self:
            labels.insert(labels.index("Hook source"), "Local signature trust")
        return tuple(labels if initialized else ["Git repository", *labels])

    def apply(self, *, trust_self: bool) -> tuple[str, ...]:
        with (
            patch("first_commit.setup._preflight_source"),
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            return setup_repository(
                self.root,
                SetupRequest(revision=REVISION, confirmed=True, trust_self=trust_self),
                contributor=self.keyed,
            )

    def test_every_preview_names_every_action_the_apply_step_takes(self) -> None:
        for initialized in (False, True):
            for person in (None, self.keyed):
                for trust_self in (False, True):
                    with (
                        self.subTest(
                            initialized=initialized,
                            contributor=person is not None,
                            trust_self=trust_self,
                        ),
                        tempfile.TemporaryDirectory() as folder,
                    ):
                        root = Path(folder)
                        if initialized:
                            run_git(root, "init", "-q")
                        preview = setup_repository(
                            root,
                            SetupRequest(
                                revision=REVISION, dry_run=True, trust_self=trust_self
                            ),
                            contributor=person,
                        )
                        self.assertEqual(
                            self.expected(
                                initialized=initialized, trust_self=trust_self
                            ),
                            self.labels(preview),
                        )
                        names = {path.name for path in root.iterdir()}
                        self.assertLessEqual(names, {".git"})

    def test_empty_folder_preview_names_the_gitleaks_download(self) -> None:
        preview = setup_repository(
            self.root, SetupRequest(revision=REVISION, dry_run=True)
        )
        self.assertIn(
            "Gitleaks: would download and install 8.30.0 from GitHub Releases",
            preview,
        )
        self.assertIn("Commit template: would set commit.template", preview)

    def test_applied_lines_match_the_preview_line_for_line(self) -> None:
        for initialized in (False, True):
            for trust_self in (False, True):
                with self.subTest(initialized=initialized, trust_self=trust_self):
                    if initialized:
                        run_git(self.root, "init", "-q")
                    self.local_hooks()
                    preview = setup_repository(
                        self.root,
                        SetupRequest(
                            revision=REVISION, dry_run=True, trust_self=trust_self
                        ),
                        contributor=self.keyed,
                    )
                    applied = self.apply(trust_self=trust_self)
                    self.assertEqual(self.labels(preview), self.labels(applied))
                    self.assertIn("Gitleaks: downloaded and installed 8.30.0", applied)
                    shutil.rmtree(self.root)
                    self.root.mkdir()

    def test_apply_checks_an_existing_repository_once_under_the_lock(self) -> None:
        self.initialized_with_hooks()
        with (
            patch(
                "first_commit.setup_files_plan.check_hook_config",
                wraps=check_hook_config,
            ) as checked,
            patch("first_commit.setup.setup_lock", wraps=setup_lock) as locked,
        ):
            self.apply(trust_self=False)
        self.assertEqual(1, checked.call_count)
        self.assertEqual(1, locked.call_count)


class SetupRecoveryTest(SetupFixture):
    def lock(self) -> Path:
        return self.root / ".git/first-commit-setup.lock"

    def apply(self) -> tuple[str, ...]:
        return setup_repository(
            self.root, SetupRequest(revision=REVISION), contributor=self.person
        )

    def local(self, key: str) -> bytes:
        return run_git(self.root, "config", "--local", "--get", key).stdout

    def test_lock_rejects_a_special_file_and_a_failed_lock_call(self) -> None:
        run_git(self.root, "init", "-q")
        os.mkfifo(self.lock())
        with self.assertRaisesRegex(
            SetupError,
            r"^The setup lock \.git/first-commit-setup\.lock is not a regular file, "
            r"(?s:.*)\nfix: run `ls -ld \.git/first-commit-setup\.lock`",
        ):
            with setup_lock(self.root):
                self.fail("unsafe lock acquired")
        self.lock().unlink()
        with (
            patch("first_commit.setup_apply.fcntl.flock", side_effect=OSError),
            self.assertRaisesRegex(SetupError, "could not be acquired"),
        ):
            with setup_lock(self.root):
                self.fail("failed lock acquired")

    def test_lock_another_process_replaced_is_kept(self) -> None:
        run_git(self.root, "init", "-q")
        with setup_lock(self.root):
            self.lock().unlink()
        with setup_lock(self.root):
            self.lock().unlink()
            self.lock().write_text("other process\n", encoding="utf-8")
        self.assertEqual("other process\n", self.lock().read_text("utf-8"))

    def test_git_config_edit_during_setup_stops_and_is_kept(self) -> None:
        self.initialized_with_hooks()

        def edited(root: Path, person: Contributor) -> None:
            create_contributor(root, person)
            run_git(root, "config", "--local", "fixture.edit", "yes")

        with (
            patch("first_commit.setup_apply.create_contributor", side_effect=edited),
            self.assertRaisesRegex(
                SetupError,
                r"^\.git/config changed while setup ran(?s:.*)\n"
                r"fix: run `git config --local --list`",
            ),
        ):
            self.apply()
        self.assertEqual(b"yes\n", self.local("fixture.edit"))
        self.assertFalse((self.root / CONTRIBUTOR_PATH).exists())
        self.assertFalse((self.root / ".repo-policy.json").exists())

    def test_failure_before_settings_leaves_git_config_unchanged(self) -> None:
        self.initialized_with_hooks()
        before = (self.root / ".git/config").read_bytes()
        with (
            patch(
                "first_commit.setup_apply.create_contributor",
                side_effect=ContributorError("Synthetic failure."),
            ),
            self.assertRaises(ContributorError),
        ):
            self.apply()
        self.assertEqual(before, (self.root / ".git/config").read_bytes())
        self.assertFalse((self.root / ".repo-policy.json").exists())
        self.assertFalse((self.root / ".local").exists())

    def test_policy_removed_during_setup_is_reported(self) -> None:
        self.initialized_with_hooks()

        def removed(root: Path, arguments: tuple[str, ...], **_options: object) -> None:
            if arguments[0] == "install-hooks":
                (root / ".repo-policy.json").unlink()

        with (
            patch("first_commit.setup_apply.run_pre_commit", side_effect=removed),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
            self.assertRaisesRegex(SetupError, "policy file was removed"),
        ):
            self.apply()
        self.assertFalse((self.root / CONTRIBUTOR_PATH).exists())

    def test_failed_identity_verification_rolls_back_settings(self) -> None:
        self.initialized_with_hooks()
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
            patch(
                "first_commit.setup_apply.contributor_findings",
                return_value=[object()],
            ),
            self.assertRaisesRegex(SetupError, "failed verification"),
        ):
            self.apply()
        with self.assertRaises(subprocess.CalledProcessError):
            self.local("user.email")

    def test_local_file_under_a_linked_local_folder_is_refused(self) -> None:
        outside = tempfile.TemporaryDirectory(prefix="first-commit outside ")
        self.addCleanup(outside.cleanup)
        external = Path(outside.name)
        (self.root / ".local").symlink_to(external)
        with self.assertRaisesRegex(SetupError, "Local trust path is unsafe"):
            create_allowed_signers(self.root, b"person@example.net ssh-ed25519 Data\n")
        self.assertEqual([], list(external.iterdir()))

    def test_restore_keeps_a_file_edited_during_the_restore(self) -> None:
        path = self.root / "config-fixture"
        path.write_bytes(b"owned")
        with patch(
            "first_commit.setup_files.read_if_present",
            side_effect=[b"owned", b"edited"],
        ):
            restore_git_config(path, b"owned", b"original")
        self.assertEqual(b"owned", path.read_bytes())
        self.assertEqual(
            ["config-fixture"], [item.name for item in self.root.iterdir()]
        )


class CloneHookConfigTest(SetupFixture):
    def write(self, raw: bytes) -> None:
        (self.root / ".pre-commit-config.yaml").write_bytes(raw)

    def test_clone_config_returns_revision_then_source(self) -> None:
        for source in (HTTPS_REPOSITORY, SSH_REPOSITORY):
            with self.subTest(source=source):
                self.write(hook_bytes(REVISION, source))
                self.assertEqual((REVISION, source), configured_source(self.root))

    def test_clone_config_uses_the_strict_reader(self) -> None:
        for raw, message in (
            (b"repos: &one []\nother: *one\n", "aliases"),
            (b"repos: []\nrepos: []\n", "duplicate fields"),
            (b"repos:\n  - repo: [\n", "malformed"),
            (
                b"repos:\n  - repo: [local]\n    hooks: [{id: first-commit-staged}]\n",
                "malformed",
            ),
        ):
            with self.subTest(message=message):
                self.write(raw)
                with self.assertRaisesRegex(SetupError, message):
                    configured_source(self.root)


if __name__ == "__main__":
    unittest.main()
