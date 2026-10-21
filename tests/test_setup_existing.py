import subprocess
import unittest
from unittest.mock import patch

from first_commit.contributor import (
    CONTRIBUTOR_PATH,
    Contributor,
    create_contributor,
    load_contributor,
)
from first_commit.gitleaks_scanner import (
    DependencyError,
    ScannerTimeoutError,
    validate_scanner,
)
from first_commit.models import SetupError
from first_commit.setup import SetupRequest, setup_repository
from first_commit.setup_command import SETUP_HOOK_COMMAND, TOOL_SETUP_COMMAND
from first_commit.starter import MARKER
from tests.gitleaks_support import trusted_local_scanner
from tests.setup_support import (
    REVISION,
    SetupFixture,
)
from tests.support import run_git

REVIEW_MARKERS = "Next action: review generated documents and remove @no-commit markers"


class ExistingRepositorySetupTest(SetupFixture):
    def test_initialized_setup_preview_and_repeat_preserve_generated_files(
        self,
    ) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        before = (self.root / ".pre-commit-config.yaml").read_bytes()
        preview = setup_repository(
            self.root,
            SetupRequest(revision=REVISION, dry_run=True),
            contributor=self.person,
        )
        self.assertIn("would create", "\n".join(preview))
        self.assertIn(
            "Hook environments: would install or verify; not checked (dry run)", preview
        )
        self.assertFalse((self.root / ".repo-policy.json").exists())
        setup_repository(
            self.root, SetupRequest(revision=REVISION), contributor=self.person
        )
        policy = (self.root / ".repo-policy.json").read_bytes()
        readme = (self.root / "README.md").read_bytes()
        repeated = setup_repository(self.root, SetupRequest(revision=REVISION))
        self.assertIn("Files: already present", repeated)
        self.assertIn("Local contributor: retained", repeated)
        self.assertIn("Private values: retained", repeated)
        self.assertIn("Hook scripts: ready", repeated)
        self.assertIn("Hook environments: installed or verified", repeated)
        self.assertEqual(REVIEW_MARKERS, repeated[-1])
        self.assertEqual(before, (self.root / ".pre-commit-config.yaml").read_bytes())
        self.assertEqual(policy, (self.root / ".repo-policy.json").read_bytes())
        self.assertEqual(readme, (self.root / "README.md").read_bytes())

    def test_repeat_setup_asks_for_the_review_until_the_markers_are_gone(
        self,
    ) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        setup_repository(
            self.root, SetupRequest(revision=REVISION), contributor=self.person
        )
        for dry_run in (True, False):
            with self.subTest(dry_run=dry_run):
                repeated = setup_repository(
                    self.root, SetupRequest(revision=REVISION, dry_run=dry_run)
                )
                self.assertEqual(REVIEW_MARKERS, repeated[-1])
        readme = self.root / "README.md"
        readme.write_bytes(readme.read_bytes().replace(MARKER.encode(), b""))
        self.assertEqual(
            REVIEW_MARKERS,
            setup_repository(self.root, SetupRequest(revision=REVISION))[-1],
        )
        agents = self.root / "AGENTS.md"
        agents.write_bytes(agents.read_bytes().replace(MARKER.encode(), b""))
        self.assertEqual(
            "Next action: run first-commit check",
            setup_repository(self.root, SetupRequest(revision=REVISION))[-1],
        )

    def test_repeat_setup_says_existing_policy_stops_new_documents(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        setup_repository(
            self.root, SetupRequest(revision=REVISION), contributor=self.person
        )
        skipped = "Documents: not created; .repo-policy.json exists"
        full = setup_repository(
            self.root,
            SetupRequest(
                revision=REVISION,
                docs="full",
                license_choice="apache-2.0",
                dry_run=True,
            ),
        )
        self.assertIn("Files: would create LICENSE", full)
        self.assertIn(skipped, full)
        self.assertFalse((self.root / "PRD.md").exists())
        core = setup_repository(
            self.root, SetupRequest(revision=REVISION, dry_run=True)
        )
        self.assertNotIn(skipped, core)

    def test_existing_document_gets_proposal_and_original_is_unchanged(self) -> None:
        self.local_hooks()
        original = b"# Existing project\n"
        (self.root / "README.md").write_bytes(original)
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, confirmed=True),
                contributor=self.person,
            )
        self.assertEqual(original, (self.root / "README.md").read_bytes())
        proposal = self.root / "README.md.first-commit-proposal.md"
        self.assertIn(b"@no-commit", proposal.read_bytes())

    def test_initialized_preview_rejects_operational_conflicts(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        hook = self.root / ".pre-commit-config.yaml"
        original_hook = hook.read_bytes()

        hook.write_text("repos: []\n", encoding="utf-8")
        with self.assertRaisesRegex(SetupError, "does not declare the first-commit"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
        hook.write_bytes(original_hook)

        ignore = self.root / ".gitignore"
        ignore.write_text(".venv/\n", encoding="utf-8")
        with self.assertRaisesRegex(SetupError, "does not ignore the .local"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
        ignore.write_text("/.local/\n", encoding="utf-8")
        actions = setup_repository(
            self.root,
            SetupRequest(revision=REVISION, dry_run=True),
            contributor=self.person,
        )
        self.assertIn("Verification: preflight passed; no changes made", actions)
        ignore.unlink()

        template = self.root / ".gitmessage"
        template.write_bytes(b"")
        with self.assertRaisesRegex(SetupError, "template is unusable"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
        template.unlink()

        run_git(self.root, "config", "--local", "core.hooksPath", "other-hooks")
        with self.assertRaisesRegex(SetupError, "hooksPath"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )

    def test_equivalent_boolean_settings_are_kept(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        for key, value in (
            ("commit.gpgsign", "True"),
            ("tag.gpgsign", "yes"),
            ("user.useConfigOnly", "1"),
        ):
            run_git(self.root, "config", "--local", key, value)
        setup_repository(
            self.root,
            SetupRequest(revision=REVISION, dry_run=True),
            contributor=self.person,
        )
        run_git(self.root, "config", "--local", "commit.gpgsign", "false")
        with self.assertRaisesRegex(SetupError, "differ from what setup sets"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )

    def test_identity_hook_and_scanner_conflicts_stop_before_writes(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        run_git(self.root, "config", "--local", "user.email", "different@example.com")
        with self.assertRaisesRegex(SetupError, "differ from what setup sets"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
        run_git(self.root, "config", "--local", "--unset", "user.email")

        hook = self.root / ".git/hooks/pre-commit"
        hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        hook.chmod(0o700)
        with self.assertRaisesRegex(SetupError, "Existing Git hook"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
        hook.unlink()

        target = self.root / ".local/bin/gitleaks"
        target.parent.mkdir(parents=True)
        target.symlink_to(self.root / "missing")
        with self.assertRaisesRegex(SetupError, "link or not a regular file"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )

    def test_dry_run_without_contributor_runs_every_plan_check(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        preview = SetupRequest(revision=REVISION, dry_run=True)
        hook = self.root / ".git/hooks/pre-commit"
        hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        hook.chmod(0o700)
        with self.assertRaisesRegex(SetupError, "Existing Git hook"):
            setup_repository(self.root, preview)
        hook.unlink()

        target = self.root / ".local/bin/gitleaks"
        target.parent.mkdir(parents=True)
        target.symlink_to(self.root / "missing")
        with self.assertRaisesRegex(SetupError, "link or not a regular file"):
            setup_repository(self.root, preview)
        target.unlink()

        lines = setup_repository(self.root, preview)
        self.assertIn("Local contributor: required", lines)
        self.assertFalse((self.root / ".repo-policy.json").exists())

    def test_dry_run_without_contributor_checks_fixed_signing_values(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        settings = {
            "user.name": "Example Contributor",
            "user.email": "public@example.net",
            "user.signingkey": "~/.ssh/id_ed25519.pub",
            "gpg.format": "openpgp",
            "commit.gpgsign": "false",
            "tag.gpgsign": "true",
            "user.useConfigOnly": "true",
        }
        for key, value in settings.items():
            run_git(self.root, "config", "--local", key, value)
        preview = SetupRequest(revision=REVISION, dry_run=True)
        with self.assertRaisesRegex(SetupError, "differ from what setup sets"):
            setup_repository(self.root, preview)
        run_git(self.root, "config", "--local", "gpg.format", "ssh")
        run_git(self.root, "config", "--local", "commit.gpgsign", "true")
        self.assertIn(
            "Git identity/signing: ready", setup_repository(self.root, preview)
        )
        run_git(self.root, "config", "--local", "--unset", "tag.gpgsign")
        self.assertIn(
            "Git identity/signing: would configure",
            setup_repository(self.root, preview),
        )

    def test_dry_run_reports_a_present_scanner_without_running_it(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        self.install_scanner(self.root)
        with patch("first_commit.setup_plan.validate_scanner") as validate:
            preview = setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
            validate.assert_not_called()
            with (
                patch("first_commit.setup_apply.run_pre_commit"),
                patch("first_commit.setup_apply.hook_findings", return_value=[]),
            ):
                applied = setup_repository(
                    self.root,
                    SetupRequest(revision=REVISION, confirmed=True),
                    contributor=self.person,
                )
            validate.assert_called_once()
        self.assertIn("Gitleaks: present, not validated; setup validates it", preview)
        self.assertIn("Gitleaks: ready", applied)

    def test_failed_local_scanner_hint_does_not_name_setup_itself(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        scanner = self.root / ".local/bin/gitleaks"
        scanner.parent.mkdir(parents=True)
        scanner.write_text("#!/bin/sh\necho 9.0.0\n", encoding="utf-8")
        scanner.chmod(0o700)
        with (
            patch("first_commit.setup_plan.validate_scanner", new=validate_scanner),
            trusted_local_scanner(scanner.read_bytes()),
            self.assertRaises(DependencyError) as failure,
        ):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, confirmed=True),
                contributor=self.person,
            )
        self.assertEqual(
            "Local Gitleaks at .local/bin/gitleaks failed validation "
            "(Installed Gitleaks is incompatible); "
            "delete .local/bin/gitleaks and run setup again, "
            "or replace it with trusted Gitleaks 8.30.0.",
            str(failure.exception),
        )
        for command in (TOOL_SETUP_COMMAND, SETUP_HOOK_COMMAND):
            self.assertNotIn(command, str(failure.exception))
        self.assertEqual("#!/bin/sh\necho 9.0.0\n", scanner.read_text("utf-8"))

    def test_local_scanner_timeout_advises_a_retry_first(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        scanner = self.root / ".local/bin/gitleaks"
        scanner.parent.mkdir(parents=True)
        scanner.write_text("#!/bin/sh\nsleep 1\n", encoding="utf-8")
        scanner.chmod(0o700)
        with (
            patch(
                "first_commit.setup_plan.validate_scanner",
                side_effect=ScannerTimeoutError("Gitleaks timed out"),
            ),
            self.assertRaises(DependencyError) as failure,
        ):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, confirmed=True),
                contributor=self.person,
            )
        self.assertEqual(
            "Local Gitleaks at .local/bin/gitleaks failed validation "
            "(Gitleaks timed out); run setup again; if it times out again, "
            "delete .local/bin/gitleaks and run setup again, "
            "or replace it with trusted Gitleaks 8.30.0.",
            str(failure.exception),
        )
        self.assertTrue(scanner.exists())

    def test_local_contributor_record_conflict_is_preserved(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        create_contributor(self.root, self.person)
        other = Contributor("Other", self.person.email, self.person.signing_key)
        with self.assertRaisesRegex(SetupError, "record differs"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=other,
            )
        self.assertEqual(self.person, load_contributor(self.root))

    def test_invalid_roots_and_missing_identity_do_not_initialize_git(self) -> None:
        with self.assertRaisesRegex(SetupError, "existing folder"):
            setup_repository(self.root / "missing", SetupRequest(revision=REVISION))
        with self.assertRaisesRegex(SetupError, "immutable revision"):
            setup_repository(
                self.root, SetupRequest(revision="main"), contributor=self.person
            )
        with self.assertRaisesRegex(SetupError, "needs a contributor identity"):
            setup_repository(self.root, SetupRequest(revision=REVISION))
        self.assertFalse((self.root / ".git").exists())

    def test_initialized_preview_without_identity_and_invalid_git_marker(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        preview = setup_repository(
            self.root, SetupRequest(revision=REVISION, dry_run=True)
        )
        self.assertIn("Local contributor: required", preview)
        with self.assertRaisesRegex(SetupError, "contributor identity"):
            setup_repository(self.root, SetupRequest(revision=REVISION))
        self.assertFalse((self.root / ".repo-policy.json").exists())
        run_git(self.root, "config", "--local", "core.bare", "true")
        with self.assertRaisesRegex(
            SetupError, "Git cannot use it as a repository; setup changed nothing"
        ):
            setup_repository(
                self.root, SetupRequest(revision=REVISION), contributor=self.person
            )

    def test_symlinked_git_directory_is_rejected_before_writes(self) -> None:
        external = self.root / "external"
        external.mkdir()
        run_git(external, "init", "-q")
        (self.root / ".git").symlink_to(external / ".git")
        with self.assertRaisesRegex(SetupError, "standard Git repository"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
        self.assertFalse((self.root / ".repo-policy.json").exists())

    def test_symlinked_hooks_folder_is_rejected_before_writes(self) -> None:
        run_git(self.root, "init", "-q")
        external = self.root / "external-hooks"
        external.mkdir()
        hooks = self.root / ".git/hooks"
        for entry in hooks.iterdir():
            entry.unlink()
        hooks.rmdir()
        hooks.symlink_to(external)
        with self.assertRaisesRegex(SetupError, "hooks folder"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
        self.assertEqual([], list(external.iterdir()))

    def test_failed_readiness_rolls_back_new_files_and_settings(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        with patch("first_commit.setup_apply.hook_findings", return_value=[object()]):
            with self.assertRaisesRegex(SetupError, "readiness"):
                setup_repository(
                    self.root, SetupRequest(revision=REVISION), contributor=self.person
                )
        self.assertFalse((self.root / ".repo-policy.json").exists())
        self.assertFalse((self.root / CONTRIBUTOR_PATH).exists())
        self.assertFalse((self.root / ".git/hooks/pre-commit").exists())
        with self.assertRaises(subprocess.CalledProcessError):
            run_git(self.root, "config", "--local", "--get", "commit.gpgsign")

    def test_existing_and_inherited_templates_are_preserved(self) -> None:
        self.initialized_with_hooks()
        custom = self.root / ".gitmessage"
        custom.write_text("Custom template\n", encoding="utf-8")
        setup_repository(
            self.root, SetupRequest(revision=REVISION), contributor=self.person
        )
        self.assertEqual("Custom template\n", custom.read_text("utf-8"))
        self.assertEqual(
            b".gitmessage\n",
            run_git(self.root, "config", "--local", "--get", "commit.template").stdout,
        )

        run_git(self.root, "config", "--local", "--unset", "commit.template")
        inherited = self.root / "inherited-config"
        inherited.write_text(
            "[commit]\n\ttemplate = custom-message.txt\n", encoding="utf-8"
        )
        (self.root / "custom-message.txt").write_text(
            "Other template\n", encoding="utf-8"
        )
        before = inherited.read_bytes()
        run_git(self.root, "config", "--local", "include.path", str(inherited))
        setup_repository(
            self.root, SetupRequest(revision=REVISION), contributor=self.person
        )
        self.assertEqual(before, inherited.read_bytes())
        with self.assertRaises(subprocess.CalledProcessError):
            run_git(self.root, "config", "--local", "--get", "commit.template")


if __name__ == "__main__":
    unittest.main()
