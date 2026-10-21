import json
from pathlib import Path
from unittest.mock import patch

from first_commit.contributor import (
    CONTRIBUTOR_PATH,
    load_contributor,
)
from first_commit.gitleaks_scanner import DependencyError
from first_commit.hooks import HTTPS_REPOSITORY, SSH_REPOSITORY
from first_commit.models import SetupError
from first_commit.policy import parse_policy
from first_commit.private_values import load_private_values
from first_commit.setup import SetupRequest, setup_repository
from first_commit.setup_apply import SetupTerminatedError
from first_commit.setup_files_plan import SetupOptions, files_plan
from first_commit.setup_hooks import hook_bytes
from first_commit.starter import IGNORE_FILE
from tests.setup_support import (
    REVISION,
    SetupFixture,
)
from tests.support import run_git


class FirstCommitSetupTest(SetupFixture):
    def test_blank_preview_lists_files_without_mutation(self) -> None:
        actions = setup_repository(
            self.root,
            SetupRequest(revision=REVISION, dry_run=True),
            contributor=self.person,
        )
        self.assertIn("Git repository: would initialize", actions)
        self.assertIn(".repo-policy.json", "\n".join(actions))
        self.assertIn("README.md", "\n".join(actions))
        self.assertIn(f"Hook source: HTTPS ({HTTPS_REPOSITORY})", actions)
        self.assertIn("Hook cache: custom PRE_COMMIT_HOME", actions)
        self.assertIn(
            "Signature verification: not performed; trust is not checked", actions
        )
        self.assertIn(
            "Next action: review generated documents and remove @no-commit markers",
            actions,
        )
        self.assertEqual([], list(self.root.iterdir()))

    def test_blank_preview_without_identity_is_read_only(self) -> None:
        actions = setup_repository(
            self.root, SetupRequest(revision=REVISION, dry_run=True)
        )
        self.assertIn("Local contributor: required", actions)
        self.assertEqual([], list(self.root.iterdir()))

    def test_onboarding_follows_the_hooks_an_existing_hook_file_declares(
        self,
    ) -> None:
        hook_file = self.root / ".pre-commit-config.yaml"
        written = hook_bytes(REVISION)
        for hook, expected in (
            ("first-commit-check", "Add the `first-commit-check` hook to"),
            ("first-commit-setup", None),
        ):
            with self.subTest(missing=hook):
                hook_file.write_bytes(
                    written.replace(f"      - id: {hook}\n".encode(), b"")
                )
                readme = (
                    files_plan(self.root, SetupOptions(revision=REVISION))
                    .pending[self.root / "README.md"]
                    .decode("utf-8")
                )
                self.assertIn("pre-commit install\n", readme)
                if expected is None:
                    self.assertNotIn(hook, readme)
                else:
                    self.assertIn(expected, readme)
        hook_file.unlink()
        readme = (
            files_plan(self.root, SetupOptions(revision=REVISION))
            .pending[self.root / "README.md"]
            .decode("utf-8")
        )
        self.assertIn("first-commit-setup", readme)
        self.assertIn("first-commit-check", readme)

    def test_apply_without_identity_names_each_way_to_give_one(self) -> None:
        with self.assertRaises(SetupError) as raised:
            setup_repository(self.root, SetupRequest(revision=REVISION, confirmed=True))
        message = str(raised.exception)
        self.assertNotIn("interactive", message)
        for detail in (
            "first-commit setup",
            "FIRST_COMMIT_IDENTITY_FILE",
            "FIRST_COMMIT_AUTHOR_NAME",
            "FIRST_COMMIT_AUTHOR_EMAIL",
            "FIRST_COMMIT_SIGNING_KEY",
        ):
            self.assertIn(detail, message)
        self.assertEqual([], list(self.root.iterdir()))

    def test_license_is_generated_only_on_explicit_selection(self) -> None:
        none = setup_repository(
            self.root,
            SetupRequest(revision=REVISION, dry_run=True),
            contributor=self.person,
        )
        self.assertNotIn("LICENSE", "\n".join(none))
        selected = setup_repository(
            self.root,
            SetupRequest(revision=REVISION, license_choice="apache-2.0", dry_run=True),
            contributor=self.person,
        )
        self.assertIn("LICENSE", "\n".join(selected))
        with self.assertRaisesRegex(SetupError, "License choice"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, license_choice="mit", dry_run=True),
                contributor=self.person,
            )
        self.assertEqual([], list(self.root.iterdir()))
        self.local_hooks()
        setup_repository(
            self.root,
            SetupRequest(
                revision=REVISION, license_choice="apache-2.0", confirmed=True
            ),
            contributor=self.person,
        )
        self.assertEqual(
            (Path(__file__).resolve().parents[1] / "LICENSE").read_bytes(),
            (self.root / "LICENSE").read_bytes(),
        )

    def test_existing_license_conflict_and_bad_packaged_copy_stop_setup(self) -> None:
        license_path = self.root / "LICENSE"
        license_path.write_bytes(b"A different project license.\n")
        with self.assertRaisesRegex(SetupError, "Existing LICENSE differs"):
            setup_repository(
                self.root,
                SetupRequest(
                    revision=REVISION, license_choice="apache-2.0", dry_run=True
                ),
                contributor=self.person,
            )
        self.assertEqual(b"A different project license.\n", license_path.read_bytes())
        license_path.unlink()
        with patch(
            "first_commit.setup_files_plan.importlib.metadata.distribution"
        ) as distribution:
            distribution.return_value.read_text.return_value = "wrong license"
            with self.assertRaisesRegex(SetupError, "Packaged Apache"):
                setup_repository(
                    self.root,
                    SetupRequest(
                        revision=REVISION, license_choice="apache-2.0", dry_run=True
                    ),
                    contributor=self.person,
                )

    def test_blank_setup_installs_real_local_hooks_and_identity(self) -> None:
        self.local_hooks()
        hook_file = (self.root / ".pre-commit-config.yaml").read_bytes()
        actions = setup_repository(
            self.root,
            SetupRequest(revision=REVISION, confirmed=True),
            contributor=self.person,
        )
        self.assertIn("Verification: passed", actions)
        self.assertEqual(
            hook_file, (self.root / ".pre-commit-config.yaml").read_bytes()
        )
        self.assertEqual(
            {"schema_version": 1},
            json.loads((self.root / ".repo-policy.json").read_text("utf-8")),
        )
        self.assertEqual(self.person, load_contributor(self.root))
        self.assertEqual(
            self.person.email,
            run_git(self.root, "config", "--local", "--get", "user.email")
            .stdout.decode()
            .strip(),
        )
        self.assertEqual(
            "true",
            run_git(self.root, "config", "--local", "--get", "commit.gpgsign")
            .stdout.decode()
            .strip(),
        )
        self.assertTrue((self.root / CONTRIBUTOR_PATH).is_file())
        values = self.root / ".local/first-commit/private-values.txt"
        self.assertEqual(0o600, values.stat().st_mode & 0o777)
        self.assertIn(b"One private value per line", values.read_bytes())
        self.assertEqual(
            (),
            load_private_values(self.root, ".local/first-commit/private-values.txt"),
        )
        self.assertIn(
            "Private values: created .local/first-commit/private-values.txt;"
            " add one private value per line",
            actions,
        )
        for stage in ("pre-commit", "commit-msg", "pre-push"):
            self.assertTrue((self.root / ".git/hooks" / stage).is_file())
        self.assertIn("@no-commit", (self.root / "README.md").read_text("utf-8"))
        self.assertEqual(b"", run_git(self.root, "rev-list", "--all").stdout)
        for name in ("README.md", "AGENTS.md"):
            self.assertTrue((self.root / name).is_file())
        for name in ("PRD.md", "CONTRIBUTING.md", "SECURITY.md"):
            self.assertFalse((self.root / name).exists())
        self.assertEqual(IGNORE_FILE, (self.root / ".gitignore").read_bytes())

    def test_document_set_selects_preview_files(self) -> None:
        optional = ("PRD.md", "CONTRIBUTING.md", "SECURITY.md")
        core = "\n".join(
            setup_repository(self.root, SetupRequest(revision=REVISION, dry_run=True))
        )
        full = "\n".join(
            setup_repository(
                self.root, SetupRequest(revision=REVISION, dry_run=True, docs="full")
            )
        )
        for name in ("README.md", "AGENTS.md"):
            self.assertIn(name, core)
            self.assertIn(name, full)
        for name in optional:
            self.assertNotIn(name, core)
            self.assertIn(name, full)
        with self.assertRaisesRegex(SetupError, "Document set"):
            setup_repository(
                self.root, SetupRequest(revision=REVISION, dry_run=True, docs="all")
            )
        self.assertEqual([], list(self.root.iterdir()))

    def test_onboarding_document_pins_the_generated_hook_source(self) -> None:
        for source, document in (
            (SSH_REPOSITORY, "README.md"),
            (HTTPS_REPOSITORY, "README.md"),
            (SSH_REPOSITORY, "CONTRIBUTING.md"),
        ):
            docs = "full" if document == "CONTRIBUTING.md" else "core"
            with self.subTest(source=source, docs=docs):
                pending = files_plan(
                    self.root, SetupOptions(REVISION, source, docs=docs)
                ).pending
                hooks = pending[self.root / ".pre-commit-config.yaml"].decode("utf-8")
                onboarding = pending[self.root / document].decode("utf-8")
                self.assertIn(f'repo: "{source}"', hooks)
                self.assertIn(f'rev: "{REVISION}"', hooks)
                self.assertIn(
                    f"`{source}` at the commit `.pre-commit-config.yaml` pins",
                    onboarding,
                )
                self.assertNotIn(REVISION, onboarding)
                self.assertIn(
                    "pre-commit run first-commit-setup --hook-stage manual\n",
                    onboarding,
                )
                self.assertIn("      - id: first-commit-setup\n", hooks)
                self.assertNotIn("private repository", onboarding)
                self.assertEqual([], list(self.root.iterdir()))

    def test_full_document_setup_writes_the_minimal_policy(self) -> None:
        self.local_hooks()
        (self.root / "PRD.md").write_text("# Existing requirements\n", "utf-8")
        actions = setup_repository(
            self.root,
            SetupRequest(revision=REVISION, confirmed=True, docs="full"),
            contributor=self.person,
        )
        self.assertIn("Verification: passed", actions)
        policy = (self.root / ".repo-policy.json").read_bytes()
        self.assertEqual(b'{\n  "schema_version": 1\n}\n', policy)
        parse_policy(policy, self.root)
        for name in (
            "README.md",
            "AGENTS.md",
            "PRD.md",
            "CONTRIBUTING.md",
            "SECURITY.md",
        ):
            with self.subTest(name=name):
                self.assertTrue((self.root / name).is_file())
        self.assertEqual(
            "# Existing requirements\n", (self.root / "PRD.md").read_text("utf-8")
        )
        self.assertTrue((self.root / "PRD.md.first-commit-proposal.md").is_file())
        self.assertIn("@no-commit", (self.root / "SECURITY.md").read_text("utf-8"))

    def test_core_setup_ignores_existing_optional_documents(self) -> None:
        (self.root / "PRD.md").write_text("# Existing requirements\n", "utf-8")
        actions = "\n".join(
            setup_repository(self.root, SetupRequest(revision=REVISION, dry_run=True))
        )
        self.assertNotIn("PRD.md", actions)
        self.assertEqual(["PRD.md"], [path.name for path in self.root.iterdir()])

    def test_conflict_and_cancel_leave_blank_directory_unchanged(self) -> None:
        (self.root / ".gitignore").write_text(".venv/\n", encoding="utf-8")
        with self.assertRaisesRegex(SetupError, "does not ignore the .local"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
        self.assertFalse((self.root / ".git").exists())
        (self.root / ".gitignore").unlink()
        with self.assertRaisesRegex(SetupError, "Confirm"):
            setup_repository(
                self.root, SetupRequest(revision=REVISION), contributor=self.person
            )
        self.assertEqual([], list(self.root.iterdir()))

    def test_hook_source_preflight_fails_before_git_initialization(self) -> None:
        with (
            patch(
                "first_commit.setup._preflight_source",
                create=True,
                side_effect=DependencyError("hook.source.preflight: unavailable"),
            ) as preflight,
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            with self.assertRaisesRegex(DependencyError, "hook.source.preflight"):
                setup_repository(
                    self.root,
                    SetupRequest(revision=REVISION, confirmed=True),
                    contributor=self.person,
                )

        preflight.assert_called_once_with(self.root.resolve(), HTTPS_REPOSITORY)
        self.assertEqual([], list(self.root.iterdir()))

    def test_failed_hook_install_restores_blank_directory(self) -> None:
        self.local_hooks()
        original = (self.root / ".pre-commit-config.yaml").read_bytes()
        with patch(
            "first_commit.setup_apply.run_pre_commit",
            side_effect=SetupError("Synthetic installer failure."),
        ):
            with self.assertRaises(SetupError):
                setup_repository(
                    self.root,
                    SetupRequest(revision=REVISION, confirmed=True),
                    contributor=self.person,
                )
        self.assertFalse((self.root / ".git").exists())
        self.assertFalse((self.root / CONTRIBUTOR_PATH).exists())
        self.assertFalse((self.root / ".local").exists())
        self.assertEqual(original, (self.root / ".pre-commit-config.yaml").read_bytes())

    def test_rollback_keeps_a_scanner_setup_did_not_install(self) -> None:
        self.local_hooks()
        scanner = self.root / ".local/bin/gitleaks"

        def appeared_meanwhile(root: Path) -> bool:
            self.install_scanner(root)
            return False

        with (
            patch(
                "first_commit.setup_apply.install_scanner",
                side_effect=appeared_meanwhile,
            ),
            patch(
                "first_commit.setup_apply.run_pre_commit",
                side_effect=SetupError("Synthetic installer failure."),
            ),
        ):
            with self.assertRaises(SetupError):
                setup_repository(
                    self.root,
                    SetupRequest(revision=REVISION, confirmed=True),
                    contributor=self.person,
                )
        self.assertTrue(scanner.is_file())

    def test_scanner_interrupt_restores_blank_directory(self) -> None:
        self.local_hooks()
        original = (self.root / ".pre-commit-config.yaml").read_bytes()
        with patch(
            "first_commit.setup_apply.install_scanner",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaisesRegex(SetupTerminatedError, "Ctrl-C"):
                setup_repository(
                    self.root,
                    SetupRequest(revision=REVISION, confirmed=True),
                    contributor=self.person,
                )

        self.assertFalse((self.root / ".git").exists())
        self.assertFalse((self.root / CONTRIBUTOR_PATH).exists())
        self.assertEqual(original, (self.root / ".pre-commit-config.yaml").read_bytes())

    def test_hook_stage_interrupts_restore_blank_directory(self) -> None:
        for interrupted in ("install-hooks", "install"):
            with self.subTest(interrupted=interrupted):
                self.local_hooks()
                original = (self.root / ".pre-commit-config.yaml").read_bytes()

                def interrupt(
                    root: Path,
                    arguments: tuple[str, ...],
                    stage: str = interrupted,
                    **_options: object,
                ) -> None:
                    if arguments[0] == stage:
                        if stage == "install":
                            hook = root / ".git/hooks/pre-commit"
                            hook.write_bytes(b"created by interrupted installer\n")
                            hook.chmod(0o700)
                        raise KeyboardInterrupt

                with patch(
                    "first_commit.setup_apply.run_pre_commit",
                    side_effect=interrupt,
                ):
                    with self.assertRaisesRegex(SetupTerminatedError, "Ctrl-C"):
                        setup_repository(
                            self.root,
                            SetupRequest(revision=REVISION, confirmed=True),
                            contributor=self.person,
                        )

                self.assertFalse((self.root / ".git").exists())
                self.assertFalse((self.root / CONTRIBUTOR_PATH).exists())
                self.assertEqual(
                    original, (self.root / ".pre-commit-config.yaml").read_bytes()
                )
