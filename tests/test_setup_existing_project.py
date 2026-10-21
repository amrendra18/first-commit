import unittest
from unittest.mock import patch

from first_commit.hooks import HTTPS_REPOSITORY
from first_commit.models import SetupError
from first_commit.setup import SetupRequest, setup_repository
from first_commit.setup_command import CHECK_HOOK_COMMAND
from first_commit.setup_hooks import hook_bytes
from first_commit.starter import STYLE_FILES
from tests.setup_support import REVISION, SetupFixture
from tests.support import run_git

EDITORCONFIG = b"root = true\n\n[*.py]\nindent_size = 2\n"
GITATTRIBUTES = b"* text=auto\n"
EXISTING_README = b"# Existing project\n"
IGNORE_LINES = (".local", ".local/", "/.local", "/.local/", ".local/*")


class ExistingProjectSetupTest(SetupFixture):
    def preview(self) -> tuple[str, ...]:
        return setup_repository(
            self.root,
            SetupRequest(revision=REVISION, dry_run=True),
            contributor=self.person,
        )

    def apply(self) -> tuple[str, ...]:
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            return setup_repository(
                self.root,
                SetupRequest(revision=REVISION, confirmed=True),
                contributor=self.person,
            )

    def test_a_repository_without_a_hook_file_checks_the_hook_source(self) -> None:
        run_git(self.root, "init", "-q")
        with patch("first_commit.setup._preflight_source") as preflight:
            self.apply()
        preflight.assert_called_once_with(self.root.resolve(), HTTPS_REPOSITORY)
        for name in (".pre-commit-config.yaml", ".repo-policy.json", "README.md"):
            self.assertTrue((self.root / name).is_file(), name)

    def test_a_repository_with_a_hook_file_skips_the_source_check(self) -> None:
        self.initialized_with_hooks()
        with patch("first_commit.setup._preflight_source") as preflight:
            self.apply()
        preflight.assert_not_called()

    def test_own_style_files_are_kept_and_documents_get_proposals(self) -> None:
        (self.root / ".editorconfig").write_bytes(EDITORCONFIG)
        (self.root / ".gitattributes").write_bytes(GITATTRIBUTES)
        (self.root / "README.md").write_bytes(EXISTING_README)
        preview = self.preview()
        self.assertIn("Files kept as they are: .editorconfig, .gitattributes", preview)
        created = next(line for line in preview if line.startswith("Files: "))
        self.assertNotIn(".editorconfig", created)
        self.assertNotIn(".gitattributes", created)
        self.assertIn("README.md.first-commit-proposal.md", created)
        self.assertIn("AGENTS.md", created)
        with patch("first_commit.setup._preflight_source"):
            applied = self.apply()
        self.assertIn("Files kept as they are: .editorconfig, .gitattributes", applied)
        self.assertEqual(EDITORCONFIG, (self.root / ".editorconfig").read_bytes())
        self.assertEqual(GITATTRIBUTES, (self.root / ".gitattributes").read_bytes())
        self.assertEqual(EXISTING_README, (self.root / "README.md").read_bytes())
        self.assertTrue((self.root / "README.md.first-commit-proposal.md").is_file())
        self.assertTrue((self.root / "AGENTS.md").is_file())

    def test_style_files_equal_to_the_starter_are_not_listed_as_kept(self) -> None:
        for name, content in STYLE_FILES.items():
            (self.root / name).write_text(content, encoding="utf-8")
        preview = self.preview()
        self.assertFalse(any(line.startswith("Files kept") for line in preview))
        self.assertNotIn(".editorconfig", "\n".join(preview))

    def test_each_ignore_line_that_git_applies_to_the_local_folder_works(
        self,
    ) -> None:
        self.initialized_with_hooks()
        ignore = self.root / ".gitignore"
        for line in IGNORE_LINES:
            with self.subTest(line=line):
                ignore.write_text(line + "\n", encoding="utf-8")
                for path in (".local/first-commit/contributor.json", ".local/bin/x"):
                    run_git(self.root, "check-ignore", "-q", path)
                self.assertIn(
                    "Verification: preflight passed; no changes made", self.preview()
                )

    def test_a_gitignore_that_misses_the_local_folder_names_the_lines(self) -> None:
        self.initialized_with_hooks()
        (self.root / ".gitignore").write_text(
            ".local/first-commit/\n.venv/\n", encoding="utf-8"
        )
        with self.assertRaises(SetupError) as refusal:
            self.preview()
        self.assertEqual(
            "Existing .gitignore does not ignore the .local/ folder.\n"
            "fix: add the line .local/ to .gitignore (.local, /.local, /.local/, "
            "or .local/* also work), then rerun setup.",
            str(refusal.exception),
        )

    def test_a_negated_local_folder_stops_preview_and_apply_alike(self) -> None:
        self.initialized_with_hooks()
        (self.root / ".gitignore").write_text(".local/\n!.local/\n", encoding="utf-8")
        before = self.files()
        for run in (self.preview, self.apply):
            with self.subTest(run=run.__name__):
                with self.assertRaises(SetupError) as refusal:
                    run()
                self.assertEqual(
                    "Contributor record must be protected by repository .gitignore.\n"
                    "fix: make .gitignore ignore .local/first-commit/contributor.json: "
                    "add the line .local/ and delete any later rule that re-includes "
                    "it, such as !.local/ (git check-ignore -v "
                    ".local/first-commit/contributor.json names it); if Git tracks the "
                    "file, run git rm --cached .local/first-commit/contributor.json; "
                    "then rerun setup.",
                    str(refusal.exception),
                )
                self.assertEqual(before, self.files())

    def test_a_local_file_state_found_only_during_apply_is_a_setup_error(
        self,
    ) -> None:
        self.initialized_with_hooks()
        values = self.root / ".local/first-commit/private-values.txt"
        values.parent.mkdir(parents=True)
        values.write_text("someone\n", encoding="utf-8")
        run_git(self.root, "add", "--force", "--", str(values))
        values.unlink()
        before = self.files()
        with self.assertRaises(SetupError) as refusal:
            self.apply()
        message, fix = str(refusal.exception).split("\n")
        self.assertEqual("Private-values file must not be tracked.", message)
        self.assertIn(
            "run git rm --cached .local/first-commit/private-values.txt;", fix
        )
        self.assertEqual(before, self.files())

    def test_the_next_action_follows_the_hook_file_shape(self) -> None:
        run_git(self.root, "init", "-q")
        (self.root / ".repo-policy.json").write_text('{"schema_version": 1}\n', "utf-8")
        hook_file = self.root / ".pre-commit-config.yaml"
        without_check = hook_bytes(REVISION).replace(
            b"      - id: first-commit-check\n", b""
        )
        for content, expected in (
            (hook_bytes(REVISION), "Next action: run " + CHECK_HOOK_COMMAND),
            (
                without_check,
                "Next action: add first-commit-check to .pre-commit-config.yaml, "
                "then run " + CHECK_HOOK_COMMAND,
            ),
            (None, "Next action: run first-commit check"),
        ):
            with self.subTest(expected=expected):
                if content is None:
                    self.local_hooks()
                else:
                    hook_file.write_bytes(content)
                self.assertEqual(expected, self.preview()[-1])


if __name__ == "__main__":
    unittest.main()
