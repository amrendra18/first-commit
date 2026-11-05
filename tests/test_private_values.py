import tempfile
import unittest
from pathlib import Path

from first_commit.checks.privacy import PrivacyPolicy, privacy_findings
from first_commit.git import main_worktree
from first_commit.models import Candidate, Origin
from first_commit.private_values import (
    MAX_PRIVATE_VALUE_CHARACTERS,
    MAX_PRIVATE_VALUES,
    MAX_PRIVATE_VALUES_BYTES,
    PrivateValuesError,
    load_private_values,
    user_values_label,
    user_values_path,
)
from tests.gitleaks_support import commit_fixture
from tests.support import (
    TemporaryRootTest,
    global_excludes,
    initialize_repository,
    run_git,
)


class PrivateValuesTest(unittest.TestCase):
    def test_absent_optional_file_provides_no_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)

            values = load_private_values(root, ".local/first-commit/private-values.txt")

        self.assertEqual((), values)

    def test_loads_only_repository_ignored_untracked_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            private_file = root / ".local" / "first-commit" / "private-values.txt"
            private_file.parent.mkdir(parents=True)
            private_file.write_text(
                "# Local private literals.\nPrivate Person\nPRIVATE@EXAMPLE.NET\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PrivateValuesError, "repository .gitignore"):
                load_private_values(root, ".local/first-commit/private-values.txt")

            (root / ".gitignore").write_text(".local/\n", encoding="utf-8")
            private_file.chmod(0o600)
            values = load_private_values(root, ".local/first-commit/private-values.txt")

        self.assertEqual(("private person", "private" + "@" + "example.net"), values)

    def test_rejects_tracked_file_without_disclosing_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            canary = "private-list-canary"
            private_file = root / "private-values.txt"
            private_file.write_text(canary + "\n", encoding="utf-8")
            run_git(root, "add", "--", "private-values.txt")

            with self.assertRaises(PrivateValuesError) as context:
                load_private_values(root, "private-values.txt")

        self.assertNotIn(canary, str(context.exception))

    def test_repository_info_exclude_does_not_protect_private_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            private_file = root / "private-values.txt"
            private_file.write_text("private-list-canary\n", encoding="utf-8")
            (root / ".git" / "info" / "exclude").write_text(
                "private-values.txt\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(PrivateValuesError, "repository .gitignore"):
                load_private_values(root, "private-values.txt")

    def test_global_gitignore_does_not_protect_private_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "repository"
            root.mkdir()
            initialize_repository(root)
            private_file = root / "private-values.txt"
            private_file.write_text("private-list-canary\n", encoding="utf-8")
            private_file.chmod(0o600)
            with global_excludes(base, "private-values.txt"):
                with self.assertRaisesRegex(
                    PrivateValuesError, "repository .gitignore"
                ):
                    load_private_values(root, "private-values.txt")

    def test_rejects_private_values_readable_by_other_users(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / ".gitignore").write_text("private-values.txt\n", encoding="utf-8")
            private_file = root / "private-values.txt"
            private_file.write_text("private-list-canary\n", encoding="utf-8")
            private_file.chmod(0o644)

            with self.assertRaises(PrivateValuesError) as refused:
                load_private_values(root, "private-values.txt")
            self.assertEqual(
                "private-values.txt: Private-values file permissions are too broad."
                "\nfix: run `chmod 600 private-values.txt`.",
                str(refused.exception),
            )

    def test_rejects_symlink_without_reading_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "repository"
            root.mkdir()
            initialize_repository(root)
            (root / ".gitignore").write_text("private-values.txt\n", encoding="utf-8")
            canary = "private-symlink-target-canary"
            target = base / "target"
            target.write_text(canary + "\n", encoding="utf-8")
            (root / "private-values.txt").symlink_to(target)

            with self.assertRaises(PrivateValuesError) as context:
                load_private_values(root, "private-values.txt")

        self.assertNotIn(canary, str(context.exception))

    def test_rejects_invalid_duplicate_and_over_limit_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / ".gitignore").write_text("private-values.txt\n", encoding="utf-8")
            private_file = root / "private-values.txt"

            cases = (
                (b"\xff\n", "UTF-8"),
                (b"Duplicate\nduplicate\n", "duplicate"),
                (
                    ("x" * (MAX_PRIVATE_VALUE_CHARACTERS + 1) + "\n").encode(),
                    "size limit",
                ),
                (
                    "".join(
                        f"value-{index}\n" for index in range(MAX_PRIVATE_VALUES + 1)
                    ).encode(),
                    "count",
                ),
                (b"x" * (MAX_PRIVATE_VALUES_BYTES + 1), "size limit"),
            )
            for content, diagnostic in cases:
                with self.subTest(diagnostic=diagnostic):
                    private_file.write_bytes(content)
                    private_file.chmod(0o600)
                    with self.assertRaisesRegex(PrivateValuesError, diagnostic):
                        load_private_values(root, "private-values.txt")

    def test_detects_normalized_literal_without_disclosing_it(self) -> None:
        canary = "Private Person"
        candidate = Candidate(
            path="docs/example.md",
            content=b"Owner: PRIVATE PERSON\n",
            origin=Origin.WORKTREE,
        )

        findings = privacy_findings(
            candidate,
            PrivacyPolicy(private_values=(canary.casefold(),)),
            max_findings=1000,
        )

        self.assertEqual("privacy.private-literal", findings[0].rule_id)
        self.assertEqual(1, findings[0].line)
        self.assertNotIn(canary.casefold(), repr(findings).casefold())


class UserValuesPathTest(unittest.TestCase):
    # The XDG base directory rules ignore a relative path.
    def test_a_relative_config_home_counts_as_unset(self) -> None:
        for config, path, label in (
            ("/x", "/x", "$XDG_CONFIG_HOME"),
            ("relative/config", "/h/.config", "~/.config"),
            ("", "/h/.config", "~/.config"),
        ):
            with self.subTest(config=config):
                environment = {"XDG_CONFIG_HOME": config, "HOME": "/h"}
                self.assertEqual(
                    Path(path, "first-commit/private-values.txt"),
                    user_values_path(environment),
                )
                self.assertEqual(
                    f"{label}/first-commit/private-values.txt",
                    user_values_label(environment),
                )


class MainWorktreeTest(TemporaryRootTest):
    def test_only_a_linked_worktree_of_a_checkout_names_a_main_worktree(self) -> None:
        main = self.root / "main"
        main.mkdir()
        initialize_repository(main)
        (main / "README.md").write_text("# Fixture\n", encoding="utf-8")
        commit_fixture(main, "README.md")
        run_git(main, "worktree", "add", "-q", str(self.root / "linked"))
        run_git(self.root, "clone", "-q", "--bare", str(main), "bare.git")
        run_git(self.root / "bare.git", "worktree", "add", "-q", "../of-bare")
        self.assertIsNone(main_worktree(main))
        self.assertEqual(main.resolve(), main_worktree(self.root / "linked"))
        self.assertIsNone(main_worktree(self.root / "of-bare"))


if __name__ == "__main__":
    unittest.main()
