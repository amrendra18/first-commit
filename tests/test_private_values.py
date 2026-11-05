import io
import os
import shutil
import tempfile
import unittest
from collections.abc import Callable
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from first_commit.checks.privacy import PrivacyPolicy, privacy_findings
from first_commit.git import main_worktree
from first_commit.models import Candidate, Origin, Result
from first_commit.private_values import (
    MAX_PRIVATE_VALUE_CHARACTERS,
    MAX_PRIVATE_VALUES,
    MAX_PRIVATE_VALUES_BYTES,
    PrivateValues,
    PrivateValuesError,
    UserList,
    load_private_values,
    user_list_state,
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
from tests.test_cli_private_values import CANARY, RULE, UserListFixture


class PrivateValuesTest(unittest.TestCase):
    def test_absent_optional_file_provides_no_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)

            values = load_private_values(root, ".local/first-commit/private-values.txt")

        self.assertEqual(PrivateValues((), ()), values)

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

        expected = ("private person", "private" + "@" + "example.net")
        self.assertEqual(PrivateValues(expected, expected), values)

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


COMMITTER = ("-c", "user.name=Example", "-c", "user.email=example@example.com")
HOME_LINE = (
    "Private values: $XDG_CONFIG_HOME/first-commit/private-values.txt is kept in "
    "this repository, so it does not apply here.\n"
)


class HomeRepositoryTest(UserListFixture):
    def setUp(self) -> None:
        super().setUp()
        self.kept = self.root / "privacy/terms.txt"
        self.kept.parent.mkdir()
        self.kept.write_text(CANARY + "\n", encoding="utf-8")
        self.kept.chmod(0o600)
        run_git(self.root, "add", "--", "privacy/terms.txt")

    def check(self, root: Path, *arguments: str) -> tuple[int, str, str]:
        with patch.object(self, "root", root):
            return self.run_without_scanner(*arguments)

    def assert_skipped(self, root: Path) -> None:
        for arguments in (("check",), ("hook", "pre-commit")):
            with self.subTest(root=root.name, command=" ".join(arguments)):
                code, output, error = self.check(root, *arguments)
                self.assertNotIn(RULE, output)
                self.assertEqual((0, HOME_LINE), (code, error), output)

    def assert_applies(self, root: Path) -> None:
        for arguments in (("check",), ("hook", "pre-commit")):
            with self.subTest(root=root.name, command=" ".join(arguments)):
                code, output, error = self.check(root, *arguments)
                self.assertEqual(1, code, output + error)
                self.assertIn(RULE, output)
                self.assertNotIn(CANARY, output + error)
                self.assertNotIn("kept in this repository", error)

    # A repository that tracks its own copy of the list, committed once.
    def list_repository(self, folder: Path) -> Path:
        folder.mkdir(exist_ok=True)
        initialize_repository(folder)
        kept = folder / "privacy/terms.txt"
        kept.parent.mkdir()
        kept.write_text(CANARY + "\n", encoding="utf-8")
        kept.chmod(0o600)
        run_git(folder, "add", "--", "privacy/terms.txt")
        run_git(folder, *COMMITTER, "commit", "-q", "--no-verify", "-m", "list")
        return kept

    def other_repository(self) -> Path:
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        root = Path(other.name)
        initialize_repository(root)
        (root / ".repo-policy.json").write_text('{"schema_version":1}\n', "utf-8")
        (root / "notes.txt").write_text(f"written by {CANARY}\n", "utf-8")
        run_git(root, "add", "--", "notes.txt")
        return root

    def linked_worktree(self) -> Path:
        linked = super().linked_worktree()
        (linked / "privacy/terms.txt").chmod(0o600)
        (linked / "staged.txt").write_text(f"written by {CANARY}\n", "utf-8")
        run_git(linked, "add", "--", "staged.txt")
        return linked

    def test_user_list_skipped_in_its_home_repository(self) -> None:
        self.user_list.symlink_to(self.kept)
        self.assert_skipped(self.root)

    def test_project_list_still_applies_in_home_repository(self) -> None:
        self.user_list.symlink_to(self.kept)
        self.private.write_text(CANARY + "\n", encoding="utf-8")
        for arguments in (("check",), ("hook", "pre-commit")):
            with self.subTest(command=" ".join(arguments)):
                code, output, error = self.check(self.root, *arguments)
                self.assertEqual((1, HOME_LINE), (code, error), output)
                self.assertIn(RULE, output)
                self.assertNotIn(CANARY, output)

    def test_kept_values_still_mask_the_repository_path(self) -> None:
        folder = self.root.name
        self.kept.write_text(f"{CANARY}\n{folder}\n", encoding="utf-8")
        self.user_list.symlink_to(self.kept)
        with redirect_stderr(io.StringIO()) as error:
            code, output = self.check_from_a_subfolder()
        self.assertEqual((0, HOME_LINE), (code, error.getvalue()), output)
        self.assertIn("<private value>", output.splitlines()[0])
        self.assertNotIn(folder.casefold(), output.casefold())

    def test_kept_values_still_mask_a_finding_path(self) -> None:
        self.user_list.symlink_to(self.kept)
        named = f"privacy/{CANARY}-x.txt"
        (self.root / named).write_text("trailing space \n", encoding="utf-8")
        run_git(self.root, "add", "--", named)
        json = ("check", "--format", "json")
        for arguments in (("check",), ("hook", "pre-commit"), json):
            with self.subTest(command=" ".join(arguments)):
                code, output, error = self.check(self.root, *arguments)
                self.assertEqual((1, HOME_LINE), (code, error), output)
                self.assertIn("privacy/<private value>-x.txt", output)
                self.assertNotIn(CANARY, output)
                self.assertNotIn("privacy.private-", output)

    def test_user_list_applies_in_other_repositories(self) -> None:
        self.user_list.symlink_to(self.kept)
        self.assert_applies(self.other_repository())

    def test_a_link_through_a_second_link_is_followed_to_its_file(self) -> None:
        hop = self.config / "hop.txt"
        hop.symlink_to(self.kept)
        self.user_list.symlink_to(hop)
        self.assert_skipped(self.root)
        self.user_list.unlink()
        folder = self.config / "privacy"
        folder.symlink_to(self.kept.parent)
        self.user_list.symlink_to(folder / "terms.txt")
        self.assert_skipped(self.root)

    # Git runs a linked worktree's hook with GIT_INDEX_FILE set to that worktree's
    # index, which lies inside the main worktree's .git folder.
    def hook_index(self, linked: Path) -> dict[str, str]:
        return {
            "GIT_INDEX_FILE": str(self.root / ".git/worktrees" / linked.name / "index")
        }

    def test_a_linked_worktree_skips_a_list_kept_in_either_worktree(self) -> None:
        self.user_list.symlink_to(self.kept)
        linked = self.linked_worktree()
        self.assert_skipped(linked)
        with patch.dict(os.environ, self.hook_index(linked)):
            self.assert_skipped(linked)
        self.user_list.unlink()
        self.user_list.symlink_to(linked / "privacy/terms.txt")
        self.assert_skipped(linked)
        self.assert_applies(self.other_repository())

    def test_a_hook_index_never_answers_for_the_main_worktree(self) -> None:
        run_git(self.root, "rm", "-q", "--cached", "--", "privacy/terms.txt")
        linked = UserListFixture.linked_worktree(self)
        copy = linked / "privacy/terms.txt"
        copy.parent.mkdir()
        copy.write_text(CANARY + "\n", encoding="utf-8")
        (linked / "staged.txt").write_text(f"written by {CANARY}\n", "utf-8")
        run_git(linked, "add", "--", "privacy/terms.txt", "staged.txt")
        self.user_list.symlink_to(self.kept)
        self.assert_applies(linked)
        with patch.dict(os.environ, self.hook_index(linked)):
            self.assert_applies(linked)

    def test_the_main_worktree_applies_a_list_kept_in_a_linked_worktree(self) -> None:
        linked = self.linked_worktree()
        self.user_list.symlink_to(linked / "privacy/terms.txt")
        (self.root / "staged.txt").write_text(f"written by {CANARY}\n", "utf-8")
        run_git(self.root, "add", "--", "staged.txt")
        self.assert_applies(self.root)

    def test_a_plain_user_list_in_the_config_folder_applies(self) -> None:
        self.user_list.write_text(CANARY + "\n", encoding="utf-8")
        self.user_list.chmod(0o600)
        self.assert_applies(self.root)

    def test_a_list_inside_the_git_folder_applies(self) -> None:
        inside = self.root / ".git/terms.txt"
        inside.write_text(CANARY + "\n", encoding="utf-8")
        inside.chmod(0o600)
        for spelling in (".git", ".GIT"):
            with self.subTest(spelling=spelling):
                if not (self.root / spelling).exists():
                    self.skipTest("this disk tells letter case apart")
                self.user_list.unlink(missing_ok=True)
                self.user_list.symlink_to(self.root / spelling / "terms.txt")
                self.assert_applies(self.root)

    def test_an_outer_repository_applies_a_list_its_inner_repository_tracks(
        self,
    ) -> None:
        outer = self.other_repository()
        self.user_list.symlink_to(self.list_repository(outer / "inner"))
        self.assert_applies(outer)

    def test_a_nested_repository_or_submodule_file_is_not_kept(self) -> None:
        self.user_list.symlink_to(self.list_repository(self.root / "nested"))
        self.assert_applies(self.root)
        source = self.list_repository(self.root.parent / (self.root.name + "-source"))
        self.addCleanup(shutil.rmtree, source.parents[1])
        run_git(
            self.root,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(source.parents[1]),
            "sub",
        )
        self.user_list.unlink()
        self.user_list.symlink_to(self.root / "sub/privacy/terms.txt")
        self.assert_applies(self.root)

    def test_an_untracked_or_ignored_file_in_the_folder_is_not_kept(self) -> None:
        for name in ("untracked.txt", ".local/terms.txt"):
            with self.subTest(name=name):
                inside = self.root / name
                inside.write_text(CANARY + "\n", encoding="utf-8")
                inside.chmod(0o600)
                self.user_list.unlink(missing_ok=True)
                self.user_list.symlink_to(inside)
                self.assert_applies(self.root)
        self.user_list.unlink()
        config = self.root / ".config"
        plain = config / "first-commit/private-values.txt"
        plain.parent.mkdir(parents=True)
        plain.write_text(CANARY + "\n", encoding="utf-8")
        plain.chmod(0o600)
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(config)}):
            self.assert_applies(self.root)

    # The decision follows the file that was opened, never the path seen before:
    # the link is moved to a file outside right after it was resolved.
    def assert_applies_after(self, move: Callable[[Path], object]) -> None:
        outside = self.config / "outside.txt"
        self.user_list.symlink_to(self.kept)
        resolve = os.path.realpath

        def moved(path: str | os.PathLike[str], **options: bool) -> str:
            resolved = resolve(path, **options)
            if Path(path) == self.user_list and self.user_list.readlink() == self.kept:
                move(outside)
                self.user_list.unlink()
                self.user_list.symlink_to(outside)
            return resolved

        with patch("os.path.realpath", side_effect=moved):
            self.assert_applies(self.root)

    def test_a_link_moved_after_it_was_resolved_applies_the_list(self) -> None:
        self.assert_applies_after(lambda outside: shutil.copy2(self.kept, outside))

    def test_a_file_moved_after_it_was_resolved_applies_the_list(self) -> None:
        self.assert_applies_after(self.kept.replace)

    def test_setup_names_the_user_list_by_the_same_rule(self) -> None:
        self.assertIs(UserList.ABSENT, user_list_state(self.root))
        self.user_list.symlink_to(self.config / "missing.txt")
        self.assertIs(UserList.APPLIES, user_list_state(self.root))
        self.user_list.unlink()
        self.user_list.symlink_to(self.kept)
        self.assertIs(UserList.KEPT, user_list_state(self.root))
        self.assertIs(UserList.APPLIES, user_list_state(None))

    def test_doctor_output_is_unchanged(self) -> None:
        passed = Result("doctor", ())
        with patch("first_commit.validation.doctor", return_value=passed):
            without = self.run_cli("doctor")
            self.user_list.symlink_to(self.kept)
            self.assertEqual(without, self.run_cli("doctor"))
        self.assertEqual("", without[2])


if __name__ == "__main__":
    unittest.main()
