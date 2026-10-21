import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit.git import GitError, IgnoreStateError, require_ignored
from tests.support import TemporaryRootTest, initialize_repository, run_git

SUBJECT = "Synthetic record"
PATH = ".local/record.json"
NOT_IGNORED = f"{SUBJECT} must be protected by repository .gitignore."


class RequireIgnoredTest(TemporaryRootTest):
    def setUp(self) -> None:
        super().setUp()
        initialize_repository(self.root)

    def ignore(self, content: str, name: str = ".gitignore") -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def refusal(self, root: Path | None = None) -> str:
        with self.assertRaises(IgnoreStateError) as caught:
            require_ignored(root or self.root, PATH, SUBJECT)
        return str(caught.exception)

    def test_present_and_absent_files_under_an_ignored_folder_pass(self) -> None:
        self.ignore(".local/\n")
        require_ignored(self.root, PATH, SUBJECT)
        record = self.root / PATH
        record.parent.mkdir()
        record.write_text("{}\n", encoding="utf-8")
        require_ignored(self.root, PATH, SUBJECT)

    def test_a_nested_gitignore_protects_its_folder(self) -> None:
        self.ignore("*\n", ".local/.gitignore")
        require_ignored(self.root, PATH, SUBJECT)

    def test_unmatched_and_negated_paths_are_refused(self) -> None:
        self.assertEqual(NOT_IGNORED, self.refusal())
        self.ignore(".local/*\n!.local/record.json\n")
        self.assertEqual(NOT_IGNORED, self.refusal())

    def test_other_exclude_sources_do_not_protect(self) -> None:
        self.ignore(".local/\n", ".git/info/exclude")
        self.assertEqual(NOT_IGNORED, self.refusal())
        (self.root / ".git/info/exclude").unlink()
        with tempfile.TemporaryDirectory() as home:
            global_ignore = Path(home) / ".gitignore"
            global_ignore.write_text(".local/\n", encoding="utf-8")
            (Path(home) / ".gitconfig").write_text(
                f"[core]\n\texcludesFile = {global_ignore}\n", encoding="utf-8"
            )
            with patch.dict(os.environ, {"HOME": home, "XDG_CONFIG_HOME": home}):
                self.assertEqual(NOT_IGNORED, self.refusal())

    def test_tracked_file_is_refused_even_when_ignored(self) -> None:
        self.ignore(".local/\n")
        record = self.root / PATH
        record.parent.mkdir()
        record.write_text("{}\n", encoding="utf-8")
        run_git(self.root, "add", "--force", "--", PATH)
        self.assertEqual(f"{SUBJECT} must not be tracked.", self.refusal())

    def test_git_failure_names_only_the_subject(self) -> None:
        unknown = f"{SUBJECT} Git state cannot be determined."
        with patch(
            "first_commit.git.is_tracked", side_effect=GitError("private-canary")
        ):
            self.assertEqual(unknown, self.refusal())
        with tempfile.TemporaryDirectory() as outside:
            self.assertEqual(unknown, self.refusal(Path(outside)))


if __name__ == "__main__":
    unittest.main()
