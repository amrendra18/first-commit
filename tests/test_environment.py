import tempfile
import unittest
from pathlib import Path

from first_commit.candidates import environment_files, working_candidates
from first_commit.checks.environment import DOTENV_PATHSPECS, environment_findings
from first_commit.models import EnvironmentFile, FileState
from first_commit.policy_fields import EnvironmentExceptionEntry
from tests.support import global_excludes, initialize_repository, run_git


class EnvironmentTest(unittest.TestCase):
    def test_environment_findings_allow_empty_budget(self) -> None:
        files = (self._file(".env", FileState.VISIBLE),)
        self.assertEqual([], environment_findings(files, (), max_findings=0))

    def test_environment_findings_ignore_repository_ignored_files(self) -> None:
        files = (self._file("private.env", FileState.IGNORED),)

        self.assertEqual([], environment_findings(files, (), max_findings=1000))

    def test_discovers_every_web_dotenv_pattern_at_nested_depths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            nested = root / "nested"
            nested.mkdir()
            paths = (
                ".env",
                ".env.production",
                "application.env",
                "application.env.local",
                "nested/.env",
                "nested/.env.production",
                "nested/application.env",
                "nested/application.env.local",
            )
            for path in paths:
                (root / path).write_text("VALUE=example\n", encoding="utf-8")

            files = environment_files(root, DOTENV_PATHSPECS, max_files=20)

        self.assertEqual(set(paths), {item.path for item in files})
        self.assertEqual({FileState.VISIBLE}, {item.state for item in files})

    def test_empty_pathspecs_select_no_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / ".env").write_text("VALUE=example\n", encoding="utf-8")
            (root / "README.md").write_text("# Project\n", encoding="utf-8")
            run_git(root, "add", "--", ".env", "README.md")

            self.assertEqual((), environment_files(root, (), max_files=10))

    def test_discovers_ignored_file_without_loading_its_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            secret = b"private-environment-canary"
            (root / ".env").write_bytes(secret)

            files = environment_files(root, DOTENV_PATHSPECS, max_files=10)
            candidates = tuple(working_candidates(root, max_files=10, max_bytes=1024))

        self.assertEqual(FileState.IGNORED, files[0].state)
        self.assertFalse(hasattr(files[0], "content"))
        self.assertNotIn(".env", {candidate.path for candidate in candidates})
        self.assertNotIn(secret.decode(), repr(files))

    def test_rejects_visible_and_tracked_private_environment_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / ".env").write_text("VALUE=example\n", encoding="utf-8")
            nested = root / "nested"
            nested.mkdir()
            (nested / "application.env").write_text("VALUE=example\n", encoding="utf-8")
            run_git(root, "add", "--", "nested/application.env")

            files = environment_files(root, DOTENV_PATHSPECS, max_files=10)
            findings = environment_findings(files, (), max_findings=1000)

        rules = {finding.path: finding.rule_id for finding in findings}
        self.assertEqual("environment.not-ignored", rules[".env"])
        self.assertEqual(
            "environment.tracked-private-file", rules["nested/application.env"]
        )

    def test_repository_gitignore_is_required_for_ignored_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / ".env").write_text("VALUE=example\n", encoding="utf-8")
            exclude = root / ".git" / "info" / "exclude"
            exclude.write_text(".env\n", encoding="utf-8")

            files = environment_files(root, DOTENV_PATHSPECS, max_files=10)

        self.assertEqual(FileState.VISIBLE, files[0].state)

    def test_global_gitignore_does_not_protect_environment_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            initialize_repository(root)
            (root / ".env").write_text("VALUE=example\n", encoding="utf-8")
            with global_excludes(Path(directory), ".env"):
                files = environment_files(root, DOTENV_PATHSPECS, max_files=10)

        self.assertEqual(FileState.VISIBLE, files[0].state)

    def test_accepts_public_template_and_exact_exception_only(self) -> None:
        files = (
            self._file(".env.example", FileState.TRACKED),
            self._file("tests/fixtures/.env", FileState.TRACKED),
            self._file("other/.env", FileState.TRACKED),
        )
        exceptions = (
            EnvironmentExceptionEntry(
                path="tests/fixtures/.env",
                reason="Synthetic parser fixture.",
            ),
        )

        findings = environment_findings(files, exceptions, max_findings=1000)

        self.assertEqual(["other/.env"], [finding.path for finding in findings])

    def test_environment_findings_respect_finding_budget(self) -> None:
        files = tuple(
            self._file(f"private-{index}.env", FileState.VISIBLE) for index in range(20)
        )

        findings = environment_findings(files, (), max_findings=3)

        self.assertEqual(3, len(findings))

    @staticmethod
    def _file(path: str, state: FileState) -> EnvironmentFile:
        return EnvironmentFile(path=path, state=state)


if __name__ == "__main__":
    unittest.main()
