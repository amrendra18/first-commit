import io
import os
import re
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from first_commit import cli, git
from first_commit.executables import find_executable
from first_commit.gitleaks_scanner import DependencyError
from first_commit.hooks import HTTPS_REPOSITORY
from first_commit.pre_commit_runner import run_pre_commit
from first_commit.scanner_install import _curl_download, _download
from first_commit.setup import _preflight_source
from tests.support import initialize_repository, run_git


class AbsolutePathLookupTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        initialize_repository(self.root)
        (self.root / "note.txt").write_text("note\n", encoding="utf-8")
        self.blob = (
            run_git(self.root, "hash-object", "-w", "note.txt").stdout.decode().strip()
        )
        self.marker = self.root / "ran"
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)

    def plant(self, name: str, folder: str = "") -> None:
        program = self.root / folder / name
        program.parent.mkdir(exist_ok=True)
        program.write_text(
            f"#!/bin/sh\necho ran >> '{self.marker}'\nexit 0\n", encoding="utf-8"
        )
        program.chmod(0o755)

    def relative_path_first(self) -> dict[str, str]:
        return {"PATH": os.pathsep.join((".", "", os.environ.get("PATH", os.defpath)))}

    def test_lookup_skips_relative_entries(self) -> None:
        self.plant("git")
        with mock.patch.dict(os.environ, {"PATH": os.pathsep.join((".", ""))}):
            self.assertIsNone(find_executable("git"))
        with mock.patch.dict(os.environ, self.relative_path_first()):
            found = find_executable("git")

        self.assertIsNotNone(found)
        self.assertTrue(Path(str(found)).is_absolute())
        self.assertNotEqual(self.root, Path(str(found)).resolve().parent)

    def test_a_planted_git_in_a_relative_path_entry_never_runs(self) -> None:
        self.plant("git")
        with mock.patch.dict(os.environ, self.relative_path_first()):
            top = git.run_git(self.root, ("rev-parse", "--show-toplevel"))
            blobs = dict(git.cat_file_blobs(self.root, {self.blob: 5}))

        self.assertEqual(str(self.root), top.decode().strip())
        self.assertEqual({self.blob: b"note\n"}, blobs)
        self.assertFalse(self.marker.exists())

    def test_git_only_in_a_relative_path_entry_is_unavailable(self) -> None:
        self.plant("git")
        with mock.patch.dict(os.environ, {"PATH": "."}):
            with self.assertRaisesRegex(git.GitError, "Git is unavailable"):
                git.run_git(self.root, ("rev-parse", "--show-toplevel"))
            with self.assertRaisesRegex(git.GitError, "Git is unavailable"):
                dict(git.cat_file_blobs(self.root, {self.blob: 5}))

        self.assertFalse(self.marker.exists())

    def test_the_hook_source_preflight_runs_git_by_absolute_path(self) -> None:
        self.plant("git")
        completed = subprocess.CompletedProcess[bytes]([], 0)
        with (
            mock.patch.dict(os.environ, self.relative_path_first()),
            mock.patch(
                "first_commit.setup.subprocess.run", return_value=completed
            ) as run,
        ):
            _preflight_source(self.root, HTTPS_REPOSITORY)

        program = Path(run.call_args.args[0][0])
        self.assertTrue(program.is_absolute())
        self.assertNotEqual(self.root, program.resolve().parent)

    def test_a_planted_curl_in_a_relative_path_entry_never_runs(self) -> None:
        self.plant("curl")
        with mock.patch.dict(os.environ, {"PATH": "."}):
            self.assertIsNone(
                _curl_download("https://example.invalid/archive", self.root)
            )

        self.assertFalse(self.marker.exists())

    def repository_folder_first(self) -> dict[str, str]:
        entries = (str(self.root / "bin"), os.environ.get("PATH", os.defpath))
        return {"PATH": os.pathsep.join(entries)}

    def test_git_in_an_absolute_path_entry_inside_the_repository_is_refused(
        self,
    ) -> None:
        self.plant("git", "bin")
        refusal = re.escape("Git on PATH is bin/git inside this repository")
        with mock.patch.dict(os.environ, self.repository_folder_first()):
            with self.assertRaisesRegex(git.GitError, refusal) as caught:
                git.run_git(self.root, ("rev-parse", "--show-toplevel"))
            with self.assertRaisesRegex(git.GitError, refusal):
                dict(git.cat_file_blobs(self.root, {self.blob: 5}))

        self.assertIn(
            "\nfix: remove the folder that holds bin/git from PATH",
            str(caught.exception),
        )
        self.assertNotIn(str(self.root), str(caught.exception))
        self.assertFalse(self.marker.exists())

    def test_git_inside_the_repository_is_refused_from_a_subfolder(self) -> None:
        self.plant("git", "bin")
        start = self.root / "src"
        start.mkdir()
        refusal = re.escape("Git on PATH is bin/git inside this repository")
        with (
            mock.patch.dict(os.environ, self.repository_folder_first()),
            self.assertRaisesRegex(git.GitError, refusal),
        ):
            git.run_git(start, ("rev-parse", "--show-toplevel"))

        self.assertFalse(self.marker.exists())

    def test_check_outside_any_repository_runs_the_system_git(self) -> None:
        os.chdir("/")
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = cli.main(("check",))

        self.assertEqual(4, code)
        self.assertTrue(
            error.getvalue().startswith("error: / is not inside a Git repository"),
            error.getvalue(),
        )

    def test_curl_in_an_absolute_path_entry_inside_the_repository_is_refused(
        self,
    ) -> None:
        self.plant("curl", "bin")
        with (
            mock.patch.dict(os.environ, self.repository_folder_first()),
            mock.patch(
                "first_commit.scanner_install.urllib.request.urlopen"
            ) as urlopen,
            self.assertRaisesRegex(
                DependencyError,
                re.escape("curl on PATH is bin/curl inside this repository"),
            ),
        ):
            _download("https://example.invalid/archive", self.root)

        urlopen.assert_not_called()
        self.assertFalse(self.marker.exists())

    def test_child_processes_get_only_the_absolute_path_entries(self) -> None:
        for value, expected in (
            (os.pathsep.join((".", "/usr/bin", "", "bin", "/bin")), "/usr/bin:/bin"),
            (os.pathsep.join((".", "")), os.devnull),
        ):
            with self.subTest(path=value):
                selected = git.sanitized_git_environment({"PATH": value})
                self.assertEqual(expected.replace(":", os.pathsep), selected["PATH"])
        self.assertNotIn("PATH", git.sanitized_git_environment({}))

    def test_setup_pre_commit_never_runs_a_planted_git(self) -> None:
        self.plant("git")
        cache = tempfile.TemporaryDirectory()
        self.addCleanup(cache.cleanup)
        # HOME keeps the user's global Git settings, such as core.hooksPath, out.
        variables = {
            **self.relative_path_first(),
            "HOME": cache.name,
            "XDG_CONFIG_HOME": cache.name,
            "PRE_COMMIT_HOME": cache.name,
        }
        with mock.patch.dict(os.environ, variables):
            run_pre_commit(self.root, ("install",))

        self.assertFalse(self.marker.exists())
        self.assertTrue((self.root / ".git/hooks/pre-commit").is_file())

    def test_check_without_git_names_the_fix_and_no_repository_doubt(self) -> None:
        self.plant("git")
        output, error = io.StringIO(), io.StringIO()
        with (
            mock.patch.dict(os.environ, {"PATH": "."}),
            redirect_stdout(output),
            redirect_stderr(error),
        ):
            code = cli.main(("check", "--root", str(self.root)))

        self.assertEqual(
            (
                4,
                (
                    "error: Git is unavailable.\nfix: install Git, or put the "
                    "folder that holds it on PATH as an absolute path.\n"
                ),
            ),
            (code, error.getvalue()),
        )
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
