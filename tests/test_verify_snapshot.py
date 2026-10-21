import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from tests.support import initialize_repository, run_git

ROOT = Path(__file__).resolve().parents[1]


def harness(name: str) -> ModuleType:
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    return importlib.import_module(f"verify_lib.{name}")


core = harness("core")
prepare = harness("prepare")


class SnapshotTest(unittest.TestCase):
    def test_snapshot_copies_what_git_shows_and_skips_ignored_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            project = folder / "project"
            files = {
                ".gitignore": "ignored/\n",
                "kept.txt": "kept\n",
                "changed.txt": "before\n",
                "deleted.txt": "deleted\n",
            }
            for name, text in files.items():
                (project / name).parent.mkdir(parents=True, exist_ok=True)
                (project / name).write_text(text, "utf-8")
            initialize_repository(project)
            run_git(project, "add", "--", *files)
            run_git(
                project,
                "-c",
                "user.name=Snapshot Test",
                "-c",
                "user.email=snapshot@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "base",
            )
            (project / "changed.txt").write_text("after\n", "utf-8")
            (project / "deleted.txt").unlink()
            for name in ("new.txt", ".claude/notes.txt", "ignored/secret.txt"):
                (project / name).parent.mkdir(parents=True, exist_ok=True)
                (project / name).write_text(name, "utf-8")
            work = folder / "work"
            work.mkdir()
            run = core.Run(
                work=work, python=sys.executable, environment=dict(os.environ)
            )
            with patch.object(prepare, "PROJECT", project):
                source = prepare.snapshot(run, None)
            self.assertEqual("after\n", (source / "changed.txt").read_text("utf-8"))
            self.assertEqual("new.txt", (source / "new.txt").read_text("utf-8"))
            self.assertTrue((source / ".claude/notes.txt").is_file())
            self.assertTrue((source / "kept.txt").is_file())
            self.assertFalse((source / "deleted.txt").exists())
            self.assertFalse((source / "ignored").exists())
            self.assertEqual(40, len(run.revision))

    def test_snapshot_includes_staged_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            project = folder / "project"
            project.mkdir()
            for name in ("edited.txt", "removed.txt", "moved.txt"):
                (project / name).write_text("before\n", "utf-8")
            initialize_repository(project)
            run_git(project, "add", "--", "edited.txt", "removed.txt", "moved.txt")
            run_git(
                project,
                "-c",
                "user.name=Snapshot Test",
                "-c",
                "user.email=snapshot@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "base",
            )
            (project / "edited.txt").write_text("after\n", "utf-8")
            (project / "added.txt").write_text("added\n", "utf-8")
            run_git(project, "add", "--", "edited.txt", "added.txt")
            run_git(project, "rm", "-q", "--", "removed.txt")
            run_git(project, "mv", "moved.txt", "renamed.txt")
            work = folder / "work"
            work.mkdir()
            run = core.Run(
                work=work, python=sys.executable, environment=dict(os.environ)
            )
            with patch.object(prepare, "PROJECT", project):
                source = prepare.snapshot(run, None)
            self.assertEqual("after\n", (source / "edited.txt").read_text("utf-8"))
            self.assertEqual("added\n", (source / "added.txt").read_text("utf-8"))
            self.assertFalse((source / "removed.txt").exists())
            self.assertFalse((source / "moved.txt").exists())
            self.assertEqual("before\n", (source / "renamed.txt").read_text("utf-8"))


if __name__ == "__main__":
    unittest.main()
