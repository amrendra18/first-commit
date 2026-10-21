import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from first_commit.paths import (
    PathError,
    confined_path,
    create_exclusive,
    make_private_folders,
    read_explicit_file_bytes,
    read_regular_bytes,
    read_worktree_bytes,
)


class PathsTest(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX named pipes")
    def test_regular_read_rejects_named_pipe_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pipe"
            os.mkfifo(path)
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
            code = (
                "import sys\nfrom pathlib import Path\n"
                "from first_commit.paths import PathError, read_regular_bytes\n"
                "try:\n    read_regular_bytes(Path(sys.argv[1]), 10)\n"
                "except PathError:\n    sys.exit(0)\n"
                "sys.exit(1)\n"
            )
            try:
                result = subprocess.run(
                    [sys.executable, "-c", code, str(path)],
                    env=environment,
                    capture_output=True,
                    timeout=2,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                self.fail("non-regular file open must not block")
            self.assertEqual(0, result.returncode)

    def test_confines_normalized_relative_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            path = confined_path(root, "nested/value.txt")

        self.assertEqual(root.resolve() / "nested" / "value.txt", path)

    def test_rejects_parent_and_absolute_candidate_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            with self.assertRaises(PathError):
                confined_path(root, "../external")
            with self.assertRaises(PathError):
                confined_path(root, "/external")

    def test_explicit_relative_read_is_anchored_to_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "value.txt").write_bytes(b"value")

            content = read_explicit_file_bytes(root, Path("value.txt"), 5)

        self.assertEqual(b"value", content)

    def test_regular_read_rejects_symlink_directory_and_oversize_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_bytes(b"private")
            link = root / "link"
            link.symlink_to(target)

            with self.assertRaises(PathError):
                read_regular_bytes(link, 1024)
            with self.assertRaises(PathError):
                read_regular_bytes(root, 1024)
            with self.assertRaises(PathError):
                read_regular_bytes(target, 3)

    def test_regular_read_maps_read_errors_and_race_size_growth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "value.txt"
            path.write_bytes(b"value")
            with patch("first_commit.paths.os.read", side_effect=OSError("failed")):
                with self.assertRaisesRegex(PathError, "cannot be read"):
                    read_regular_bytes(path, 1024)

        metadata = SimpleNamespace(st_mode=stat.S_IFREG, st_size=3)
        with patch("first_commit.paths.os.open", return_value=7):
            with patch("first_commit.paths.os.fstat", return_value=metadata):
                with patch("first_commit.paths.os.read", return_value=b"1234"):
                    with patch("first_commit.paths.os.close"):
                        with self.assertRaisesRegex(PathError, "size limit"):
                            read_regular_bytes(Path("value.txt"), 3)

    def test_confined_path_rejects_symlinked_parent_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "repository"
            root.mkdir()
            outside = base / "outside"
            outside.mkdir()
            (root / "link").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(PathError, "escapes"):
                confined_path(root, "link/value.txt")

    def test_read_functions_handle_missing_and_unreadable_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(PathError, "cannot be read"):
                read_regular_bytes(root / "missing", 10)
            (root / "directory").mkdir()
            self.assertEqual(b"", read_worktree_bytes(root, "directory", 10))

        with tempfile.TemporaryDirectory() as directory:
            # Resolved, as read_worktree_bytes resolves the root: on macOS the
            # temporary folder is under /var, a link to /private/var.
            root = Path(directory).resolve()
            link = root / "link"
            link.symlink_to(root / "target")
            real_readlink = os.readlink

            def readlink(path):
                if Path(path) == link:
                    raise OSError("failed")
                return real_readlink(path)

            with patch("first_commit.paths.os.readlink", side_effect=readlink):
                with self.assertRaisesRegex(PathError, "^File cannot be read.$"):
                    read_worktree_bytes(root, "link", 10)

    def test_create_exclusive_sets_mode_and_never_replaces(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            create_exclusive(path, b"first\n", 0o600)
            self.assertEqual(b"first\n", path.read_bytes())
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            with self.assertRaises(FileExistsError):
                create_exclusive(path, b"second\n", 0o600)
            self.assertEqual(b"first\n", path.read_bytes())
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                create_exclusive(link, b"second\n", 0o600)
            self.assertEqual(b"first\n", path.read_bytes())

    def test_create_exclusive_removes_its_own_partial_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            with (
                patch("first_commit.paths.os.fdopen", side_effect=OSError("full")),
                self.assertRaises(OSError),
            ):
                create_exclusive(path, b"content\n", 0o600)
            self.assertFalse(os.path.lexists(path))

    def test_private_folders_are_owner_only_and_only_new_ones_are_recorded(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".local").mkdir()
            created: list[Path] = []
            make_private_folders((root / ".local", root / ".local/inner"), created)
            self.assertEqual([root / ".local/inner"], created)
            self.assertEqual(
                0o700, stat.S_IMODE((root / ".local/inner").stat().st_mode)
            )

    def test_private_folders_refuse_a_symlink_or_a_file_in_their_place(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "file").write_text("", "utf-8")
            (root / "link").symlink_to(root, target_is_directory=True)
            for name in ("file", "link"):
                with self.subTest(name=name):
                    created: list[Path] = []
                    with self.assertRaisesRegex(PathError, "not a plain folder"):
                        make_private_folders((root / "new", root / name), created)
                    self.assertEqual([root / "new"], created)
                    (root / "new").rmdir()

    def test_worktree_symlink_value_obeys_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            link = root / "link"
            link.symlink_to("long-target")

            with self.assertRaisesRegex(PathError, "size limit"):
                read_worktree_bytes(root, "link", 3)

    def test_explicit_read_rejects_external_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            external = Path(directory) / "message"
            external.write_bytes(b"private")

            with self.assertRaisesRegex(PathError, "escapes"):
                read_explicit_file_bytes(root, external, 10)


if __name__ == "__main__":
    unittest.main()
