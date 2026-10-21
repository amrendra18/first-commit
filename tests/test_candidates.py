import io
import os
import signal
import subprocess
import tempfile
import time
import unittest
from collections.abc import Generator
from pathlib import Path
from typing import cast
from unittest.mock import patch

from first_commit.candidates import (
    CandidateError,
    _index_blobs,
    _split_paths,
    _stage_zero_entries,
    environment_files,
    index_candidate,
    staged_candidate_paths,
    staged_candidates,
    working_candidate_paths,
    working_candidates,
)
from first_commit.git import GitError, _kill_on_timeout, _read_object, cat_file_blobs
from first_commit.models import Origin
from tests.support import initialize_repository, run_git

Blobs = Generator[tuple[str, bytes], None, None]

OBJECT_ID = "a" * 40
ENTRY = ("100644", OBJECT_ID)


class CandidatesTest(unittest.TestCase):
    def test_rejects_path_and_index_metadata_limits(self) -> None:
        with self.assertRaisesRegex(CandidateError, "count"):
            _split_paths(b"one\0two\0", max_files=1)
        self.assertEqual({}, _stage_zero_entries(b"malformed\0"))

        with self.assertRaisesRegex(CandidateError, "metadata"):
            _stage_zero_entries(b"100644 \xff 0\tvalue\0")

    def test_environment_file_discovery_handles_git_errors_and_union_limits(
        self,
    ) -> None:
        with patch("first_commit.candidates.run_git", side_effect=GitError("failed")):
            with self.assertRaisesRegex(CandidateError, "failed"):
                environment_files(Path("/repository"), (".env",), max_files=10)

        with patch(
            "first_commit.candidates.run_git",
            side_effect=(b"one\0", b"two\0", b"three\0"),
        ):
            with self.assertRaisesRegex(CandidateError, "count"):
                environment_files(Path("/repository"), (".env",), max_files=2)

    def test_index_blobs_reject_bad_metadata_and_inconsistent_git_output(
        self,
    ) -> None:
        root = Path("/repository")
        header = OBJECT_ID.encode() + b" blob 3\n"
        with self.assertRaisesRegex(CandidateError, "submodule"):
            _index_blobs(root, {"value": ("160000", OBJECT_ID)}, 10)
        with self.assertRaisesRegex(CandidateError, "metadata"):
            _index_blobs(root, {"value": ("100644", "object")}, 10)
        cases = (
            ((b"",), "inconsistent"),
            ((b"b" * 40 + b" blob 3\n",), "inconsistent"),
            ((OBJECT_ID.encode() + b" missing\n",), "no content in the Git index"),
            ((OBJECT_ID.encode() + b" tree 3\n",), "no content in the Git index"),
            ((OBJECT_ID.encode() + b" blob many\n",), "inconsistent"),
        )
        for outputs, message in cases:
            with (
                self.subTest(outputs=outputs),
                patch("first_commit.candidates.run_git", side_effect=outputs),
                self.assertRaisesRegex(CandidateError, message),
            ):
                _index_blobs(root, {"value": ENTRY}, 10)
        with (
            patch("first_commit.candidates.run_git", return_value=header),
            patch(
                "first_commit.candidates.cat_file_blobs",
                side_effect=GitError("Git returned inconsistent object content."),
            ),
            self.assertRaisesRegex(CandidateError, "inconsistent"),
        ):
            tuple(_index_blobs(root, {"value": ENTRY}, 10))

    def test_index_blobs_skip_oversized_blobs_without_reading_them(self) -> None:
        with patch(
            "first_commit.candidates.run_git",
            return_value=OBJECT_ID.encode() + b" blob 11\n",
        ) as git:
            loaded = _index_blobs(Path("/repository"), {"value": ENTRY}, 10)
            self.assertEqual((), tuple(loaded))
        self.assertEqual(["value"], loaded.oversized)
        self.assertEqual(1, git.call_count)

    def test_index_candidate_rejects_missing_and_oversized_entries(self) -> None:
        root = Path("/repository")
        with patch("first_commit.candidates.run_git", return_value=b""):
            with self.assertRaisesRegex(CandidateError, "no content in the Git index"):
                index_candidate(root, "value", 10)
        entry = b"100644 " + OBJECT_ID.encode() + b" 0\tvalue\0"
        with patch(
            "first_commit.candidates.run_git",
            side_effect=(entry, OBJECT_ID.encode() + b" blob 11\n"),
        ):
            with self.assertRaisesRegex(CandidateError, "size limit"):
                index_candidate(root, "value", 10)

    def test_staged_scope_rejects_a_path_missing_from_the_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            with self.assertRaisesRegex(CandidateError, "no content in the Git index"):
                staged_candidates(root, 10, 10, paths=("absent.txt",))
            with self.assertRaisesRegex(CandidateError, "count"):
                staged_candidates(root, 1, 10, paths=("one", "two"))

    def test_staged_scope_reads_each_shared_blob_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            for name in ("one.txt", "two.txt"):
                (root / name).write_bytes(b"same\n")
            run_git(root, "add", "--", "one.txt", "two.txt")

            loaded = tuple(staged_candidates(root, max_files=10, max_bytes=1024))

        self.assertEqual(
            [("one.txt", b"same\n"), ("two.txt", b"same\n")],
            [(item.path, item.content) for item in loaded],
        )

    def test_staged_and_index_candidate_wrap_git_errors(self) -> None:
        with patch("first_commit.candidates.run_git", side_effect=GitError("failed")):
            with self.assertRaisesRegex(CandidateError, "failed"):
                tuple(staged_candidates(Path("/repository"), 10, 10))
            with self.assertRaisesRegex(CandidateError, "failed"):
                index_candidate(Path("/repository"), "value", 10)

    def test_working_scope_excludes_ignored_local_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / ".gitignore").write_text(".local/\n", encoding="utf-8")
            (root / "public.txt").write_text("public\n", encoding="utf-8")
            (root / ".local").mkdir()
            (root / ".local" / "private.txt").write_text("private\n", encoding="utf-8")

            candidates = tuple(working_candidates(root, max_files=10, max_bytes=1024))

        paths = {candidate.path for candidate in candidates}
        self.assertIn("public.txt", paths)
        self.assertNotIn(".local/private.txt", paths)

    def test_working_scope_excludes_deleted_paths_and_preserves_empty_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            deleted = root / "deleted.txt"
            deleted.write_text("tracked\n", encoding="utf-8")
            empty = root / "empty.txt"
            empty.write_bytes(b"")
            run_git(root, "add", "--", "deleted.txt", "empty.txt")
            deleted.unlink()

            candidates = tuple(working_candidates(root, max_files=10, max_bytes=1024))

        by_path = {candidate.path: candidate for candidate in candidates}
        self.assertNotIn("deleted.txt", by_path)
        self.assertEqual(b"", by_path["empty.txt"].content)

    def test_staged_scope_reads_index_blob_not_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            path = root / "value.txt"
            path.write_bytes(b"staged-value\n")
            run_git(root, "add", "--", "value.txt")
            path.write_bytes(b"working-value\n")

            candidates = tuple(staged_candidates(root, max_files=10, max_bytes=1024))

        self.assertEqual(1, len(candidates))
        self.assertEqual(b"staged-value\n", candidates[0].content)
        self.assertEqual(Origin.INDEX, candidates[0].origin)

    def test_reports_candidates_above_byte_limit_by_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / "large.txt").write_bytes(b"12345")
            (root / "small.txt").write_bytes(b"1234")
            run_git(root, "add", "--", "large.txt", "small.txt")

            loads = (
                working_candidates(root, max_files=10, max_bytes=4),
                staged_candidates(root, max_files=10, max_bytes=4),
            )
            read = [[item.path for item in loaded] for loaded in loads]

        for loaded, paths in zip(loads, read, strict=True):
            self.assertEqual(["large.txt"], loaded.oversized)
            self.assertEqual(["small.txt"], paths)

    def test_explicit_path_selection_does_not_read_omitted_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / "allowed.txt").write_bytes(b"ok\n")
            (root / "blocked.kdbx").write_bytes(b"12345")
            run_git(root, "add", "--", "allowed.txt", "blocked.kdbx")

            working_paths = working_candidate_paths(root, max_files=10)
            staged_paths = staged_candidate_paths(root, max_files=10)
            allowed_working = tuple(
                path for path in working_paths if path != "blocked.kdbx"
            )
            allowed_staged = tuple(
                path for path in staged_paths if path != "blocked.kdbx"
            )
            working = tuple(
                working_candidates(
                    root, max_files=10, max_bytes=4, paths=allowed_working
                )
            )
            staged = tuple(
                staged_candidates(root, max_files=10, max_bytes=4, paths=allowed_staged)
            )

        self.assertEqual(["allowed.txt"], [item.path for item in working])
        self.assertEqual(["allowed.txt"], [item.path for item in staged])

    def test_working_symlink_reads_link_value_not_external_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            initialize_repository(root)
            external = Path(directory) / "external"
            external.write_text("private-external-content\n", encoding="utf-8")
            (root / "link").symlink_to(external)

            candidates = tuple(working_candidates(root, max_files=10, max_bytes=1024))

        link = next(item for item in candidates if item.path == "link")
        self.assertNotIn(b"private-external-content", link.content)

    def test_working_and_staged_scopes_exclude_submodule_gitlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            child = base / "child"
            child.mkdir()
            initialize_repository(child)
            (child / "value.txt").write_text("child\n", encoding="utf-8")
            run_git(child, "add", "--", "value.txt")
            run_git(
                child,
                "-c",
                "user.name=Example Person",
                "-c",
                "user.email=person@example.com",
                "commit",
                "-q",
                "-m",
                "child",
            )
            commit = run_git(child, "rev-parse", "HEAD").stdout.decode().strip()

            root = base / "repository"
            root.mkdir()
            initialize_repository(root)
            run_git(
                root,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{commit},vendor",
            )

            working = tuple(working_candidates(root, max_files=10, max_bytes=1024))
            staged = tuple(staged_candidates(root, max_files=10, max_bytes=1024))
            named = tuple(staged_candidates(root, 10, 1024, paths=("vendor",)))

        self.assertNotIn("vendor", {item.path for item in working})
        self.assertNotIn("vendor", {item.path for item in staged})
        self.assertEqual((), named)

    def test_explicit_paths_keep_the_count_limit(self) -> None:
        for load in (working_candidates, staged_candidates):
            with (
                self.subTest(load=load.__name__),
                self.assertRaisesRegex(CandidateError, "count exceeds"),
            ):
                tuple(load(Path("/repository"), 1, 10, paths=("a", "b")))

    def test_preserves_spaces_unicode_newlines_and_leading_dashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            names = (
                "space name.txt",
                "unicode-\N{SNOWMAN}.txt",
                "line\nbreak.txt",
                "-value.txt",
            )
            for name in names:
                (root / name).write_text("value\n", encoding="utf-8")
                run_git(root, "add", "--", name)

            working = tuple(working_candidates(root, max_files=10, max_bytes=1024))
            staged = tuple(staged_candidates(root, max_files=10, max_bytes=1024))

        self.assertEqual(set(names), {item.path for item in working})
        self.assertEqual(set(names), {item.path for item in staged})


# `exec 0<&-` closes input, then prints a byte: Popen returns and the first write fails.
def fake_git(script: str):
    real = subprocess.Popen

    def start(_arguments, **options):
        process = real(["/bin/sh", "-c", script], **options)
        if script.startswith("exec 0<&-"):
            cast("io.BufferedReader", process.stdout).peek(1)
        return process

    return patch("first_commit.git.subprocess.Popen", side_effect=start)


class CatFileBlobsTest(unittest.TestCase):
    def test_reads_blobs_one_at_a_time_and_ends_git_when_stopped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            sizes = {}
            for name, content in (("one", b"one\n"), ("two", b"second\n")):
                (root / name).write_bytes(content)
                written = run_git(root, "hash-object", "-w", "--", name)
                sizes[written.stdout.decode("ascii").strip()] = len(content)
            blobs = list(cat_file_blobs(root, sizes))
            stopped = cast("Blobs", cat_file_blobs(root, sizes))
            next(stopped)
            stopped.close()
        self.assertEqual([b"one\n", b"second\n"], [content for _, content in blobs])
        self.assertEqual([], list(cat_file_blobs(root, {})))

    def test_read_object_rejects_inconsistent_answers(self) -> None:
        header = OBJECT_ID.encode() + b" blob 3\n"
        for answer in (
            OBJECT_ID.encode() + b" missing\n",
            header + b"xx",
            header + b"abc",
            header + b"abcx",
        ):
            with (
                self.subTest(answer=answer),
                self.assertRaisesRegex(GitError, "inconsistent"),
            ):
                _read_object(io.BytesIO(answer), OBJECT_ID, "blob", 3)

    def test_process_failures_become_git_errors(self) -> None:
        answer = 'read id; printf "%s blob 3\\nabc\\n" "$id"'
        cases = (
            (answer + "; printf extra", "inconsistent"),
            (
                answer + "; exit 3",
                "^Git command `git cat-file` failed with exit code 3",
            ),
            (
                "exec 0<&-; printf x; exec sleep 5",
                "^Git command `git cat-file` stopped before it answered",
            ),
            ("exec sleep 5", "^Git command `git cat-file` timed out"),
        )
        for script, message in cases:
            with (
                self.subTest(script=script),
                fake_git(script),
                patch("first_commit.git.GIT_TIMEOUT_SECONDS", 0.5),
                self.assertRaisesRegex(GitError, message),
            ):
                list(cat_file_blobs(Path("/repository"), {OBJECT_ID: 3}))
        with (
            patch("first_commit.git.subprocess.Popen", side_effect=OSError),
            self.assertRaisesRegex(GitError, "unavailable"),
        ):
            list(cat_file_blobs(Path("/repository"), {OBJECT_ID: 3}))

    def test_timeout_also_ends_the_processes_git_started(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            started = Path(directory) / "child"
            script = f"sleep 30 & echo $! > '{started}'; wait"
            begun = time.monotonic()
            with (
                fake_git(script),
                patch("first_commit.git.GIT_TIMEOUT_SECONDS", 0.5),
                self.assertRaisesRegex(GitError, "timed out"),
            ):
                list(cat_file_blobs(Path("/repository"), {OBJECT_ID: 3}))
            # A child that keeps the output pipe open would hold the read for 30 s.
            self.assertLess(time.monotonic() - begun, 10)
            child = int(started.read_text("ascii"))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and _running(child):
            time.sleep(0.05)
        self.assertFalse(_running(child))

    def test_blobs_are_read_when_the_system_reaps_children(self) -> None:
        # With SIGCHLD ignored, the system reaps Git itself; os.waitid then fails.
        previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        self.addCleanup(signal.signal, signal.SIGCHLD, previous)
        answer = 'read id; printf "%s blob 3\\nabc\\n" "$id"'
        with fake_git(answer):
            blobs = list(cat_file_blobs(Path("/repository"), {OBJECT_ID: 3}))
        self.assertEqual([(OBJECT_ID, b"abc")], blobs)

    def test_deadline_leaves_a_reaped_process_alone(self) -> None:
        process = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
        process.wait()
        with (
            patch("first_commit.git.GIT_TIMEOUT_SECONDS", 0.01),
            patch("first_commit.git._kill_group") as kill,
            _kill_on_timeout(process),
        ):
            time.sleep(0.2)
        kill.assert_not_called()

    @unittest.skipUnless(
        hasattr(os, "waitid"), "needs os.waitid, which macOS has from Python 3.13"
    )
    def test_git_that_exits_still_has_its_children_ended(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            started = Path(directory) / "child"
            script = (
                f"sleep 30 >/dev/null 2>&1 </dev/null & echo $! > '{started}'; "
                'read id; printf "%s blob 3\\nabc\\n" "$id"'
            )
            with fake_git(script):
                blobs = list(cat_file_blobs(Path("/repository"), {OBJECT_ID: 3}))
            child = int(started.read_text("ascii"))
        self.assertEqual([(OBJECT_ID, b"abc")], blobs)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and _running(child):
            time.sleep(0.05)
        self.assertFalse(_running(child))

    def test_group_is_never_killed_after_git_is_reaped(self) -> None:
        # A reaped Git's process id can name a new process; killing it is unsafe.
        states = []
        real_killpg = os.killpg

        def killpg(pid: int, signal_number: int) -> None:
            try:
                os.kill(pid, 0)
                states.append("unreaped")
            except ProcessLookupError:
                states.append("reaped")
            real_killpg(pid, signal_number)

        answer = 'read id; printf "%s blob 3\\nabc\\n" "$id"'
        with fake_git(answer), patch("os.killpg", side_effect=killpg):
            blobs = list(cat_file_blobs(Path("/repository"), {OBJECT_ID: 3}))
            stopped = cast(
                "Blobs",
                cat_file_blobs(Path("/repository"), {OBJECT_ID: 3, "0" * 40: 3}),
            )
            next(stopped)
            stopped.close()
        self.assertEqual([(OBJECT_ID, b"abc")], blobs)
        self.assertNotIn("reaped", states)
        self.assertIn("unreaped", states)


def _running(pid: int) -> bool:
    state = subprocess.run(
        ["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, check=False
    )
    return state.returncode == 0 and not state.stdout.strip().startswith(b"Z")


if __name__ == "__main__":
    unittest.main()
