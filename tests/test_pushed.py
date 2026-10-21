import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from first_commit import cli
from first_commit.gitleaks import scan_history, scan_pushed
from first_commit.gitleaks_scanner import (
    CALIBRATION_INPUT,
    HISTORY_TIMEOUT_SECONDS,
    SCAN_TIMEOUT_SECONDS,
    DependencyError,
)
from first_commit.models import Result
from first_commit.pushed import (
    HISTORY_REVISIONS,
    MAX_REVISION_BYTES,
    PushedScope,
    push_revisions,
    pushed_scope,
)
from tests.gitleaks_support import (
    SLACK_LINE,
    commit_fixture,
    history_cli,
    needs_real_scanner,
    pushed_base_commit,
)
from tests.support import initialize_repository, run_git

START = "a" * 40
END = "b" * 40


def _head(root: Path) -> str:
    return run_git(root, "rev-parse", "HEAD").stdout.decode().strip()


class PushedScopeTest(unittest.TestCase):
    def test_scope_comes_from_the_object_id_and_a_plain_remote_name(self) -> None:
        environment = {
            "PRE_COMMIT_FROM_REF": START,
            "PRE_COMMIT_TO_REF": END,
            "PRE_COMMIT_REMOTE_NAME": "origin",
        }
        self.assertEqual(PushedScope(END, "origin"), pushed_scope(environment))
        long_id = {"PRE_COMMIT_TO_REF": "d" * 64, "PRE_COMMIT_REMOTE_NAME": "up"}
        self.assertEqual(PushedScope("d" * 64, "up"), pushed_scope(long_id))
        for remote in ("", "-x", "a b", "or*", "../bare repo.git", "a\nb"):
            with self.subTest(remote=remote):
                unnamed = {"PRE_COMMIT_TO_REF": END, "PRE_COMMIT_REMOTE_NAME": remote}
                self.assertEqual(PushedScope(END, None), pushed_scope(unnamed))
        for environment in (
            {},
            {"PRE_COMMIT_FROM_REF": START},
            {"PRE_COMMIT_TO_REF": "HEAD"},
        ):
            with self.subTest(environment=environment):
                self.assertIsNone(pushed_scope(environment))

    def test_revisions_exclude_only_the_remote_tips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / "a.txt").write_text("a\n", "utf-8")
            commit_fixture(root, "a.txt")
            first = _head(root)
            (root / "a.txt").write_text("b\n", "utf-8")
            commit_fixture(root, "a.txt")
            second = _head(root)
            run_git(root, "remote", "add", "origin/x", "https://example.invalid/x")
            run_git(root, "update-ref", "refs/remotes/origin/main", first)
            run_git(root, "update-ref", "refs/remotes/origin/x/main", second)

            self.assertEqual(
                (END, *HISTORY_REVISIONS, "--not", first),
                push_revisions(root, PushedScope(END, "origin")),
            )
            self.assertEqual(
                (END, *HISTORY_REVISIONS),
                push_revisions(root, PushedScope(END, "upstream")),
            )
            self.assertEqual(
                (END, *HISTORY_REVISIONS), push_revisions(root, PushedScope(END, None))
            )

    def test_a_remote_named_in_other_case_keeps_its_refs_out(self) -> None:
        # On a case-insensitive disk, Git files refs of Origin/x under origin/x/.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / "a.txt").write_text("a\n", "utf-8")
            commit_fixture(root, "a.txt")
            first = _head(root)
            (root / "a.txt").write_text("b\n", "utf-8")
            commit_fixture(root, "a.txt")
            second = _head(root)
            run_git(root, "remote", "add", "Origin/x", "https://example.invalid/x")
            run_git(root, "update-ref", "refs/remotes/origin/main", first)
            run_git(root, "update-ref", "refs/remotes/origin/x/main", second)

            self.assertEqual(
                (END, *HISTORY_REVISIONS, "--not", first),
                push_revisions(root, PushedScope(END, "origin")),
            )

    def test_remotes_that_differ_only_in_case_scan_all_local_commits(self) -> None:
        # On a case-insensitive disk, ORIGIN and origin share refs/remotes/origin/.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / "a.txt").write_text("a\n", "utf-8")
            commit_fixture(root, "a.txt")
            run_git(root, "remote", "add", "origin", "https://example.invalid/a")
            run_git(root, "remote", "add", "ORIGIN", "https://example.invalid/b")
            run_git(root, "update-ref", "refs/remotes/origin/main", _head(root))

            for remote in ("origin", "ORIGIN"):
                with self.subTest(remote=remote):
                    self.assertEqual(
                        (END, *HISTORY_REVISIONS),
                        push_revisions(root, PushedScope(END, remote)),
                    )

    def test_too_many_remote_tips_scan_all_local_commits(self) -> None:
        tips = tuple(f"{number:040x}" for number in range(2000))
        scope = PushedScope(END, "origin")
        with mock.patch("first_commit.pushed._remote_tips", return_value=tips):
            self.assertEqual(
                (END, *HISTORY_REVISIONS), push_revisions(Path("/repository"), scope)
            )
        with mock.patch("first_commit.pushed._remote_tips", return_value=tips[:100]):
            self.assertEqual(
                (END, *HISTORY_REVISIONS, "--not", *tips[:100]),
                push_revisions(Path("/repository"), scope),
            )
        self.assertGreater(len(" ".join(tips)), MAX_REVISION_BYTES)

    def test_scope_scan_passes_log_options_and_the_shorter_timeout(self) -> None:
        calls = []

        def record(arguments, **keywords):
            calls.append((arguments, keywords["timeout"]))
            code = 10 if arguments[1] == "stdin" else 0
            return subprocess.CompletedProcess(arguments, code, b"8.30.0", b"")

        with mock.patch(
            "first_commit.gitleaks_scanner.subprocess.run", side_effect=record
        ):
            scan_history(Path("/repository"), max_findings=1, executable="/gitleaks")
            scan_pushed(
                Path("/repository"),
                PushedScope(END, None),
                executable="/gitleaks",
                max_findings=1,
            )

        self.assertEqual(HISTORY_TIMEOUT_SECONDS, calls[2][1])
        self.assertIn("--log-opts=--exclude=refs/stash --all", calls[2][0])
        self.assertEqual(SCAN_TIMEOUT_SECONDS, calls[5][1])
        self.assertIn(f"--log-opts={END} --exclude=refs/stash --all", calls[5][0])
        self.assertNotIn("--reflog", " ".join(calls[5][0]))

    def test_invalid_scope_and_unreadable_remote_refs_are_refused(self) -> None:
        for scope in (
            PushedScope("HEAD", None),
            PushedScope(f"{START}..{END}", None),
            PushedScope(END, "a b"),
            PushedScope(END, "*"),
        ):
            with self.subTest(scope=scope):
                with self.assertRaisesRegex(DependencyError, "scope is invalid"):
                    scan_pushed(
                        Path("/repository"),
                        scope,
                        executable="/gitleaks",
                        max_findings=1,
                    )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(DependencyError, "remote's commits"):
                scan_pushed(
                    Path(directory),
                    PushedScope(END, "origin"),
                    executable="/gitleaks",
                    max_findings=1,
                )
        with (
            mock.patch(
                "first_commit.pushed.run_git",
                side_effect=(b"", b"HEAD refs/remotes/origin/main\n"),
            ),
            self.assertRaisesRegex(DependencyError, "remote's commits"),
        ):
            scan_pushed(
                Path("/repository"),
                PushedScope(END, "origin"),
                executable="/gitleaks",
                max_findings=1,
            )

    def test_pre_push_scans_the_pushed_scope_and_check_scans_all(self) -> None:
        passed = Result("test", ())
        environment = {
            "PRE_COMMIT_FROM_REF": START,
            "PRE_COMMIT_TO_REF": END,
            "PRE_COMMIT_REMOTE_NAME": "origin",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / ".repo-policy.json").write_text('{"schema_version":1}\n', "utf-8")
            for stage, expected in (
                (("hook", "pre-push"), PushedScope(END, "origin")),
                (("check",), None),
            ):
                with (
                    self.subTest(stage=stage),
                    mock.patch.dict("os.environ", environment),
                    mock.patch("first_commit.validation.doctor", return_value=passed),
                    mock.patch("first_commit.validation.working", return_value=passed),
                    mock.patch("first_commit.validation.staged", return_value=passed),
                    mock.patch(
                        "first_commit.validation.history", return_value=passed
                    ) as history,
                    redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(0, cli.main((*stage, "--root", str(root))))
                    self.assertEqual(expected, history.call_args.args[2])


class RealPushScanTest(unittest.TestCase):
    @needs_real_scanner
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        (self.root / "old.txt").write_bytes(CALIBRATION_INPUT)
        commit_fixture(self.root, "old.txt")
        # The remote already holds the old secret, so a push does not rescan it.
        run_git(self.root, "update-ref", "refs/remotes/origin/main", _head(self.root))
        (self.root / "new.txt").write_text("clean\n", encoding="utf-8")
        commit_fixture(self.root, "new.txt")

    def secret_commit(self, name: str) -> str:
        (self.root / name).write_bytes(CALIBRATION_INPUT)
        commit_fixture(self.root, name)
        return _head(self.root)

    def test_scan_skips_commits_the_remote_has(self) -> None:
        scope = PushedScope(_head(self.root), "origin")

        self.assertEqual((), scan_pushed(self.root, scope, max_findings=1))
        self.assertEqual("old.txt", scan_history(self.root, max_findings=1)[0].path)
        unnamed = PushedScope(_head(self.root), None)
        self.assertEqual(
            "old.txt", scan_pushed(self.root, unnamed, max_findings=1)[0].path
        )

    def test_second_pushed_branch_is_scanned(self) -> None:
        main = _head(self.root)
        run_git(self.root, "checkout", "-q", "-b", "second")
        self.secret_commit("second.txt")
        run_git(self.root, "checkout", "-q", "main")

        findings = scan_pushed(self.root, PushedScope(main, "origin"), max_findings=1)

        self.assertEqual("second.txt", findings[0].path)

    def test_a_commit_amended_away_does_not_block_the_push(self) -> None:
        leaked = self.secret_commit("leak.txt")
        (self.root / "leak.txt").write_text("clean\n", encoding="utf-8")
        run_git(self.root, "add", "--", "leak.txt")
        run_git(self.root, "commit", "-q", "--no-verify", "--amend", "--no-edit")
        reflog = run_git(self.root, "reflog", "--format=%H").stdout.decode().split()
        # The amended-away commit is still in the reflog, and only there.
        self.assertIn(leaked, reflog)
        self.assertNotEqual(leaked, _head(self.root))

        scope = PushedScope(_head(self.root), "origin")
        self.assertEqual((), scan_pushed(self.root, scope, max_findings=1))

    def test_refs_of_a_remote_named_like_a_branch_are_not_excluded(self) -> None:
        main = _head(self.root)
        run_git(self.root, "checkout", "-q", "-b", "side")
        side = self.secret_commit("side.txt")
        run_git(self.root, "checkout", "-q", "main")
        run_git(self.root, "remote", "add", "origin/x", "https://example.invalid/x")
        run_git(self.root, "update-ref", "refs/remotes/origin/x/main", side)

        findings = scan_pushed(self.root, PushedScope(main, "origin"), max_findings=1)

        self.assertEqual("side.txt", findings[0].path)


class StashTest(unittest.TestCase):
    @needs_real_scanner
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        pushed_base_commit(self.root)
        (self.root / "notes.txt").write_text("clean\n", encoding="utf-8")
        commit_fixture(self.root, "notes.txt")

    def scans(self) -> list[int]:
        environment = {
            "PRE_COMMIT_TO_REF": _head(self.root),
            "PRE_COMMIT_REMOTE_NAME": "origin",
        }
        return [
            history_cli(self.root, ("hook", "pre-push"), environment)[0],
            history_cli(self.root, ("check",), {})[0],
        ]

    def test_a_stashed_secret_blocks_neither_push_nor_check(self) -> None:
        (self.root / "notes.txt").write_bytes(CALIBRATION_INPUT)
        # Staged, so the stash's index commit adds the secret as a plain diff.
        run_git(self.root, "add", "--", "notes.txt")
        run_git(self.root, "stash", "push", "-q", "-m", SLACK_LINE.strip())

        self.assertEqual([0, 0], self.scans())
        self.assertIn("refs/stash", run_git(self.root, "for-each-ref").stdout.decode())

        run_git(self.root, "stash", "pop", "-q")
        commit_fixture(self.root, "notes.txt")
        self.assertEqual([1, 1], self.scans())

    def test_a_pushed_stash_is_still_scanned(self) -> None:
        (self.root / "notes.txt").write_bytes(CALIBRATION_INPUT)
        run_git(self.root, "add", "--", "notes.txt")
        run_git(self.root, "stash", "push", "-q")
        stash = run_git(self.root, "rev-parse", "refs/stash").stdout.decode().strip()

        scope = PushedScope(stash, "origin")
        self.assertEqual(
            "notes.txt", scan_pushed(self.root, scope, max_findings=1)[0].path
        )


if __name__ == "__main__":
    unittest.main()
