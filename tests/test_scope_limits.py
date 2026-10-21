import subprocess
import time
from unittest.mock import patch

from first_commit.candidates import (
    CandidateError,
    staged_candidates,
    working_candidates,
)
from first_commit.paths import PathSizeError
from first_commit.policy import REQUIRED_DOCUMENTS, parse_policy
from first_commit.policy_fields import DEFAULT_LIMITS
from first_commit.validation import staged, working
from tests.cli_support import CliFixture
from tests.support import run_git

OVER_LIMIT = DEFAULT_LIMITS["max_file_bytes"] + 1024 * 1024
UNTRACKED_FILES = DEFAULT_LIMITS["max_files"] + 1
STAGED_FILES = 1000
STAGED_SECONDS = 10
TOO_LARGE = 'files.too-large "large.bin"'


class ScopeLimitsTest(CliFixture):
    def setUp(self) -> None:
        super().setUp()
        for path in REQUIRED_DOCUMENTS:
            (self.root / path).write_text("# Reviewed\n", encoding="utf-8")
        run_git(self.root, "add", "--", *REQUIRED_DOCUMENTS, ".repo-policy.json")

    def pre_commit(self) -> tuple[int, str, str]:
        with patch("first_commit.validation.scan_staged", return_value=()):
            return self.run_cli("hook", "pre-commit")

    def write_large_file(self) -> None:
        (self.root / "large.bin").write_bytes(b"a" * OVER_LIMIT)

    def test_untracked_over_limit_file_does_not_block_a_clean_commit(self) -> None:
        self.write_large_file()
        self.assertEqual((0, "PASS staged\n", ""), self.pre_commit())

    def test_working_scope_reports_untracked_over_limit_file_by_path(self) -> None:
        self.write_large_file()
        policy = parse_policy(b'{"schema_version":1}', self.root)
        result = working(self.root, policy)
        self.assertEqual(
            [("files.too-large", "large.bin")],
            [(item.rule_id, item.path) for item in result.findings],
        )

    def test_tracked_over_limit_file_is_a_path_finding(self) -> None:
        self.write_large_file()
        run_git(self.root, "add", "--", "large.bin")
        code, output, error = self.pre_commit()
        self.assertEqual((1, ""), (code, error))
        self.assertIn(TOO_LARGE, output)
        self.assertIn("MiB, or keep it out of Git", output)

    def test_full_finding_budget_keeps_the_too_large_finding(self) -> None:
        policy = parse_policy(b'{"schema_version":1}', self.root)
        (self.root / "a-noise.txt").write_bytes(b"x \n" * (policy.max_findings + 1))
        self.write_large_file()
        run_git(self.root, "add", "--", "a-noise.txt", "large.bin")

        with patch("first_commit.validation.scan_staged", return_value=()):
            results = (working(self.root, policy), staged(self.root, policy))

        for result in results:
            with self.subTest(scope=result.scope):
                self.assertEqual(policy.max_findings, len(result.findings))
                self.assertEqual(
                    ["large.bin"],
                    [
                        item.path
                        for item in result.findings
                        if item.rule_id == "files.too-large"
                    ],
                )

    def test_full_finding_budget_keeps_the_generated_too_large_finding(
        self,
    ) -> None:
        policy = parse_policy(b'{"schema_version":1}', self.root)
        proposal = "README.md.first-commit-proposal.md"
        (self.root / "a-noise.txt").write_bytes(b"x \n" * (policy.max_findings + 1))
        (self.root / proposal).write_bytes(b"a" * OVER_LIMIT)
        run_git(self.root, "add", "--", "a-noise.txt")

        with patch("first_commit.validation.scan_staged", return_value=()):
            result = staged(self.root, policy)

        self.assertEqual(policy.max_findings, len(result.findings))
        self.assertEqual(
            [proposal],
            [
                item.path
                for item in result.findings
                if item.rule_id == "files.too-large"
            ],
        )

    def test_working_oversized_paths_are_known_before_reading(self) -> None:
        (self.root / "large.txt").write_bytes(b"12345")
        (self.root / "small.txt").write_bytes(b"1234")
        (self.root / "link").symlink_to("long-target")
        paths = ("large.txt", "small.txt", "link")

        with patch(
            "first_commit.candidates.read_worktree_bytes",
            side_effect=AssertionError("read"),
        ) as read:
            loaded = working_candidates(self.root, 10, 4, paths=paths)
        read.assert_not_called()
        self.assertEqual(["large.txt", "link"], loaded.oversized)

        with (
            patch(
                "first_commit.candidates.read_worktree_bytes",
                side_effect=PathSizeError("grew"),
            ),
            self.assertRaisesRegex(CandidateError, "grew"),
        ):
            list(loaded)

    def test_working_size_pass_rejects_unconfined_and_unreadable_paths(
        self,
    ) -> None:
        (self.root / "file.txt").write_bytes(b"x")
        for path in ("../outside", "file.txt/child"):
            with self.subTest(path=path), self.assertRaises(CandidateError):
                working_candidates(self.root, 10, 4, paths=(path,))

    def test_untracked_over_limit_proposal_blocks_the_commit_by_path(self) -> None:
        proposal = "README.md.first-commit-proposal.md"
        (self.root / proposal).write_bytes(b"a" * OVER_LIMIT)
        code, output, _ = self.pre_commit()
        self.assertEqual(1, code)
        self.assertIn(f'files.too-large "{proposal}"', output)

    def test_untracked_files_over_the_count_limit_do_not_affect_the_commit(
        self,
    ) -> None:
        bulk = self.root / "bulk"
        bulk.mkdir()
        for number in range(UNTRACKED_FILES):
            (bulk / f"{number}.txt").write_bytes(b"x\n")
        self.assertEqual((0, "PASS staged\n", ""), self.pre_commit())

    def test_path_count_error_names_the_limit_and_the_fix(self) -> None:
        limit = DEFAULT_LIMITS["max_files"]
        listing = b"".join(f"{number}.txt\0".encode() for number in range(limit + 1))
        expected = (
            f"File count exceeds the limit of {limit:,} paths. Tracked files "
            "count, and so do untracked files that .gitignore does not hide; a "
            "staged check counts only the staged files.\n"
            "fix: add generated folders such as node_modules/ to .gitignore, "
            "untrack any that Git tracks with `git rm -r --cached <folder>`, "
            "then rerun."
        )
        paths = tuple(f"{number}.txt" for number in range(limit + 1))
        with patch("first_commit.candidates.run_git", return_value=listing):
            loads = (
                lambda: working_candidates(self.root, limit, 1024),
                lambda: staged_candidates(self.root, limit, 1024),
                lambda: working_candidates(self.root, limit, 1024, paths=paths),
                lambda: staged_candidates(self.root, limit, 1024, paths=paths),
            )
            for number, load in enumerate(loads):
                with (
                    self.subTest(load=number),
                    self.assertRaises(CandidateError) as context,
                ):
                    load()
                self.assertEqual(expected, str(context.exception))
            code, _, error = self.run_cli("check")
        self.assertEqual(4, code)
        self.assertIn(expected, error)

    def test_staged_blobs_are_read_by_two_git_processes(self) -> None:
        names = [f"file-{number}.txt" for number in range(STAGED_FILES)]
        for name in names:
            (self.root / name).write_text(name + "\n", encoding="utf-8")
        run_git(self.root, "add", "--", *names)
        with patch.object(subprocess, "Popen", wraps=subprocess.Popen) as processes:
            started = time.monotonic()
            loaded = tuple(
                staged_candidates(
                    self.root,
                    DEFAULT_LIMITS["max_files"],
                    DEFAULT_LIMITS["max_file_bytes"],
                )
            )
            elapsed = time.monotonic() - started
        self.assertEqual(STAGED_FILES + len(REQUIRED_DOCUMENTS) + 1, len(loaded))
        cat_file = [
            call.args[0][3:]
            for call in processes.call_args_list
            if call.args[0][3] == "cat-file"
        ]
        self.assertEqual(
            [["cat-file", "--batch-check"], ["cat-file", "--batch"]], cat_file
        )
        self.assertLess(elapsed, STAGED_SECONDS)
