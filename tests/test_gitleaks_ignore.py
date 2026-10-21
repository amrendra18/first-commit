import hashlib
import io
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from first_commit import cli
from first_commit.gitleaks import scan_history, scan_staged
from first_commit.gitleaks_ignore import check_ignore_file
from first_commit.gitleaks_ignore_format import (
    IGNORE_PATH,
    MAX_IGNORE_ENTRIES,
    IgnoreFileError,
    parse_ignore,
)
from tests.gitleaks_support import TOKEN, commit_fixture, needs_real_scanner
from tests.support import initialize_repository, run_git

LINE = f'token = "{TOKEN}"'.encode()
OTHER_LINE = f'token = "{TOKEN[:-4]}WXYZ"'.encode()
FINGERPRINT = "config.txt:github-pat:1"


def _digest(line: bytes) -> str:
    return hashlib.sha256(line + b"\n").hexdigest()


def _entry(fingerprint: str = FINGERPRINT, line: bytes = LINE) -> str:
    return (
        f"# reason: Synthetic fixture token.\n# file-sha256: {_digest(line)}\n"
        f"{fingerprint}\n"
    )


class IgnoreFileTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        self.ignore = self.root / IGNORE_PATH

    def stage(self, content: bytes, ignore: str) -> None:
        (self.root / "config.txt").write_bytes(content + b"\n")
        self.ignore.write_text(ignore, encoding="utf-8")
        run_git(self.root, "add", "--", "config.txt", IGNORE_PATH)

    def refused(self, message: str) -> str:
        with self.assertRaisesRegex(IgnoreFileError, message) as context:
            check_ignore_file(self.root)
        self.assertIn("\n  fix: ", str(context.exception))
        return str(context.exception)

    def test_absent_file_needs_no_check(self) -> None:
        check_ignore_file(self.root)

    def test_reviewed_staged_entry_is_accepted(self) -> None:
        self.stage(LINE, _entry())

        check_ignore_file(self.root)

    def test_untracked_and_ignored_files_are_refused(self) -> None:
        self.ignore.write_text(_entry(), encoding="utf-8")
        self.refused("not tracked")

        (self.root / ".gitignore").write_text(f"{IGNORE_PATH}\n", encoding="utf-8")
        message = self.refused("not tracked")
        self.assertIn(f"git add {IGNORE_PATH}", message)

    def test_worktree_copy_must_equal_the_staged_copy(self) -> None:
        self.stage(LINE, _entry())
        self.ignore.write_text(_entry() + "\n" + _entry("x.txt:rule:2"), "utf-8")

        message = self.refused("differs from its staged copy")
        self.assertIn(f"git restore {IGNORE_PATH}", message)

    def test_links_and_unreadable_files_are_refused(self) -> None:
        target = self.root / "outside"
        target.write_text(_entry(), encoding="utf-8")
        self.ignore.symlink_to(target)

        self.refused("not a regular file")

    def test_same_line_with_a_different_secret_is_refused(self) -> None:
        self.stage(OTHER_LINE, _entry())

        message = self.refused("no longer matches its file-sha256")
        self.assertIn("git show :0:config.txt | shasum -a 256", message)
        self.assertNotIn(TOKEN, message)

    def test_staged_entry_needs_the_file_and_line_in_the_index(self) -> None:
        self.stage(LINE, _entry("missing.txt:github-pat:1"))
        self.refused("missing.txt is not in the staged snapshot")

        self.stage(LINE, _entry("config.txt:github-pat:9"))
        self.refused("line 9 of config.txt in the staged snapshot is past the end")

    def test_commit_entries_are_checked_against_that_commit(self) -> None:
        (self.root / "config.txt").write_bytes(LINE + b"\n")
        commit_fixture(self.root, "config.txt")
        commit = run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()
        (self.root / "config.txt").write_bytes(b"safe\n")
        fingerprint = f"{commit}:config.txt:github-pat:1"
        self.stage(b"safe", _entry(fingerprint))

        check_ignore_file(self.root)

        self.stage(b"safe", _entry(fingerprint, OTHER_LINE))
        self.refused(f"in commit {commit} no longer matches")

        absent = "0" * 40
        self.stage(b"safe", _entry(f"{absent}:config.txt:github-pat:1"))
        self.refused(f"config.txt is not in commit {absent}")

    def test_git_failure_is_refused(self) -> None:
        shutil.rmtree(self.root / ".git")
        self.ignore.write_text(_entry(), encoding="utf-8")

        self.refused("Git cannot say whether the file is tracked")


class IgnoreFormatTest(unittest.TestCase):
    def assert_refused(self, content: str, message: str) -> None:
        with self.assertRaisesRegex(IgnoreFileError, message) as context:
            parse_ignore(content.encode("utf-8"))
        self.assertIn("\n  fix: ", str(context.exception))

    def test_entries_need_a_reason_and_a_file_digest_directly_above(self) -> None:
        digest = f"# file-sha256: {_digest(LINE)}\n"
        for content in (
            FINGERPRINT + "\n",
            "# reason: Synthetic.\n" + FINGERPRINT + "\n",
            digest + FINGERPRINT + "\n",
            "# reason: Synthetic.\n" + digest + "\n" + FINGERPRINT + "\n",
            "# reason:\n" + digest + FINGERPRINT + "\n",
        ):
            with self.subTest(content=content):
                self.assert_refused(content, "has no '# reason:' and '# file-sha256:'")

    def test_comment_lines_in_any_order_and_other_comments_are_accepted(self) -> None:
        content = (
            "# Exceptions reviewed in pull requests.\n\n"
            f"# file-sha256: {_digest(LINE)}\n# reason: Synthetic.\n"
            f"{FINGERPRINT}\n\n{_entry('a/b.txt:generic-api-key:3')}"
        )

        entries = parse_ignore(content.encode("utf-8"))

        self.assertEqual(["config.txt", "a/b.txt"], [item.path for item in entries])
        self.assertEqual(":0:a/b.txt", entries[1].source)
        self.assertEqual(3, entries[1].line)

    def test_invalid_forms_are_refused_with_a_fix_line(self) -> None:
        for content, message in (
            (_entry() + _entry(), "duplicate"),
            ("# reason: No fingerprint follows.\n", "no fingerprint below it"),
            ("# file-sha256: ABC\n", "64 lowercase hex digits"),
            (_entry("config.txt:github-pat:\u0661"), "not a Gitleaks fingerprint"),
            (_entry("config.txt:github-pat"), "not a Gitleaks fingerprint"),
            (_entry("config.txt:github-pat:0"), "not a Gitleaks fingerprint"),
            (_entry("../config.txt:github-pat:1"), "not a Gitleaks fingerprint"),
            (_entry("/abs.txt:github-pat:1"), "not a Gitleaks fingerprint"),
            (_entry("a:b:c:d:1"), "not a Gitleaks fingerprint"),
            (_entry("config.txt:bad rule:1"), "not a Gitleaks fingerprint"),
        ):
            with self.subTest(content=content):
                self.assert_refused(content, message)

        with self.assertRaisesRegex(IgnoreFileError, "UTF-8"):
            parse_ignore(b"\xff\n")

    def test_a_line_digest_without_a_file_digest_is_refused(self) -> None:
        # generic-api-key reports the key name's line; the secret may sit on the
        # next line, so a line digest fits every secret written below that name.
        content = _entry("a/b.txt:generic-api-key:1").replace(
            "file-sha256", "line-sha256"
        )

        with self.assertRaisesRegex(
            IgnoreFileError,
            "line 3: the fingerprint has no '# reason:' and '# file-sha256:' lines",
        ):
            parse_ignore(content.encode("utf-8"))

    def test_characters_go_reads_differently_are_refused(self) -> None:
        # Python strips 0x1c-0x1f and splits lines on them; Gitleaks (Go) does not,
        # so it would apply the first line as an exception nobody reviewed.
        for line in (
            "\x1f#x:github-pat:1",
            "# reason: x\x1cconfig.txt:github-pat:1",
            "\xa0config.txt:github-pat:1",
            "# reason:\u2028config.txt:github-pat:1",
            "config.txt:github-pat:1\x0b",
            "con\rfig.txt:github-pat:1",
        ):
            with self.subTest(line=line):
                self.assert_refused(line + "\n", "control character or a space")

    def test_carriage_returns_and_indents_are_read_like_gitleaks(self) -> None:
        content = "\t" + _entry().replace("\n", " \r\n")

        entries = parse_ignore(content.encode("utf-8"))

        self.assertEqual(
            [("config.txt", 1)], [(item.path, item.line) for item in entries]
        )

    def test_entry_count_is_bounded(self) -> None:
        content = "".join(
            _entry(f"f{number}.txt:rule:1") for number in range(MAX_IGNORE_ENTRIES + 1)
        )

        self.assert_refused(content, f"more than {MAX_IGNORE_ENTRIES}")


class IgnoreFileExitTest(unittest.TestCase):
    def test_bad_file_exits_2_with_a_fix_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / ".repo-policy.json").write_text('{"schema_version":1}\n', "utf-8")
            (root / IGNORE_PATH).write_text(FINGERPRINT + "\n", encoding="utf-8")
            run_git(root, "add", "--", IGNORE_PATH)
            output, error = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(error):
                code = cli.main(("hook", "pre-commit", "--root", str(root)))

        self.assertEqual(2, code)
        lines = error.getvalue().splitlines()
        self.assertTrue(lines[0].startswith(f"error: {IGNORE_PATH} line 1: "))
        self.assertTrue(lines[1].startswith("  fix: add '# reason:"))


class RealScannerIgnoreTest(unittest.TestCase):
    @needs_real_scanner
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        (self.root / "config.txt").write_bytes(LINE + b"\n")
        run_git(self.root, "add", "--", "config.txt")

    def test_ignored_untracked_file_no_longer_hides_a_finding(self) -> None:
        (self.root / ".gitignore").write_text(f"{IGNORE_PATH}\n", encoding="utf-8")
        (self.root / IGNORE_PATH).write_text(FINGERPRINT + "\n", encoding="utf-8")

        with self.assertRaisesRegex(IgnoreFileError, "not tracked"):
            scan_staged(self.root, max_findings=1)
        with self.assertRaisesRegex(IgnoreFileError, "not tracked"):
            scan_history(self.root, max_findings=1)

    def test_reviewed_entry_hides_only_the_line_it_was_written_for(self) -> None:
        (self.root / IGNORE_PATH).write_text(_entry(), encoding="utf-8")
        run_git(self.root, "add", "--", IGNORE_PATH)
        self.assertEqual((), scan_staged(self.root, max_findings=1))

        (self.root / "config.txt").write_bytes(OTHER_LINE + b"\n")
        run_git(self.root, "add", "--", "config.txt")
        with self.assertRaisesRegex(IgnoreFileError, "no longer matches"):
            scan_staged(self.root, max_findings=1)

    def test_fingerprint_help_matches_the_scanner_output(self) -> None:
        result = subprocess.run(
            ["gitleaks", "git", "--pre-commit", "--staged", "--redact", "--verbose"],
            cwd=self.root,
            capture_output=True,
            check=False,
            timeout=120,
        )

        self.assertIn(f"Fingerprint: {FINGERPRINT}", result.stdout.decode())
        self.assertNotIn(TOKEN, result.stdout.decode())


if __name__ == "__main__":
    unittest.main()
