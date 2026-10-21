import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from first_commit.gitleaks import scan_history, scan_pushed, scan_staged
from first_commit.gitleaks_ignore import check_ignore_file
from first_commit.gitleaks_ignore_format import (
    IGNORE_PATH,
    IgnoreFileError,
    parse_ignore,
)
from first_commit.pushed import PushedScope, push_revisions
from tests.gitleaks_support import TOKEN, commit_fixture, needs_real_scanner
from tests.support import initialize_repository, run_git

LINE = f'token = "{TOKEN}"\n'.encode()
OTHER_LINE = f'token = "{TOKEN[:-4]}WXYZ"\n'.encode()
FINGERPRINT = "config.txt:github-pat:1"
HISTORY = ("--all",)
# Split so this file holds no private-key block.
HEADER = b"-----BEGIN RSA " + b"PRIVATE KEY-----\n"
FOOTER = b"-----END RSA " + b"PRIVATE KEY-----\n"


def _key(fill: bytes) -> bytes:
    return HEADER + (fill * 64 + b"\n") * 3 + FOOTER


# Gitleaks generic-api-key reports line 1; the secret is on line 2.
def _api_key(value: str) -> bytes:
    return f'api_key =\n  "{value}"\n'.encode()


def _entry(fingerprint: str = FINGERPRINT, content: bytes = LINE) -> str:
    digest = hashlib.sha256(content).hexdigest()
    return f"# reason: Synthetic fixture.\n# file-sha256: {digest}\n{fingerprint}\n"


class RepositoryTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)

    def head(self) -> str:
        return run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()

    def stage(
        self, ignore: str, content: bytes = LINE, name: str = "config.txt"
    ) -> None:
        (self.root / name).write_bytes(content)
        (self.root / IGNORE_PATH).write_text(ignore, "utf-8")
        run_git(self.root, "add", "--", name, IGNORE_PATH)


class HistoryDigestTest(RepositoryTest):
    def commit(self, content: bytes | None) -> str:
        if content is None:
            run_git(self.root, "rm", "-q", "--", "config.txt")
            run_git(self.root, "commit", "-q", "--no-verify", "-m", "chore: remove")
        else:
            (self.root / "config.txt").write_bytes(content)
            commit_fixture(self.root, "config.txt")
        return self.head()

    def refused(self, revisions: tuple[str, ...], message: str) -> str:
        with self.assertRaisesRegex(IgnoreFileError, message) as context:
            check_ignore_file(self.root, revisions)
        self.assertNotIn(TOKEN, str(context.exception))
        return str(context.exception)

    def test_older_commit_with_a_different_file_is_refused_in_history(self) -> None:
        older = self.commit(OTHER_LINE)
        self.stage(_entry())

        check_ignore_file(self.root)
        message = self.refused(HISTORY, f"in commit {older} does not match")
        self.assertIn(f"add the fingerprint {older}:{FINGERPRINT}", message)
        self.assertIn(f"git show {older}:config.txt | shasum -a 256", message)

        self.stage(_entry() + "\n" + _entry(f"{older}:{FINGERPRINT}", OTHER_LINE))
        check_ignore_file(self.root, HISTORY)

    def test_deleted_and_shorter_versions_are_skipped(self) -> None:
        self.commit(b"short\n")
        self.commit(None)
        content = b"first\n" + LINE
        self.commit(content)
        self.stage(_entry("config.txt:github-pat:2", content), content)

        check_ignore_file(self.root, HISTORY)

    def test_an_oversized_older_version_stops_the_check(self) -> None:
        older = self.commit(OTHER_LINE * 4)
        self.stage(_entry())

        with mock.patch("first_commit.gitleaks_ignore.MAX_SOURCE_BYTES", len(LINE)):
            check_ignore_file(self.root)
            self.refused(HISTORY, f"config.txt in commit {older} is larger than")

    def test_push_scope_checks_only_commits_the_remote_lacks(self) -> None:
        older = self.commit(OTHER_LINE)
        self.stage(_entry())
        commit_fixture(self.root, "config.txt", IGNORE_PATH)
        scope = PushedScope(self.head(), "origin")

        self.refused(push_revisions(self.root, scope), f"commit {older}")
        run_git(self.root, "update-ref", "refs/remotes/origin/main", older)
        check_ignore_file(self.root, push_revisions(self.root, scope))

    def test_unreadable_history_is_refused(self) -> None:
        self.stage(_entry())

        self.refused(("--bad-option",), "Git could not read")


class FileDigestTest(RepositoryTest):
    def test_file_digest_binds_the_whole_key(self) -> None:
        reviewed = _key(b"A")
        entry = _entry("key.pem:private-key:1", reviewed)
        self.stage(entry, reviewed, "key.pem")
        check_ignore_file(self.root)

        self.stage(entry, _key(b"B"), "key.pem")
        with self.assertRaisesRegex(
            IgnoreFileError, "no longer matches its file-sha256"
        ):
            check_ignore_file(self.root)

    def test_one_digest_per_fingerprint(self) -> None:
        digest = "# file-sha256: " + "0" * 64 + "\n"
        with self.assertRaisesRegex(IgnoreFileError, "two file-sha256 lines"):
            parse_ignore((digest + _entry()).encode())


class BoundedReadTest(RepositoryTest):
    def stage_files(self, count: int) -> None:
        entries = []
        for number in range(count):
            (self.root / f"f{number}.txt").write_bytes(LINE)
            entries.append(_entry(f"f{number}.txt:github-pat:1"))
        (self.root / IGNORE_PATH).write_text("\n".join(entries), "utf-8")
        run_git(self.root, "add", "--all")

    def processes(self) -> int:
        started = []
        popen = subprocess.Popen

        def count(arguments, **options):
            started.append(arguments)
            return popen(arguments, **options)

        with mock.patch("first_commit.git.subprocess.Popen", side_effect=count):
            check_ignore_file(self.root)
        return len(started)

    def test_git_process_count_does_not_grow_with_the_entries(self) -> None:
        self.stage_files(1)
        one = self.processes()
        self.stage_files(6)

        # ls-files, two reads of .gitleaksignore, one batch-check, one batch read.
        self.assertEqual(5, one)
        self.assertEqual(5, self.processes())

    def test_read_limits_are_refused(self) -> None:
        self.stage_files(2)
        for name, value, message in (
            ("MAX_TOTAL_SOURCE_BYTES", 8, "MiB of file versions read"),
            ("MAX_SOURCES", 1, "more than 1 file versions checked"),
            ("MAX_SOURCE_BYTES", 8, "in the staged snapshot is larger than"),
        ):
            with (
                self.subTest(name=name),
                mock.patch(f"first_commit.gitleaks_ignore.{name}", value),
                self.assertRaisesRegex(IgnoreFileError, message),
            ):
                check_ignore_file(self.root)


class RealScannerHistoryTest(RepositoryTest):
    @needs_real_scanner
    def setUp(self) -> None:
        super().setUp()

    def test_reviewed_staged_file_does_not_hide_an_older_secret(self) -> None:
        (self.root / "config.txt").write_bytes(OTHER_LINE)
        commit_fixture(self.root, "config.txt")
        self.stage(_entry())
        commit_fixture(self.root, "config.txt", IGNORE_PATH)
        scope = PushedScope(self.head(), "origin")

        self.assertEqual((), scan_staged(self.root, max_findings=1))
        with self.assertRaisesRegex(IgnoreFileError, "does not match"):
            scan_history(self.root, max_findings=1)
        with self.assertRaisesRegex(IgnoreFileError, "does not match"):
            scan_pushed(self.root, scope, max_findings=1)

    def test_exception_does_not_hide_another_secret_under_the_same_line(
        self,
    ) -> None:
        for name, fingerprint, reviewed, other in (
            ("key.pem", "key.pem:private-key:1", _key(b"A"), _key(b"B")),
            (
                "settings.txt",
                "settings.txt:generic-api-key:1",
                _api_key("Zq8vLp2mX9rT4wK7bN3c"),
                _api_key("Hy3nQw7eRt1uKo9pLs5d"),
            ),
        ):
            with self.subTest(name=name):
                self.setUp()
                self.stage(_entry(fingerprint, reviewed), reviewed, name)
                self.assertEqual((), scan_staged(self.root, max_findings=1))

                (self.root / name).write_bytes(other)
                run_git(self.root, "add", "--", name)
                with self.assertRaisesRegex(IgnoreFileError, "file-sha256"):
                    scan_staged(self.root, max_findings=1)


if __name__ == "__main__":
    unittest.main()
