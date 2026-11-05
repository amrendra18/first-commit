import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from first_commit.gitleaks import scan_history, scan_pushed
from first_commit.gitleaks_scanner import DependencyError
from first_commit.models import Finding
from first_commit.pushed import PushedScope
from tests.gitleaks_support import SLACK_LINE, commit_fixture, needs_real_scanner
from tests.support import initialize_repository, run_git

INCOMPLETE = "could not read the whole history"
# A Gitleaks that passes the version and capability checks, then logs this text
# and exits 0, as 8.30.0 does when Git fails under it.
LOGGING_SCANNER = (
    "#!/bin/sh\n"
    "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
    'if [ "$1" = stdin ]; then exit 10; fi\n'
    "printf '%b' \"$FIRST_COMMIT_TEST_LOG\" >&2\n"
    "exit 0\n"
)
GIT_ERROR_LOG = (
    "\\033[90m1:12PM\\033[0m \\033[31mERR\\033[0m [git] fatal: bad object\\n"
    "\\033[90m1:12PM\\033[0m \\033[32mINF\\033[0m 2 commits scanned.\\n"
)


class HistoryScanTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.scratch = Path(temporary.name)
        self.root = self.scratch / "repository"
        self.root.mkdir()
        initialize_repository(self.root)

    def commit(self, name: str, content: str) -> str:
        (self.root / name).write_text(content, encoding="utf-8")
        commit_fixture(self.root, name)
        return run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()

    def scanner(self) -> str:
        executable = self.scratch / "gitleaks"
        executable.write_text(LOGGING_SCANNER, encoding="utf-8")
        executable.chmod(0o755)
        return str(executable)

    def scans(self, log: str) -> tuple[Callable[[], tuple[Finding, ...]], ...]:
        if not (self.root / "two.txt").exists():
            self.commit("one.txt", "one\n")
            self.commit("two.txt", "two\n")
        head = run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()
        executable = self.scanner()
        environment = {"FIRST_COMMIT_TEST_LOG": log}
        return (
            lambda: scan_history(
                self.root,
                max_findings=1,
                executable=executable,
                environment=environment,
            ),
            lambda: scan_pushed(
                self.root,
                PushedScope(head, None),
                max_findings=1,
                executable=executable,
                environment=environment,
            ),
        )

    def test_a_git_error_in_the_scanner_log_fails_the_scan(self) -> None:
        for scan in self.scans(GIT_ERROR_LOG):
            with self.assertRaisesRegex(DependencyError, INCOMPLETE) as context:
                scan()
            self.assertIn("full clone", str(context.exception))

    def test_fewer_scanned_commits_than_git_lists_fail_the_scan(self) -> None:
        for log in ("1:12PM INF 1 commits scanned.\\n", ""):
            for scan in self.scans(log):
                with (
                    self.subTest(log=log),
                    self.assertRaisesRegex(DependencyError, INCOMPLETE),
                ):
                    scan()

    def test_a_commit_made_during_the_scan_does_not_fail_it(self) -> None:
        self.commit("one.txt", "one\n")
        self.commit("two.txt", "two\n")
        # The scanner commits a third file while it runs, then reports the two
        # commits that existed when the scan started.
        committing = LOGGING_SCANNER.replace(
            "printf '%b'",
            'cd "$FIRST_COMMIT_TEST_REPOSITORY" && echo three > three.txt && '
            "git add three.txt && git -c user.name=Scratch "
            "-c user.email=scratch@example.invalid -c commit.gpgsign=false "
            "commit -qm three && printf '%b'",
        )
        executable = self.scratch / "gitleaks"
        executable.write_text(committing, encoding="utf-8")
        executable.chmod(0o755)

        found = scan_history(
            self.root,
            max_findings=1,
            executable=str(executable),
            environment={
                "FIRST_COMMIT_TEST_LOG": "1:12PM INF 2 commits scanned.\\n",
                "FIRST_COMMIT_TEST_REPOSITORY": str(self.root),
            },
        )

        self.assertEqual((), found)
        self.assertTrue((self.root / "three.txt").exists())

    def test_every_scanned_commit_passes_the_scan(self) -> None:
        for scan in self.scans("1:12PM INF 2 commits scanned.\\n"):
            self.assertEqual((), scan())

    @needs_real_scanner
    def test_a_blobless_clone_fails_the_history_and_push_scans(self) -> None:
        self.commit("config.txt", SLACK_LINE)
        self.commit("config.txt", "clean\n")
        run_git(self.root, "config", "uploadpack.allowFilter", "true")
        clone = self.scratch / "partial"
        run_git(
            self.scratch,
            "clone",
            "-q",
            "--no-local",
            "--filter=blob:none",
            self.root.as_uri(),
            str(clone),
        )
        head = run_git(clone, "rev-parse", "HEAD").stdout.decode().strip()

        with self.assertRaisesRegex(DependencyError, INCOMPLETE):
            scan_history(clone, max_findings=1)
        with self.assertRaisesRegex(DependencyError, INCOMPLETE):
            scan_pushed(clone, PushedScope(head, None), max_findings=1)


if __name__ == "__main__":
    unittest.main()
