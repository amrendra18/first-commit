import io
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from first_commit import cli
from first_commit.gitleaks import scan_history, scan_staged
from first_commit.gitleaks_scanner import (
    BINARY_DIGESTS,
    LOCAL_SCANNER_PATH,
    DependencyError,
    validate_scanner,
)
from first_commit.scanner_install import ARCHIVE_DIGESTS, install_scanner
from tests.gitleaks_support import trusted_local_scanner
from tests.support import initialize_repository, run_git

START = "a" * 40
END = "b" * 40


def _fake(marker: Path) -> bytes:
    return (
        "#!/bin/sh\n"
        f"echo ran >> '{marker}'\n"
        'if [ "$1" = version ]; then echo 8.30.0; exit 0; fi\n'
        'if [ "$1" = stdin ]; then exit 10; fi\n'
        "exit 0\n"
    ).encode()


class LocalScannerTrustTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        self.marker = self.root / "ran"
        self.scanner = self.root / LOCAL_SCANNER_PATH
        self.scanner.parent.mkdir(parents=True)
        self.content = _fake(self.marker)
        self.scanner.write_bytes(self.content)
        self.scanner.chmod(0o755)

    def refused(self, message: str) -> None:
        for name, call in (
            ("doctor", lambda: validate_scanner(self.root)),
            ("staged", lambda: scan_staged(self.root, max_findings=1)),
            ("history", lambda: scan_history(self.root, max_findings=1)),
        ):
            with self.subTest(scope=name):
                with self.assertRaisesRegex(DependencyError, message):
                    call()
        self.assertFalse(self.marker.exists())

    def test_wrong_digest_binary_never_runs(self) -> None:
        self.refused("does not match the pinned Gitleaks 8.30.0 release binary")

    def test_tracked_binary_never_runs_even_with_the_pinned_digest(self) -> None:
        run_git(self.root, "add", "--force", "--", LOCAL_SCANNER_PATH)

        with trusted_local_scanner(self.content):
            self.refused("tracked by Git")

    def test_pinned_digest_binary_runs(self) -> None:
        with trusted_local_scanner(self.content):
            validate_scanner(self.root)

        self.assertTrue(self.marker.exists())

    def test_unsupported_platform_and_unknown_git_state_are_refused(self) -> None:
        with mock.patch(
            "first_commit.gitleaks_scanner.scanner_platform",
            return_value=("plan9", "x64"),
        ):
            self.refused("cannot be checked on this platform")

        shutil.rmtree(self.root / ".git")
        self.refused("cannot be determined")

    def test_oversized_and_unreadable_binaries_are_refused(self) -> None:
        with (
            trusted_local_scanner(self.content),
            mock.patch("first_commit.gitleaks_scanner.MAX_SCANNER_BYTES", 4),
        ):
            self.refused("does not match")
        with (
            trusted_local_scanner(self.content),
            mock.patch("pathlib.Path.open", side_effect=OSError("canary")),
        ):
            self.refused("does not match")

    def test_setup_refuses_an_existing_untrusted_binary(self) -> None:
        with self.assertRaisesRegex(
            DependencyError,
            r"failed validation \(Local Gitleaks at \.local/bin/gitleaks does not match",
        ):
            install_scanner(self.root)
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.content, self.scanner.read_bytes())

    def test_check_exits_3_for_an_untrusted_binary(self) -> None:
        (self.root / ".repo-policy.json").write_text('{"schema_version":1}\n', "utf-8")
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = cli.main(("check", "--root", str(self.root)))

        self.assertEqual(3, code)
        self.assertIn("does not match the pinned", error.getvalue())
        self.assertFalse(self.marker.exists())

    def test_every_pinned_archive_has_a_pinned_binary(self) -> None:
        self.assertEqual(set(ARCHIVE_DIGESTS), set(BINARY_DIGESTS))
        for digest in BINARY_DIGESTS.values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


class PathScannerTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "repository"
        self.root.mkdir()
        initialize_repository(self.root)
        self.marker = Path(temporary.name) / "ran"
        self.outside = Path(temporary.name) / "bin"
        self.outside.mkdir()

    def plant(self, folder: Path) -> None:
        folder.mkdir(parents=True, exist_ok=True)
        scanner = folder / "gitleaks"
        scanner.write_bytes(_fake(self.marker))
        scanner.chmod(0o755)

    def test_relative_path_entries_never_run_a_repository_scanner(self) -> None:
        self.plant(self.root)
        self.plant(self.root / "tools")
        for search in ("", ".", "tools", f":tools:.:{os.defpath}"):
            with (
                self.subTest(search=search),
                mock.patch.dict("os.environ", {"PATH": search}),
                self.assertRaisesRegex(DependencyError, "unavailable"),
            ):
                validate_scanner(self.root)
        self.assertFalse(self.marker.exists())

    def test_absolute_path_entry_inside_the_repository_is_refused(self) -> None:
        self.plant(self.root / "tools")
        search = f"{self.root / 'tools'}:{os.defpath}"
        with (
            mock.patch.dict("os.environ", {"PATH": search}),
            self.assertRaisesRegex(DependencyError, "inside this repository"),
        ):
            scan_staged(self.root, max_findings=1)
        self.assertFalse(self.marker.exists())

    def test_differently_cased_path_inside_the_repository_is_refused(self) -> None:
        self.plant(self.root / "tools")
        other_case = self.root.parent / self.root.name.upper() / "TOOLS"
        if not other_case.exists():
            self.skipTest("the disk is case-sensitive")
        with (
            mock.patch.dict("os.environ", {"PATH": f"{other_case}:{os.defpath}"}),
            self.assertRaisesRegex(DependencyError, "inside this repository"),
        ):
            validate_scanner(self.root)
        self.assertFalse(self.marker.exists())

    def test_scanner_outside_the_repository_runs_by_absolute_path(self) -> None:
        self.plant(self.outside)
        calls = []
        real = subprocess.run

        def record(arguments, **keywords):
            calls.append(arguments[0])
            return real(arguments, **keywords)

        with (
            mock.patch.dict("os.environ", {"PATH": f".:{self.outside}:{os.defpath}"}),
            mock.patch(
                "first_commit.gitleaks_scanner.subprocess.run", side_effect=record
            ),
        ):
            validate_scanner(self.root)

        self.assertEqual({str(self.outside / "gitleaks")}, set(calls))
        self.assertTrue(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
