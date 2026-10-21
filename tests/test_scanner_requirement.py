import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit.gitleaks_scanner import DependencyError, validate_scanner
from tests.gitleaks_support import (
    ALLOW_NO_SCANNER,
    NO_SCANNER,
    needs_real_scanner,
    stop_at_missing_scanner,
)


class RealScannerRequirementTest(unittest.TestCase):
    def run_marked(self, scanner: str | None, allow: str | None) -> unittest.TestResult:
        ran = []

        class Marked(unittest.TestCase):
            @needs_real_scanner
            def test_scan(self) -> None:
                ran.append(True)

        result = unittest.TestResult()
        with (
            patch("tests.gitleaks_support.shutil.which", return_value=scanner),
            patch.dict(os.environ, {ALLOW_NO_SCANNER: allow or ""}),
        ):
            if allow is None:
                del os.environ[ALLOW_NO_SCANNER]
            Marked("test_scan").run(result)
        self.assertEqual(scanner is not None, bool(ran))
        return result

    def test_missing_scanner_fails_with_the_install_step(self) -> None:
        for allow in (None, "", "0", "yes"):
            with self.subTest(allow=allow):
                result = self.run_marked(None, allow)
                self.assertEqual((1, []), (len(result.failures), result.skipped))
                self.assertIn(
                    "AssertionError: install the pinned Gitleaks 8.30.0 as "
                    ".local/bin/gitleaks (setup does) and put .local/bin on PATH, "
                    "as scripts/check does; or set "
                    "FIRST_COMMIT_TEST_ALLOW_NO_GITLEAKS=1 to skip this test.",
                    result.failures[0][1],
                )

    def test_allowed_skip_and_present_scanner(self) -> None:
        result = self.run_marked(None, "1")
        self.assertEqual(([], 1), (result.failures, len(result.skipped)))
        self.assertIn(ALLOW_NO_SCANNER, result.skipped[0][1])
        result = self.run_marked("/opt/gitleaks", None)
        self.assertEqual(
            ([], [], 1), (result.failures, result.skipped, result.testsRun)
        )


class MissingScannerLookupTest(unittest.TestCase):
    def run_lookup(self, allow: str | None, *, hidden: bool) -> unittest.TestResult:
        reached = []
        empty = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, empty)

        class Lookup(unittest.TestCase):
            def test_scan(self) -> None:
                if hidden:
                    with patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}):
                        with self.assertRaisesRegex(DependencyError, "is unavailable"):
                            validate_scanner(Path(empty))
                else:
                    validate_scanner(Path(empty))
                reached.append(True)

        result = unittest.TestResult()
        with (
            patch.dict(os.environ, {"PATH": empty, ALLOW_NO_SCANNER: allow or ""}),
            patch(
                "first_commit.gitleaks_scanner.find_executable",
                stop_at_missing_scanner(empty),
            ),
        ):
            if allow is None:
                del os.environ[ALLOW_NO_SCANNER]
            Lookup("test_scan").run(result)
        self.assertEqual(hidden, bool(reached))
        return result

    def test_missing_scanner_on_the_test_path_skips_only_when_allowed(self) -> None:
        result = self.run_lookup("1", hidden=False)
        self.assertEqual(
            ([], [], 1), (result.failures, result.errors, len(result.skipped))
        )
        self.assertIn(ALLOW_NO_SCANNER, result.skipped[0][1])
        for allow in (None, "0"):
            with self.subTest(allow=allow):
                result = self.run_lookup(allow, hidden=False)
                self.assertEqual((1, []), (len(result.failures), result.skipped))
                self.assertIn(NO_SCANNER, result.failures[0][1])

    def test_a_test_that_hides_the_scanner_still_gets_the_product_error(self) -> None:
        for allow in (None, "1"):
            with self.subTest(allow=allow):
                result = self.run_lookup(allow, hidden=True)
                self.assertEqual(
                    ([], [], []), (result.failures, result.errors, result.skipped)
                )


if __name__ == "__main__":
    unittest.main()
