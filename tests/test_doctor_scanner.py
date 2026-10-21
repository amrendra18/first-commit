import os
from unittest.mock import patch

from first_commit.models import ExitCode
from tests.cli_support import CliFixture

# Git stays reachable; no folder here holds Gitleaks.
NO_SCANNER_PATH = "/usr/bin:/bin"


class MissingScannerTest(CliFixture):
    def test_doctor_lists_the_scanner_beside_other_findings(self) -> None:
        with patch.dict(os.environ, {"PATH": NO_SCANNER_PATH}):
            code, output, error = self.run_cli("doctor")
        self.assertEqual((ExitCode.FINDING, ""), (code, error))
        self.assertIn("FAIL doctor", output)
        self.assertIn(
            'secrets.scanner-unavailable ".local/bin/gitleaks": Gitleaks 8.30.0 is '
            "unavailable;",
            output,
        )
        self.assertIn('git.contributor-record ".local/first-commit', output)

    def test_check_still_stops_with_exit_3_at_the_scan(self) -> None:
        with patch.dict(os.environ, {"PATH": NO_SCANNER_PATH}):
            code, output, error = self.run_cli("check")
        self.assertEqual(ExitCode.DEPENDENCY, code)
        self.assertIn("secrets.scanner-unavailable", output)
        self.assertIn("error: Gitleaks 8.30.0 is unavailable;", error)
