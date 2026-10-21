import json
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from first_commit.gitleaks import (
    REPORT_FOLDER_PREFIX,
    REPORT_NAME,
    scan_history,
    scan_staged,
)
from first_commit.gitleaks_report import REPORT_FIELDS, report_fields
from first_commit.gitleaks_scanner import FINDINGS_EXIT, DependencyError
from first_commit.models import Result
from first_commit.reporting import render_human
from tests.gitleaks_support import (
    SCANNER_PATH,
    TOKEN,
    captured_reports,
    commit_fixture,
    needs_real_scanner,
    recorded_report_folders,
    write_reporting_scanner,
)
from tests.support import initialize_repository, run_git
from tests.validation_support import render_json


class GitleaksLocationTest(unittest.TestCase):
    def _report(self, root: Path, entries: object) -> dict[str, str]:
        report = root / "fixture-report.json"
        report.write_text(json.dumps(entries), encoding="utf-8")
        return {
            "PATH": SCANNER_PATH,
            "FIRST_COMMIT_TEST_REPORT": str(report),
        }

    @needs_real_scanner
    def test_real_staged_scan_reports_the_exact_path_and_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / "service").mkdir()
            (root / "service" / "client.py").write_text(
                f"# Fixture client.\n# Holds one token.\n\nAPI = '{TOKEN}'\n",
                encoding="utf-8",
            )
            run_git(root, "add", "--", "service/client.py")

            findings = scan_staged(root, max_findings=10)

        self.assertEqual(
            [("secrets.gitleaks", "service/client.py", 4)],
            [(item.rule_id, item.path, item.line) for item in findings],
        )
        self.assertEqual(
            "Gitleaks reported a staged-content finding.", findings[0].summary
        )

    @needs_real_scanner
    def test_real_history_scan_names_the_file_and_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / "service").mkdir()
            (root / "service" / "client.py").write_text(
                f"# Fixture client.\n# Holds one token.\n\nAPI = '{TOKEN}'\n",
                encoding="utf-8",
            )
            commit_fixture(root, "service/client.py")

            findings = scan_history(root, max_findings=10)

        self.assertEqual(
            [("secrets.gitleaks", "service/client.py", 4)],
            [(item.rule_id, item.path, item.line) for item in findings],
        )
        self.assertEqual(
            "Gitleaks reported a repository-history finding.", findings[0].summary
        )

    @needs_real_scanner
    def test_real_scans_never_disclose_the_secret_value(self) -> None:
        for scope, scan in (("staged", scan_staged), ("history", scan_history)):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                initialize_repository(root)
                (root / "client.py").write_text(
                    f"# Fixture client.\n# Holds one token.\n\nAPI = '{TOKEN}'\n",
                    encoding="utf-8",
                )
                if scope == "staged":
                    run_git(root, "add", "--", "client.py")
                else:
                    commit_fixture(root, "client.py")

                with (
                    recorded_report_folders() as directories,
                    captured_reports() as reports,
                ):
                    findings = scan(root, max_findings=10)

                result = Result(scope=scope, findings=findings)
                human = render_human(result)
                document = render_json(result)
                report = reports[0].decode("utf-8", errors="replace")

                self.assertNotEqual((), findings)
                self.assertNotIn(TOKEN, repr(findings))
                self.assertNotIn(TOKEN, human)
                self.assertNotIn(TOKEN, document)
                self.assertNotIn(TOKEN, report)
                self.assertNotIn("ghp_", report)
                self.assertFalse(directories[0].exists())
                self.assertFalse((directories[0] / REPORT_NAME).exists())
                self.assertIn("client.py", human)

    @needs_real_scanner
    def test_real_scan_orders_and_truncates_several_located_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            for name in ("zeta.py", "alpha.py", "middle.py"):
                (root / name).write_text(
                    f"# Fixture client.\n# Holds one token.\n\nAPI = '{TOKEN}'\n",
                    encoding="utf-8",
                )
            run_git(root, "add", "--", "alpha.py", "middle.py", "zeta.py")

            located = scan_staged(root, max_findings=10)
            truncated = scan_staged(root, max_findings=2)
            minimal = scan_staged(root, max_findings=0)

        self.assertEqual(
            [("alpha.py", 4), ("middle.py", 4), ("zeta.py", 4)],
            [(item.path, item.line) for item in located],
        )
        self.assertEqual(
            [("alpha.py", 4), ("middle.py", 4)],
            [(item.path, item.line) for item in truncated],
        )
        self.assertEqual((), minimal)

    def test_unusable_reports_still_fail_closed(self) -> None:
        cases = {
            "malformed": b"{not json",
            "empty": b"",
            "blank-list": b"[]",
            "not-a-list": b'{"File": "a.txt"}',
            "non-utf8": b"\xff\xfe[]",
        }
        for label, content in cases.items():
            for scope, scan, path in (
                ("staged", scan_staged, "<staged-content>"),
                ("history", scan_history, ".git"),
            ):
                with (
                    self.subTest(case=label, scope=scope),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    executable = write_reporting_scanner(root)
                    report = root / "fixture-report.json"
                    report.write_bytes(content)

                    with recorded_report_folders() as directories:
                        findings = scan(
                            root,
                            executable=str(executable),
                            environment={
                                "PATH": SCANNER_PATH,
                                "FIRST_COMMIT_TEST_REPORT": str(report),
                            },
                            max_findings=10,
                        )

                    self.assertEqual(
                        [("secrets.gitleaks", path, None)],
                        [(item.rule_id, item.path, item.line) for item in findings],
                    )
                    self.assertFalse(directories[0].exists())

    def test_unreadable_report_content_never_reaches_output(self) -> None:
        bodies = (
            ('[{"File": "a.txt", "StartLine": 1, "Secret": "' + TOKEN + '"').encode(),
            b"\xff\xfe" + TOKEN.encode(),
            TOKEN.encode(),
        )
        for index, body in enumerate(bodies):
            for scope, scan, path in (
                ("staged", scan_staged, "<staged-content>"),
                ("history", scan_history, ".git"),
            ):
                with (
                    self.subTest(body=index, scope=scope),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    executable = write_reporting_scanner(root)
                    report = root / "fixture-report.json"
                    report.write_bytes(body)

                    findings = scan(
                        root,
                        executable=str(executable),
                        environment={
                            "PATH": SCANNER_PATH,
                            "FIRST_COMMIT_TEST_REPORT": str(report),
                        },
                        max_findings=10,
                    )

                    result = Result(scope=scope, findings=findings)
                    rendered = (
                        repr(findings) + render_human(result) + render_json(result)
                    )
                    self.assertEqual(
                        [("secrets.gitleaks", path, None)],
                        [(item.rule_id, item.path, item.line) for item in findings],
                    )
                    self.assertNotIn(TOKEN, rendered)
                    self.assertNotIn("ghp_", rendered)

    def test_missing_and_oversized_reports_still_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = write_reporting_scanner(root)
            environment = self._report(root, [{"File": "a.txt", "StartLine": 1}])

            environment["FIRST_COMMIT_TEST_MODE"] = "missing"
            missing = scan_staged(
                root,
                executable=str(executable),
                environment=environment,
                max_findings=10,
            )
            del environment["FIRST_COMMIT_TEST_MODE"]
            with mock.patch("first_commit.gitleaks_report.MAX_REPORT_BYTES", 4):
                oversized = scan_staged(
                    root,
                    executable=str(executable),
                    environment=environment,
                    max_findings=10,
                )

        for findings in (missing, oversized):
            self.assertEqual(
                [("secrets.gitleaks", "<staged-content>", None)],
                [(item.rule_id, item.path, item.line) for item in findings],
            )

    def test_unsafe_report_paths_fall_back_to_the_scope_path(self) -> None:
        unsafe = [
            {"File": "/etc/passwd", "StartLine": 1},
            {"File": "../outside.txt", "StartLine": 2},
            {"File": "service/\nclient.py", "StartLine": 3},
            {"File": "service/\u0000client.py", "StartLine": 4},
            {"File": "", "StartLine": 5},
            {"File": "./service/client.py", "StartLine": 6},
            {"File": "service//client.py", "StartLine": 7},
            {"File": "~/private.txt", "StartLine": 8},
            {"File": "service\\client.py", "StartLine": 9},
            {"File": 12, "StartLine": 10},
            {"StartLine": 11},
            "not-an-entry",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = write_reporting_scanner(root)

            findings = scan_staged(
                root,
                executable=str(executable),
                environment=self._report(root, unsafe),
                max_findings=50,
            )

        self.assertEqual(
            [("secrets.gitleaks", "<staged-content>", None)],
            [(item.rule_id, item.path, item.line) for item in findings],
        )
        rendered = render_human(Result(scope="staged", findings=findings))
        for entry in unsafe:
            if isinstance(entry, dict) and isinstance(entry.get("File"), str):
                raw = entry["File"]
                if raw:
                    self.assertNotIn(raw, rendered)

    def test_unusable_report_lines_keep_the_located_path(self) -> None:
        entries = [
            {"File": "a.txt", "StartLine": 0},
            {"File": "b.txt", "StartLine": -1},
            {"File": "c.txt", "StartLine": "3"},
            {"File": "d.txt", "StartLine": True},
            {"File": "e.txt"},
            {"File": "f.txt", "StartLine": 10**12},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = write_reporting_scanner(root)

            findings = scan_staged(
                root,
                executable=str(executable),
                environment=self._report(root, entries),
                max_findings=50,
            )

        self.assertEqual(
            [
                ("a.txt", None),
                ("b.txt", None),
                ("c.txt", None),
                ("d.txt", None),
                ("e.txt", None),
                ("f.txt", None),
            ],
            [(item.path, item.line) for item in findings],
        )

    def test_report_fields_are_limited_to_the_location_allowlist(self) -> None:
        self.assertEqual(("RuleID", "File", "StartLine"), REPORT_FIELDS)
        self.assertEqual(
            ("rule", "a.txt", 1),
            report_fields(
                {"RuleID": "rule", "File": "a.txt", "StartLine": 1, "Secret": "x"}
            ),
        )
        canaries = {
            "RuleID": "private-rule-canary",
            "Description": "private-description-canary",
            "Match": "private-match-canary",
            "Secret": "private-secret-canary",
            "Commit": "private-commit-canary",
            "Fingerprint": "private-fingerprint-canary",
            "Author": "private-author-canary",
            "Email": "private-email-canary",
            "Date": "private-date-canary",
            "Message": "private-message-canary",
            "Link": "private-link-canary",
            "Entropy": 4.76,
            "SymlinkFile": "private-symlink-canary",
            "Tags": ["private-tag-canary"],
            "EndLine": 99,
            "StartColumn": 98,
            "EndColumn": 97,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = write_reporting_scanner(root)
            entries = [dict(canaries, File="service/client.py", StartLine=7)]

            findings = scan_history(
                root,
                executable=str(executable),
                environment=self._report(root, entries),
                max_findings=10,
            )

        result = Result(scope="history", findings=findings)
        rendered = (
            repr(findings) + render_human(result) + render_json(result) + str(findings)
        )
        self.assertEqual(
            [("service/client.py", 7)], [(i.path, i.line) for i in findings]
        )
        for key, value in canaries.items():
            with self.subTest(field=key):
                self.assertNotIn(str(value), rendered)

    def test_report_directory_is_removed_after_timeout_and_failure(self) -> None:
        version = subprocess.CompletedProcess(["gitleaks"], 0, stdout=b"8.30.0")
        calibration = subprocess.CompletedProcess[bytes](["gitleaks"], FINDINGS_EXIT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                recorded_report_folders() as timed_out,
                mock.patch(
                    "first_commit.gitleaks_scanner.subprocess.run",
                    side_effect=(
                        version,
                        calibration,
                        subprocess.TimeoutExpired("private-command", 1),
                    ),
                ),
            ):
                with self.assertRaisesRegex(DependencyError, "timed out") as timeout:
                    scan_history(root, max_findings=1, executable="/gitleaks")

            with (
                recorded_report_folders() as failed,
                mock.patch(
                    "first_commit.gitleaks_scanner.subprocess.run",
                    side_effect=(
                        version,
                        calibration,
                        subprocess.CompletedProcess(["gitleaks"], 1),
                    ),
                ),
            ):
                with self.assertRaisesRegex(DependencyError, "scan failed"):
                    scan_staged(root, max_findings=1, executable="/gitleaks")

        self.assertNotIn("private-command", str(timeout.exception))
        self.assertEqual(1, len(timed_out))
        self.assertEqual(1, len(failed))
        self.assertFalse(timed_out[0].exists())
        self.assertFalse(failed[0].exists())

    def test_report_directory_is_private_to_the_scan(self) -> None:
        observed = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = write_reporting_scanner(root)
            real = shutil.rmtree

            def observe(path, *arguments, **keywords):
                if Path(path).name.startswith(REPORT_FOLDER_PREFIX):
                    observed.append(stat.S_IMODE(Path(path).stat().st_mode))
                return real(path, *arguments, **keywords)

            with mock.patch("first_commit.gitleaks.shutil.rmtree", side_effect=observe):
                scan_staged(
                    root,
                    executable=str(executable),
                    environment=self._report(root, [{"File": "a.txt", "StartLine": 1}]),
                    max_findings=10,
                )

        self.assertEqual([0o700], observed)


if __name__ == "__main__":
    unittest.main()
