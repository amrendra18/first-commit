import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from first_commit import validation
from first_commit.candidates import filtered_staged_paths
from first_commit.checks.text import text_findings
from first_commit.gitleaks_scanner import (
    LOCAL_SCANNER_PATH,
    DependencyError,
    validate_scanner,
)
from first_commit.models import Result, Severity
from first_commit.policy import REQUIRED_DOCUMENTS, parse_policy
from first_commit.validation import FILTERED_UNREADABLE_RULE
from tests.gitleaks_support import trusted_local_scanner
from tests.support import initialize_repository, run_git
from tests.test_checks import candidate

PRIVATE_VALUE = "bobcanary"
LFS_CLEAN = "sed 's,.*,version https://git-lfs.github.com/spec/v1,'"


class LfsWorkingCopyEdgeTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        run_git(self.root, "config", "filter.lfs.clean", LFS_CLEAN)
        for path in (*REQUIRED_DOCUMENTS, ".gitattributes"):
            text = "*.dat filter=lfs\n" if path == ".gitattributes" else "# Notes\n"
            (self.root / path).write_text(text, encoding="utf-8")
            run_git(self.root, "add", "--", path)
        self.policy = parse_policy(b'{"schema_version":1}', self.root)

    def add_file(self, path: str, content: bytes) -> None:
        (self.root / path).write_bytes(content)
        run_git(self.root, "add", "--", path)

    def staged(self) -> Result:
        with (
            patch("first_commit.validation.scan_staged", return_value=()),
            patch("first_commit.validation.scan_hidden_staged", return_value=()),
        ):
            return validation.staged(self.root, self.policy, (PRIVATE_VALUE,))

    def test_a_missing_working_copy_blocks_the_commit(self) -> None:
        self.add_file("gone.dat", b"public\n")
        (self.root / "gone.dat").unlink()

        result = self.staged()

        self.assertEqual(
            [(FILTERED_UNREADABLE_RULE, Severity.ERROR)],
            [(f.rule_id, f.severity) for f in result.findings if f.path == "gone.dat"],
        )
        self.assertFalse(result.passed)

    def test_a_filter_named_only_in_the_staged_attributes_counts(self) -> None:
        (self.root / ".gitattributes").write_text("*.csv filter=lfs\n", "utf-8")
        run_git(self.root, "add", "--", ".gitattributes")
        self.add_file("table.csv", f"{PRIVATE_VALUE}\n".encode())
        (self.root / ".gitattributes").write_text("*.dat filter=lfs\n", "utf-8")

        self.assertEqual(
            ("table.csv",), filtered_staged_paths(self.root, ["table.csv"])
        )
        self.assertIn(
            ("privacy.private-literal", "table.csv"),
            {(item.rule_id, item.path) for item in self.staged().findings},
        )

    def test_a_working_copy_of_exactly_the_size_limit_is_read(self) -> None:
        content = b"public " * 8 + PRIVATE_VALUE.encode() + b"\n"
        self.add_file("data.dat", content)
        self.policy = replace(self.policy, max_file_bytes=len(content))

        rules = {(item.rule_id, item.path) for item in self.staged().findings}

        self.assertIn(("privacy.private-literal", "data.dat"), rules)
        self.assertNotIn(("files.filtered-too-large", "data.dat"), rules)


class LinkedLocalScannerTest(unittest.TestCase):
    def test_a_link_at_the_local_scanner_path_never_runs(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            initialize_repository(root)
            marker = root / "ran"
            content = (
                f"#!/bin/sh\necho ran >> '{marker}'\n"
                'if [ "$1" = version ]; then echo 8.30.0; fi\n'
            ).encode()
            target = root / "elsewhere/gitleaks"
            target.parent.mkdir()
            target.write_bytes(content)
            target.chmod(0o755)
            local = root / LOCAL_SCANNER_PATH
            local.parent.mkdir(parents=True)
            local.symlink_to(target)

            with (
                trusted_local_scanner(content),
                self.assertRaisesRegex(DependencyError, "is a link or not a regular"),
            ):
                validate_scanner(root)
            self.assertFalse(marker.exists())


class CrlfTextTest(unittest.TestCase):
    def test_a_crlf_line_ending_is_not_trailing_whitespace_or_control(self) -> None:
        for content, expected in (
            (b"a\r\n", []),
            (b"a \r\n", [("text.trailing-whitespace", 1)]),
        ):
            with self.subTest(content=content):
                findings = text_findings(
                    candidate("notes.txt", content), max_findings=1000
                )
                self.assertEqual(
                    expected, [(item.rule_id, item.line) for item in findings]
                )


if __name__ == "__main__":
    unittest.main()
