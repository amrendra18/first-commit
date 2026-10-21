import re
import unittest
from pathlib import Path

from first_commit import (
    gitleaks_ignore,
    gitleaks_ignore_format,
    gitleaks_scanner,
    policy,
    policy_fields,
)
from first_commit.git import GIT_TIMEOUT_SECONDS

ROOT = Path(__file__).resolve().parents[1]
MIB = 1024 * 1024


def limits_table() -> dict[str, str]:
    architecture = (ROOT / "ARCHITECTURE.md").read_text("utf-8")
    section = architecture.split("\n## Limits\n", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"^\| ([^|]+?) \| ([^|]+?) \|", section, re.MULTILINE)
    return {limit: value for limit, value in rows if limit not in {"Limit", "---"}}


class FixedLimitsTest(unittest.TestCase):
    def test_policy_limits_have_their_documented_values(self) -> None:
        self.assertEqual(
            {
                "max_files": 10_000,
                "max_file_bytes": 10 * MIB,
                "max_findings": 1_000,
                "max_message_bytes": 1 * MIB,
            },
            policy_fields.DEFAULT_LIMITS,
        )
        self.assertEqual(1 * MIB, policy.MAX_POLICY_BYTES)
        self.assertEqual(120, GIT_TIMEOUT_SECONDS)
        self.assertEqual(
            (120, 600),
            (
                gitleaks_scanner.SCAN_TIMEOUT_SECONDS,
                gitleaks_scanner.HISTORY_TIMEOUT_SECONDS,
            ),
        )

    def test_the_architecture_limits_table_matches_the_code(self) -> None:
        self.assertEqual(
            {
                "Bytes per file": "10 MiB",
                "Paths per scope": "10,000",
                "Findings per scope": "1,000",
                "Commit message": "1 MiB",
                "Policy file": "1 MiB",
                "One Git command, or one blob from `git cat-file --batch`": "120 seconds",
                "One Gitleaks scan": "120 seconds; 600 for a full history scan",
            },
            limits_table(),
        )

    def test_gitleaksignore_limits_have_their_documented_values(self) -> None:
        self.assertEqual(1 * MIB, gitleaks_ignore_format.MAX_IGNORE_BYTES)
        self.assertEqual(1_000, gitleaks_ignore_format.MAX_IGNORE_ENTRIES)
        self.assertEqual(10 * MIB, gitleaks_ignore.MAX_SOURCE_BYTES)
        self.assertEqual(10_000, gitleaks_ignore.MAX_SOURCES)
        self.assertEqual(256 * MIB, gitleaks_ignore.MAX_TOTAL_SOURCE_BYTES)
        architecture = " ".join((ROOT / "ARCHITECTURE.md").read_text("utf-8").split())
        for promise in (
            "A file version over 10 MiB stops the check too",
            "The file holds at most 1,000 fingerprints and 1 MiB.",
            "The checks read at most 10,000 file versions and 256 MiB,",
        ):
            with self.subTest(promise=promise):
                self.assertIn(promise, architecture)


if __name__ == "__main__":
    unittest.main()
