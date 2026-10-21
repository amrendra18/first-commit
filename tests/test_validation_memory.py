import tempfile
import tracemalloc
import unittest
import weakref
from pathlib import Path
from unittest.mock import patch

from first_commit import validation
from first_commit.checks.privacy import privacy_findings
from first_commit.models import Candidate, Origin
from first_commit.paths import MEBIBYTE
from first_commit.policy import parse_policy
from first_commit.policy_fields import DEFAULT_LIMITS
from tests.support import initialize_repository, run_git
from tests.validation_support import evaluate_candidates

NAMES = ("README.md", "AGENTS.md", *(f"file{number}.txt" for number in range(6)))
# ARCHITECTURE.md states this bound: at most 256 MiB for a 10 MiB file.
PEAK_BYTES_PER_FILE_BYTE = 25.6
PRIVATE_VALUE = "private-value"


class LiveCandidates:
    def __init__(self) -> None:
        self.seen: list[weakref.ref[Candidate]] = []
        self.alive: list[int] = []

    def __call__(self, candidate, *arguments, **keywords):
        self.seen.append(weakref.ref(candidate))
        self.alive.append(sum(ref() is not None for ref in self.seen))
        return privacy_findings(candidate, *arguments, **keywords)


class OneCandidateAtATimeTest(unittest.TestCase):
    def test_each_scope_releases_a_file_before_reading_the_next(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            for name in NAMES:
                (root / name).write_text(f"# {name}\n", encoding="utf-8")
            run_git(root, "add", "--", *NAMES)
            policy = parse_policy(b'{"schema_version": 1}', root)
            for scope in ("working", "staged"):
                live = LiveCandidates()
                with (
                    self.subTest(scope=scope),
                    patch("first_commit.finding_collector.privacy_findings", live),
                    patch("first_commit.validation.scan_staged", return_value=()),
                ):
                    result = getattr(validation, scope)(root, policy)
                    self.assertTrue(result.passed, result.findings)
                    self.assertEqual(len(NAMES), len(live.alive))
                    self.assertEqual(1, max(live.alive))


# Ends with the private value, so its finding proves the check read the whole file.
def _filled(start: bytes, line: bytes, size: int, last: bytes) -> tuple[bytes, int]:
    repeats = (size - len(start) - len(last)) // len(line)
    return start + line * repeats + last, repeats + 1


class PerFilePeakMemoryTest(unittest.TestCase):
    def test_checking_one_file_stays_under_the_stated_peak(self) -> None:
        size = DEFAULT_LIMITS["max_file_bytes"]
        cases = (
            (
                "UTF-16 text, one CJK character per line",
                _filled(
                    b"\xff\xfe",
                    "\u4e2d\n".encode("utf-16-le"),
                    size,
                    f"{PRIVATE_VALUE}\n".encode("utf-16-le"),
                ),
                size,
            ),
            (
                "UTF-8 text with one emoji and one decomposed character",
                _filled(
                    "\U0001f600e\u0301".encode(),
                    b"x" * 79 + b"\n",
                    size,
                    f"{PRIVATE_VALUE}\n".encode(),
                ),
                size,
            ),
            (
                "UTF-8 lines of two characters",
                _filled(b"", b"xy\n", MEBIBYTE, f"{PRIVATE_VALUE}\n".encode()),
                MEBIBYTE,
            ),
        )
        policy = parse_policy(b'{"schema_version": 1}', Path.cwd())
        for name, (content, last_line), checked in cases:
            with self.subTest(case=name):
                candidate = Candidate("file.txt", content, Origin.INDEX)
                tracemalloc.start()
                try:
                    base = tracemalloc.get_traced_memory()[0]
                    result = evaluate_candidates(
                        "staged", (candidate,), policy, {}, (PRIVATE_VALUE,)
                    )
                    peak = tracemalloc.get_traced_memory()[1] - base
                finally:
                    tracemalloc.stop()
                self.assertLess(peak, PEAK_BYTES_PER_FILE_BYTE * checked)
                self.assertEqual(
                    [("privacy.private-literal", last_line)],
                    [
                        (finding.rule_id, finding.line)
                        for finding in result.findings
                        if finding.path == "file.txt"
                    ],
                )


if __name__ == "__main__":
    unittest.main()
