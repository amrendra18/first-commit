import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path

from first_commit.finding_collector import FindingCollector
from first_commit.history_messages import TAG_MESSAGE_PATH
from first_commit.models import Finding, Result, Severity, capped
from first_commit.policy import parse_policy
from first_commit.reporting import json_value, render_human
from first_commit.validation import history, message
from tests.gitleaks_support import history_cli, needs_real_scanner, pushed_base_commit
from tests.support import initialize_repository, run_git

CAP = 1000
SCISSORS = "# ------------------------ >8 ------------------------\n"
EMAILS = "".join(f"- person{number}@contrib-mail.org\n" for number in range(CAP + 1))
HOME_LINE = "- Built in /Users/" + "someone/work.\n"


def _warning(number: int) -> Finding:
    return Finding(
        rule_id="test.warning",
        path=f"warned-{number:04}.txt",
        summary="A warning.",
        severity=Severity.WARNING,
    )


ERROR = Finding(rule_id="test.error", path="error.txt", summary="An error.")
WARNINGS = tuple(_warning(number) for number in range(CAP))


class FindingCapTest(unittest.TestCase):
    def test_an_error_after_a_full_cap_of_warnings_fails_the_result(self) -> None:
        found = FindingCollector(CAP)
        found.add(WARNINGS)
        found.add((ERROR,))
        result = found.result("staged")
        self.assertFalse(result.passed)
        self.assertIn(ERROR, result.findings)
        self.assertEqual((CAP, 1), (len(result.findings), result.not_shown))

    def test_one_check_keeps_an_error_that_follows_a_full_cap_of_warnings(self) -> None:
        kept = capped((*WARNINGS, ERROR), CAP)
        self.assertEqual(CAP, len(kept))
        self.assertIn(ERROR, kept)

    def test_a_full_cap_of_errors_stops_reading_the_check(self) -> None:
        read: list[int] = []

        def errors() -> Iterator[Finding]:
            for number in range(10):
                read.append(number)
                yield ERROR

        self.assertEqual([ERROR] * 3, capped(errors(), 3))
        self.assertEqual([0, 1, 2], read)

    def test_the_output_says_how_many_findings_were_not_shown(self) -> None:
        result = Result("message", (ERROR,), not_shown=3)
        self.assertEqual(
            "At least 3 more findings were not shown; each check shows at most 1,000.",
            render_human(result).splitlines()[-2],
        )
        self.assertEqual(3, json_value(result)["not_shown"])
        self.assertNotIn("not_shown", json_value(Result("message", (ERROR,))))
        self.assertNotIn("not shown", render_human(Result("message", (ERROR,))))


class FindingCapRunTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    @needs_real_scanner
    def test_a_bad_header_after_many_scissors_warnings_fails_the_message(self) -> None:
        initialize_repository(self.root)
        policy = parse_policy(b'{"schema_version":1}', self.root)
        path = self.root / ".git/test-message"
        path.write_text("bad message without a type\n\n" + SCISSORS + EMAILS, "utf-8")

        result = message(self.root, policy, path)

        self.assertFalse(result.passed)
        self.assertIn("message.header", [item.rule_id for item in result.findings])
        self.assertEqual(CAP, len(result.findings))
        self.assertGreaterEqual(result.not_shown, 1)

    @needs_real_scanner
    def test_a_tag_message_after_many_remote_warnings_fails_the_check(self) -> None:
        pushed_base_commit(self.root)
        text = self.root / ".git/test-message"
        text.write_text("feat: add contacts\n\n" + EMAILS, encoding="utf-8")
        run_git(
            self.root, "commit", "-q", "--allow-empty", "--no-verify", "-F", str(text)
        )
        run_git(self.root, "update-ref", "refs/remotes/origin/main", "HEAD")
        text.write_text("Release one\n\n" + HOME_LINE, encoding="utf-8")
        run_git(self.root, "tag", "-a", "-F", str(text), "v1")
        policy = parse_policy(b'{"schema_version":1}', self.root)

        result = history(self.root, policy, warn_on_remote=True)

        self.assertFalse(result.passed)
        self.assertIn(TAG_MESSAGE_PATH, [item.path for item in result.findings])
        code, output = history_cli(self.root, ("check",), {})
        self.assertEqual(1, code)
        self.assertIn("not shown; each check shows at most 1,000.", output)
