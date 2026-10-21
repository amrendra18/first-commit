import json
import unittest
from typing import cast

from first_commit.fixes import HOOK_FIXES
from first_commit.models import Finding, Result, Severity
from first_commit.reporting import (
    NEXT_ACTION,
    SETUP_RECOVERY_RULES,
    next_action_line,
    render_human,
)
from first_commit.setup_command import SETUP_HOOK_COMMAND
from tests.validation_support import render_json

NEXT_ACTION_LINE = NEXT_ACTION + SETUP_HOOK_COMMAND


class ReportingTest(unittest.TestCase):
    def test_warning_only_results_pass_and_errors_still_fail(self) -> None:
        warning = Finding(
            rule_id="message.subject-length",
            severity=Severity.WARNING,
            path="<commit-message>",
            summary="Keep the subject within 72 characters.",
            line=1,
        )
        error = Finding(
            rule_id="message.header",
            severity=Severity.ERROR,
            path="<commit-message>",
            summary="Use a supported commit header.",
            line=1,
        )
        for findings, passed in (
            ((), True),
            ((warning,), True),
            ((error,), False),
            ((warning, error), False),
        ):
            with self.subTest(findings=findings):
                result = Result("message", findings)
                self.assertEqual(passed, result.passed)
                self.assertEqual(passed, json.loads(render_json(result))["passed"])
                human = render_human(result)
                if passed:
                    self.assertIn("ok - message policy passed", human)
                else:
                    self.assertNotIn("policy passed", human)
        unknown = Finding(
            rule_id="unknown",
            severity=cast("Severity", "invalid"),
            path="message",
            summary="Unknown severity.",
        )
        self.assertFalse(Result("message", (unknown,)).passed)

    def test_outputs_only_safe_finding_fields(self) -> None:
        result = Result(
            scope="working",
            findings=(
                Finding(
                    rule_id="privacy.github-token",
                    severity=Severity.ERROR,
                    path="value.txt",
                    line=1,
                    summary="Detected a GitHub credential shape.",
                ),
            ),
        )

        human = render_human(result)
        machine = render_json(result)

        self.assertIn("privacy.github-token", human)
        self.assertEqual("1", str(json.loads(machine)["schema_version"]))
        self.assertNotIn("ghp_", human + machine)

    def test_human_output_escapes_control_characters_in_paths(self) -> None:
        result = Result(
            scope="working",
            findings=(
                Finding(
                    rule_id="text.final-newline",
                    severity=Severity.ERROR,
                    path="line-one\nline-two",
                    summary="Text file has no final newline.",
                ),
            ),
        )

        output = render_human(result)

        self.assertNotIn("line-one\nline-two", output)
        self.assertIn(r"line-one\nline-two", output)

    def test_next_action_line_only_names_setup_for_recoverable_doctor_findings(
        self,
    ) -> None:
        self.assertEqual(
            "Next action: run pre-commit run first-commit-setup --hook-stage manual",
            NEXT_ACTION_LINE,
        )
        self.assertIsNone(next_action_line(Result("doctor", ())))
        record = Finding(
            rule_id="git.contributor-record",
            severity=Severity.ERROR,
            path="a",
            summary="Missing.",
        )
        self.assertEqual(
            "Next action: run first-commit setup",
            next_action_line(Result("doctor", (record,)), setup_hook=False),
        )

        trust = Finding(
            rule_id="git.signature-verification-trust",
            severity=Severity.WARNING,
            path=".git/config",
            summary="Local SSH signature-verification trust is not configured.",
        )
        self.assertIsNone(next_action_line(Result("doctor", (trust,))))
        self.assertNotIn("git.signature-verification-trust", SETUP_RECOVERY_RULES)

        for rule in sorted(SETUP_RECOVERY_RULES):
            finding = Finding(
                rule_id=rule,
                severity=Severity.ERROR,
                path=".git/config",
                summary="Setup would fix this.",
            )
            with self.subTest(rule=rule):
                self.assertEqual(
                    NEXT_ACTION_LINE,
                    next_action_line(Result("doctor", (trust, finding))),
                )
                for scope in ("working", "staged", "history", "message"):
                    self.assertIsNone(next_action_line(Result(scope, (finding,))))

    def test_next_action_rules_cover_every_setup_owned_readiness_rule(self) -> None:
        setup_owned = {
            rule
            for rule, fix in HOOK_FIXES.items()
            if SETUP_HOOK_COMMAND in fix
            and rule
            not in {
                "git.signature-verification-trust",
                "git.allowed-signers-file",
                "secrets.scanner-unavailable",
            }
        }
        self.assertEqual(16, len(setup_owned))
        self.assertEqual(setup_owned, set(SETUP_RECOVERY_RULES))


if __name__ == "__main__":
    unittest.main()
