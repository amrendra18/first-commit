import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import cli
from first_commit.gitleaks_scanner import DependencyError
from first_commit.models import Finding, Result, Severity
from first_commit.reporting import NEXT_ACTION
from first_commit.setup_command import SETUP_HOOK_COMMAND
from first_commit.setup_hooks import hook_bytes
from tests.cli_support import GIT_CONFIG, HOOK, RECORD, CliFixture
from tests.support import commit_message

TOOL_SETUP = "first-commit setup"
NEXT_ACTION_LINE = NEXT_ACTION + SETUP_HOOK_COMMAND
PROJECT_CONFIG = """\
repos:
  - repo: local
    hooks:
      - id: first-commit-staged
        name: first-commit staged hygiene
        entry: first-commit hook pre-commit
        language: system
        pass_filenames: false
        stages: [pre-commit]
      - id: first-commit-message
        name: first-commit commit-message hygiene
        entry: first-commit hook commit-msg
        language: system
        stages: [commit-msg]
      - id: first-commit-push
        name: first-commit pre-push hygiene
        entry: first-commit hook pre-push
        language: system
        pass_filenames: false
        stages: [pre-push]
"""


class CliOutputTest(CliFixture):
    def setUp(self) -> None:
        super().setUp()
        (self.root / ".pre-commit-config.yaml").write_bytes(hook_bytes("1" * 40))

    def test_doctor_and_hook_dispatch_use_new_policy(self) -> None:
        (self.root / "message.txt").write_text(
            commit_message("feat: add checks"), encoding="utf-8"
        )
        with (
            patch("first_commit.validation.validate_scanner"),
            patch("first_commit.validation.hook_findings", return_value=[]),
        ):
            code, output, error = self.run_cli("doctor")
        self.assertEqual((1, ""), (code, error))
        self.assertIn("git.contributor-record", output)
        self.assertIn("template.", output)
        message = str(self.root / "message.txt")
        code, output, error = self.run_cli("hook", "commit-msg", message)
        self.assertEqual((1, ""), (code, error))
        self.assertIn("FAIL message", output)
        self.assertIn("git.contributor-record", output)

    def run_in(self, folder: Path, *arguments: str) -> tuple[int, str, str]:
        previous = Path.cwd()
        os.chdir(folder)
        self.addCleanup(os.chdir, previous)
        output, error = io.StringIO(), io.StringIO()
        with (
            patch("first_commit.validation.doctor", return_value=Result("doctor", ())),
            redirect_stdout(output),
            redirect_stderr(error),
        ):
            code = cli.main(arguments)
        return code, output.getvalue(), error.getvalue()

    def test_a_run_from_a_subfolder_names_the_repository_first(self) -> None:
        nested = self.root / "nested" / "deeper"
        nested.mkdir(parents=True)
        repository = str(self.root.resolve())

        human = self.run_in(nested, "doctor")
        machine = self.run_in(nested, "doctor", "--format", "json")
        named = self.run_in(self.root, "doctor", "--root", str(nested))

        self.assertEqual(
            (0, [f"Repository: {repository}", "PASS doctor"], ""),
            (human[0], human[1].splitlines(), human[2]),
        )
        self.assertEqual((0, ""), (machine[0], machine[2]))
        self.assertEqual(repository, json.loads(machine[1])["repository"])
        self.assertEqual(f"Repository: {repository}", named[1].splitlines()[0])

    def test_a_run_in_the_repository_root_prints_no_repository_line(self) -> None:
        human = self.run_in(self.root, "doctor")
        machine = self.run_in(self.root, "doctor", "--format", "json")
        named = self.run_in(self.root.parent, "doctor", "--root", str(self.root))

        self.assertEqual("PASS doctor\n", human[1])
        self.assertEqual("PASS doctor\n", named[1])
        self.assertEqual(str(self.root.resolve()), json.loads(machine[1])["repository"])

    def test_terminal_status_can_be_color_coded(self) -> None:
        with (
            patch("first_commit.cli._color", return_value=True),
            patch(
                "first_commit.validation.doctor",
                return_value=Result("doctor", ()),
            ),
        ):
            code, output, _ = self.run_cli("doctor")
        self.assertEqual(0, code)
        self.assertIn("\x1b[32mPASS doctor", output)

    def test_human_check_shows_completed_steps_before_a_late_failure(self) -> None:
        passed = Result("test", ())
        with (
            patch("first_commit.validation.doctor", return_value=passed),
            patch("first_commit.validation.working", return_value=passed),
            patch("first_commit.validation.staged", return_value=passed),
            patch(
                "first_commit.validation.history",
                side_effect=DependencyError("scanner unavailable"),
            ),
        ):
            code, output, error = self.run_cli("check")
        self.assertEqual(3, code)
        self.assertIn("PASS doctor", output)
        self.assertIn("PASS staged", output)
        self.assertIn("scanner unavailable", error)

    def test_doctor_names_setup_once_for_recoverable_readiness_findings(self) -> None:
        with patch("first_commit.validation.validate_scanner"):
            code, output, error = self.run_cli("doctor")

        lines = output.splitlines()
        self.assertEqual((1, ""), (code, error))
        for rule in ("git.contributor-record", "hooks.missing", "template.missing"):
            self.assertTrue(any(rule in line for line in lines), rule)
        self.assertEqual(1, lines.count(NEXT_ACTION_LINE))
        self.assertEqual(NEXT_ACTION_LINE, lines[-1])

    def test_doctor_omits_setup_line_for_verification_trust_warning_alone(self) -> None:
        trust = Finding(
            rule_id="git.signature-verification-trust",
            severity=Severity.WARNING,
            path=GIT_CONFIG,
            summary="Local SSH signature-verification trust is not configured.",
        )
        with patch(
            "first_commit.validation.doctor",
            return_value=Result("doctor", (trust,)),
        ):
            code, output, error = self.run_cli("doctor")

        self.assertEqual((0, ""), (code, error))
        self.assertIn("git.signature-verification-trust", output)
        self.assertNotIn("Next action", output)

    def test_check_names_setup_once_rather_than_once_per_step(self) -> None:
        passed = Result("test", ())
        with (
            patch("first_commit.validation.validate_scanner"),
            patch("first_commit.validation.working", return_value=passed),
            patch("first_commit.validation.staged", return_value=passed),
            patch("first_commit.validation.history", return_value=passed),
        ):
            code, output, error = self.run_cli("check")

        self.assertEqual((1, ""), (code, error))
        self.assertEqual(1, output.splitlines().count(NEXT_ACTION_LINE))

        record = Result(
            "doctor",
            (
                Finding(
                    rule_id="git.contributor-record",
                    severity=Severity.ERROR,
                    path=RECORD,
                    summary="Local contributor record is missing; run setup.",
                ),
            ),
        )
        for arguments in (("check",), ("hook", "pre-push")):
            with self.subTest(arguments=arguments):
                with patch(
                    "first_commit.cli._checks",
                    return_value=[("doctor", record), ("doctor", record)],
                ):
                    code, output, error = self.run_cli(*arguments)

                self.assertEqual((1, ""), (code, error))
                self.assertEqual(1, output.splitlines().count(NEXT_ACTION_LINE))

    def test_setup_line_never_reaches_json_output(self) -> None:
        ready = Result("doctor", ())
        unready = Result(
            "doctor",
            (
                Finding(
                    rule_id="hooks.missing",
                    severity=Severity.ERROR,
                    path=HOOK,
                    summary="Declared Git hook is missing.",
                ),
            ),
        )
        for result, expected in ((ready, 0), (unready, 1)):
            with self.subTest(passed=result.passed):
                with patch("first_commit.validation.doctor", return_value=result):
                    code, output, error = self.run_cli("doctor", "--format", "json")

                data = json.loads(output)
                self.assertEqual((expected, ""), (code, error))
                self.assertNotIn("Next action", output)
                self.assertEqual(
                    {
                        "checks",
                        "passed",
                        "repository",
                        "schema_version",
                        "tool_version",
                    },
                    set(data),
                )
                self.assertEqual(
                    {
                        "findings",
                        "name",
                        "passed",
                        "schema_version",
                        "scope",
                        "tool_version",
                    },
                    set(data["checks"][0]),
                )
                for finding in data["checks"][0]["findings"]:
                    self.assertEqual(
                        {"fix", "path", "rule_id", "severity", "summary"}, set(finding)
                    )

    def test_project_owned_config_without_setup_hook_gets_a_working_command(
        self,
    ) -> None:
        (self.root / ".pre-commit-config.yaml").write_text(
            PROJECT_CONFIG, encoding="utf-8"
        )
        with patch("first_commit.validation.validate_scanner"):
            code, output, error = self.run_cli("doctor")

        self.assertEqual((1, ""), (code, error))
        lines = output.splitlines()
        trust = lines.index(
            next(line for line in lines if "git.signature-verification-trust" in line)
        )
        self.assertIn(TOOL_SETUP + " --trust-self", lines[trust + 1])
        self.assertEqual(NEXT_ACTION + TOOL_SETUP, lines[-1])
        for line in lines:
            if "first-commit-setup" in line:
                with self.subTest(line=line):
                    self.assertIn(TOOL_SETUP, line)

    def test_missing_hook_config_names_the_tool_setup_command(self) -> None:
        (self.root / ".pre-commit-config.yaml").unlink()
        with patch("first_commit.validation.validate_scanner"):
            code, output, error = self.run_cli("doctor", "--format", "json")

        self.assertEqual((1, ""), (code, error))
        fixes = [item["fix"] for item in json.loads(output)["checks"][0]["findings"]]
        self.assertIn(
            "Run first-commit setup --trust-self in this checkout to trust your own "
            "signing key.",
            fixes,
        )
        self.assertFalse(any("first-commit-setup" in fix for fix in fixes))

    def test_generated_config_names_the_setup_hook_command(self) -> None:
        with patch("first_commit.validation.validate_scanner"):
            _, output, _ = self.run_cli("doctor")

        self.assertNotIn(TOOL_SETUP, output)
        self.assertIn("FIRST_COMMIT_TRUST_SELF=1 pre-commit run", output)


if __name__ == "__main__":
    unittest.main()
