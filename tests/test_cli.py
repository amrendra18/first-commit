import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import cli
from first_commit.candidates import CandidateError
from first_commit.contributor import Contributor, ContributorError, create_contributor
from first_commit.git import GitError, IndexFileError
from first_commit.gitleaks_ignore_format import IgnoreFileError
from first_commit.gitleaks_scanner import DependencyError, ScannerTimeoutError
from first_commit.models import Result, SetupError
from first_commit.paths import PathError
from first_commit.policy_fields import PolicyError
from first_commit.private_values import PrivateValuesError
from tests.cli_support import PROJECT, CliFixture
from tests.gitleaks_support import needs_real_scanner
from tests.support import commit_message, run_git


class FirstCommitCliTest(CliFixture):
    def test_check_runs_labeled_steps_and_reports_missing_local_identity(self) -> None:
        passed = Result("test", ())
        with (
            patch("first_commit.validation.validate_scanner"),
            patch("first_commit.validation.hook_findings", return_value=[]),
            patch("first_commit.validation.working", return_value=passed),
            patch("first_commit.validation.staged", return_value=passed),
            patch("first_commit.validation.history", return_value=passed),
        ):
            code, output, error = self.run_cli("check")
        self.assertEqual((1, ""), (code, error))
        labels = [
            line.split()[1]
            for line in output.splitlines()
            if line[:5] in {"PASS ", "WARN ", "FAIL "}
        ]
        self.assertEqual(["doctor", "working", "staged", "history"], labels)
        self.assertNotIn("coverage", output)
        self.assertIn("git.contributor-record", output)

    def test_check_json_contains_each_step_without_legacy_scopes(self) -> None:
        passed = Result("test", ())
        with (
            patch("first_commit.validation.validate_scanner"),
            patch("first_commit.validation.hook_findings", return_value=[]),
            patch("first_commit.validation.working", return_value=passed),
            patch("first_commit.validation.staged", return_value=passed),
            patch("first_commit.validation.history", return_value=passed),
        ):
            code, output, error = self.run_cli("check", "--format", "json")
        self.assertEqual((1, ""), (code, error))
        data = json.loads(output)
        self.assertEqual(1, data["schema_version"])
        self.assertFalse(data["passed"])
        self.assertEqual(
            ["doctor", "working", "staged", "history"],
            [check["name"] for check in data["checks"]],
        )
        self.assertEqual(
            {"checks", "passed", "repository", "schema_version", "tool_version"},
            set(data),
        )
        for check in data["checks"]:
            self.assertEqual(
                {
                    "findings",
                    "name",
                    "passed",
                    "schema_version",
                    "scope",
                    "tool_version",
                },
                set(check),
            )
            for finding in check["findings"]:
                self.assertEqual(
                    {"fix", "path", "rule_id", "severity", "summary"}, set(finding)
                )
        code, _, error = self.run_cli("check", "working")
        self.assertEqual(2, code)
        self.assertIn("Invalid command", error)

    def test_unknown_policy_field_exits_two_without_its_value(self) -> None:
        canary = "docs/private-upgrade-canary.md"
        (self.root / ".repo-policy.json").write_text(
            json.dumps({"schema_version": 1, "additional_documents": [canary]}) + "\n",
            encoding="utf-8",
        )
        code, output, error = self.run_cli("check")
        self.assertEqual(2, code)
        self.assertEqual(
            "error: The project policy file .repo-policy.json has unknown fields.\n",
            error,
        )
        self.assertEqual("", output)
        self.assertNotIn(canary, error)

    def test_unreadable_configuration_names_the_file_and_the_next_step(self) -> None:
        policy = self.root / ".repo-policy.json"
        policy.unlink()
        code, output, error = self.run_cli("doctor")
        self.assertEqual((2, ""), (code, output))
        self.assertIn(".repo-policy.json does not exist", error)
        self.assertIn("first-commit setup", error)

        policy.mkdir()
        code, _, error = self.run_cli("doctor")
        self.assertEqual(2, code)
        self.assertIn(".repo-policy.json cannot be read", error)
        self.assertIn("regular file", error)

    def test_deeply_nested_policy_exits_two(self) -> None:
        (self.root / ".repo-policy.json").write_bytes(b"[" * 200_000 + b"]" * 200_000)
        for arguments in (("check",), ("hook", "pre-commit")):
            with self.subTest(arguments=arguments):
                code, output, error = self.run_cli(*arguments)
                self.assertEqual((2, ""), (code, output))
                self.assertIn("not valid UTF-8 JSON", error)

    def test_invalid_contributor_record_names_the_cause_file_and_next_step(
        self,
    ) -> None:
        with patch(
            "first_commit.policy.load_contributor",
            side_effect=ContributorError("synthetic-canary"),
        ):
            code, _, error = self.run_cli("doctor")
        self.assertEqual(2, code)
        self.assertEqual(
            "error: synthetic-canary\n"
            "fix: delete .local/first-commit/contributor.json and run "
            "`first-commit setup`.\n",
            error,
        )

    def test_folder_outside_git_names_the_next_step(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            for command in ("doctor", "check"):
                with self.subTest(command=command):
                    output, error = io.StringIO(), io.StringIO()
                    with redirect_stdout(output), redirect_stderr(error):
                        code = cli.main((command, "--root", folder))
                    self.assertEqual((4, ""), (code, output.getvalue()))
                    self.assertIn("not inside a Git repository", error.getvalue())
                    self.assertIn("first-commit setup", error.getvalue())

    def test_invalid_arguments_point_to_help(self) -> None:
        code, _, error = self.run_cli("check", "--bogus")
        self.assertEqual(2, code)
        self.assertIn("first-commit check --help", error)

    def test_configuration_error_is_redacted_and_version_works(self) -> None:
        with patch(
            "first_commit.cli.load_policy",
            side_effect=PolicyError("synthetic configuration failure"),
        ):
            code, output, error = self.run_cli("doctor")
        self.assertEqual((2, ""), (code, output))
        self.assertIn("configuration failure", error)
        printed = io.StringIO()
        with redirect_stdout(printed):
            code = cli.main(("version",))
        self.assertEqual(0, code)
        self.assertTrue(printed.getvalue().strip())

    def test_pre_commit_and_pre_push_hook_dispatch(self) -> None:
        passed = Result("test", ())
        with (
            patch("first_commit.validation.staged", return_value=passed) as staged,
            patch("first_commit.cli._checks", return_value=[("all", passed)]) as checks,
        ):
            code, output, _ = self.run_cli("hook", "pre-commit")
            self.assertEqual(0, code)
            self.assertIn("PASS staged", output)
            staged.assert_called_once()
            code, output, _ = self.run_cli("hook", "pre-push")
            self.assertEqual(0, code)
            self.assertIn("PASS all", output)
            checks.assert_called_once()

    def test_pre_push_runs_fixed_steps_without_project_coverage(self) -> None:
        passed = Result("test", ())
        with (
            patch("first_commit.validation.doctor", return_value=passed),
            patch("first_commit.validation.working", return_value=passed),
            patch("first_commit.validation.staged", return_value=passed),
            patch("first_commit.validation.history", return_value=passed),
        ):
            code, output, error = self.run_cli("hook", "pre-push")
        self.assertEqual((0, ""), (code, error))
        self.assertEqual(
            ["PASS doctor", "PASS working", "PASS staged", "PASS history"],
            output.splitlines(),
        )

    def test_error_classes_map_to_fixed_exit_codes(self) -> None:
        for error, expected in (
            (PolicyError("configuration"), 2),
            (SetupError("setup"), 2),
            (IgnoreFileError("ignore file"), 2),
            (ContributorError("contributor"), 2),
            (PrivateValuesError("private values"), 2),
            (DependencyError("dependency"), 3),
            (ScannerTimeoutError("scanner timeout"), 3),
            (GitError("git"), 4),
            (IndexFileError("index file"), 4),
            (CandidateError("candidate"), 4),
            (PathError("path"), 4),
            (OSError("operating system"), 4),
        ):
            with (
                self.subTest(error=type(error).__name__),
                patch("first_commit.cli._run", side_effect=error),
            ):
                code, output, stderr = self.run_cli("doctor")
            self.assertEqual((expected, ""), (code, output))
            self.assertEqual(f"error: {error}\n", stderr)

    def test_ctrl_c_prints_one_line_and_exits_two(self) -> None:
        with patch("first_commit.validation.doctor", side_effect=KeyboardInterrupt):
            code, output, error = self.run_cli("doctor")

        self.assertEqual(
            (2, "", "error: first-commit stopped on Ctrl-C.\n"), (code, output, error)
        )

    def test_invalid_arguments_are_not_echoed(self) -> None:
        canary = "private-argument-canary"
        for arguments in (("--" + canary,), ("check", canary), ("hook", canary)):
            with self.subTest(arguments=arguments):
                code, output, error = self.run_cli(*arguments)
                self.assertEqual((2, ""), (code, output))
                self.assertIn("Invalid command arguments", error)
                self.assertNotIn(canary, error)

    def test_unreadable_commit_message_is_a_redacted_repository_error(self) -> None:
        message = self.root / "message"
        for content in (b"private-message-canary\0", b"private-message-canary\xff"):
            with self.subTest(content=content):
                message.write_bytes(content)
                code, output, error = self.run_cli("hook", "commit-msg", str(message))
                self.assertEqual((4, ""), (code, output))
                self.assertNotIn("private-message-canary", error)
        with tempfile.TemporaryDirectory() as outside:
            external = Path(outside) / "message"
            external.write_text("private-message-canary\n", encoding="utf-8")
            code, output, error = self.run_cli("hook", "commit-msg", str(external))
        self.assertEqual((4, ""), (code, output))
        self.assertNotIn("private-message-canary", error)

    def test_commit_msg_hook_follows_commit_body_sections_fact(self) -> None:
        person = Contributor("Example", "public@" + "example.net", "key.pub")
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        create_contributor(self.root, person)
        for key, value in {
            "user.name": person.name,
            "user.email": person.email,
            "user.signingkey": person.signing_key,
            "gpg.format": "ssh",
            "commit.gpgsign": "true",
            "tag.gpgsign": "true",
            "user.useConfigOnly": "true",
        }.items():
            run_git(self.root, "config", "--local", key, value)
        unlisted = "private@" + "nonexample.dev"
        message = self.root / ".local/message"
        cases = (
            (None, "feat: add checks\n", 1, "message.sections"),
            (True, "feat: add checks\n", 1, "message.sections"),
            (False, "feat: add checks\n", 0, None),
            (False, commit_message("feat: add checks"), 0, None),
            (False, "plain subject\n", 1, "message.header"),
            (False, "feat: add checks\n\nMail " + unlisted + "\n", 1, "privacy."),
        )
        for setting, text, expected, rule in cases:
            with self.subTest(setting=setting, text=text[:20]):
                policy = {"schema_version": 1}
                if setting is not None:
                    policy["commit_body_sections"] = setting
                (self.root / ".repo-policy.json").write_text(
                    json.dumps(policy), encoding="utf-8"
                )
                message.write_text(text, encoding="utf-8")
                code, output, error = self.run_cli(
                    "hook", "commit-msg", str(message), "--format", "json"
                )
                self.assertEqual((expected, ""), (code, error), output)
                rules = [
                    finding["rule_id"]
                    for check in json.loads(output)["checks"]
                    for finding in check["findings"]
                ]
                if rule:
                    self.assertTrue(any(item.startswith(rule) for item in rules))
                if setting is False:
                    self.assertNotIn("message.sections", rules)
                self.assertNotIn(unlisted, output)

    @needs_real_scanner
    def test_pre_commit_managed_message_hook_enforces_policy(self) -> None:
        person = Contributor(
            "Example Contributor", "public@" + "example.net", "~/.ssh/id_ed25519.pub"
        )
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        create_contributor(self.root, person)
        for key, value in {
            "user.name": person.name,
            "user.email": person.email,
            "user.signingkey": person.signing_key,
            "gpg.format": "ssh",
            "commit.gpgsign": "true",
            "tag.gpgsign": "true",
            "user.useConfigOnly": "true",
        }.items():
            run_git(self.root, "config", "--local", key, value)
        canary = "synthetic-hook-private-canary"
        private = self.root / ".local/first-commit/private-values.txt"
        private.write_text(canary + "\n", encoding="utf-8")
        private.chmod(0o600)
        entry = shlex.quote(sys.executable) + " -m first_commit.cli"
        (self.root / ".pre-commit-config.yaml").write_text(
            "repos:\n  - repo: local\n    hooks:\n"
            "      - id: first-commit-message\n"
            "        name: first-commit message policy\n"
            "        entry: " + json.dumps(entry + " hook commit-msg") + "\n"
            "        language: system\n        stages: [commit-msg]\n"
            "        always_run: true\n        pass_filenames: true\n"
            "        verbose: true\n",
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(PROJECT / "src")
        environment["PRE_COMMIT_HOME"] = str(self.root / ".local/pre-commit")
        installed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pre_commit",
                "install",
                "--hook-type",
                "commit-msg",
            ],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(0, installed.returncode, installed.stderr)
        message = self.root / ".git/COMMIT_EDITMSG"
        for text, expected, rule in (
            (commit_message("feat: add checks"), 0, None),
            ("plain subject\n", 1, "message.header"),
            (commit_message("feat: " + "a" * 73), 0, "message.subject-length"),
            (commit_message("feat: " + "a" * 101), 1, "message.subject-length"),
            ("fixup! " + canary + "\n", 1, "privacy.private-literal"),
            (
                "feat: add checks\n\nWhy:\n- " + canary + "\n",
                1,
                "privacy.private-literal",
            ),
            ("# " + canary + "\nfeat: add checks\n", 1, "privacy.private-literal"),
        ):
            with self.subTest(text=text[:40]):
                message.write_text(text, encoding="utf-8")
                result = subprocess.run(
                    [str(self.root / ".git/hooks/commit-msg"), str(message)],
                    cwd=self.root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                output = result.stdout + result.stderr
                self.assertEqual(expected, result.returncode, output)
                self.assertNotIn(canary, output)
                if rule:
                    self.assertIn(rule, output)
                if expected == 0 and rule:
                    self.assertIn("warnings only", output)
