import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from first_commit.contributor import Contributor
from first_commit.machine_identity import create_identity
from tests.cli_support import PROJECT, RECORD, CliFixture, PatchedSetupFixture

FILE_PERSON = Contributor("File Person", "file@" + "example.net", "file.pub")
RECORD_PERSON = Contributor("Record Person", "record@" + "example.com", "record.pub")
VARIABLES = {
    "FIRST_COMMIT_AUTHOR_NAME": "Variable Person",
    "FIRST_COMMIT_AUTHOR_EMAIL": "variable@" + "example.org",
    "FIRST_COMMIT_SIGNING_KEY": "var.pub",
}
APPLY_PROMPT = "Apply this setup? [y/N] "


class SetupConfirmationTest(PatchedSetupFixture):
    def applied(self) -> bool:
        return any(call.args[1].confirmed for call in self.setup.call_args_list)

    def test_no_terminal_refuses_a_saved_identity_without_yes(self) -> None:
        create_identity(self.identity, FILE_PERSON)
        code, output, error = self.run_cli("setup", "--revision", "1" * 40)
        self.assertEqual(2, code)
        self.assertFalse(self.applied())
        for detail in ("did not apply", "no terminal", str(self.identity), "--yes"):
            self.assertIn(detail, error)
        self.assertIn("Identity: File Person <file@example.net>", output)

    def test_no_terminal_refuses_variables_without_yes(self) -> None:
        with patch.dict(os.environ, VARIABLES):
            code, _, error = self.run_cli("setup", "--revision", "1" * 40)
        self.assertEqual(2, code)
        self.assertFalse(self.applied())
        self.assertIn("FIRST_COMMIT_AUTHOR_NAME", error)
        self.assertFalse(self.identity.exists())

    def test_yes_applies_a_saved_identity_without_a_terminal(self) -> None:
        create_identity(self.identity, FILE_PERSON)
        code, output, error = self.run_cli("setup", "--revision", "1" * 40, "--yes")
        self.assertEqual((0, ""), (code, error))
        self.assertTrue(self.applied())
        self.assertIn(
            "Identity: File Person <file@example.net>, signing key file.pub "
            f"(from the identity file {self.identity})",
            output,
        )

    def test_the_checkout_record_applies_without_a_terminal_or_yes(self) -> None:
        with patch(
            "first_commit.setup_cli.load_contributor", return_value=RECORD_PERSON
        ):
            code, output, error = self.run_cli("setup", "--revision", "1" * 40)
        self.assertEqual((0, ""), (code, error))
        self.assertTrue(self.applied())
        self.assertIn(f"(from this checkout's record {RECORD})", output)

    def test_variables_are_named_as_the_identity_source(self) -> None:
        with patch.dict(os.environ, VARIABLES):
            code, output, error = self.run_cli(
                "setup", "--revision", "1" * 40, "--dry-run"
            )
        self.assertEqual((0, ""), (code, error))
        self.assertIn(
            "Identity: Variable Person <variable@example.org>, signing key var.pub "
            "(from FIRST_COMMIT_AUTHOR_NAME, FIRST_COMMIT_AUTHOR_EMAIL, and "
            "FIRST_COMMIT_SIGNING_KEY)",
            output,
        )

    def test_a_dry_run_without_an_identity_names_none(self) -> None:
        code, output, _ = self.run_cli("setup", "--revision", "1" * 40, "--dry-run")
        self.assertEqual(0, code)
        self.assertNotIn("Identity:", output)

    def test_a_terminal_with_a_saved_identity_asks_only_to_apply(self) -> None:
        create_identity(self.identity, FILE_PERSON)
        self.stdin.isatty.return_value = True
        with patch("builtins.input", side_effect=["y"]) as typed:
            code, output, error = self.run_cli("setup", "--revision", "1" * 40)
        self.assertEqual(0, code)
        self.assertEqual(1, typed.call_count)
        self.assertEqual(APPLY_PROMPT, error)
        self.assertIn("Identity: File Person <file@example.net>", output)
        self.assertTrue(self.applied())

    def test_a_typed_yes_applies_the_plan(self) -> None:
        create_identity(self.identity, FILE_PERSON)
        self.stdin.isatty.return_value = True
        for answer in ("yes", "Y"):
            with self.subTest(answer=answer):
                self.setup.reset_mock()
                with patch("builtins.input", side_effect=[answer]):
                    code, _, _ = self.run_cli("setup", "--revision", "1" * 40)
                self.assertEqual(0, code)
                self.assertTrue(self.applied())

    def test_yes_in_a_terminal_skips_the_question(self) -> None:
        create_identity(self.identity, FILE_PERSON)
        self.stdin.isatty.return_value = True
        with patch("builtins.input") as typed:
            code, _, error = self.run_cli("setup", "--revision", "1" * 40, "--yes")
        self.assertEqual((0, ""), (code, error))
        typed.assert_not_called()
        self.assertTrue(self.applied())

    def test_typed_answers_are_named_as_the_identity_source(self) -> None:
        self.stdin.isatty.return_value = True
        answers = ["Typed Person", "typed@" + "example.net", "typed.pub", "y"]
        with patch("builtins.input", side_effect=answers):
            code, output, _ = self.run_cli("setup", "--revision", "1" * 40)
        self.assertEqual(0, code)
        self.assertIn(
            "Identity: Typed Person <typed@example.net>, signing key typed.pub "
            "(from the answers typed above)",
            output,
        )


class CombinedOutputTest(CliFixture):
    def test_the_plan_comes_before_the_refusal_in_a_combined_log(self) -> None:
        result = subprocess.run(
            [
                *(sys.executable, "-m", "first_commit", "setup"),
                *("--revision", "1" * 40, "--root", str(self.root)),
            ],
            env={**os.environ, **VARIABLES, "PYTHONPATH": str(PROJECT / "src")},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        log = result.stdout
        self.assertEqual(2, result.returncode, log)
        self.assertLess(
            log.index("Identity: Variable Person"),
            log.index("error: Setup did not apply the plan"),
        )


if __name__ == "__main__":
    unittest.main()
