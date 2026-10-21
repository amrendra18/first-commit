import os
from unittest.mock import patch

from tests.cli_support import CliFixture, PatchedSetupFixture

NAME_PROMPT = "Public Git author name: "
EMAIL_PROMPT = "Public Git author email: "
EMAIL = "public@" + "example.net"
VARIABLES = {
    "FIRST_COMMIT_AUTHOR_NAME": "Variable Person",
    "FIRST_COMMIT_AUTHOR_EMAIL": "variable@" + "example.org",
    "FIRST_COMMIT_SIGNING_KEY": "var.pub",
}


class TypedAnswersTest(CliFixture):
    def test_a_wrong_name_or_email_asks_that_question_again(self) -> None:
        code, error = self.typed_setup(
            "", "Example Contributor", "not-an-email", EMAIL, "key.pub", "y"
        )
        self.assertEqual(0, code)
        self.assertEqual(2, error.count(NAME_PROMPT))
        self.assertEqual(2, error.count(EMAIL_PROMPT))
        self.assertIn("Contributor name is invalid.", error)
        self.assertIn("Contributor email is invalid.", error)

    def test_a_third_wrong_email_stops_before_the_key_question(self) -> None:
        code, error = self.typed_setup("Example Contributor", "one", "two", "three")
        self.assertEqual(2, code)
        self.assertEqual(3, error.count(EMAIL_PROMPT))
        self.assertNotIn("signing-key path", error)
        self.assertTrue(
            error.endswith(
                "error: The identity from the answers typed above is not usable: "
                "Contributor email is invalid.\n"
                "fix: rerun setup and type your public name, email, and the path of "
                "your SSH public key, such as ~/.ssh/id_ed25519.pub.\n"
            ),
            error,
        )


class IdentityVariablesTest(PatchedSetupFixture):
    def test_a_wrong_variable_is_named_with_its_fix(self) -> None:
        for name, value, fix in (
            ("FIRST_COMMIT_AUTHOR_NAME", " ", "your public name"),
            (
                "FIRST_COMMIT_AUTHOR_EMAIL",
                "not-an-email",
                "your public email address, such as you@example.com",
            ),
        ):
            with self.subTest(variable=name):
                with patch.dict(os.environ, {**VARIABLES, name: value}):
                    code, _, error = self.run_cli("setup", "--dry-run")
                self.assertEqual(2, code)
                self.assertRegex(
                    error,
                    f"^error: The value of {name} is not usable: Contributor "
                    "[a-z]+ is invalid\\.\n"
                    f"fix: set {name} to {fix}, then rerun setup\\.\n$",
                )

    def test_a_missing_variable_is_named_with_its_fix(self) -> None:
        partial = {**VARIABLES, "FIRST_COMMIT_SIGNING_KEY": ""}
        with patch.dict(os.environ, partial):
            code, _, error = self.run_cli("setup", "--dry-run")
        self.assertEqual(2, code)
        self.assertEqual(
            "error: FIRST_COMMIT_SIGNING_KEY is unset, but the other identity "
            "variables are set.\n"
            "fix: set all three of FIRST_COMMIT_AUTHOR_NAME, FIRST_COMMIT_AUTHOR_EMAIL, "
            "and FIRST_COMMIT_SIGNING_KEY, or unset them all, then rerun setup.\n",
            error,
        )
