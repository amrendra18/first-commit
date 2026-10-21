import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import __version__, cli
from first_commit.contributor import Contributor
from first_commit.git import GitError
from first_commit.gitleaks_scanner import DependencyError
from first_commit.hooks import HTTPS_REPOSITORY
from first_commit.machine_identity import create_identity, load_identity
from first_commit.setup import SetupRequest
from tests.cli_support import CliFixture, PatchedSetupFixture

KEY_PROMPT = (
    "SSH public signing-key path (ends in .pub, for example ~/.ssh/id_ed25519.pub): "
)
PERSON = ("Example Contributor", "public@" + "example.net")


class CliSetupTest(CliFixture):
    def test_setup_dry_run_and_interactive_identity_confirmation(self) -> None:
        revision = "1" * 40
        with patch(
            "first_commit.setup_cli.setup_repository",
            return_value=("Files: would create README.md",),
        ) as setup:
            code, output, error = self.run_cli(
                "setup", "--revision", revision, "--dry-run"
            )
        self.assertEqual((0, ""), (code, error))
        self.assertIn("README.md", output)
        setup.assert_called_once_with(
            self.root.resolve(),
            SetupRequest(
                revision=revision,
                transport=None,
                license_choice="none",
                docs="core",
                trust_self=False,
                dry_run=True,
            ),
            contributor=None,
        )

        with patch(
            "first_commit.setup_cli.setup_repository",
            return_value=("Hook source: SSH",),
        ) as setup:
            code, _, error = self.run_cli(
                "setup", "--revision", revision, "--transport", "ssh", "--dry-run"
            )
        self.assertEqual((0, ""), (code, error))
        self.assertEqual("ssh", setup.call_args.args[1].transport)

        with (
            patch(
                "first_commit.setup_cli.setup_repository",
                side_effect=[
                    ("Local contributor: required",),
                    ("Local contributor: would create",),
                    ("Verification: passed",),
                ],
            ) as setup,
            patch("first_commit.setup_cli.load_contributor", return_value=None),
            patch("first_commit.cli.sys.stdin") as stream,
            patch(
                "builtins.input",
                side_effect=[
                    "Example Contributor",
                    "public@" + "example.net",
                    "key.pub",
                    "y",
                ],
            ),
        ):
            stream.isatty.return_value = True
            code, output, error = self.run_cli("setup", "--revision", revision)
        self.assertEqual(0, code)
        self.assertIn("Public Git author name", error)
        self.assertIn("Verification: passed", output)
        self.assertEqual(3, setup.call_count)
        self.assertIn("Local contributor: would create", output)
        self.assertEqual(
            "Example Contributor", setup.call_args.kwargs["contributor"].name
        )
        self.assertTrue(setup.call_args.args[1].confirmed)
        self.assertTrue(callable(setup.call_args.kwargs["progress"]))
        self.assertEqual(
            ["core"] * 3, [call.args[1].docs for call in setup.call_args_list]
        )

    def test_setup_trust_self_is_opt_in_on_every_pass(self) -> None:
        with patch(
            "first_commit.setup_cli.setup_repository",
            return_value=("Local signature trust: would write",),
        ) as setup:
            code, output, error = self.run_cli("setup", "--dry-run")
        self.assertEqual((0, ""), (code, error))
        self.assertFalse(setup.call_args.args[1].trust_self)

        person = Contributor("Example Contributor", "public@example.net", "key.pub")
        with (
            patch(
                "first_commit.setup_cli.setup_repository",
                return_value=("Local signature trust: wrote",),
            ) as setup,
            patch("first_commit.setup_cli.load_contributor", return_value=person),
            patch("first_commit.cli.sys.stdin") as stream,
        ):
            stream.isatty.return_value = False
            code, output, error = self.run_cli("setup", "--trust-self")
        self.assertEqual((0, ""), (code, error))
        self.assertIn("Local signature trust: wrote", output)
        self.assertEqual(
            [True] * setup.call_count,
            [call.args[1].trust_self for call in setup.call_args_list],
        )

    def test_setup_dry_run_lists_selected_document_set(self) -> None:
        head = "Files: would create .repo-policy.json, .editorconfig, .gitattributes"
        core = "README.md, AGENTS.md"
        full = core + ", PRD.md, CONTRIBUTING.md, SECURITY.md"
        tail = ".pre-commit-config.yaml, .gitignore, .gitmessage"
        for arguments, documents in (((), core), (("--docs", "full"), full)):
            with (
                self.subTest(arguments=arguments),
                tempfile.TemporaryDirectory() as blank,
            ):
                output = io.StringIO()
                error = io.StringIO()
                with redirect_stdout(output), redirect_stderr(error):
                    code = cli.main(
                        (
                            "setup",
                            "--dry-run",
                            "--revision",
                            "1" * 40,
                            *arguments,
                            "--root",
                            blank,
                        )
                    )
                self.assertEqual((0, ""), (code, error.getvalue()))
                files = [
                    line
                    for line in output.getvalue().splitlines()
                    if line.startswith("Files: ")
                ]
                self.assertEqual([f"{head}, {documents}, {tail}"], files)
                self.assertEqual([], list(Path(blank).iterdir()))

    def test_setup_forwards_full_documents_and_rejects_unknown_set(self) -> None:
        with patch(
            "first_commit.setup_cli.setup_repository",
            return_value=("Plan",),
        ) as setup:
            code, _, error = self.run_cli("setup", "--dry-run", "--docs", "full")
        self.assertEqual((0, ""), (code, error))
        self.assertEqual("full", setup.call_args.args[1].docs)
        with patch("first_commit.setup_cli.setup_repository") as setup:
            code, output, error = self.run_cli("setup", "--dry-run", "--docs", "all")
        self.assertEqual((2, ""), (code, output))
        self.assertIn("Invalid command arguments", error)
        setup.assert_not_called()

    def test_setup_json_preview_and_existing_identity_do_not_prompt(self) -> None:
        person = Contributor("Example", "public@" + "example.net", "key.pub")
        with patch(
            "first_commit.setup_cli.setup_repository",
            return_value=("Plan",),
        ):
            code, output, error = self.run_cli("setup", "--dry-run", "--format", "json")
        self.assertEqual((0, ""), (code, error))
        self.assertTrue(json.loads(output)["dry_run"])
        with (
            patch(
                "first_commit.setup_cli.setup_repository",
                side_effect=[("Plan",), ("Verification: passed",)],
            ) as setup,
            patch("first_commit.setup_cli.load_contributor", return_value=person),
            patch("first_commit.cli.sys.stdin") as stream,
        ):
            stream.isatty.return_value = False
            code, output, error = self.run_cli("setup", "--format", "json")
        self.assertEqual((0, ""), (code, error))
        self.assertFalse(json.loads(output)["dry_run"])
        self.assertEqual(person, setup.call_args.kwargs["contributor"])

    def test_cancelled_setup_and_dependency_errors_have_distinct_exit_codes(
        self,
    ) -> None:
        person = Contributor("Example", "public@" + "example.net", "key.pub")
        with (
            patch(
                "first_commit.setup_cli.setup_repository",
                return_value=("Plan",),
            ) as setup,
            patch("first_commit.setup_cli.load_contributor", return_value=person),
            patch("first_commit.cli.sys.stdin") as stream,
            patch("builtins.input", return_value="n"),
        ):
            stream.isatty.return_value = True
            code, _, error = self.run_cli("setup")
        self.assertEqual(2, code)
        self.assertIn("cancelled", error)
        setup.assert_called_once()
        for exception, expected in (
            (DependencyError("missing"), 3),
            (GitError("unavailable"), 4),
        ):
            with (
                self.subTest(exception=exception),
                patch(
                    "first_commit.cli.load_policy",
                    side_effect=exception,
                ),
            ):
                code, _, error = self.run_cli("doctor")
            self.assertEqual(expected, code)
            self.assertIn(str(exception), error)

    def test_interactive_json_setup_keeps_prompts_out_of_stdout(self) -> None:
        answers = iter(["Example", "public@" + "example.net", "key.pub", "y"])

        def answer(prompt: str = "") -> str:
            print(prompt, end="")
            return next(answers)

        with (
            patch(
                "first_commit.setup_cli.setup_repository",
                side_effect=[("Need identity",), ("Ready",), ("Verification: passed",)],
            ),
            patch("first_commit.setup_cli.load_contributor", return_value=None),
            patch("first_commit.cli.sys.stdin") as stream,
            patch("builtins.input", side_effect=answer),
        ):
            stream.isatty.return_value = True
            code, output, error = self.run_cli("setup", "--format", "json")
        self.assertEqual(0, code)
        self.assertFalse(json.loads(output)["dry_run"])
        self.assertIn("Ready", error)

    def test_signing_key_prompt_names_the_format_and_asks_again(self) -> None:
        code, error = self.typed_setup(
            *PERSON, "id_ed25519", "missing.pub", "key.pub", "y"
        )
        self.assertEqual(0, code)
        self.assertEqual(1, error.count("Public Git author name: "))
        self.assertEqual(3, error.count(KEY_PROMPT))
        self.assertIn("ends in .pub; a private-key reference is refused", error)

    def test_third_wrong_signing_key_stops_setup_with_a_fix(self) -> None:
        code, error = self.typed_setup(*PERSON, "one", "two", "three")
        self.assertEqual(2, code)
        self.assertEqual(3, error.count(KEY_PROMPT))
        self.assertIn("fix: rerun setup and type your public name", error)

    def test_ctrl_c_at_a_prompt_starts_the_error_on_its_own_line(self) -> None:
        with (
            patch("first_commit.setup_cli.setup_repository", return_value=("Plan",)),
            patch("first_commit.setup_cli.load_contributor", return_value=None),
            patch("first_commit.cli.sys.stdin") as stream,
            patch("builtins.input", side_effect=KeyboardInterrupt),
        ):
            stream.isatty.return_value = True
            code, _, error = self.run_cli("setup")
        self.assertEqual(
            (2, "Public Git author name: \nerror: first-commit stopped on Ctrl-C.\n"),
            (code, error),
        )

    def test_setup_json_names_the_schema_and_tool_version(self) -> None:
        with patch(
            "first_commit.setup_cli.setup_repository",
            return_value=("Plan",),
        ):
            code, output, _ = self.run_cli("setup", "--dry-run", "--format", "json")
        self.assertEqual(0, code)
        self.assertEqual(
            {
                "schema_version": 1,
                "tool_version": __version__,
                "passed": True,
                "dry_run": True,
                "actions": ["Plan"],
            },
            json.loads(output),
        )

    def test_clone_setup_trusts_the_own_key_only_when_asked(self) -> None:
        person = Contributor("Example", "public@" + "example.net", "key.pub")
        for value, expected in (
            ("1", True),
            ("0", False),
            ("yes", False),
            (None, False),
        ):
            environment = {} if value is None else {"FIRST_COMMIT_TRUST_SELF": value}
            with (
                self.subTest(value=value),
                patch.dict(os.environ, environment),
                patch(
                    "first_commit.setup_cli.setup_repository",
                    return_value=("Verification: passed",),
                ) as setup,
                patch("first_commit.setup_cli.load_contributor", return_value=person),
                patch(
                    "first_commit.setup_cli.configured_source",
                    return_value=("1" * 40, HTTPS_REPOSITORY),
                ),
            ):
                if value is None:
                    os.environ.pop("FIRST_COMMIT_TRUST_SELF", None)
                code, output, _ = self.run_cli("hook", "setup")
            self.assertEqual(0, code)
            self.assertIn("Verification: passed", output)
            self.assertEqual(expected, setup.call_args.args[1].trust_self)
            self.assertEqual("1" * 40, setup.call_args.args[1].revision)
            self.assertEqual("https", setup.call_args.args[1].transport)

    def test_json_setup_keeps_progress_out_of_stdout(self) -> None:
        person = Contributor("Example", "public@" + "example.net", "key.pub")

        def setup(_root, request, **options):
            if request.confirmed:
                options["progress"]("Installing hook environment...")
                return ("Verification: passed",)
            return ("Plan",)

        with (
            patch(
                "first_commit.setup_cli.setup_repository",
                side_effect=setup,
            ),
            patch("first_commit.setup_cli.load_contributor", return_value=person),
            patch("first_commit.cli.sys.stdin") as stream,
        ):
            stream.isatty.return_value = False
            code, output, error = self.run_cli("setup", "--format", "json")

        self.assertEqual(0, code)
        self.assertTrue(json.loads(output)["passed"])
        self.assertNotIn("Installing", output)
        self.assertIn("Installing hook environment", error)


FILE_PERSON = Contributor("File Person", "file@" + "example.net", "file.pub")
VARIABLE_PERSON = Contributor("Variable Person", "variable@" + "example.org", "var.pub")
VARIABLES = {
    "FIRST_COMMIT_AUTHOR_NAME": VARIABLE_PERSON.name,
    "FIRST_COMMIT_AUTHOR_EMAIL": VARIABLE_PERSON.email,
    "FIRST_COMMIT_SIGNING_KEY": VARIABLE_PERSON.signing_key,
}


class SetupIdentitySourcesTest(PatchedSetupFixture):
    def contributors(self) -> list[Contributor | None]:
        return [call.kwargs.get("contributor") for call in self.setup.call_args_list]

    def test_identity_file_runs_setup_without_a_terminal(self) -> None:
        create_identity(self.identity, FILE_PERSON)
        code, output, error = self.run_cli("setup", "--revision", "1" * 40, "--yes")
        self.assertEqual((0, ""), (code, error))
        self.assertEqual([FILE_PERSON, FILE_PERSON], self.contributors())
        self.assertIn(f"Machine identity: retained {self.identity}", output)

    def test_variables_run_setup_without_a_terminal_and_save_the_file(self) -> None:
        with patch.dict(os.environ, VARIABLES):
            code, output, error = self.run_cli("setup", "--revision", "1" * 40, "--yes")
        self.assertEqual((0, ""), (code, error))
        self.assertEqual([VARIABLE_PERSON, VARIABLE_PERSON], self.contributors())
        self.assertIn(f"Machine identity: saved to {self.identity}", output)
        self.assertEqual(VARIABLE_PERSON, load_identity(self.identity))

    def test_variables_that_differ_from_the_identity_file_stop_setup(self) -> None:
        create_identity(self.identity, FILE_PERSON)
        with patch.dict(os.environ, VARIABLES):
            code, _, error = self.run_cli("setup", "--revision", "1" * 40, "--yes")
        self.assertEqual(2, code)
        self.assertIn(f"another identity than the identity file {self.identity}", error)
        self.assertEqual([], self.contributors())

    def test_checkout_record_wins_over_the_identity_file(self) -> None:
        record = Contributor("Record Person", "record@" + "example.com", "record.pub")
        create_identity(self.identity, FILE_PERSON)
        with patch("first_commit.setup_cli.load_contributor", return_value=record):
            code, _, _ = self.run_cli("setup", "--revision", "1" * 40)
        self.assertEqual(0, code)
        self.assertEqual([record, record], self.contributors())

    def test_dry_run_plans_with_the_saved_identity(self) -> None:
        create_identity(self.identity, FILE_PERSON)
        code, _, error = self.run_cli("setup", "--dry-run", "--revision", "1" * 40)
        self.assertEqual((0, ""), (code, error))
        self.assertEqual([FILE_PERSON], self.contributors())

    def test_no_source_and_no_terminal_names_every_source(self) -> None:
        code, output, error = self.run_cli("setup", "--revision", "1" * 40)
        self.assertEqual((2, ""), (code, output))
        for detail in (
            str(self.identity),
            "FIRST_COMMIT_AUTHOR_NAME",
            "FIRST_COMMIT_AUTHOR_EMAIL",
            "FIRST_COMMIT_SIGNING_KEY",
            "terminal",
            "--yes",
        ):
            self.assertIn(detail, error)
        self.assertEqual([None], self.contributors())
        self.assertFalse(self.identity.exists())


if __name__ == "__main__":
    unittest.main()
