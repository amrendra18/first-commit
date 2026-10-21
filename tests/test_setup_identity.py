import io
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from first_commit import cli
from first_commit.checks.identity import (
    SIGNERS_FILE_RULE,
    SIGNING_KEY_FILE_RULE,
    signing_file_findings,
)
from first_commit.contributor import Contributor, create_contributor
from first_commit.generated_files import HOOK_PROPOSAL
from first_commit.hooks import HTTPS_REPOSITORY
from first_commit.machine_identity import create_identity, load_identity
from first_commit.models import SetupError, Severity
from first_commit.setup_hooks import PROPOSAL_HEADER, HooksMissingError
from first_commit.setup_trust import check_signing_key
from tests.cli_support import PROJECT, PatchedSetupFixture
from tests.setup_support import PRIVATE_KEY_HEADER, synthetic_key

REVISION = "a" * 40
PERSON = Contributor("Example Contributor", "public@" + "example.net", "key.pub")
OTHER = Contributor("Other Person", "other@" + "example.org", "other.pub")
VARIABLES = {
    "FIRST_COMMIT_AUTHOR_NAME": PERSON.name,
    "FIRST_COMMIT_AUTHOR_EMAIL": PERSON.email,
    "FIRST_COMMIT_SIGNING_KEY": PERSON.signing_key,
}
HOOK_FILE = (
    f'repos:\n  - repo: "{HTTPS_REPOSITORY}"\n'
    f'    rev: "{REVISION}"\n    hooks:\n'
    "      - id: first-commit-staged\n      - id: first-commit-message\n"
    "      - id: first-commit-setup\n"
)


class CloneSetupIdentityTest(PatchedSetupFixture):
    def setUp(self) -> None:
        super().setUp()
        (self.root / ".pre-commit-config.yaml").write_text(HOOK_FILE, "utf-8")
        (self.root / ".gitignore").write_text(".local/\n", "utf-8")

    def clone_setup(self) -> tuple[int, str, str]:
        return self.run_cli("hook", "setup")

    def test_a_failed_setup_saves_no_identity_file(self) -> None:
        self.setup.side_effect = SetupError("Hook environment failed.")
        with patch.dict(os.environ, VARIABLES):
            code, _, error = self.clone_setup()
        self.assertEqual(2, code)
        self.assertIn("Hook environment failed.", error)
        self.assertFalse(self.identity.exists())

    def test_missing_hooks_in_a_clone_get_the_proposal_and_its_fix(self) -> None:
        missing = HooksMissingError(("first-commit-push",))
        missing.proposal = PROPOSAL_HEADER.encode("utf-8") + b"repos: []\n"
        self.setup.side_effect = missing
        with patch.dict(os.environ, VARIABLES):
            code, _, error = self.clone_setup()
        self.assertEqual(2, code)
        self.assertIn("first-commit-push", error)
        self.assertIn(f"fix: merge {HOOK_PROPOSAL} into .pre-commit-config.yaml", error)
        self.assertEqual(missing.proposal, (self.root / HOOK_PROPOSAL).read_bytes())
        self.assertFalse(self.identity.exists())

    def test_a_corrected_rerun_uses_the_corrected_variables(self) -> None:
        self.setup.side_effect = SetupError("Hook environment failed.")
        typo = {**VARIABLES, "FIRST_COMMIT_SIGNING_KEY": "other.pub"}
        with patch.dict(os.environ, typo):
            self.assertEqual(2, self.clone_setup()[0])
        self.setup.side_effect = None
        with patch.dict(os.environ, VARIABLES):
            code, output, _ = self.clone_setup()
        self.assertEqual(0, code)
        self.assertEqual(PERSON, self.setup.call_args.kwargs["contributor"])
        self.assertEqual(PERSON, load_identity(self.identity))
        self.assertIn(f"Machine identity: saved to {self.identity}", output)

    def test_clone_setup_prints_the_identity_line_first(self) -> None:
        with patch.dict(os.environ, VARIABLES):
            code, output, _ = self.clone_setup()
        self.assertEqual(0, code)
        self.assertTrue(
            output.startswith(
                "Identity: Example Contributor <public@example.net>, signing key "
                "key.pub (from FIRST_COMMIT_AUTHOR_NAME, FIRST_COMMIT_AUTHOR_EMAIL, "
                "and FIRST_COMMIT_SIGNING_KEY)\n"
            ),
            output,
        )

    def test_variables_that_differ_from_the_checkout_record_stop_setup(self) -> None:
        create_contributor(self.root, OTHER)
        with patch.dict(os.environ, VARIABLES):
            code, output, error = self.clone_setup()
        self.assertEqual((2, ""), (code, output))
        self.assertIn("name another identity than this checkout's record", error)
        self.assertIn("fix: unset the three variables", error)
        self.assertIn("contributor.json", error)
        self.setup.assert_not_called()
        self.assertFalse(self.identity.exists())

    def test_variables_that_differ_from_the_identity_file_stop_setup(self) -> None:
        create_identity(self.identity, OTHER)
        with patch.dict(os.environ, VARIABLES):
            code, _, error = self.clone_setup()
        self.assertEqual(2, code)
        self.assertIn(f"the identity file {self.identity}", error)
        self.assertIn(f"correct or delete {self.identity}", error)
        self.setup.assert_not_called()

    def test_variables_equal_to_the_record_are_accepted(self) -> None:
        create_contributor(self.root, PERSON)
        with patch.dict(os.environ, VARIABLES):
            code, output, _ = self.clone_setup()
        self.assertEqual(0, code)
        self.assertIn("(from this checkout's record", output)

    def test_a_missing_key_file_stops_before_setup_with_the_source(self) -> None:
        missing = {**VARIABLES, "FIRST_COMMIT_SIGNING_KEY": "missing.pub"}
        with patch.dict(os.environ, missing):
            code, _, error = self.clone_setup()
        self.assertEqual(2, code)
        self.assertIn("The identity from FIRST_COMMIT_AUTHOR_NAME", error)
        self.assertIn("The signing key is not a readable", error)
        self.assertIn("fix: correct FIRST_COMMIT_AUTHOR_NAME", error)
        self.setup.assert_not_called()
        self.assertFalse(self.identity.exists())


class SetupKeyCheckTest(PatchedSetupFixture):
    def test_dry_runs_refuse_a_key_that_is_not_a_public_key_file(self) -> None:
        (self.root / "id_ed25519").write_text(PRIVATE_KEY_HEADER + "\n", "utf-8")
        for key in ("hello world", "id_ed25519", "missing.pub"):
            with self.subTest(key=key):
                variables = {**VARIABLES, "FIRST_COMMIT_SIGNING_KEY": key}
                with patch.dict(os.environ, variables):
                    code, output, error = self.run_cli(
                        "setup", "--revision", REVISION, "--dry-run"
                    )
                self.assertEqual((2, ""), (code, output))
                self.assertIn("The signing key", error)
                self.assertNotIn(key, error.replace("FIRST_COMMIT_SIGNING_KEY", ""))
                self.assertIn("\nfix: ", error)
        self.setup.assert_not_called()

    def test_typed_answers_are_checked_before_the_plan(self) -> None:
        self.stdin.isatty.return_value = True
        answers = ["Typed Person", "typed@" + "example.net", *["~/.ssh/id_ed25519"] * 3]
        with patch("builtins.input", side_effect=answers):
            code, output, error = self.run_cli("setup", "--revision", REVISION)
        self.assertEqual(2, code)
        self.assertNotIn("Identity:", output)
        self.assertIn("The identity from the answers typed above is not usable", error)
        self.assertIn("ends in .pub", error)
        self.assertIn("fix: rerun setup and type", error)
        self.assertEqual(1, self.setup.call_count)

    def test_a_typed_bad_email_names_the_retry(self) -> None:
        self.stdin.isatty.return_value = True
        with patch("builtins.input", side_effect=["Typed", *["nope"] * 3]):
            code, _, error = self.run_cli("setup", "--revision", REVISION)
        self.assertEqual(2, code)
        self.assertIn("email is invalid", error)
        self.assertIn("fix: rerun setup and type", error)

    def test_a_record_with_a_moved_key_names_the_recovery_steps(self) -> None:
        record = Contributor(PERSON.name, PERSON.email, "moved.pub")
        with patch("first_commit.setup_cli.load_contributor", return_value=record):
            code, _, error = self.run_cli("setup", "--revision", REVISION, "--yes")
        self.assertEqual(2, code)
        self.assertIn("Stop and recover", error)
        self.assertIn("git config --local --unset", error)

    def test_a_public_key_file_holding_a_private_key_is_refused(self) -> None:
        (self.root / "renamed.pub").write_text(PRIVATE_KEY_HEADER + "\n", "utf-8")
        with self.assertRaisesRegex(SetupError, "private-key material"):
            check_signing_key(self.root, "renamed.pub")
        (self.root / "good.pub").write_text(synthetic_key() + "\n", "ascii")
        check_signing_key(self.root, "good.pub")


class DoctorSigningFileTest(unittest.TestCase):
    def test_a_missing_signing_key_file_is_an_error(self) -> None:
        root = PROJECT
        findings = signing_file_findings(root, {"user.signingkey": "gone/key.pub"})
        self.assertEqual([SIGNING_KEY_FILE_RULE], [item.rule_id for item in findings])
        self.assertEqual(Severity.ERROR, findings[0].severity)
        self.assertNotIn("gone/key.pub", findings[0].summary)

    def test_literal_keys_and_present_files_pass(self) -> None:
        for value in ("key::ssh-ed25519 AAAA", "ssh-ed25519 AAAA", "README.md"):
            with self.subTest(value=value):
                self.assertEqual(
                    [], signing_file_findings(PROJECT, {"user.signingkey": value})
                )

    def test_an_unknown_home_counts_as_no_file(self) -> None:
        settings = {"user.signingkey": "~no-such-user-for-first-commit/key.pub"}
        self.assertEqual(
            [SIGNING_KEY_FILE_RULE],
            [item.rule_id for item in signing_file_findings(PROJECT, settings)],
        )

    def test_a_stale_allowed_signers_path_is_a_warning(self) -> None:
        settings = {"gpg.ssh.allowedSignersFile": ".local/moved-away/allowed-signers"}
        findings = signing_file_findings(PROJECT, settings)
        self.assertEqual([SIGNERS_FILE_RULE], [item.rule_id for item in findings])
        self.assertEqual(Severity.WARNING, findings[0].severity)
        settings = {"gpg.ssh.allowedSignersFile": str(PROJECT / "README.md")}
        self.assertEqual([], signing_file_findings(PROJECT, settings))


class UnsupportedSystemTest(unittest.TestCase):
    def test_every_command_stops_with_exit_3_and_a_fix_line(self) -> None:
        for arguments in (("version",), ("check",), ("setup", "--dry-run")):
            with self.subTest(arguments=arguments):
                error = io.StringIO()
                with patch.object(sys, "platform", "win32"), redirect_stderr(error):
                    code = cli.main(arguments)
                self.assertEqual(3, code)
                self.assertIn("macOS and Linux only", error.getvalue())
                self.assertIn("\nfix: ", error.getvalue())

    def test_a_system_without_posix_locks_gets_no_traceback(self) -> None:
        program = (
            "import sys; sys.path.insert(0, sys.argv[1]); sys.modules['fcntl'] = None; "
            "from first_commit.cli import main; sys.platform = 'win32'; "
            "raise SystemExit(main(['setup', '--dry-run']))"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", program, str(PROJECT / "src")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(3, result.returncode, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("macOS and Linux only; this system reports win32", result.stderr)
        self.assertIn("\nfix: ", result.stderr)

    def test_readme_states_the_supported_systems(self) -> None:
        readme = " ".join((PROJECT / "README.md").read_text("utf-8").split())
        self.assertIn("macOS or Linux", readme)
        self.assertIn("exit 3", readme)


if __name__ == "__main__":
    unittest.main()
