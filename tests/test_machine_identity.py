import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import cli, setup_cli
from first_commit.contributor import Contributor, ContributorError, create_contributor
from first_commit.hooks import HTTPS_REPOSITORY as HTTPS
from first_commit.hooks import SSH_REPOSITORY as SSH
from first_commit.machine_identity import (
    create_identity,
    identity_from_environment,
    identity_path,
    load_identity,
    missing_identity_message,
)
from first_commit.models import SetupError
from first_commit.setup_command import SETUP_HOOK_COMMAND
from first_commit.setup_hooks import configured_source
from tests.cli_support import write_keys
from tests.support import initialize_repository

PERSON = Contributor("Example Contributor", "public@" + "example.net", "key.pub")
REVISION = "a" * 40
VARIABLES = {
    "FIRST_COMMIT_AUTHOR_NAME": PERSON.name,
    "FIRST_COMMIT_AUTHOR_EMAIL": PERSON.email,
    "FIRST_COMMIT_SIGNING_KEY": PERSON.signing_key,
}


def hook_config(source: str = HTTPS, revision: str = REVISION) -> str:
    hooks = "".join(
        f"      - id: {name}\n"
        for name in (
            "first-commit-staged",
            "first-commit-message",
            "first-commit-push",
            "first-commit-setup",
        )
    )
    return f'repos:\n  - repo: "{source}"\n    rev: "{revision}"\n    hooks:\n{hooks}'


class IdentityFileTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)

    def test_path_is_chosen_by_variable_then_xdg_then_home(self) -> None:
        self.assertEqual(
            Path("~/ids/me.json").expanduser(),
            identity_path(
                {"FIRST_COMMIT_IDENTITY_FILE": "~/ids/me.json", "HOME": "/h"}
            ),
        )
        self.assertEqual(
            Path("/x/first-commit/identity.json"),
            identity_path({"XDG_CONFIG_HOME": "/x", "HOME": "/h"}),
        )
        self.assertEqual(
            Path("/h/.config/first-commit/identity.json"),
            identity_path({"HOME": "/h"}),
        )

    def test_save_then_load_round_trips_with_owner_only_modes(self) -> None:
        path = self.home / "deep" / "identity.json"
        self.assertIsNone(load_identity(path))
        create_identity(path, PERSON)
        self.assertEqual(PERSON, load_identity(path))
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertEqual(0o700, path.parent.stat().st_mode & 0o777)
        with self.assertRaisesRegex(ContributorError, "could not be written"):
            create_identity(path, PERSON)

    def test_invalid_or_linked_identity_files_name_the_file(self) -> None:
        path = self.home / "identity.json"
        path.write_text('{"name": "x"}\n', encoding="utf-8")
        with self.assertRaisesRegex(ContributorError, str(path)):
            load_identity(path)
        path.unlink()
        path.symlink_to(self.home / "other.json")
        with self.assertRaisesRegex(ContributorError, "regular file"):
            load_identity(path)

    def test_environment_needs_all_three_valid_values(self) -> None:
        self.assertIsNone(identity_from_environment({}))
        self.assertEqual(PERSON, identity_from_environment(VARIABLES))
        with self.assertRaisesRegex(ContributorError, "all three"):
            identity_from_environment({"FIRST_COMMIT_AUTHOR_NAME": PERSON.name})
        with self.assertRaisesRegex(ContributorError, "email is invalid"):
            identity_from_environment(
                {**VARIABLES, "FIRST_COMMIT_AUTHOR_EMAIL": "nope"}
            )

    def test_missing_message_names_the_file_command_and_variables(self) -> None:
        message = missing_identity_message(self.home / "identity.json")
        self.assertIn(str(self.home / "identity.json"), message)
        self.assertIn(SETUP_HOOK_COMMAND, message)
        self.assertIn("\nfix: ", message)
        for name in (*VARIABLES, "FIRST_COMMIT_IDENTITY_FILE"):
            self.assertIn(name, message)


class CloneRevisionTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, text: str) -> None:
        (self.root / ".pre-commit-config.yaml").write_text(text, encoding="utf-8")

    def test_revision_and_address_come_from_the_clone_config(self) -> None:
        for source in (HTTPS, SSH, HTTPS + ".git"):
            with self.subTest(source=source):
                self.write(hook_config(source))
                self.assertEqual(
                    (REVISION, source.removesuffix(".git")),
                    configured_source(self.root),
                )

    def test_missing_foreign_or_malformed_config_stops(self) -> None:
        with self.assertRaisesRegex(SetupError, "declares no first-commit hooks"):
            configured_source(self.root)
        self.write("repos:\n  - repo: local\n    hooks:\n      - id: other\n")
        with self.assertRaisesRegex(SetupError, "declares no first-commit hooks"):
            configured_source(self.root)
        self.write(hook_config("https://github.com/someone/else"))
        with self.assertRaisesRegex(SetupError, "conflicts"):
            configured_source(self.root)
        self.write("repos: [")
        with self.assertRaisesRegex(SetupError, "malformed"):
            configured_source(self.root)

    def test_a_foreign_source_names_the_approved_addresses_only(self) -> None:
        other = "https://token-canary" + "@" + "example.com/hooks"
        self.write(hook_config(other))
        with self.assertRaises(SetupError) as error:
            configured_source(self.root)
        self.assertIn(HTTPS, str(error.exception))
        self.assertIn(SSH, str(error.exception))
        self.assertNotIn("token-canary", str(error.exception))

    def test_a_tag_revision_asks_for_the_frozen_commit(self) -> None:
        self.write(hook_config(revision="v0.3.0"))
        with self.assertRaises(SetupError) as error:
            configured_source(self.root)
        self.assertIn("rev to v0.3.0", str(error.exception))
        self.assertIn("pre-commit autoupdate --freeze", str(error.exception))
        self.write(hook_config(revision="private-canary"))
        with self.assertRaises(SetupError) as error:
            configured_source(self.root)
        self.assertNotIn("private-canary", str(error.exception))
        self.assertIn("pre-commit autoupdate --freeze", str(error.exception))

    def test_a_frozen_revision_with_its_tag_comment_is_accepted(self) -> None:
        self.write(
            hook_config().replace(f'"{REVISION}"', f'"{REVISION}"  # frozen: v0.3.0')
        )
        self.assertEqual((REVISION, HTTPS), configured_source(self.root))


class HookSetupTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "clone"
        self.root.mkdir()
        initialize_repository(self.root)
        write_keys(self.root)
        (self.root / ".pre-commit-config.yaml").write_text(
            hook_config(), encoding="utf-8"
        )
        self.identity = Path(temporary.name) / "machine" / "identity.json"
        self.enterContext(
            patch.dict(os.environ, {"FIRST_COMMIT_IDENTITY_FILE": str(self.identity)})
        )
        self.setup = self.enterContext(
            patch.object(
                setup_cli, "setup_repository", return_value=("Verification: passed",)
            )
        )

    def run_hook(self) -> tuple[int, str, str]:
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = cli.main(("hook", "setup", "--root", str(self.root)))
        return code, output.getvalue(), error.getvalue()

    def test_no_identity_stops_with_the_exact_command(self) -> None:
        code, output, error = self.run_hook()
        self.assertEqual(2, code)
        self.assertEqual("", output)
        self.assertIn(str(self.identity), error)
        self.assertIn(SETUP_HOOK_COMMAND, error)
        self.setup.assert_not_called()
        self.assertFalse(self.identity.exists())

    def test_variables_set_up_the_clone_and_save_the_identity(self) -> None:
        with patch.dict(os.environ, VARIABLES):
            code, output, _ = self.run_hook()
        self.assertEqual(0, code)
        self.assertIn(f"Machine identity: saved to {self.identity}", output)
        self.assertIn("Verification: passed", output)
        self.assertEqual(PERSON, load_identity(self.identity))
        request = self.setup.call_args.args[1]
        self.assertEqual(
            (REVISION, "https", PERSON, True),
            (
                request.revision,
                request.transport,
                self.setup.call_args.kwargs["contributor"],
                request.confirmed,
            ),
        )

    def test_saved_identity_is_used_without_variables(self) -> None:
        create_identity(self.identity, PERSON)
        code, output, _ = self.run_hook()
        self.assertEqual(0, code)
        self.assertIn(f"Machine identity: retained {self.identity}", output)
        self.assertEqual(PERSON, self.setup.call_args.kwargs["contributor"])

    def test_clone_record_wins_over_the_machine_identity(self) -> None:
        other = Contributor("Other Person", "other@" + "example.org", "other.pub")
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        create_contributor(self.root, other)
        create_identity(self.identity, PERSON)
        code, _, _ = self.run_hook()
        self.assertEqual(0, code)
        self.assertEqual(other, self.setup.call_args.kwargs["contributor"])

    def test_ssh_address_selects_ssh_transport(self) -> None:
        (self.root / ".pre-commit-config.yaml").write_text(
            hook_config(SSH), encoding="utf-8"
        )
        create_identity(self.identity, PERSON)
        self.assertEqual(0, self.run_hook()[0])
        self.assertEqual("ssh", self.setup.call_args.args[1].transport)


class SetupRemembersIdentityTest(unittest.TestCase):
    def test_saved_once_then_retained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            with patch.dict(os.environ, {"FIRST_COMMIT_IDENTITY_FILE": str(path)}):
                self.assertEqual(
                    f"Machine identity: saved to {path}",
                    setup_cli.remember_identity(PERSON),
                )
                self.assertEqual(
                    f"Machine identity: retained {path}",
                    setup_cli.remember_identity(PERSON),
                )
            self.assertEqual(json.loads(path.read_text("utf-8"))["email"], PERSON.email)


if __name__ == "__main__":
    unittest.main()
