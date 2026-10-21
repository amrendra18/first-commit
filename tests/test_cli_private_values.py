import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import cli
from first_commit.models import Result
from first_commit.policy import REQUIRED_DOCUMENTS
from tests.cli_support import CliFixture
from tests.support import run_git

CANARY = "synthetic-cli-private-canary"
RULE = "privacy.private-literal"


class PrivateValuesCliTest(CliFixture):
    def setUp(self) -> None:
        super().setUp()
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        for name in REQUIRED_DOCUMENTS:
            (self.root / name).write_text("# Reviewed\n", encoding="utf-8")
        self.private = self.root / ".local/first-commit/private-values.txt"
        self.private.parent.mkdir(parents=True)
        self.private.write_text(CANARY + "\n", encoding="utf-8")
        self.private.chmod(0o600)
        (self.root / "notes.txt").write_text(f"written by {CANARY}\n", "utf-8")
        run_git(self.root, "add", "--", ".gitignore", *REQUIRED_DOCUMENTS, "notes.txt")

    def run_without_scanner(self, *arguments: str) -> tuple[int, str, str]:
        passed = Result("test", ())
        with (
            patch("first_commit.validation.doctor", return_value=passed),
            patch("first_commit.validation.history", return_value=passed),
            patch("first_commit.validation.scan_staged", return_value=[]),
        ):
            return self.run_cli(*arguments)

    def test_each_command_blocks_a_private_value_in_every_scope_it_checks(
        self,
    ) -> None:
        for arguments, scopes in (
            (("check",), {"working", "staged"}),
            (("hook", "pre-commit"), {"staged"}),
            (("hook", "pre-push"), {"working", "staged"}),
        ):
            with self.subTest(command=" ".join(arguments)):
                code, output, error = self.run_without_scanner(*arguments)
                self.assertEqual(1, code, output + error)
                self.assertIn(RULE, output)
                self.assertNotIn(CANARY, output + error)
                code, output, error = self.run_without_scanner(
                    *arguments, "--format", "json"
                )
                self.assertEqual((1, ""), (code, error))
                self.assertNotIn(CANARY, output)
                found = {
                    check["name"]
                    for check in json.loads(output)["checks"]
                    if any(item["rule_id"] == RULE for item in check["findings"])
                }
                self.assertEqual(scopes, found)

    def check_from_a_subfolder(self, *arguments: str) -> tuple[int, str]:
        subfolder = self.root / "docs"
        subfolder.mkdir(exist_ok=True)
        previous = Path.cwd()
        os.chdir(subfolder)
        self.addCleanup(os.chdir, previous)
        output = io.StringIO()
        passed = Result("test", ())
        with (
            redirect_stdout(output),
            patch("first_commit.validation.doctor", return_value=passed),
            patch("first_commit.validation.history", return_value=passed),
            patch("first_commit.validation.scan_staged", return_value=[]),
        ):
            code = cli.main(("check", *arguments))
        return code, output.getvalue()

    def test_the_repository_path_hides_a_private_value(self) -> None:
        folder = self.root.name
        self.private.write_text(f"{CANARY}\n{folder}\n", encoding="utf-8")
        code, output = self.check_from_a_subfolder()
        self.assertEqual(1, code)
        self.assertTrue(output.startswith("Repository: "), output)
        self.assertIn("<private value>", output.splitlines()[0])
        self.assertNotIn(folder.casefold(), output.casefold())
        code, output = self.check_from_a_subfolder("--format", "json")
        self.assertEqual(1, code)
        repository = json.loads(output)["repository"]
        self.assertIn("<private value>", repository)
        self.assertNotIn(folder.casefold(), repository.casefold())

    def test_a_refused_program_is_named_inside_the_repository(self) -> None:
        program = self.root / "bin/git"
        program.parent.mkdir()
        program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        program.chmod(0o755)
        search = os.pathsep.join((str(program.parent), os.environ["PATH"]))
        with patch.dict(os.environ, {"PATH": search}):
            code, _, error = self.run_cli("check")
        self.assertEqual(4, code)
        self.assertIn("Git on PATH is bin/git inside this repository", error)
        self.assertNotIn(self.root.name.casefold(), error.casefold())

    def test_a_refused_scanner_error_hides_a_private_value(self) -> None:
        program = self.root / f"tools-{CANARY}/gitleaks"
        program.parent.mkdir()
        program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        program.chmod(0o755)
        search = os.pathsep.join((str(program.parent), os.environ["PATH"]))
        for arguments in (
            ("check",),
            ("check", "--format", "json"),
            ("hook", "pre-commit"),
        ):
            with (
                self.subTest(command=" ".join(arguments)),
                patch.dict(os.environ, {"PATH": search}),
            ):
                code, output, error = self.run_cli(*arguments)
                self.assertEqual(3, code, output + error)
                self.assertIn(
                    "Gitleaks on PATH is tools-<private value>/gitleaks", error
                )
                self.assertNotIn(CANARY, output + error)
