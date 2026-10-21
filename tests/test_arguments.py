import argparse
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from first_commit import __version__, arguments, cli
from first_commit.arguments import ArgumentError, build_parser, parse
from first_commit.models import EXIT_CODE_MEANINGS, ExitCode

CANARY = "private-argument-canary"


# argparse has no public way to list a parser's options and subcommands, so only this
# function reads its private fields.
def _parsers_and_actions(
    parser: argparse.ArgumentParser,
) -> list[tuple[argparse.ArgumentParser, list[argparse.Action]]]:
    actions: list[argparse.Action] = []
    found = [(parser, actions)]
    for action in parser._actions:  # noqa: SLF001 - argparse internals, see above
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001 - see above
            actions.extend(action._choices_actions)  # noqa: SLF001 - see above
            for child in action.choices.values():
                found.extend(_parsers_and_actions(child))
        else:
            actions.append(action)
    return found


def _help(*words: str) -> str:
    output = io.StringIO()
    with redirect_stdout(output), redirect_stderr(io.StringIO()):
        try:
            cli.main((*words, "--help"))
        except SystemExit as stop:
            if stop.code != 0:
                raise
    return output.getvalue()


def _error(*words: str) -> str:
    with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
        try:
            parse(words)
        except ArgumentError as error:
            return str(error)
    raise AssertionError(f"no argument error for {words}")


class HelpTest(unittest.TestCase):
    def test_every_command_and_option_has_a_description(self) -> None:
        parsers = _parsers_and_actions(build_parser())
        self.assertEqual(10, len(parsers))
        for parser, actions in parsers:
            with self.subTest(parser=parser.prog):
                self.assertTrue(parser.description, parser.prog)
                for action in actions:
                    self.assertTrue(action.help, action.dest)
                    self.assertNotEqual(argparse.SUPPRESS, action.help)

    def test_root_is_documented_for_every_command_that_takes_it(self) -> None:
        for words in (
            ("check",),
            ("doctor",),
            ("setup",),
            ("hook", "pre-commit"),
            ("hook", "commit-msg"),
            ("hook", "pre-push"),
            ("hook", "setup"),
        ):
            with self.subTest(words=words):
                text = " ".join(_help(*words).split())
                self.assertIn("--root FOLDER", text)
                self.assertIn("(default: the current folder)", text)

    def test_top_level_help_lists_commands_and_the_exit_code_map(self) -> None:
        text = " ".join(_help().split())
        for command in ("version", "check", "doctor", "setup", "hook"):
            self.assertIn(command, text)
        for code, meaning in EXIT_CODE_MEANINGS.items():
            self.assertIn(f"{int(code)} {' '.join(meaning.split())}", text)

    def test_setup_help_names_each_choice_and_default(self) -> None:
        text = " ".join(_help("setup").split())
        for detail in (
            "--dry-run",
            "--yes",
            "--trust-self",
            "--revision SHA",
            "{ssh,https}",
            "{none,apache-2.0}",
            "{core,full}",
        ):
            self.assertIn(detail, text)

    def test_setup_help_says_the_ssh_address_needs_a_github_ssh_key(self) -> None:
        text = " ".join(_help("setup").split())
        self.assertIn("The SSH address needs a GitHub SSH key.", text)
        self.assertNotIn("can read", text)

    def test_the_version_option_prints_what_the_version_command_prints(self) -> None:
        printed = {}
        for word in ("version", "--version"):
            code: int | str | None
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                try:
                    code = cli.main((word,))
                except SystemExit as stop:
                    code = stop.code
            self.assertEqual(0, code, word)
            printed[word] = output.getvalue()
        self.assertEqual(f"{__version__}\n", printed["version"])
        self.assertEqual(printed["version"], printed["--version"])


class ArgumentErrorTest(unittest.TestCase):
    def test_bad_choice_names_the_option_and_its_choices_without_the_value(
        self,
    ) -> None:
        for words, expected in (
            (("setup", "--docs", CANARY), "`--docs` must be one of core, full"),
            (("check", "--format", CANARY), "`--format` must be one of human, json"),
            (("hook", CANARY), "`STAGE` must be one of pre-commit, commit-msg"),
            ((CANARY,), "`COMMAND` must be one of version, check, doctor"),
        ):
            with self.subTest(words=words):
                error = _error(*words)
                self.assertIn("Invalid command arguments:", error)
                self.assertIn(expected, error)
                self.assertNotIn(CANARY, error)

    def test_missing_value_and_missing_argument_are_named(self) -> None:
        for words, expected, command in (
            (("check", "--root"), "`--root` needs a value", "first-commit check"),
            (("hook", "commit-msg"), "needs MESSAGE_FILE", "first-commit hook"),
            ((), "needs COMMAND", "first-commit"),
            (("hook",), "needs STAGE", "first-commit hook"),
        ):
            with self.subTest(words=words):
                error = _error(*words)
                self.assertIn(expected, error)
                self.assertIn(f"run `{command}", error)

    def test_unaccepted_arguments_are_named_by_position_only(self) -> None:
        for words, expected in (
            (
                ("check", "--" + CANARY),
                "`first-commit check` does not accept argument 2",
            ),
            (("check", CANARY), "`first-commit check` does not accept argument 2"),
            (
                ("hook", "pre-push", "--root", ".", CANARY),
                "`first-commit hook pre-push` does not accept argument 5",
            ),
            (("check", "--form", "json"), "does not accept argument 2"),
            (("version", CANARY), "`first-commit version` does not accept argument 2"),
            (
                ("check", "--root", CANARY, CANARY),
                "`first-commit check` does not accept one of its arguments",
            ),
        ):
            with self.subTest(words=words):
                error = _error(*words)
                self.assertIn(expected, error)
                self.assertNotIn(CANARY, error)

    def test_other_argument_problems_never_echo_the_typed_value(self) -> None:
        error = _error("setup", "--yes=" + CANARY)
        self.assertIn("`--yes` takes no value", error)
        self.assertNotIn(CANARY, error)
        self.assertEqual(
            "`--root` has an invalid value",
            arguments.detail("first-commit", "argument --root: odd " + CANARY),
        )
        self.assertEqual(
            "`first-commit` was given arguments it does not accept",
            arguments.detail("first-commit", "unknown problem " + CANARY),
        )

    def test_argument_errors_exit_with_the_input_code(self) -> None:
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = cli.main(("setup", "--docs", CANARY))
        self.assertEqual((ExitCode.INPUT, ""), (code, output.getvalue()))
        self.assertTrue(error.getvalue().startswith("error: Invalid command"))


class ExitCodeTest(unittest.TestCase):
    def test_exit_codes_are_the_documented_integers(self) -> None:
        self.assertEqual([0, 1, 2, 3, 4], [int(code) for code in ExitCode])
        self.assertEqual(list(ExitCode), list(EXIT_CODE_MEANINGS))


if __name__ == "__main__":
    unittest.main()
