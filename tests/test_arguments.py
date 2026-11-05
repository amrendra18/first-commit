import argparse
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import __version__, arguments, cli
from first_commit.arguments import ArgumentError, build_parser, json_requested, parse
from first_commit.models import EXIT_CODE_MEANINGS, ExitCode

CANARY = "private-argument-canary"
HELP_FLAG = re.compile(r"(?<![\w-])--?[A-Za-z][\w-]*")
READS = "reads"
CHECKS = "reads, writes own state"
SETS_UP = "writes repository, writes own state, network github.com, network pypi.org"
STAGES = ("pre-commit", "commit-msg", "pre-push", "setup")
# Each verb, with the effects and exit codes contract 3.1 and 2.5 give it.
VERB_HELP = {
    ("version",): (READS, [0, 1, 2]),
    ("check",): (CHECKS, [0, 1, 2]),
    ("doctor",): (READS, [0, 1, 2]),
    ("setup",): (SETS_UP, [0, 1, 2, 5]),
    ("help",): (READS, [0, 1, 2]),
    ("hook", "pre-commit"): (CHECKS, [0, 1, 2]),
    ("hook", "commit-msg"): (CHECKS, [0, 1, 2]),
    ("hook", "pre-push"): (CHECKS, [0, 1, 2]),
    ("hook", "setup"): (SETS_UP, [0, 1, 2]),
}
TOP_VERBS = ["version", "check", "doctor", "setup", "hook", "help"]


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


def _run(*words: str) -> tuple[int, str, str]:
    output, error = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(error):
        code = cli.main(words)
    return code, output.getvalue(), error.getvalue()


# The last two paragraphs of a help text: the Writes, Before, and Effects lines, each
# with its wrapped lines joined, and the codes the Exit codes paragraph names.
def _fields(text: str) -> tuple[dict[str, str], list[int]]:
    *_, lines, codes = text.rstrip().split("\n\n")
    fields: dict[str, str] = {}
    for line in re.split(r"\n(?! )", lines):
        name, _, value = line.partition(": ")
        fields[name] = " ".join(value.split())
    joined = " ".join(codes.split())
    if not joined.startswith("Exit codes: "):
        raise AssertionError(f"no Exit codes paragraph at the end: {joined}")
    return fields, [int(code) for code in re.findall(r"(?:: |; )(\d+) ", joined)]


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
        self.assertEqual(11, len(parsers))
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
        for command in TOP_VERBS:
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

    def test_an_unaccepted_flag_lists_every_flag_the_verbs_help_shows(self) -> None:
        for words in (
            ("version",),
            ("help",),
            ("check",),
            ("doctor",),
            ("setup",),
            ("hook", "pre-commit"),
            ("hook", "commit-msg", "message.txt"),
            ("hook", "pre-push"),
            ("hook", "setup"),
        ):
            with self.subTest(words=words):
                verb = words[:2] if words[0] == "hook" else words[:1]
                shown = HELP_FLAG.findall(_help(*verb))
                error = _error(*words, "--no-such-flag")
                listed = error.split("; it accepts ", 1)[1].split(".\n", 1)[0]
                self.assertEqual(sorted(set(shown)), sorted(listed.split(", ")))
                self.assertNotIn("no-such-flag", error)

    def test_an_unknown_verb_still_lists_the_verbs(self) -> None:
        error = _error("no-such-verb", "--format", "json")
        self.assertIn("must be one of version, check, doctor, setup, hook", error)

    def test_json_is_read_from_the_format_option_before_parsing(self) -> None:
        for words, expected in (
            (("check", "--format", "json"), True),
            (("check", "--format=json"), True),
            (("no-such-verb", "--format", "json"), True),
            (("check", "--format", "json", "--format", "human"), False),
            (("check",), False),
            (("check", "--format"), False),
            (("hook", "commit-msg", "json"), False),
            (("check", "--root", "json"), False),
            (("hook", "commit-msg", "--", "--format", "json"), False),
        ):
            with self.subTest(words=words):
                self.assertEqual(expected, json_requested(words))

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
        self.assertEqual([0, 1, 2, 5], [int(code) for code in ExitCode])
        self.assertEqual(list(ExitCode), list(EXIT_CODE_MEANINGS))

    def test_the_help_states_the_four_exit_codes_in_plain_words(self) -> None:
        self.assertIn(
            "Exit codes: 0 done; 1 a finding or not done (read the error); 2 bad call "
            "(unknown verb or flag, invalid or missing input); 5 held for a "
            "person's yes.",
            " ".join(_help().split()),
        )


class VerbHelpTest(unittest.TestCase):
    def test_each_verb_help_ends_with_writes_before_effects_and_exit_codes(
        self,
    ) -> None:
        for words, (effects, codes) in VERB_HELP.items():
            with self.subTest(words=words):
                fields, named = _fields(_help(*words))
                self.assertEqual(["Writes", "Before", "Effects"], list(fields))
                self.assertTrue(fields["Writes"] and fields["Before"])
                self.assertEqual(effects, fields["Effects"])
                self.assertEqual(codes, named)

    def test_an_effects_line_stays_whole_in_a_narrow_terminal(self) -> None:
        with patch.dict(os.environ, {"COLUMNS": "40"}):
            text = _help("setup")
        self.assertIn(f"\nEffects: {SETS_UP}\n", text)

    def test_the_exit_codes_name_each_meaning_in_plain_words(self) -> None:
        text = " ".join(_help("setup").split())
        meanings = "; ".join(
            f"{int(code)} {meaning}" for code, meaning in EXIT_CODE_MEANINGS.items()
        )
        self.assertIn(f"Exit codes: {meanings}.", text)

    def test_read_only_verbs_write_nothing(self) -> None:
        for words in (("version",), ("help",)):
            with self.subTest(words=words):
                self.assertEqual("nothing.", _fields(_help(*words))[0]["Writes"])
        writes = _fields(_help("doctor"))[0]["Writes"]
        self.assertTrue(writes.startswith("nothing in the repository"), writes)
        self.assertIn("private temporary folder, removed on exit", writes)

    def test_writes_prose_names_caches_and_temporary_folders_outside_effects(
        self,
    ) -> None:
        for words in (("check",), *(("hook", stage) for stage in STAGES[:3])):
            with self.subTest(words=words):
                writes = _fields(_help(*words))[0]["Writes"]
                self.assertIn("~/.config/first-commit/private-values.txt", writes)
                self.assertIn("private temporary folder, removed on exit", writes)
        for words in (("setup",), ("hook", "setup")):
            with self.subTest(words=words):
                writes = _fields(_help(*words))[0]["Writes"]
                self.assertIn("<repository>/.local/first-commit/", writes)
                self.assertIn("~/.config/first-commit/identity.json", writes)
                self.assertIn("~/.cache/pre-commit/", writes)

    def test_the_hook_group_names_the_effects_of_each_stage(self) -> None:
        text = _help("hook")
        fields, codes = _fields(text)
        self.assertEqual([0, 1, 2], codes)
        self.assertTrue(fields["Writes"] and fields["Before"])
        for stage in STAGES:
            effects = VERB_HELP["hook", stage][0]
            with self.subTest(stage=stage):
                self.assertIn(f"\nhook {stage}\n  Effects: {effects}\n", text)


class HelpVerbTest(unittest.TestCase):
    def test_help_prints_the_top_help(self) -> None:
        self.assertEqual((0, _help(), ""), _run("help"))

    def test_help_json_lists_the_verbs_and_the_fields_each_help_shows(self) -> None:
        code, output, _ = _run("help", "--format", "json")
        self.assertEqual(0, code)
        value = json.loads(output)
        self.assertEqual({"verbs", "commands"}, set(value))
        self.assertEqual(TOP_VERBS, value["verbs"])
        commands = value["commands"]
        self.assertEqual(
            {*TOP_VERBS, *(f"hook {stage}" for stage in STAGES)}, set(commands)
        )
        for words, (effects, codes) in VERB_HELP.items():
            with self.subTest(words=words):
                entry = commands[" ".join(words)]
                text = _help(*words)
                fields, _ = _fields(text)
                self.assertEqual(effects, ", ".join(entry["effects"]))
                self.assertEqual(codes, [int(code) for code in entry["exit_codes"]])
                self.assertEqual(fields["Writes"], entry["writes"])
                self.assertEqual(fields["Before"], entry["before"])
                self.assertIn(entry["description"], " ".join(text.split()))
                shown = set(HELP_FLAG.findall(text))
                listed = {
                    word
                    for option in entry["options"]
                    for word in HELP_FLAG.findall(option["argument"])
                }
                self.assertEqual(shown, listed)

    def test_the_hook_entry_holds_what_its_stages_may_do(self) -> None:
        entry = json.loads(_run("help", "--format", "json")[1])["commands"]["hook"]
        self.assertEqual(
            [
                "reads",
                "writes own state",
                "writes repository",
                "network github.com",
                "network pypi.org",
            ],
            entry["effects"],
        )

    def test_help_markdown_has_front_matter_and_every_command(self) -> None:
        code, output, _ = _run("help", "--format", "markdown")
        self.assertEqual(0, code)
        match = re.fullmatch(
            r"---\n(name: first-commit\ndescription: [^\n]+\.)\n---\n\n(.*)",
            output,
            re.DOTALL,
        )
        self.assertIsNotNone(match, output[:200])
        front, body = match.groups() if match else ("", "")
        self.assertEqual(1, front.count(". ") + 1)
        commands = json.loads(_run("help", "--format", "json")[1])["commands"]
        headings = re.findall(r"^## first-commit (.+)$", body, re.MULTILINE)
        self.assertEqual(sorted(commands), sorted(headings))
        for name, entry in commands.items():
            with self.subTest(name=name):
                self.assertIn(entry["description"], body)
        for effects, _ in VERB_HELP.values():
            self.assertIn(f"- Effects: {effects}\n", body)
        named = set(
            re.findall(r"(?:^## |`)first-commit ([a-z-]+)", output, re.MULTILINE)
        )
        self.assertLessEqual(named, {*TOP_VERBS, *STAGES})
        self.assertNotIn(str(Path.home()), output)

    def test_help_and_version_read_no_state_and_start_no_process(self) -> None:
        for words in (
            ("help",),
            ("help", "--format", "json"),
            ("help", "--format", "markdown"),
            ("--version", "--format", "json"),
            ("version", "--format", "json"),
        ):
            with (
                self.subTest(words=words),
                tempfile.TemporaryDirectory() as state,
                patch.dict(os.environ, {"XDG_CONFIG_HOME": state}),
                patch("subprocess.Popen", side_effect=AssertionError("a process")),
            ):
                self.assertEqual(0, _run(*words)[0])
                self.assertEqual([], list(Path(state).iterdir()))


class VersionTest(unittest.TestCase):
    def test_version_json_names_the_version_and_the_installed_revision(self) -> None:
        for revision in ("c" * 40, None):
            for words in (
                ("--version", "--format", "json"),
                ("version", "--format=json"),
            ):
                with (
                    self.subTest(words=words, revision=revision),
                    patch(
                        "first_commit.hooks.installed_revision", return_value=revision
                    ),
                ):
                    code, output, _ = _run(*words)
                self.assertEqual(0, code)
                self.assertEqual(
                    {"version": __version__, "revision": revision, "modified": None},
                    json.loads(output),
                )
                self.assertEqual(1, len(output.splitlines()))

    def test_version_in_human_form_is_one_line(self) -> None:
        for words in (("--version",), ("--version", "--format", "human")):
            with self.subTest(words=words):
                self.assertEqual((0, f"{__version__}\n", ""), _run(*words))

    def test_the_version_option_refuses_other_arguments(self) -> None:
        for words in (
            ("--version", "--format", "xml"),
            ("--version", "check"),
            ("--version", "--root", "."),
        ):
            with self.subTest(words=words):
                code, output, error = _run(*words)
                self.assertEqual((ExitCode.INPUT, ""), (code, output))
                self.assertIn("run `first-commit --help`", error)
        for words in (("--version", "check"), ("--version", "--root", ".")):
            with self.subTest(words=words):
                _, _, error = _run(*words)
                self.assertIn(
                    "`first-commit --version` does not accept argument 2; it accepts "
                    "--format",
                    error,
                )
        code, output, _ = _run("--version", CANARY, "--format", "json")
        self.assertEqual(ExitCode.INPUT, code)
        error_object = json.loads(output)["error"]
        self.assertEqual("invalid-arguments", error_object["code"])
        # The next command must itself run: the top help, never `--version --help`.
        self.assertEqual(1, len(error_object["next"]))
        self.assertTrue(error_object["next"][0].endswith("first-commit --help"))
        self.assertNotIn(CANARY, output)


if __name__ == "__main__":
    unittest.main()
