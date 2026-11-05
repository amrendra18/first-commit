import argparse
import re
from collections.abc import Sequence
from typing import NoReturn

from first_commit.help_text import (
    Formatter,
    epilog,
    exit_codes,
    option_actions,
    subcommands,
)
from first_commit.models import ExitCode

PROGRAM = "first-commit"
VERSION_HELP = "Print the installed first-commit version."
HELP_HELP = "Print the help, or all of it as JSON or Markdown."
ARGUMENT_PROBLEM = re.compile(r"argument (?P<name>[^:]+): (?P<problem>.*)", re.DOTALL)
CHOICES = re.compile(
    r"invalid choice: .*\(choose from (?P<choices>[^()]*)\)$", re.DOTALL
)
REQUIRED = "the following arguments are required: "
FORMAT_HELP = "Output: human text, or one JSON object (default: human)."
HELP_FORMAT_HELP = (
    "Output: human text, one JSON object, or Markdown with front matter "
    "(default: human)."
)
NEW_ONLY_HELP = (
    "Limit the history check to commits no configured remote holds, as its "
    "remote-tracking branches show (with no remote, the whole history)."
)
CHECK_ROOT_HELP = "A folder inside the Git repository (default: the current folder)."
SETUP_ROOT_HELP = (
    "The project folder; setup creates a Git repository there when it has none "
    "(default: the current folder)."
)


# prog names the command whose help lists the accepted arguments.
class ArgumentError(ValueError):
    def __init__(self, message: str, prog: str = PROGRAM) -> None:
        super().__init__(message)
        self.prog = prog


# Read before parsing, so a call that fails to parse still answers in JSON. Only the
# --format option counts, never a positional value that happens to be json; the last
# one wins, as in argparse.
def json_requested(arguments: Sequence[str]) -> bool:
    words = list(arguments)
    chosen = None
    for index, word in enumerate(words):
        if word == "--":
            break
        if word.startswith("--format="):
            chosen = word.removeprefix("--format=")
        elif word == "--format" and index + 1 < len(words):
            chosen = words[index + 1]
    return chosen == "json"


# Names only declared options and choices: a typed value may be private.
def detail(prog: str, message: str) -> str:
    if message.startswith(REQUIRED):
        return f"`{prog}` needs {message.removeprefix(REQUIRED)}"
    match = ARGUMENT_PROBLEM.fullmatch(message)
    if match is None:
        return f"`{prog}` was given arguments it does not accept"
    name, problem = match["name"], match["problem"]
    if problem.startswith("ignored explicit argument"):
        return f"`{name}` takes no value"
    if problem == "expected one argument":
        return f"`{name}` needs a value"
    choices = CHOICES.fullmatch(problem)
    if choices is not None:
        allowed = choices["choices"].replace("'", "")
        return f"`{name}` must be one of {allowed}"
    return f"`{name}` has an invalid value"


def _argument_error(prog: str, problem: str) -> ArgumentError:
    return ArgumentError(
        f"Invalid command arguments: {problem}.\n"
        f"fix: run `{prog} --help` for the accepted arguments.",
        prog,
    )


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _argument_error(self.prog, detail(self.prog, message))


# The epilog comes from help_text.HELP, under the words after the program name.
def _command(
    commands: "argparse._SubParsersAction[Parser]", name: str, description: str
) -> Parser:
    parser: Parser = commands.add_parser(
        name,
        help=description,
        description=description,
        allow_abbrev=False,
        formatter_class=Formatter,
    )
    parser.epilog = epilog(parser.prog.removeprefix(f"{PROGRAM} "))
    return parser


def _format(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format", choices=("human", "json"), default="human", help=FORMAT_HELP
    )


def _common(parser: argparse.ArgumentParser, root_help: str = CHECK_ROOT_HELP) -> None:
    parser.add_argument("--root", metavar="FOLDER", default=None, help=root_help)
    _format(parser)


def _setup_options(setup: Parser) -> None:
    _common(setup, SETUP_ROOT_HELP)
    setup.add_argument(
        "--revision",
        metavar="SHA",
        default=None,
        help="The 40-character commit the hooks pin (default: the commit this "
        "install was built from, or the rev in an existing .pre-commit-config.yaml).",
    )
    setup.add_argument(
        "--transport",
        choices=("ssh", "https"),
        default=None,
        help="The address new hooks use (default: https). The SSH address needs a "
        "GitHub SSH key.",
    )
    setup.add_argument(
        "--hooks",
        choices=("pinned", "installed"),
        default="pinned",
        help="pinned: hooks from the first-commit repository at one commit, which "
        "pre-commit installs; installed: hooks that run the first-commit command on "
        "PATH, with no --revision or --transport (default: pinned).",
    )
    setup.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the plan only: write, fetch, and run nothing.",
    )
    setup.add_argument(
        "--license",
        choices=("none", "apache-2.0"),
        default="none",
        help="The license file to create (default: none).",
    )
    setup.add_argument(
        "--docs",
        choices=("core", "full"),
        default="core",
        help="core creates README.md and AGENTS.md; full adds PRD.md, "
        "CONTRIBUTING.md, and SECURITY.md (default: core).",
    )
    setup.add_argument(
        "--trust-self",
        action="store_true",
        help="Trust your own signing key in this checkout: write "
        ".local/first-commit/allowed-signers and set gpg.ssh.allowedSignersFile.",
    )
    setup.add_argument(
        "--yes",
        action="store_true",
        help="Apply the plan without asking first.",
    )


def _hook_stages(hook: Parser) -> None:
    stages = hook.add_subparsers(
        dest="stage", metavar="STAGE", required=True, parser_class=Parser
    )
    _common(_command(stages, "pre-commit", "Check the staged bytes."))
    message = _command(
        stages, "commit-msg", "Check the commit message that MESSAGE_FILE holds."
    )
    message.add_argument(
        "message_file",
        metavar="MESSAGE_FILE",
        help="The file Git passes to the commit-msg hook.",
    )
    _common(message)
    _common(
        _command(
            stages,
            "pre-push",
            "Check readiness and the commits a push sends.",
        )
    )
    _common(
        _command(
            stages,
            "setup",
            "Set up a clone from its pinned hooks; pre-commit runs it at the manual "
            "stage.",
        )
    )


def build_parser() -> Parser:
    parser = Parser(
        prog=PROGRAM,
        description="Sets up a project once, then checks staged bytes, commit "
        "messages, and pushes for secrets and private data. Only setup writes in a "
        "project.",
        epilog=exit_codes(tuple(ExitCode)),
        allow_abbrev=False,
        formatter_class=Formatter,
    )
    # parse answers --version before this parser runs; the option is here for the help.
    parser.add_argument("--version", action="store_true", help=VERSION_HELP)
    commands = parser.add_subparsers(
        dest="command", metavar="COMMAND", required=True, parser_class=Parser
    )
    _format(_command(commands, "version", VERSION_HELP))
    check = _command(
        commands,
        "check",
        "Run the doctor, working-tree, staged, and history checks (read-only).",
    )
    _common(check)
    check.add_argument("--new-only", action="store_true", help=NEW_ONLY_HELP)
    _common(
        _command(
            commands,
            "doctor",
            "Check the local identity, signing, hooks, and scanner (read-only).",
        )
    )
    _setup_options(
        _command(
            commands,
            "setup",
            "Preview or apply the one-time setup: files, Git settings, hooks, and "
            "Gitleaks.",
        )
    )
    _hook_stages(
        _command(
            commands,
            "hook",
            "Entry points the installed Git hooks run; not for direct use.",
        )
    )
    _command(commands, "help", HELP_HELP).add_argument(
        "--format",
        choices=("human", "json", "markdown"),
        default="human",
        help=HELP_FORMAT_HELP,
    )
    return parser


# --version takes only --format, so it needs no verb.
def _version_parser() -> Parser:
    parser = Parser(prog=PROGRAM, add_help=False, allow_abbrev=False)
    parser.add_argument("--version", action="store_true")
    _format(parser)
    parser.set_defaults(command="version")
    return parser


def _accepted_flags(parser: argparse.ArgumentParser, verbs: Sequence[str]) -> str:
    for verb in verbs:
        parser = subcommands(parser)[verb]
    return ", ".join(
        option for action in option_actions(parser) for option in action.option_strings
    )


# prog names the command whose help lists the flags; name is what the call ran.
def _unaccepted(
    prog: str, name: str, arguments: Sequence[str], extra: str, flags: str
) -> ArgumentError:
    # The position is known only when the extra word appears once.
    if list(arguments).count(extra) == 1:
        which = f"argument {list(arguments).index(extra) + 1}"
    else:
        which = "one of its arguments"
    return _argument_error(
        prog, f"`{name}` does not accept {which}; it accepts {flags}"
    )


def parse(arguments: Sequence[str]) -> argparse.Namespace:
    if list(arguments)[:1] == ["--version"]:
        options, unaccepted = _version_parser().parse_known_args(arguments)
        if unaccepted:
            name = f"{PROGRAM} --version"
            raise _unaccepted(PROGRAM, name, arguments, unaccepted[0], "--format")
        return options
    parser = build_parser()
    options, unaccepted = parser.parse_known_args(arguments)
    if unaccepted:
        verbs = [
            word for word in (options.command, getattr(options, "stage", None)) if word
        ]
        prog = " ".join((PROGRAM, *verbs))
        flags = _accepted_flags(parser, verbs)
        raise _unaccepted(prog, prog, arguments, unaccepted[0], flags)
    return options
