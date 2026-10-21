import argparse
import re
from collections.abc import Sequence
from typing import NoReturn

from first_commit import __version__
from first_commit.models import EXIT_CODE_MEANINGS

PROGRAM = "first-commit"
VERSION_HELP = "Print the installed first-commit version."
ARGUMENT_PROBLEM = re.compile(r"argument (?P<name>[^:]+): (?P<problem>.*)", re.DOTALL)
CHOICES = re.compile(
    r"invalid choice: .*\(choose from (?P<choices>[^()]*)\)$", re.DOTALL
)
REQUIRED = "the following arguments are required: "
FORMAT_HELP = "Output: human text, or one JSON object (default: human)."
CHECK_ROOT_HELP = "A folder inside the Git repository (default: the current folder)."
SETUP_ROOT_HELP = (
    "The project folder; setup creates a Git repository there when it has none "
    "(default: the current folder)."
)
EXIT_CODES = "Exit codes: " + "; ".join(
    f"{int(code)} {meaning}" for code, meaning in EXIT_CODE_MEANINGS.items()
)


class ArgumentError(ValueError):
    pass


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
        f"fix: run `{prog} --help` for the accepted arguments."
    )


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _argument_error(self.prog, detail(self.prog, message))


def _command(
    commands: "argparse._SubParsersAction[Parser]", name: str, description: str
) -> Parser:
    return commands.add_parser(
        name, help=description, description=description, allow_abbrev=False
    )


def _common(parser: argparse.ArgumentParser, root_help: str = CHECK_ROOT_HELP) -> None:
    parser.add_argument("--root", metavar="FOLDER", default=None, help=root_help)
    parser.add_argument(
        "--format", choices=("human", "json"), default="human", help=FORMAT_HELP
    )


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
            "Check readiness, the working tree, staged bytes, and the commits a "
            "push sends.",
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
        "messages, and pushes for secrets and private data. Only setup writes.",
        epilog=EXIT_CODES + ".",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version", action="version", version=__version__, help=VERSION_HELP
    )
    commands = parser.add_subparsers(
        dest="command", metavar="COMMAND", required=True, parser_class=Parser
    )
    _command(commands, "version", VERSION_HELP)
    _common(
        _command(
            commands,
            "check",
            "Run the doctor, working-tree, staged, and history checks (read-only).",
        )
    )
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
    return parser


def parse(arguments: Sequence[str]) -> argparse.Namespace:
    options, unaccepted = build_parser().parse_known_args(arguments)
    if unaccepted:
        words = (PROGRAM, options.command, getattr(options, "stage", None))
        prog = " ".join(word for word in words if word)
        # The position is known only when the extra word appears once.
        if list(arguments).count(unaccepted[0]) == 1:
            which = f"argument {list(arguments).index(unaccepted[0]) + 1}"
        else:
            which = "one of its arguments"
        raise _argument_error(prog, f"`{prog}` does not accept {which}")
    return options
