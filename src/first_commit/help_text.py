import argparse
import textwrap
from collections.abc import Iterator
from dataclasses import dataclass, replace

from first_commit.models import EXIT_CODE_MEANINGS, ExitCode

SKILL_DESCRIPTION = (
    "Use first-commit when a Git project, new or existing, needs its hooks, signing, "
    "and starter files, or when staged files, commit messages, or pushes need a check for secrets "
    "and private data before they leave the machine."
)
# The skill prints these for an agent that adopts first-commit in a project.
AGENT_RULES = (
    (
        "Preview first with `first-commit setup --dry-run`. Review each conflict and "
        "each `@no-commit` proposal by hand; never overwrite a project file to clear "
        "one."
    ),
    (
        "Run setup only when the user allows Git initialization, local Git settings, "
        "dependency installation, and hooks."
    ),
    "Setup writes each starter file once; the project owns it from then on.",
    "After setup, run `first-commit doctor` and `first-commit check`.",
    "Never stage, commit, change remotes, or publish without the user's permission.",
    (
        "`first-commit doctor` and `first-commit check` are read-only, except that "
        "check and the hooks remove group and other access from the user's "
        "private-values list when the user owns it."
    ),
    (
        "Keep the contributor identity in the ignored "
        "`.local/first-commit/contributor.json`."
    ),
    "Never read private-key contents or print matched private content.",
    "Put the project's own tests and builds in the project's own hooks.",
    "Never add a switch or setting that turns a check off.",
)
NOT_HELD = (ExitCode.PASSED, ExitCode.FINDING, ExitCode.INPUT)
CHECK_WRITES = (
    "nothing in the repository. It removes group and other access from "
    "~/.config/first-commit/private-values.txt (or the same file under "
    "$XDG_CONFIG_HOME) when you own that file. The scanner writes its report to a "
    "private temporary folder, removed on exit."
)
CHECK_BEFORE = (
    "a Git repository with a .repo-policy.json file, and Gitleaks 8.30.0 on PATH or "
    "at `<repository>/.local/bin/gitleaks`; setup prepares both."
)
SETUP_WRITES = (
    "the missing files in `<repository>/`, the --root folder, such as README.md, "
    "AGENTS.md, .gitignore, .pre-commit-config.yaml, and .repo-policy.json, or a "
    "`*.first-commit-proposal.md` beside a document you already have; "
    "`<repository>/.git/` (git init when it has none, local Git settings, and "
    "hooks); `<repository>/.local/first-commit/`; `<repository>/.local/bin/gitleaks` "
    "when no Gitleaks is found; and ~/.config/first-commit/identity.json (or the "
    "same file under $XDG_CONFIG_HOME) when it does not exist. pre-commit fills its "
    "cache, ~/.cache/pre-commit/. A Gitleaks download and the scanner use private "
    "temporary folders, removed on exit."
)
IDENTITY_SOURCES = (
    "`<repository>/.local/first-commit/contributor.json`, the identity file, or the "
    "FIRST_COMMIT_AUTHOR_NAME, FIRST_COMMIT_AUTHOR_EMAIL, and "
    "FIRST_COMMIT_SIGNING_KEY variables"
)
CHECKS = ("reads", "writes own state")
SETS_UP = (
    "writes repository",
    "writes own state",
    "network github.com",
    "network pypi.org",
)


@dataclass(frozen=True)
class VerbHelp:
    writes: str
    before: str
    effects: tuple[str, ...]
    codes: tuple[ExitCode, ...] = NOT_HELD


READ_ONLY = VerbHelp("nothing.", "nothing.", ("reads",))
# Keyed by the words after first-commit. A group, such as hook, may do whatever its
# stages do, so its effects come from theirs.
HELP = {
    "version": READ_ONLY,
    "check": VerbHelp(CHECK_WRITES, f"run it inside {CHECK_BEFORE}", CHECKS),
    "doctor": VerbHelp(
        "nothing in the repository or ~/.config/first-commit/. Its Gitleaks check runs "
        "in a private temporary folder, removed on exit.",
        "run it inside a Git repository that has a .repo-policy.json file.",
        ("reads",),
    ),
    "setup": VerbHelp(
        f"{SETUP_WRITES} --dry-run writes nothing.",
        "an identity (a public Git author name and email, and an SSH public key) from "
        f"{IDENTITY_SOURCES}, or typed in a terminal. Git and pre-commit 3.2.0 or "
        "newer on PATH, and network access. Without a terminal, --yes applies the "
        "plan.",
        SETS_UP,
        tuple(ExitCode),
    ),
    "hook": VerbHelp(
        "what the stage writes; first-commit hook STAGE --help names it.",
        "Git and pre-commit run these stages from the hooks setup installed.",
        (),
    ),
    "hook pre-commit": VerbHelp(
        CHECK_WRITES,
        f"Git runs it from the pre-commit hook, inside {CHECK_BEFORE}",
        CHECKS,
    ),
    "hook commit-msg": VerbHelp(
        CHECK_WRITES,
        "Git runs it from the commit-msg hook with MESSAGE_FILE, inside "
        + CHECK_BEFORE,
        CHECKS,
    ),
    "hook pre-push": VerbHelp(
        CHECK_WRITES,
        "pre-commit runs it from the pre-push hook and says what the push sends, "
        f"inside {CHECK_BEFORE}",
        CHECKS,
    ),
    "hook setup": VerbHelp(
        SETUP_WRITES,
        "a clone whose .pre-commit-config.yaml pins the first-commit hooks; "
        "pre-commit runs it from the first-commit-setup hook at the manual stage. "
        f"The identity comes from {IDENTITY_SOURCES}; it never asks. Network access.",
        SETS_UP,
    ),
    "help": READ_ONLY,
}


def _stages(path: str) -> list[str]:
    return [name for name in HELP if name.startswith(f"{path} ")]


def fields(path: str) -> VerbHelp:
    found = HELP[path]
    effects = (effect for stage in _stages(path) for effect in HELP[stage].effects)
    return replace(found, effects=found.effects or tuple(dict.fromkeys(effects)))


def exit_codes(codes: tuple[ExitCode, ...]) -> str:
    return (
        "Exit codes: "
        + "; ".join(f"{int(code)} {EXIT_CODE_MEANINGS[code]}" for code in codes)
        + "."
    )


def epilog(path: str) -> str:
    found = fields(path)
    lines = [f"Writes: {found.writes}", f"Before: {found.before}"]
    stages = _stages(path)
    for stage in stages:
        lines += [stage, f"  Effects: {', '.join(HELP[stage].effects)}"]
    if not stages:
        lines.append(f"Effects: {', '.join(found.effects)}")
    return "\n".join((*lines, "", exit_codes(found.codes)))


# Each line of a description or epilog wraps on its own, so the Writes:, Before:,
# Effects:, and Exit codes: lines keep their starts. An Effects: line never wraps: a
# reader takes the verb's effects from that one line.
class Formatter(argparse.HelpFormatter):
    def _fill_text(self, text: str, width: int, indent: str) -> str:
        return "\n".join(
            line
            if line.lstrip().startswith("Effects:")
            else textwrap.fill(
                line,
                width,
                initial_indent=indent,
                subsequent_indent=indent + "  ",
                break_long_words=False,
                break_on_hyphens=False,
            )
            for line in text.splitlines()
        )


# argparse has no public way to list a parser's options or subcommands, so only these
# two functions read its private fields.
def subcommands(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    return {
        name: child
        for action in parser._actions  # noqa: SLF001 - argparse internals, see above
        if isinstance(action, argparse._SubParsersAction)  # noqa: SLF001 - see above
        for name, child in action.choices.items()
    }


def option_actions(parser: argparse.ArgumentParser) -> list[argparse.Action]:
    return [
        action
        for action in parser._actions  # noqa: SLF001 - see above
        if not isinstance(action, argparse._SubParsersAction)  # noqa: SLF001
    ]


def _commands(
    parser: argparse.ArgumentParser, prefix: str = ""
) -> Iterator[tuple[str, argparse.ArgumentParser]]:
    for name, child in subcommands(parser).items():
        yield prefix + name, child
        yield from _commands(child, f"{prefix}{name} ")


def _argument(action: argparse.Action) -> str:
    if not action.option_strings:
        return str(action.metavar or action.dest)
    names = ", ".join(action.option_strings)
    if action.nargs == 0:
        return names
    if action.choices:
        return f"{names} {{{','.join(map(str, action.choices))}}}"
    return f"{names} {action.metavar or action.dest.upper()}"


def _entry(path: str, parser: argparse.ArgumentParser) -> dict[str, object]:
    found = fields(path)
    return {
        "description": parser.description,
        "options": [
            {"argument": _argument(action), "help": action.help}
            for action in option_actions(parser)
        ],
        "writes": found.writes,
        "before": found.before,
        "effects": list(found.effects),
        "exit_codes": {
            str(int(code)): EXIT_CODE_MEANINGS[code] for code in found.codes
        },
    }


def help_object(parser: argparse.ArgumentParser) -> dict[str, object]:
    return {
        "verbs": list(subcommands(parser)),
        "commands": {path: _entry(path, child) for path, child in _commands(parser)},
    }


def _markdown_section(path: str, parser: argparse.ArgumentParser) -> list[str]:
    found = fields(path)
    return [
        f"## {parser.prog}",
        "",
        str(parser.description),
        "",
        f"- Writes: {found.writes}",
        f"- Before: {found.before}",
        f"- Effects: {', '.join(found.effects)}",
        f"- {exit_codes(found.codes)}",
        "",
        "Options:",
        "",
        *(
            f"- `{_argument(action)}`: {action.help}"
            for action in option_actions(parser)
        ),
        "",
    ]


def help_markdown(parser: argparse.ArgumentParser) -> str:
    lines = [
        "---",
        f"name: {parser.prog}",
        f"description: {SKILL_DESCRIPTION}",
        "---",
        "",
        f"# {parser.prog}",
        "",
        str(parser.description),
        "",
        exit_codes(tuple(ExitCode)),
        "",
        "## Rules for agents",
        "",
        *(f"{number}. {rule}" for number, rule in enumerate(AGENT_RULES, 1)),
        "",
    ]
    for path, child in _commands(parser):
        lines += _markdown_section(path, child)
    return "\n".join(lines)
