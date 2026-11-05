import argparse
import os
import re
import shlex
import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from pathlib import Path

from first_commit import __version__, hooks, validation
from first_commit.arguments import ArgumentError, build_parser, json_requested, parse
from first_commit.candidates import CandidateError
from first_commit.contributor import ContributorError
from first_commit.executables import find_executable
from first_commit.git import (
    GitError,
    GitUnavailableError,
    IndexFileError,
    repository_root,
    sanitized_git_environment,
)
from first_commit.gitleaks_scanner import DependencyError
from first_commit.help_text import help_markdown, help_object
from first_commit.models import (
    ConfirmationNeededError,
    ExitCode,
    Result,
    SetupBlockedError,
    SetupCancelledError,
    SetupError,
    SetupFailedError,
    SetupTerminatedError,
)
from first_commit.paths import PathError
from first_commit.policy import POLICY_PATH, Policy, PolicyMissingError, load_policy
from first_commit.policy_fields import PolicyError
from first_commit.private_values import (
    PrivateValues,
    PrivateValuesError,
    load_private_values,
    masked_path,
    masked_result,
)
from first_commit.pushed import HistoryRange, PushedScope, pushed_scope
from first_commit.reporting import (
    json_value,
    next_action_line,
    print_error,
    print_json,
    print_object,
    render_human,
)
from first_commit.setup_command import CHECK_HOOK_COMMAND, declares_setup_hook

SUPPORTED_PLATFORMS = frozenset({"darwin", "linux"})
UNSUPPORTED_PLATFORM = (
    "first-commit runs on macOS and Linux only; this system reports {platform}.\n"
    "fix: run first-commit on macOS or Linux, such as in WSL (Windows Subsystem for "
    "Linux) on Windows."
)

# Each error class main reports, with its JSON error code and exit code; the first
# matching row wins, so a subclass comes before its parent.
ERRORS: tuple[tuple[type[Exception], str, ExitCode], ...] = (
    (ArgumentError, "invalid-arguments", ExitCode.INPUT),
    (ConfirmationNeededError, "needs-confirmation", ExitCode.HELD),
    (SetupCancelledError, "cancelled", ExitCode.FINDING),
    (SetupTerminatedError, "interrupted", ExitCode.FINDING),
    (SetupBlockedError, "setup-blocked", ExitCode.FINDING),
    (SetupFailedError, "setup-failed", ExitCode.FINDING),
    (SetupError, "setup-input", ExitCode.INPUT),
    (PolicyMissingError, "policy-missing", ExitCode.INPUT),
    (PolicyError, "policy-invalid", ExitCode.INPUT),
    (ContributorError, "contributor-record", ExitCode.INPUT),
    (PrivateValuesError, "private-values", ExitCode.INPUT),
    (DependencyError, "dependency-missing", ExitCode.FINDING),
    (GitError, "git-access", ExitCode.FINDING),
    (CandidateError, "git-access", ExitCode.FINDING),
    (PathError, "file-access", ExitCode.FINDING),
    (OSError, "file-access", ExitCode.FINDING),
)
HANDLED_ERRORS = tuple(kind for kind, _, _ in ERRORS)
INTERRUPTED = "first-commit stopped on Ctrl-C."
# bin/first-commit sets this to its own absolute path; main removes it, so no
# program that first-commit starts inherits it.
EXECUTABLE_VARIABLE = "FIRST_COMMIT_EXECUTABLE"
# Inside these stages the program path is pre-commit's cache, which no one runs.
HOOK_STAGES = frozenset({"pre-commit", "commit-msg", "pre-push"})
FIX_LINE = re.compile(r"\n\s*fix: ")
UNKNOWN_PROGRAM = (
    " The command that fixes this cannot be named: first-commit did not start from a "
    "program file, and PATH holds no first-commit."
)


def _color() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _checks(
    root: Path,
    policy: Policy,
    values: tuple[str, ...],
    scope: PushedScope | HistoryRange | None = None,
    *,
    warn_on_remote: bool = False,
) -> Iterator[tuple[str, Result]]:
    yield "doctor", validation.doctor(root, policy)
    yield "working", validation.working(root, policy, values)
    yield "staged", validation.staged(root, policy, values)
    yield (
        "history",
        validation.history(root, policy, scope, values, warn_on_remote=warn_on_remote),
    )


def _render(
    results: Iterable[tuple[str, Result]],
    output_format: str,
    repository: str,
    *,
    setup_hook: bool,
    name_root: bool,
) -> bool:
    if output_format == "json":
        checks = []
        passed = True
        for name, result in results:
            passed = passed and result.passed
            checks.append({"name": name, **json_value(result, setup_hook=setup_hook)})
        print_json({"repository": repository, "passed": passed, "checks": checks})
        return passed
    if name_root:
        print(f"Repository: {repository}")
    colors = {"PASS": "\x1b[32m", "WARN": "\x1b[33m", "FAIL": "\x1b[31m"}
    passed = True
    advised = False
    for name, result in results:
        passed = passed and result.passed
        status = "FAIL" if not result.passed else "WARN" if result.findings else "PASS"
        label = f"{status} {name}"
        if _color():
            label = colors[status] + label + "\x1b[0m"
        print(label)
        if result.findings:
            print(render_human(result, setup_hook=setup_hook))
        if not advised:
            line = next_action_line(result, setup_hook=setup_hook)
            if line is not None:
                print(line)
                advised = True
    return passed


# By file identity, so a link to the root or another casing of it is the root.
def _started_in(root: Path, options: argparse.Namespace) -> bool:
    start = Path(options.root) if options.root else Path.cwd()
    try:
        return start.samefile(root)
    except OSError:
        return False


# Runs before any check, so no check reads an index outside root's Git folder.
def _require_readable_index_file(root: Path, options: argparse.Namespace) -> None:
    try:
        sanitized_git_environment(root=root)
    except IndexFileError as error:
        command = " ".join(
            part for part in (options.command, getattr(options, "stage", None)) if part
        )
        raise IndexFileError(
            f"The first-commit {command} command refused to run: {error}"
        ) from error


def _version(output_format: str) -> None:
    if output_format == "json":
        # A pip install records no edits to its source, so modified is unknown.
        revision = hooks.installed_revision()
        print_object({"version": __version__, "revision": revision, "modified": None})
    else:
        print(__version__)


def _help(output_format: str) -> None:
    parser = build_parser()
    if output_format == "json":
        print_object(help_object(parser))
    elif output_format == "markdown":
        sys.stdout.write(help_markdown(parser))
    else:
        parser.print_help()


# These verbs read no state and start no process.
STATELESS: dict[str, Callable[[str], None]] = {"version": _version, "help": _help}


def _run(arguments: Sequence[str]) -> int:
    options = parse(arguments)
    if options.command in STATELESS:
        STATELESS[options.command](options.format)
        return ExitCode.PASSED
    if options.command == "setup" or getattr(options, "stage", None) == "setup":
        # Imported here: setup needs POSIX file locks, which other systems lack.
        from first_commit import setup_cli

        if options.command == "setup":
            return setup_cli.run_setup(options)
        return setup_cli.clone_setup(options)
    try:
        root = repository_root(options.root)
    # Its own message and fix line say what is wrong; no folder is in doubt.
    except GitUnavailableError:
        raise
    except GitError as error:
        folder = options.root or Path.cwd()
        raise GitError(
            f"{folder} is not inside a Git repository, or Git cannot read it.\n"
            "fix: run first-commit in a Git checkout, or run `first-commit setup` to "
            "create one; `git status` in that folder shows Git's own error."
        ) from error
    _require_readable_index_file(root, options)
    policy = load_policy(root / POLICY_PATH, root)
    if options.command == "doctor":
        results = [("doctor", validation.doctor(root, policy))]
        return _report(results, options, root, str(root))
    values = load_private_values(root, policy.private_values_file)
    try:
        return _report_validation(root, policy, options, values)
    # An error may name a path that holds a private value, such as a refused
    # program's folder; the message is masked, and its row keeps the exit code.
    except HANDLED_ERRORS as error:
        kind = next(kind for kind, _, _ in ERRORS if isinstance(error, kind))
        raise kind(masked_path(str(error), values.masked)) from error


def _report_validation(
    root: Path, policy: Policy, options: argparse.Namespace, loaded: PrivateValues
) -> int:
    results: Iterable[tuple[str, Result]]
    values = loaded.checked
    if options.command == "check":
        scope = HistoryRange.NEW_ONLY if options.new_only else None
        results = _checks(root, policy, values, scope, warn_on_remote=True)
    elif options.stage == "pre-push":
        results = _checks(root, policy, values, pushed_scope(os.environ))
    elif options.stage == "pre-commit":
        results = [("staged", validation.staged(root, policy, values))]
    else:
        message_path = Path(options.message_file)
        results = [("message", validation.message(root, policy, message_path, values))]
    hidden = loaded.masked
    masked = ((name, masked_result(result, hidden)) for name, result in results)
    return _report(masked, options, root, masked_path(str(root), hidden))


def _report(
    results: Iterable[tuple[str, Result]],
    options: argparse.Namespace,
    root: Path,
    repository: str,
) -> int:
    passed = _render(
        results,
        options.format,
        repository,
        setup_hook=declares_setup_hook(root),
        name_root=not _started_in(root, options),
    )
    return ExitCode.PASSED if passed else ExitCode.FINDING


# A start as a module (python -m, python -c) leaves no program file in sys.argv[0].
def _program(exported: str) -> str | None:
    if Path(exported).is_absolute():
        return exported
    started = Path(sys.argv[0]).resolve()
    if started.is_file() and os.access(started, os.X_OK):
        return str(started)
    return find_executable("first-commit")


def _without_root(words: Sequence[str]) -> list[str]:
    kept: list[str] = []
    value_follows = False
    for word in words:
        if not value_follows and word != "--root" and not word.startswith("--root="):
            kept.append(word)
        value_follows = word == "--root" and not value_follows
    return kept


def _in_hook_stage(words: Sequence[str]) -> bool:
    return len(words) > 1 and words[0] == "hook" and words[1] in HOOK_STAGES


# The check hook command, or none, and what message adds. The command runs only from
# inside the repository, so a git-access error names none.
def _check_hook(code: str) -> tuple[list[str], str]:
    if code == "git-access":
        return [], (
            " The check hook command runs only inside a repository Git can read, so "
            "no command can rerun this check."
        )
    pre_commit = find_executable("pre-commit")
    if pre_commit is None:
        return [], " pre-commit is not on PATH, so no command can rerun this check."
    hook = CHECK_HOOK_COMMAND.split()[1:]
    return [shlex.join((pre_commit, *hook))], (
        " Run the next command inside the repository."
    )


# The commands, or the reason no command can be named.
def _commands(
    error: BaseException, words: Sequence[str], exported: str
) -> list[str] | str:
    if isinstance(error, ArgumentError):
        arguments = [*error.prog.split()[1:], "--help"]
    elif isinstance(error, ConfirmationNeededError):
        arguments = [*_without_root(words), "--root", str(error.root), "--yes"]
    else:
        return []
    program = _program(exported)
    return UNKNOWN_PROGRAM if program is None else [shlex.join((program, *arguments))]


# message drops the fix line, and says why when next holds no command.
def _report_error(
    words: Sequence[str], code: str, text: str, commands: list[str] | str
) -> None:
    if not json_requested(words):
        print(f"error: {text}", file=sys.stderr)
        return
    message, fix = [*FIX_LINE.split(text, maxsplit=1), ""][:2]
    if _in_hook_stage(words):
        commands, reason = _check_hook(code)
        message += reason
    elif isinstance(commands, str):
        message += commands
        commands = []
    elif not commands:
        message += " No single command fixes this" + (f"; {fix}" if fix else ".")
    print_error(code, message, commands)


def main(arguments: Sequence[str] | None = None) -> int:
    words = list(sys.argv[1:] if arguments is None else arguments)
    exported = os.environ.pop(EXECUTABLE_VARIABLE, "")
    if sys.platform not in SUPPORTED_PLATFORMS:
        text = UNSUPPORTED_PLATFORM.format(platform=sys.platform)
        _report_error(words, "unsupported-platform", text, [])
        return ExitCode.FINDING
    try:
        return _run(words)
    except HANDLED_ERRORS as error:
        _, code, exit_code = next(row for row in ERRORS if isinstance(error, row[0]))
        _report_error(words, code, str(error), _commands(error, words, exported))
        return exit_code
    # Ctrl-C stops the run before its job is done.
    except KeyboardInterrupt:
        _report_error(words, "interrupted", INTERRUPTED, [])
        return ExitCode.FINDING


if __name__ == "__main__":
    raise SystemExit(main())
