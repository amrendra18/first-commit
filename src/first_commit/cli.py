import argparse
import os
import sys
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path

from first_commit import __version__, validation
from first_commit.arguments import ArgumentError, parse
from first_commit.candidates import CandidateError
from first_commit.contributor import ContributorError
from first_commit.git import (
    GitError,
    GitUnavailableError,
    IndexFileError,
    repository_root,
    sanitized_git_environment,
)
from first_commit.gitleaks_scanner import DependencyError
from first_commit.models import ExitCode, Result, SetupError
from first_commit.paths import PathError
from first_commit.policy import POLICY_PATH, Policy, load_policy
from first_commit.policy_fields import PolicyError
from first_commit.private_values import (
    PrivateValuesError,
    load_private_values,
    masked_path,
    masked_result,
)
from first_commit.pushed import PushedScope, pushed_scope
from first_commit.reporting import (
    json_value,
    next_action_line,
    print_json,
    render_human,
)
from first_commit.setup_command import declares_setup_hook

SUPPORTED_PLATFORMS = frozenset({"darwin", "linux"})
UNSUPPORTED_PLATFORM = (
    "first-commit runs on macOS and Linux only; this system reports {platform}.\n"
    "fix: run first-commit on macOS or Linux, such as in WSL (Windows Subsystem for "
    "Linux) on Windows."
)

# Each error class main reports, with its exit code; the first matching row wins.
ERROR_EXIT_CODES: tuple[tuple[type[Exception], ExitCode], ...] = (
    (ArgumentError, ExitCode.INPUT),
    (SetupError, ExitCode.INPUT),
    (PolicyError, ExitCode.INPUT),
    (ContributorError, ExitCode.INPUT),
    (PrivateValuesError, ExitCode.INPUT),
    (DependencyError, ExitCode.DEPENDENCY),
    (GitError, ExitCode.ACCESS),
    (CandidateError, ExitCode.ACCESS),
    (PathError, ExitCode.ACCESS),
    (OSError, ExitCode.ACCESS),
)
HANDLED_ERRORS = tuple(kind for kind, _ in ERROR_EXIT_CODES)
INTERRUPTED = "first-commit stopped on Ctrl-C."


def _color() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _checks(
    root: Path,
    policy: Policy,
    values: tuple[str, ...],
    scope: PushedScope | None = None,
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


def _run(arguments: Sequence[str]) -> int:
    options = parse(arguments)
    if options.command == "version":
        print(__version__)
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
        kind = next(kind for kind, _ in ERROR_EXIT_CODES if isinstance(error, kind))
        raise kind(masked_path(str(error), values)) from error


def _report_validation(
    root: Path, policy: Policy, options: argparse.Namespace, values: tuple[str, ...]
) -> int:
    results: Iterable[tuple[str, Result]]
    if options.command == "check":
        results = _checks(root, policy, values, warn_on_remote=True)
    elif options.stage == "pre-push":
        results = _checks(root, policy, values, pushed_scope(os.environ))
    elif options.stage == "pre-commit":
        results = [("staged", validation.staged(root, policy, values))]
    else:
        message_path = Path(options.message_file)
        results = [("message", validation.message(root, policy, message_path, values))]
    masked = ((name, masked_result(result, values)) for name, result in results)
    return _report(masked, options, root, masked_path(str(root), values))


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


def main(arguments: Sequence[str] | None = None) -> int:
    if sys.platform not in SUPPORTED_PLATFORMS:
        print(
            "error: " + UNSUPPORTED_PLATFORM.format(platform=sys.platform),
            file=sys.stderr,
        )
        return ExitCode.DEPENDENCY
    try:
        return _run(sys.argv[1:] if arguments is None else arguments)
    except HANDLED_ERRORS as error:
        print(f"error: {error}", file=sys.stderr)
        return next(code for kind, code in ERROR_EXIT_CODES if isinstance(error, kind))
    # Ctrl-C cancels the run, so it exits 2 like a cancelled setup.
    except KeyboardInterrupt:
        print(f"error: {INTERRUPTED}", file=sys.stderr)
        return ExitCode.INPUT


if __name__ == "__main__":
    raise SystemExit(main())
