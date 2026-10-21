import argparse
import os
import sys
from collections.abc import Callable
from dataclasses import replace
from enum import StrEnum
from pathlib import Path

from first_commit.contributor import (
    CONTRIBUTOR_PATH,
    Contributor,
    ContributorError,
    load_contributor,
    parse_contributor,
    record_bytes,
    require_email,
    require_name,
)
from first_commit.git import repository_root
from first_commit.machine_identity import (
    EMAIL_VARIABLE,
    KEY_VARIABLE,
    NAME_VARIABLE,
    create_identity,
    identity_from_environment,
    identity_path,
    load_identity,
    missing_identity_message,
)
from first_commit.models import ExitCode, SetupError
from first_commit.reporting import print_json
from first_commit.setup import SetupRequest, hook_proposal_error, setup_repository
from first_commit.setup_command import TRUST_SELF_VARIABLE
from first_commit.setup_hooks import HooksMissingError, configured_source
from first_commit.setup_trust import check_signing_key

RECOVERY = 'see "Stop and recover" in the first-commit README'
SIGNING_KEY_PROMPT = (
    "SSH public signing-key path (ends in .pub, for example ~/.ssh/id_ed25519.pub): "
)
ANSWER_ATTEMPTS = 3


class IdentitySource(StrEnum):
    RECORD = f"this checkout's record {CONTRIBUTOR_PATH}"
    FILE = "the identity file"
    VARIABLES = f"{NAME_VARIABLE}, {EMAIL_VARIABLE}, and {KEY_VARIABLE}"
    TYPED = "the answers typed above"


def _source_text(source: IdentitySource) -> str:
    if source is IdentitySource.FILE:
        return f"{source} {identity_path()}"
    return str(source)


def remember_identity(contributor: Contributor) -> str:
    path = identity_path()
    if os.path.lexists(path):
        return f"Machine identity: retained {path}"
    try:
        create_identity(path, contributor)
    except ContributorError as error:
        return f"Machine identity: not saved ({error})"
    return f"Machine identity: saved to {path}"


def _correction(source: IdentitySource) -> str:
    match source:
        case IdentitySource.RECORD:
            return (
                f"replace this checkout's identity ({RECOVERY}): delete "
                f"{CONTRIBUTOR_PATH}, unset user.name, user.email, and "
                "user.signingkey with `git config --local --unset`, then rerun setup"
            )
        case IdentitySource.TYPED:
            return (
                "rerun setup and type your public name, email, and the path of your "
                "SSH public key, such as ~/.ssh/id_ed25519.pub"
            )
        case IdentitySource.VARIABLES:
            return f"correct {IdentitySource.VARIABLES}, then rerun setup"
        case IdentitySource.FILE:
            return f"correct or delete {identity_path()}, then rerun setup"


def _unusable_identity(source: IdentitySource, error: Exception) -> SetupError:
    return SetupError(
        f"The identity from {_source_text(source)} is not usable: {error}\n"
        f"fix: {_correction(source)}."
    )


def _require_usable(
    root: Path, contributor: Contributor, source: IdentitySource
) -> None:
    try:
        parse_contributor(record_bytes(contributor))
        check_signing_key(root, contributor.signing_key)
    except (ContributorError, SetupError) as error:
        raise _unusable_identity(source, error) from error


# A variable that names another identity stops setup, so no correction is ignored.
def _found_contributor(root: Path) -> tuple[Contributor, IdentitySource] | None:
    variables = identity_from_environment()
    record = load_contributor(root)
    found, source = (
        (record, IdentitySource.RECORD)
        if record is not None
        else (load_identity(identity_path()), IdentitySource.FILE)
    )
    if found is None:
        return None if variables is None else (variables, IdentitySource.VARIABLES)
    if variables is not None and variables != found:
        text = _source_text(source)
        raise SetupError(
            f"{IdentitySource.VARIABLES} name another identity than {text}, which "
            f"setup uses first.\nfix: unset the three variables to keep {text}, or "
            f"{_correction(source)}."
        )
    return found, source


def _identity_line(contributor: Contributor, source: IdentitySource) -> str:
    return (
        f"Identity: {contributor.name} <{contributor.email}>, signing key "
        f"{contributor.signing_key} (from {_source_text(source)})"
    )


def clone_setup(options: argparse.Namespace) -> int:
    root = repository_root(options.root)
    found = _found_contributor(root)
    if found is None:
        raise SetupError(missing_identity_message(identity_path()))
    contributor, source = found
    _require_usable(root, contributor, source)
    revision, address = configured_source(root)
    request = SetupRequest(
        revision=revision,
        transport="ssh" if address.startswith("ssh://") else "https",
        trust_self=os.environ.get(TRUST_SELF_VARIABLE) == "1",
        confirmed=True,
    )
    print(_identity_line(contributor, source), flush=True)
    try:
        actions = setup_repository(
            root,
            request,
            contributor=contributor,
            progress=lambda message: print(message, flush=True),
        )
    except HooksMissingError as error:
        raise hook_proposal_error(root, error, dry_run=False) from error
    print("\n".join((*actions, remember_identity(contributor))))
    return ExitCode.PASSED


def _ask(prompt: str) -> str:
    print(prompt, file=sys.stderr, end="", flush=True)
    try:
        return input().strip()
    except EOFError as error:
        raise SetupError("Setup input ended; no changes made.") from error
    # The cursor is still after the prompt; the error line starts on a new line.
    except KeyboardInterrupt:
        print(file=sys.stderr, flush=True)
        raise


def _unconfirmed(source: IdentitySource) -> SetupError:
    return SetupError(
        "Setup did not apply the plan: there is no terminal to confirm it, and the "
        f"identity comes from {_source_text(source)}, not from this checkout's "
        "record.\n"
        "fix: check the plan above, then rerun with --yes to apply it."
    )


def _ask_checked(prompt: str, check: Callable[[str], None]) -> str:
    attempts_left = ANSWER_ATTEMPTS
    while True:
        answer = _ask(prompt)
        attempts_left -= 1
        try:
            check(answer)
        except (ContributorError, SetupError) as error:
            if not attempts_left:
                raise _unusable_identity(IdentitySource.TYPED, error) from error
            print(error, file=sys.stderr, flush=True)
        else:
            return answer


def _ask_contributor(root: Path) -> Contributor:
    if not sys.stdin.isatty():
        raise SetupError(
            f"No identity for setup: {identity_path()} does not exist, "
            f"{IdentitySource.VARIABLES} are unset, and there is no terminal to "
            "ask.\n"
            "fix: run setup in a terminal, or set all three variables and pass --yes."
        )
    return Contributor(
        _ask_checked("Public Git author name: ", require_name),
        _ask_checked("Public Git author email: ", require_email),
        _ask_checked(
            SIGNING_KEY_PROMPT, lambda reference: check_signing_key(root, reference)
        ),
    )


def _report_setup(
    actions: tuple[str, ...], output_format: str, *, dry_run: bool
) -> None:
    if output_format == "json":
        print_json({"passed": True, "dry_run": dry_run, "actions": actions})
    else:
        print("\n".join(actions))


def _plan(
    root: Path, request: SetupRequest, contributor: Contributor | None
) -> tuple[str, ...]:
    return setup_repository(
        root, replace(request, dry_run=True), contributor=contributor
    )


def _setup(options: argparse.Namespace, root: Path, request: SetupRequest) -> int:
    found = _found_contributor(root)
    if found is not None:
        _require_usable(root, *found)
    plan = _plan(root, request, found[0] if found is not None else None)
    if options.dry_run:
        if found is not None:
            plan = (_identity_line(*found), *plan)
        _report_setup(plan, options.format, dry_run=True)
        return ExitCode.PASSED
    if found is None:
        found = _ask_contributor(root), IdentitySource.TYPED
        _require_usable(root, *found)
        plan = _plan(root, request, found[0])
    contributor, source = found
    identity = _identity_line(contributor, source)
    stream = sys.stderr if options.format == "json" else sys.stdout
    terminal = sys.stdin.isatty()
    if not options.yes and (terminal or source is not IdentitySource.RECORD):
        print("\n".join((identity, *plan)), file=stream, flush=True)
        if not terminal:
            raise _unconfirmed(source)
        if _ask("Apply this setup? [y/N] ").lower() not in {"y", "yes"}:
            raise SetupError("Setup was cancelled; no changes made.")
    actions = setup_repository(
        root,
        replace(request, confirmed=True),
        contributor=contributor,
        progress=lambda message: print(message, file=stream, flush=True),
    )
    _report_setup(
        (identity, *actions, remember_identity(contributor)),
        options.format,
        dry_run=False,
    )
    return ExitCode.PASSED


def run_setup(options: argparse.Namespace) -> int:
    root = Path(options.root).resolve() if options.root else Path.cwd().resolve()
    request = SetupRequest(
        revision=options.revision,
        transport=options.transport,
        license_choice=options.license,
        docs=options.docs,
        trust_self=options.trust_self,
    )
    try:
        return _setup(options, root, request)
    except HooksMissingError as error:
        raise hook_proposal_error(root, error, dry_run=options.dry_run) from error
