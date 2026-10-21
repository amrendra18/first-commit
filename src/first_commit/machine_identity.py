import os
from collections.abc import Callable, Mapping
from pathlib import Path

from first_commit.contributor import (
    MAX_CONTRIBUTOR_BYTES,
    Contributor,
    ContributorError,
    parse_contributor,
    record_bytes,
    require_email,
    require_key_reference,
    require_name,
)
from first_commit.paths import create_exclusive
from first_commit.setup_command import SETUP_HOOK_COMMAND

PATH_VARIABLE = "FIRST_COMMIT_IDENTITY_FILE"
NAME_VARIABLE = "FIRST_COMMIT_AUTHOR_NAME"
EMAIL_VARIABLE = "FIRST_COMMIT_AUTHOR_EMAIL"
KEY_VARIABLE = "FIRST_COMMIT_SIGNING_KEY"
VARIABLE_CHECKS: tuple[tuple[str, Callable[[str], None], str], ...] = (
    (NAME_VARIABLE, require_name, "your public name"),
    (
        EMAIL_VARIABLE,
        require_email,
        "your public email address, such as you@example.com",
    ),
    (
        KEY_VARIABLE,
        require_key_reference,
        "the path of your SSH public key, such as ~/.ssh/id_ed25519.pub",
    ),
)


def _expand_home(value: str) -> Path:
    try:
        return Path(value).expanduser()
    except RuntimeError:
        return Path(value)


def identity_path(environment: Mapping[str, str] | None = None) -> Path:
    values = os.environ if environment is None else environment
    chosen = values.get(PATH_VARIABLE)
    if chosen:
        return _expand_home(chosen)
    base = values.get("XDG_CONFIG_HOME") or Path(
        values.get("HOME") or _expand_home("~"), ".config"
    )
    return Path(base) / "first-commit" / "identity.json"


def load_identity(path: Path) -> Contributor | None:
    if not os.path.lexists(path):
        return None
    if path.is_symlink() or not path.is_file():
        raise ContributorError(f"Identity file {path} must be a regular file.")
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_CONTRIBUTOR_BYTES + 1)
    except OSError as error:
        raise ContributorError(f"Identity file {path} cannot be read.") from error
    try:
        return parse_contributor(raw)
    except ContributorError as error:
        raise ContributorError(f"Identity file {path}: {error}") from error


def identity_from_environment(
    environment: Mapping[str, str] | None = None,
) -> Contributor | None:
    values = os.environ if environment is None else environment
    fields = [
        values.get(name, "") for name in (NAME_VARIABLE, EMAIL_VARIABLE, KEY_VARIABLE)
    ]
    if not any(fields):
        return None
    for (variable, require, wanted), value in zip(VARIABLE_CHECKS, fields, strict=True):
        if not value:
            raise ContributorError(
                f"{variable} is unset, but the other identity variables are set.",
                f"set all three of {NAME_VARIABLE}, {EMAIL_VARIABLE}, and "
                f"{KEY_VARIABLE}, or unset them all, then rerun setup.",
            )
        try:
            require(value)
        except ContributorError as error:
            raise ContributorError(
                f"The value of {variable} is not usable: {error}",
                f"set {variable} to {wanted}, then rerun setup.",
            ) from error
    return parse_contributor(record_bytes(Contributor(*fields)))


def create_identity(path: Path, contributor: Contributor) -> None:
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        create_exclusive(path, record_bytes(contributor), 0o600)
    except OSError as error:
        raise ContributorError(f"Identity file {path} could not be written.") from error


def missing_identity_message(path: Path) -> str:
    return (
        f"no identity for this machine: {path} does not exist.\n"
        "fix: run once on this machine, with your public name, email, and SSH "
        "public signing key:\n"
        f'  {NAME_VARIABLE}="Your Name" {EMAIL_VARIABLE}="you@example.com" '
        f'{KEY_VARIABLE}="~/.ssh/id_ed25519.pub" {SETUP_HOOK_COMMAND}\n'
        f"It saves the identity to that file for every later clone. Set "
        f"{PATH_VARIABLE} to choose another file."
    )
