import json
import os
import re
import string
from collections.abc import Callable, Iterator, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from first_commit.characters import has_control_characters
from first_commit.git import IgnoreStateError, require_ignored
from first_commit.json_values import is_exact_int
from first_commit.models import GIT_CONFIG_PATH, Finding
from first_commit.paths import (
    PathError,
    PathPermissionsError,
    confined_path,
    create_exclusive,
    make_private_folders,
    read_regular_bytes,
)

CONTRIBUTOR_PATH = ".local/first-commit/contributor.json"
CONTRIBUTOR_SUBJECT = "Contributor record"
MAX_CONTRIBUTOR_BYTES = 16 * 1024
MAX_NAME_CHARS = 200
# The longest address SMTP carries (RFC 5321); the policy's public_emails share it.
MAX_EMAIL_CHARS = 254
MAX_SIGNING_KEY_CHARS = 1024
EMAIL = re.compile(r"[A-Za-z0-9._%+-]++@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
EMAIL_LOCAL_CHARACTERS = frozenset(string.ascii_letters + string.digits + "._%+-")
EMAIL_DOMAIN = re.compile(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RECORD_FIELDS = {"schema_version", "name", "email", "signing_key"}
LOCAL_FILE_FIX = (
    "make .gitignore ignore {path}: add the line .local/ and delete any later rule "
    "that re-includes it, such as !.local/ (git check-ignore -v {path} names it); if "
    "Git tracks the file, run git rm --cached {path}; then rerun setup."
)


class ContributorError(ValueError):
    def __init__(self, message: str, fix: str | None = None) -> None:
        super().__init__(message if fix is None else f"{message}\nfix: {fix}")
        self.fix = fix


@dataclass(frozen=True)
class Contributor:
    name: str
    email: str
    signing_key: str


# Searches from each "@" in linear time; EMAIL.finditer would take quadratic time.
def email_spans(text: str) -> Iterator[tuple[int, int]]:
    floor = 0
    at = text.find("@")
    while at >= 0:
        start = at
        while start > floor and text[start - 1] in EMAIL_LOCAL_CHARACTERS:
            start -= 1
        domain = EMAIL_DOMAIN.match(text, at + 1) if start < at else None
        if domain is None:
            at = text.find("@", at + 1)
            continue
        yield start, domain.end()
        floor = domain.end()
        at = text.find("@", floor)


def unique_fields(
    error: Callable[[], Exception],
) -> Callable[[list[tuple[str, Any]]], dict[str, Any]]:

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise error()
            result[key] = value
        return result

    return hook


def _text(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 0 < len(value) <= maximum
        and not has_control_characters(value)
    )


def record_bytes(contributor: Contributor) -> bytes:
    record = {
        "schema_version": 1,
        "name": contributor.name,
        "email": contributor.email,
        "signing_key": contributor.signing_key,
    }
    return (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")


def parse_contributor(raw: bytes) -> Contributor:
    if len(raw) > MAX_CONTRIBUTOR_BYTES:
        raise ContributorError("Contributor record exceeds the size limit.")
    duplicate = unique_fields(
        lambda: ContributorError("Contributor record has duplicate fields.")
    )
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ContributorError("Contributor record is not valid UTF-8 JSON.") from error
    if not isinstance(data, dict) or set(data) != RECORD_FIELDS:
        raise ContributorError("Contributor record has invalid fields.")
    if not is_exact_int(data["schema_version"]) or data["schema_version"] != 1:
        raise ContributorError("Contributor record has an unsupported schema.")
    require_name(data["name"])
    require_email(data["email"])
    require_key_reference(data["signing_key"])
    return Contributor(data["name"], data["email"], data["signing_key"])


def require_name(name: object) -> None:
    if not _text(name, MAX_NAME_CHARS):
        raise ContributorError("Contributor name is invalid.")


def require_email(email: object) -> None:
    if isinstance(email, str) and len(email) > MAX_EMAIL_CHARS:
        raise ContributorError(
            f"Contributor email is longer than {MAX_EMAIL_CHARS} characters."
        )
    if not isinstance(email, str) or EMAIL.fullmatch(email) is None:
        raise ContributorError("Contributor email is invalid.")


def require_key_reference(key: object) -> None:
    if not _text(key, MAX_SIGNING_KEY_CHARS) or "PRIVATE KEY" in str(key).upper():
        raise ContributorError("Contributor signing-key reference is invalid.")


def _record_path(root: Path) -> Path:
    try:
        return confined_path(root, CONTRIBUTOR_PATH)
    except PathError as error:
        raise ContributorError("Contributor path is unsafe.") from error


def load_contributor(root: Path) -> Contributor | None:
    path = _record_path(root)
    if path.is_symlink():
        raise ContributorError("Contributor record must be a regular file.")
    if not path.exists():
        return None
    try:
        require_ignored(root, CONTRIBUTOR_PATH, CONTRIBUTOR_SUBJECT)
    except IgnoreStateError as error:
        raise ContributorError(
            str(error), LOCAL_FILE_FIX.format(path=CONTRIBUTOR_PATH)
        ) from error
    try:
        raw = read_regular_bytes(path, MAX_CONTRIBUTOR_BYTES, 0o077)
    except PathPermissionsError as error:
        raise ContributorError(
            "Contributor record permissions are too broad.",
            f"run `chmod 600 {CONTRIBUTOR_PATH}`.",
        ) from error
    except PathError as error:
        raise ContributorError(
            "Contributor record is unreadable or too large."
        ) from error
    return parse_contributor(raw)


def _remove_if_unchanged(path: Path, content: bytes) -> None:
    if not path.is_file() or path.is_symlink():
        return
    try:
        if read_regular_bytes(path, MAX_CONTRIBUTOR_BYTES) == content:
            path.unlink()
    except PathError:
        pass


def _write_record(
    root: Path, path: Path, content: bytes, created_folders: list[Path]
) -> None:
    try:
        make_private_folders((root / ".local", path.parent), created_folders)
    except PathError as error:
        raise ContributorError("Contributor folder is unsafe.") from error
    if os.path.lexists(path):
        raise ContributorError("Contributor record already exists.")
    create_exclusive(path, content, 0o600)
    try:
        load_contributor(root)
    except ContributorError:
        _remove_if_unchanged(path, content)
        raise


def create_contributor(root: Path, contributor: Contributor) -> None:
    content = record_bytes(contributor)
    parse_contributor(content)
    path = _record_path(root)
    created_folders: list[Path] = []
    try:
        _write_record(root, path, content, created_folders)
    except OSError as error:
        raise ContributorError("Contributor record could not be created.") from error
    finally:
        for folder in reversed(created_folders):
            with suppress(OSError):
                folder.rmdir()


def contributor_findings(
    contributor: Contributor | None, git_settings: Mapping[str, str]
) -> list[Finding]:
    if contributor is None:
        return [
            Finding(
                rule_id="git.contributor-record",
                path=CONTRIBUTOR_PATH,
                summary="Local contributor record is missing.",
            )
        ]
    findings = []
    for key, expected, rule_id in (
        ("user.name", contributor.name, "git.contributor-name"),
        ("user.email", contributor.email, "git.contributor-email"),
        ("user.signingkey", contributor.signing_key, "git.contributor-signing-key"),
    ):
        if git_settings.get(key) != expected:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    path=GIT_CONFIG_PATH,
                    summary="Local Git setting differs from the contributor record.",
                )
            )
    return findings
