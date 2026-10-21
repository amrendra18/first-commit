import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from first_commit.contributor import (
    CONTRIBUTOR_PATH,
    Contributor,
    ContributorError,
    load_contributor,
    unique_fields,
)
from first_commit.json_values import is_exact_int
from first_commit.paths import MEBIBYTE, PathError, read_explicit_file_bytes
from first_commit.policy_fields import (
    DEFAULT_LIMITS,
    DetectorExceptionEntry,
    EnvironmentExceptionEntry,
    ForbiddenPath,
    ImmutableVendorFile,
    LiteralExceptionEntry,
    PolicyError,
    detector_exceptions,
    environment_exceptions,
    flag,
    forbidden_paths,
    immutable_vendor_files,
    literal_exceptions,
    public_emails,
)
from first_commit.setup_command import declares_setup_hook, setup_command

MAX_POLICY_BYTES = MEBIBYTE
REQUIRED_DOCUMENTS = ("README.md", "AGENTS.md")
FIELDS = {
    "schema_version",
    "public_environment_files",
    "private_literal_exceptions",
    "privacy_detector_exceptions",
    "forbidden_paths",
    "public_emails",
    "commit_body_sections",
    "immutable_vendor_files",
    "public_github_owner_urls",
}
POLICY_PATH = ".repo-policy.json"
POLICY_NAME = f"The project policy file {POLICY_PATH}"
PRIVATE_VALUES_PATH = ".local/first-commit/private-values.txt"


@dataclass(frozen=True)
class Policy:
    environment_exceptions: tuple[EnvironmentExceptionEntry, ...]
    max_files: int
    max_file_bytes: int
    max_findings: int
    max_message_bytes: int
    contributor_emails: tuple[str, ...]
    private_values_file: str
    literal_exceptions: tuple[LiteralExceptionEntry, ...]
    detector_exceptions: tuple[DetectorExceptionEntry, ...] = ()
    forbidden_paths: tuple[ForbiddenPath, ...] = ()
    public_emails: tuple[str, ...] = ()
    commit_body_sections: bool = True
    immutable_vendor_files: tuple[ImmutableVendorFile, ...] = ()
    public_github_owner_urls: bool = False


def _policy_data(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError(f"{POLICY_NAME} exceeds the size limit.")
    duplicate = unique_fields(
        lambda: PolicyError(f"{POLICY_NAME} contains duplicate fields.")
    )
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise PolicyError(f"{POLICY_NAME} is not valid UTF-8 JSON.") from error
    if not isinstance(data, dict) or set(data) - FIELDS:
        raise PolicyError(f"{POLICY_NAME} has unknown fields.")
    if not is_exact_int(data.get("schema_version")) or data["schema_version"] != 1:
        raise PolicyError(f"{POLICY_NAME} has an unsupported schema.")
    return data


def parse_policy(
    raw: bytes, root: Path, contributor: Contributor | None = None
) -> Policy:
    data = _policy_data(raw)
    commit_body_sections = flag(data, "commit_body_sections", default=True)
    public_github_owner_urls = flag(data, "public_github_owner_urls", default=False)
    # Keyword arguments run in order, so the fields are checked in this order.
    return Policy(
        environment_exceptions=environment_exceptions(
            data.get("public_environment_files", []),
            "public_environment_files",
            root=root,
        ),
        max_files=DEFAULT_LIMITS["max_files"],
        max_file_bytes=DEFAULT_LIMITS["max_file_bytes"],
        max_findings=DEFAULT_LIMITS["max_findings"],
        max_message_bytes=DEFAULT_LIMITS["max_message_bytes"],
        contributor_emails=(contributor.email,) if contributor else (),
        private_values_file=PRIVATE_VALUES_PATH,
        literal_exceptions=literal_exceptions(
            data.get("private_literal_exceptions", []),
            "private_literal_exceptions",
            root=root,
        ),
        detector_exceptions=detector_exceptions(
            data.get("privacy_detector_exceptions", []),
            "privacy_detector_exceptions",
            root=root,
        ),
        forbidden_paths=forbidden_paths(
            data.get("forbidden_paths", []), "forbidden_paths", root=root
        ),
        public_emails=public_emails(data.get("public_emails", []), "public_emails"),
        commit_body_sections=commit_body_sections,
        public_github_owner_urls=public_github_owner_urls,
        immutable_vendor_files=immutable_vendor_files(
            data.get("immutable_vendor_files", []), "immutable_vendor_files", root=root
        ),
    )


def _unreadable_policy(path: Path, root: Path) -> PolicyError:
    name = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
    if os.path.lexists(path):
        reason = (
            "cannot be read; make it a regular file of at most "
            f"{MAX_POLICY_BYTES // MEBIBYTE} MiB"
        )
    else:
        command = setup_command(setup_hook=declares_setup_hook(root))
        reason = (
            f'does not exist; run `{command}`, or create it as {{"schema_version": 1}}'
        )
    return PolicyError(f"The project policy file {name} {reason}.")


def load_policy(path: Path, root: Path) -> Policy:
    if path.is_symlink():
        raise _unreadable_policy(path, root)
    try:
        raw = read_explicit_file_bytes(root, path, MAX_POLICY_BYTES)
    except PathError as error:
        raise _unreadable_policy(path, root) from error
    try:
        contributor = load_contributor(root)
    except ContributorError as error:
        if error.fix is not None:
            raise
        command = setup_command(setup_hook=declares_setup_hook(root))
        raise ContributorError(
            str(error), f"delete {CONTRIBUTOR_PATH} and run `{command}`."
        ) from error
    return parse_policy(raw, root, contributor)
