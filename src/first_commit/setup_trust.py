import base64
import binascii
from collections.abc import Mapping
from enum import Enum
from pathlib import Path
from typing import NamedTuple

from first_commit.characters import has_control_characters
from first_commit.checks.identity import ALLOWED_SIGNERS_PATH, TRUST_SETTING
from first_commit.contributor import Contributor
from first_commit.git import GitError, is_tracked
from first_commit.models import SetupError
from first_commit.paths import PathError, confined_path, read_regular_bytes
from first_commit.setup_files import read_if_present

MAX_PUBLIC_KEY_BYTES = 8 * 1024
SSH_SIGNING_KEY_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)
PUBLIC_KEY_SUFFIX = ".pub"
MIN_KEY_FIELDS = 2
LENGTH_BYTES = 4
# Characters that widen a principal pattern, and the option that makes a key a CA.
PRINCIPAL_PATTERN_CHARACTERS = frozenset('*?!"')
CERTIFICATE_AUTHORITY = "cert-authority"
NOT_YOUR_FILE = (
    f"{ALLOWED_SIGNERS_PATH} must hold only lines of your email and your signing "
    "key; delete the file and run setup again, or make every line the line setup "
    "would write."
)


class TrustAction(Enum):
    KEEP_SETTING = "keep the existing setting"
    KEEP_FILE = "keep the existing file and set the setting"
    WRITE = "write the file and set the setting"
    PREVIEW_WRITE = "would write the file once the key is known"


class TrustPlan(NamedTuple):
    action: TrustAction
    content: bytes = b""

    @property
    def writes_file(self) -> bool:
        return self.action in (TrustAction.WRITE, TrustAction.PREVIEW_WRITE)

    @property
    def sets_setting(self) -> bool:
        return self.action is not TrustAction.KEEP_SETTING


def _public_key_bytes(root: Path, reference: str) -> bytes:
    unreadable = SetupError(
        "The signing key is not a readable bounded regular SSH "
        "public-key file; name it by an absolute path, a ~ path, or a path inside "
        "the repository."
    )
    try:
        expanded = Path(reference).expanduser()
    except RuntimeError as error:
        raise unreadable from error
    if expanded.name == PUBLIC_KEY_SUFFIX or not expanded.name.endswith(
        PUBLIC_KEY_SUFFIX
    ):
        raise SetupError(
            "The signing key must be an SSH public-key file whose name "
            "ends in .pub; a private-key reference is refused and never read."
        )
    try:
        path = expanded if expanded.is_absolute() else confined_path(root, reference)
        return read_regular_bytes(path, MAX_PUBLIC_KEY_BYTES)
    except PathError as error:
        raise unreadable from error


def _key_fields(raw: bytes) -> list[str]:
    if b"PRIVATE KEY" in raw.upper():
        raise SetupError(
            "The named public-key file holds private-key material; it is refused."
        )
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise SetupError("An SSH public key must be one ASCII line.") from error
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0].strip():
        raise SetupError("An SSH public-key file must hold exactly one key line.")
    fields = lines[0].split()
    if len(fields) < MIN_KEY_FIELDS or fields[0] not in SSH_SIGNING_KEY_TYPES:
        raise SetupError(
            "A signing key must be one of these SSH key types: "
            + ", ".join(SSH_SIGNING_KEY_TYPES)
            + "."
        )
    return fields


def check_signing_key(root: Path, reference: str) -> None:
    _key_fields(_public_key_bytes(root, reference))


def allowed_signers_line(root: Path, contributor: Contributor) -> bytes:
    fields = _key_fields(_public_key_bytes(root, contributor.signing_key))
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError) as error:
        raise SetupError("The named public key holds malformed key data.") from error
    label = fields[0].encode("ascii")
    if (
        blob[:LENGTH_BYTES] != len(label).to_bytes(LENGTH_BYTES, "big")
        or blob[LENGTH_BYTES : LENGTH_BYTES + len(label)] != label
    ):
        raise SetupError("The named public key holds malformed key data.")
    return f"{contributor.email} {fields[0]} {fields[1]}\n".encode()


def _split_outside_quotes(line: str) -> list[str] | None:
    tokens, current, quoted = [], "", False
    for character in line:
        if character == '"':
            quoted = not quoted
        if character in " \t" and not quoted:
            if current:
                tokens.append(current)
            current = ""
        else:
            current += character
    if current:
        tokens.append(current)
    return None if quoted else tokens


# An allowed-signers line is "principals [options] key-type key-data [comment]".
def _principals_for_key(line: str, key: tuple[str, str]) -> set[str] | None:
    tokens = _split_outside_quotes(line)
    if not tokens or has_control_characters(line, "\t"):
        return None
    principals, rest = tokens[0], tokens[1:]
    options = rest.pop(0) if rest and rest[0] not in SSH_SIGNING_KEY_TYPES else ""
    if (
        tuple(rest[:MIN_KEY_FIELDS]) != key
        or PRINCIPAL_PATTERN_CHARACTERS & set(principals)
        or CERTIFICATE_AUTHORITY in options.lower().split(",")
    ):
        return None
    return set(principals.split(","))


def _check_own_key(existing: bytes, expected: bytes) -> None:
    email, key_type, key_data = expected.decode("utf-8").split()
    try:
        lines = existing.decode("utf-8").split("\n")
    except UnicodeDecodeError as error:
        raise SetupError(NOT_YOUR_FILE) from error
    named = False
    for raw in lines:
        line = raw.removesuffix("\r").strip(" \t")
        if not line or line.startswith("#"):
            continue
        principals = _principals_for_key(line, (key_type, key_data))
        if principals is None:
            raise SetupError(NOT_YOUR_FILE)
        named = named or email in principals
    if not named:
        raise SetupError(
            f"{ALLOWED_SIGNERS_PATH} does not hold your email and signing key; add "
            "the line setup would write, or delete the file and run setup again."
        )


def _check_existing_file(
    root: Path,
    existing: bytes,
    contributor: Contributor | None,
    *,
    repository_exists: bool,
) -> None:
    if repository_exists:
        try:
            tracked = is_tracked(root, ALLOWED_SIGNERS_PATH)
        except GitError as error:
            raise SetupError(
                f"Git state of {ALLOWED_SIGNERS_PATH} cannot be determined."
            ) from error
        if tracked:
            raise SetupError(
                f"{ALLOWED_SIGNERS_PATH} is tracked by Git, so anyone who changes the "
                f"repository chooses whose signatures verify; run git rm --cached "
                f"{ALLOWED_SIGNERS_PATH}, then run setup again."
            )
    if contributor is not None:
        _check_own_key(existing, allowed_signers_line(root, contributor))


def trust_plan(
    root: Path,
    contributor: Contributor | None,
    *,
    trust_self: bool,
    settings: Mapping[str, str],
    repository_exists: bool = True,
) -> TrustPlan | None:
    if not trust_self:
        return None
    if settings.get(TRUST_SETTING):
        return TrustPlan(TrustAction.KEEP_SETTING)
    existing = read_if_present(confined_path(root, ALLOWED_SIGNERS_PATH))
    if existing is not None:
        _check_existing_file(
            root, existing, contributor, repository_exists=repository_exists
        )
        return TrustPlan(TrustAction.KEEP_FILE)
    if contributor is None:
        return TrustPlan(TrustAction.PREVIEW_WRITE)
    return TrustPlan(TrustAction.WRITE, allowed_signers_line(root, contributor))


def trust_line(plan: TrustPlan, *, dry_run: bool) -> str:
    parts = []
    if plan.writes_file:
        parts.append(("would write " if dry_run else "wrote ") + ALLOWED_SIGNERS_PATH)
    if plan.action is TrustAction.KEEP_SETTING:
        parts.append("retained existing " + TRUST_SETTING)
    if plan.action is TrustAction.KEEP_FILE:
        parts.append("retained existing " + ALLOWED_SIGNERS_PATH)
    if plan.sets_setting:
        parts.append(("would set " if dry_run else "set ") + TRUST_SETTING)
    return "Local signature trust: " + "; ".join(parts)
