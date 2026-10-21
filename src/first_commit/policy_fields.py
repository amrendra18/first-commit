import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from first_commit.characters import has_control_characters
from first_commit.contributor import EMAIL, MAX_EMAIL_CHARS
from first_commit.json_values import line_number
from first_commit.paths import MEBIBYTE, relative_path_problem

DEFAULT_LIMITS = {
    "max_files": 10000,
    "max_file_bytes": 10 * MEBIBYTE,
    "max_findings": 1000,
    "max_message_bytes": MEBIBYTE,
}
PRIVACY_DETECTOR_RULES = (
    "privacy.private-key",
    "privacy.github-token",
    "privacy.aws-access-key",
    "privacy.ssh-fingerprint",
    "privacy.user-home-path",
    "privacy.unapproved-email",
)
MAX_PUBLIC_EMAILS = 32
MAX_EXCEPTIONS = 128
MAX_EXCEPTION_LINE = DEFAULT_LIMITS["max_file_bytes"]
MAX_FORBIDDEN_PATHS = 128
MAX_FORBIDDEN_VALUE_CHARS = 1024
MAX_REASON_CHARS = 500
MIN_SUFFIX_CHARS = 2
FORBIDDEN_MATCHES = {"exact", "prefix", "suffix"}
GLOB_CHARACTERS = "*?[]"
DIGEST = re.compile(r"[0-9a-f]{64}")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class EnvironmentExceptionEntry:
    path: str
    reason: str


@dataclass(frozen=True)
class LiteralExceptionEntry:
    path: str
    line: int
    sha256: str
    reason: str


@dataclass(frozen=True)
class DetectorExceptionEntry:
    path: str
    line: int
    rule: str
    sha256: str
    reason: str


@dataclass(frozen=True)
class ImmutableVendorFile:
    path: str
    sha256: str
    reason: str


@dataclass(frozen=True)
class ForbiddenPath:
    match: str
    value: str
    reason: str


def _object(value: object, label: str, *, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        accepted = ", ".join(sorted(fields))
        raise PolicyError(f"{label} has invalid fields; use exactly {accepted}.")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{label} must be non-empty text.")
    return value


def _entries(value: object, label: str, *, limit: int | None) -> list[tuple[str, Any]]:
    if not isinstance(value, list):
        raise PolicyError(f"{label} must be an array.")
    if limit is not None and len(value) > limit:
        raise PolicyError(f"{label} count exceeds the limit of {limit}.")
    return [(f"{label}[{index}]", item) for index, item in enumerate(value)]


def _has_glob(value: str) -> bool:
    return any(character in value for character in GLOB_CHARACTERS)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise PolicyError(
            f"{label} must be a SHA-256 digest of 64 lowercase hex digits."
        )
    return value


def _line(value: object, label: str) -> int:
    line = line_number(value, MAX_EXCEPTION_LINE)
    if line is None:
        raise PolicyError(
            f"{label} must be a line number from 1 to {MAX_EXCEPTION_LINE}."
        )
    return line


def _reason(value: object, label: str) -> str:
    reason = _string(value, label)
    if (
        reason != reason.strip()
        or len(reason) > MAX_REASON_CHARS
        or has_control_characters(reason)
    ):
        raise PolicyError(
            f"{label} must be one line of at most {MAX_REASON_CHARS} characters, "
            "without control characters or surrounding spaces."
        )
    return reason


def _path(value: object, label: str, *, root: Path) -> str:
    raw = _string(value, label)
    problem = relative_path_problem(raw)
    if problem is not None:
        raise PolicyError(
            f"{label} must be a normalized repository-relative path: it {problem}."
        )
    try:
        (root.resolve() / raw).resolve(strict=False).relative_to(root.resolve())
    except ValueError as error:
        raise PolicyError(f"{label} escapes the repository.") from error
    return raw


def _exact_path(value: object, label: str, *, root: Path) -> str:
    path = _path(value, label, root=root)
    if _has_glob(path):
        raise PolicyError(f"{label} must be an exact path without glob characters.")
    return path


def _require_unique(keys: list[Any], label: str, *, key_name: str) -> None:
    seen = set()
    for index, key in enumerate(keys):
        if key in seen:
            entry = f"{label}[{index}]"
            raise PolicyError(f"{entry} duplicates the {key_name} of an earlier entry.")
        seen.add(key)


def flag(data: dict[str, Any], name: str, *, default: bool) -> bool:
    value = data.get(name, default)
    if not isinstance(value, bool):
        raise PolicyError(f"{name} must be true or false.")
    return value


def public_emails(value: object, label: str) -> tuple[str, ...]:
    emails = []
    for entry, email in _entries(value, label, limit=MAX_PUBLIC_EMAILS):
        if isinstance(email, str) and len(email) > MAX_EMAIL_CHARS:
            raise PolicyError(f"{entry} is longer than {MAX_EMAIL_CHARS} characters.")
        if not isinstance(email, str) or EMAIL.fullmatch(email) is None:
            raise PolicyError(f"{entry} must be a single email address.")
        emails.append(email)
    _require_unique(emails, label, key_name="address")
    return tuple(emails)


def environment_exceptions(
    value: object, label: str, *, root: Path
) -> tuple[EnvironmentExceptionEntry, ...]:
    exceptions = []
    for entry, item in _entries(value, label, limit=None):
        fact = _object(item, entry, fields={"path", "reason"})
        exceptions.append(
            EnvironmentExceptionEntry(
                _exact_path(fact["path"], f"{entry}.path", root=root),
                _reason(fact["reason"], f"{entry}.reason"),
            )
        )
    _require_unique([item.path for item in exceptions], label, key_name="path")
    return tuple(exceptions)


def literal_exceptions(
    value: object, label: str, *, root: Path
) -> tuple[LiteralExceptionEntry, ...]:
    exceptions = []
    for entry, item in _entries(value, label, limit=MAX_EXCEPTIONS):
        fact = _object(item, entry, fields={"path", "line", "sha256", "reason"})
        exceptions.append(
            LiteralExceptionEntry(
                _exact_path(fact["path"], f"{entry}.path", root=root),
                _line(fact["line"], f"{entry}.line"),
                _digest(fact["sha256"], f"{entry}.sha256"),
                _reason(fact["reason"], f"{entry}.reason"),
            )
        )
    _require_unique(
        [(item.path, item.line) for item in exceptions],
        label,
        key_name="path and line",
    )
    return tuple(exceptions)


def _rule(value: object, label: str) -> str:
    if value not in PRIVACY_DETECTOR_RULES:
        raise PolicyError(f"{label} must name a supported privacy rule.")
    return str(value)


def detector_exceptions(
    value: object, label: str, *, root: Path
) -> tuple[DetectorExceptionEntry, ...]:
    exceptions = []
    for entry, item in _entries(value, label, limit=MAX_EXCEPTIONS):
        fact = _object(item, entry, fields={"path", "line", "rule", "sha256", "reason"})
        exceptions.append(
            DetectorExceptionEntry(
                _exact_path(fact["path"], f"{entry}.path", root=root),
                _line(fact["line"], f"{entry}.line"),
                _rule(fact["rule"], f"{entry}.rule"),
                _digest(fact["sha256"], f"{entry}.sha256"),
                _reason(fact["reason"], f"{entry}.reason"),
            )
        )
    _require_unique(
        [(item.path, item.line, item.rule) for item in exceptions],
        label,
        key_name="path, line, and rule",
    )
    return tuple(exceptions)


def _forbidden_match(value: object, label: str) -> str:
    match = _string(value, label)
    if match not in FORBIDDEN_MATCHES:
        raise PolicyError(f"{label} must be exact, prefix, or suffix.")
    return match


def _forbidden_suffix(raw: str, label: str) -> str:
    if (
        len(raw) < MIN_SUFFIX_CHARS
        or not raw.startswith(".")
        or not raw.strip(".")
        or raw != raw.strip()
        or "/" in raw
        or "\\" in raw
        or has_control_characters(raw)
    ):
        raise PolicyError(f"{label} must be a normalized extension.")
    return raw


def _forbidden_value(value: object, label: str, *, match: str, root: Path) -> str:
    raw = _string(value, label)
    if len(raw) > MAX_FORBIDDEN_VALUE_CHARS or _has_glob(raw):
        raise PolicyError(f"{label} is invalid or exceeds the limit.")
    if match == "exact":
        return _path(raw, label, root=root)
    if match == "prefix":
        if not raw.endswith("/") or raw.endswith("//"):
            raise PolicyError(f"{label} must be a path ending in '/'.")
        return _path(raw[:-1], label, root=root) + "/"
    return _forbidden_suffix(raw, label)


def forbidden_paths(
    value: object, label: str, *, root: Path
) -> tuple[ForbiddenPath, ...]:
    forbidden = []
    for entry, item in _entries(value, label, limit=MAX_FORBIDDEN_PATHS):
        fact = _object(item, entry, fields={"match", "value", "reason"})
        match = _forbidden_match(fact["match"], f"{entry}.match")
        forbidden.append(
            ForbiddenPath(
                match,
                _forbidden_value(
                    fact["value"], f"{entry}.value", match=match, root=root
                ),
                _reason(fact["reason"], f"{entry}.reason"),
            )
        )
    _require_unique(
        [(item.match, item.value) for item in forbidden],
        label,
        key_name="match and value",
    )
    return tuple(forbidden)


def _vendor_path(value: object, label: str, *, root: Path) -> str:
    path = _path(value, label, root=root)
    if not path.startswith("vendor/") or _has_glob(path):
        raise PolicyError(f"{label} must be exact and under vendor/.")
    parts = PurePosixPath(path).parts
    if any(
        root.joinpath(*parts[:length]).is_symlink() for length in range(1, len(parts))
    ):
        raise PolicyError(f"{label} must not traverse symlinks.")
    return path


def immutable_vendor_files(
    value: object, label: str, *, root: Path
) -> tuple[ImmutableVendorFile, ...]:
    files = []
    for entry, item in _entries(value, label, limit=DEFAULT_LIMITS["max_files"]):
        fact = _object(item, entry, fields={"path", "sha256", "reason"})
        files.append(
            ImmutableVendorFile(
                _vendor_path(fact["path"], f"{entry}.path", root=root),
                _digest(fact["sha256"], f"{entry}.sha256"),
                _reason(fact["reason"], f"{entry}.reason"),
            )
        )
    _require_unique([item.path for item in files], label, key_name="path")
    return tuple(files)
