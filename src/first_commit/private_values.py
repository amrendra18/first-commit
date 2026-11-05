import os
import stat
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import replace
from pathlib import Path

from first_commit.git import IgnoreStateError, main_worktree, require_ignored
from first_commit.machine_identity import config_folder, xdg_config_home
from first_commit.models import Result
from first_commit.paths import (
    PathError,
    PathPermissionsError,
    confined_path,
    read_open_file,
    read_regular_bytes,
)

MAX_PRIVATE_VALUES_BYTES = 64 * 1024
MAX_PRIVATE_VALUES = 256
MAX_PRIVATE_VALUE_CHARACTERS = 1024
PRIVATE_VALUES_SUBJECT = "Private-values file"
PRIVATE_VALUE_MASK = "<private value>"
USER_VALUES_NAME = "private-values.txt"


class PrivateValuesError(ValueError):
    pass


# Without a chmod fix, the file is the user-level list: a link is followed, and
# a broad mode is fixed or reported instead of refused.
def _read_text(path: Path, label: str, chmod_fix: str | None) -> str:
    try:
        if chmod_fix is None:
            raw = _read_user_list(path, label)
        else:
            raw = read_regular_bytes(path, MAX_PRIVATE_VALUES_BYTES, 0o077)
        return raw.decode("utf-8")
    except PathPermissionsError as error:
        raise PrivateValuesError(
            f"{label}: Private-values file permissions are too broad.\n"
            f"fix: {chmod_fix}."
        ) from error
    except PathError as error:
        raise PrivateValuesError(
            f"{label}: Private-values file is unreadable or exceeds the size limit."
        ) from error
    except UnicodeDecodeError as error:
        raise PrivateValuesError(
            f"{label}: Private-values file is not valid UTF-8 text."
        ) from error


def _parse_values(text: str, label: str) -> tuple[str, ...]:
    values = []
    for line in text.splitlines():
        value = unicodedata.normalize("NFC", line.strip()).casefold()
        if not value or value.startswith("#"):
            continue
        if len(value) > MAX_PRIVATE_VALUE_CHARACTERS:
            raise PrivateValuesError(f"{label}: Private value exceeds the size limit.")
        values.append(value)
        if len(values) > MAX_PRIVATE_VALUES:
            raise PrivateValuesError(
                f"{label}: Private-values count exceeds the limit."
            )
    if len(set(values)) != len(values):
        raise PrivateValuesError(
            f"{label}: Private-values file contains a duplicate value."
        )
    return tuple(values)


def user_values_path(environment: Mapping[str, str] | None = None) -> Path:
    return config_folder(environment) / USER_VALUES_NAME


# Names the user-level list without the home folder, which may hold a private value.
def user_values_label(environment: Mapping[str, str] | None = None) -> str:
    values = os.environ if environment is None else environment
    base = "$XDG_CONFIG_HOME" if xdg_config_home(values) else "~/.config"
    return f"{base}/first-commit/{USER_VALUES_NAME}"


# The user-level list may link to a file kept elsewhere, such as a versioned copy.
# A checkout can reset that file's mode, so a broad mode is fixed or reported,
# never a reason to stop.
def _user_values() -> tuple[str, ...]:
    path = user_values_path()
    if not os.path.lexists(path):
        return ()
    label = user_values_label()
    return _parse_values(_read_text(path, label, None), label)


def _not_regular(label: str) -> PrivateValuesError:
    return PrivateValuesError(
        "User private-values file must be a regular file or a link to one.\n"
        f"fix: replace {label} with a file, or a link to a file."
    )


# One open file serves the type check, the mode change, and the read, so a link
# changed between those steps cannot point any of them at another file.
def _read_user_list(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise _not_regular(label) from error
    except OSError as error:
        raise PathError("File cannot be read.") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise _not_regular(label)
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            _tighten(descriptor, metadata, label)
        return read_open_file(descriptor, MAX_PRIVATE_VALUES_BYTES, 0)
    except OSError as error:
        raise PathError("File cannot be read.") from error
    finally:
        os.close(descriptor)


def _tighten(descriptor: int, metadata: os.stat_result, label: str) -> None:
    mode = stat.S_IMODE(metadata.st_mode) & 0o700
    if metadata.st_uid == os.getuid():
        with suppress(OSError):
            os.fchmod(descriptor, mode)
            print(f"Private values: set {label} to mode {mode:03o}.", file=sys.stderr)
            return
    print(
        f"warning: {label} is open to other users; first-commit cannot set it "
        "to mode 600, so its owner should run `chmod 600` on it.",
        file=sys.stderr,
    )


def _project_values(root: Path, relative_path: str, where: str = "") -> tuple[str, ...]:
    label = relative_path + where
    try:
        path = confined_path(root, relative_path)
    except PathError as error:
        raise PrivateValuesError(f"{label}: Private-values path is invalid.") from error
    if path.is_symlink():
        raise PrivateValuesError(
            f"{label}: Private-values file must be a regular file."
        )
    if not path.exists():
        return ()
    try:
        require_ignored(root, relative_path, f"{label}: {PRIVATE_VALUES_SUBJECT}")
    except IgnoreStateError as error:
        raise PrivateValuesError(str(error)) from error
    fix = f"run `chmod 600 {relative_path}`{where}"
    return _parse_values(_read_text(path, label, fix), label)


# A linked worktree applies the main worktree's project list as well as its own.
def load_private_values(root: Path, relative_path: str) -> tuple[str, ...]:
    values = _user_values() + _project_values(root, relative_path)
    main = main_worktree(root)
    if main is not None:
        values += _project_values(main, relative_path, " in the main worktree")
    return tuple(dict.fromkeys(values))


# Values are stored NFC and casefolded, and casefolding can change a text's length
# ("ß" becomes "ss"), so each folded character remembers its source character.
def masked_path(path: str, values: Sequence[str]) -> str:
    text = unicodedata.normalize("NFC", path)
    sources = [
        index for index, character in enumerate(text) for _ in character.casefold()
    ]
    folded = text.casefold()
    hidden = [False] * len(text)
    for value in values:
        start = folded.find(value)
        while start >= 0:
            for position in range(start, start + len(value)):
                hidden[sources[position]] = True
            start = folded.find(value, start + 1)
    if not any(hidden):
        return path
    return "".join(
        PRIVATE_VALUE_MASK if hidden[index] else character
        for index, character in enumerate(text)
        if not (hidden[index] and index > 0 and hidden[index - 1])
    )


def masked_result(result: Result, values: Sequence[str]) -> Result:
    findings = tuple(
        replace(
            item,
            path=masked_path(item.path, values),
            summary=masked_path(item.summary, values),
        )
        for item in result.findings
    )
    return replace(result, findings=findings)
