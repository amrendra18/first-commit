import unicodedata
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from first_commit.git import IgnoreStateError, require_ignored
from first_commit.models import Result
from first_commit.paths import (
    PathError,
    PathPermissionsError,
    confined_path,
    read_regular_bytes,
)

MAX_PRIVATE_VALUES_BYTES = 64 * 1024
MAX_PRIVATE_VALUES = 256
MAX_PRIVATE_VALUE_CHARACTERS = 1024
PRIVATE_VALUES_SUBJECT = "Private-values file"
PRIVATE_VALUE_MASK = "<private value>"


class PrivateValuesError(ValueError):
    pass


def _read_text(path: Path, relative_path: str) -> str:
    try:
        raw = read_regular_bytes(path, MAX_PRIVATE_VALUES_BYTES, 0o077)
        return raw.decode("utf-8")
    except PathPermissionsError as error:
        raise PrivateValuesError(
            "Private-values file permissions are too broad.\n"
            f"fix: run `chmod 600 {relative_path}`."
        ) from error
    except PathError as error:
        raise PrivateValuesError(
            "Private-values file is unreadable or exceeds the size limit."
        ) from error
    except UnicodeDecodeError as error:
        raise PrivateValuesError(
            "Private-values file is not valid UTF-8 text."
        ) from error


def _parse_values(text: str) -> tuple[str, ...]:
    values = []
    for line in text.splitlines():
        value = unicodedata.normalize("NFC", line.strip()).casefold()
        if not value or value.startswith("#"):
            continue
        if len(value) > MAX_PRIVATE_VALUE_CHARACTERS:
            raise PrivateValuesError("Private value exceeds the size limit.")
        values.append(value)
        if len(values) > MAX_PRIVATE_VALUES:
            raise PrivateValuesError("Private-values count exceeds the limit.")
    if len(set(values)) != len(values):
        raise PrivateValuesError("Private-values file contains a duplicate value.")
    return tuple(values)


def load_private_values(root: Path, relative_path: str) -> tuple[str, ...]:
    try:
        path = confined_path(root, relative_path)
    except PathError as error:
        raise PrivateValuesError("Private-values path is invalid.") from error
    if path.is_symlink():
        raise PrivateValuesError("Private-values file must be a regular file.")
    if not path.exists():
        return ()
    try:
        require_ignored(root, relative_path, PRIVATE_VALUES_SUBJECT)
    except IgnoreStateError as error:
        raise PrivateValuesError(str(error)) from error
    return _parse_values(_read_text(path, relative_path))


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
