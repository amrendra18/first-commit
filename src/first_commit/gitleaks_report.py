import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import NamedTuple

from first_commit.json_values import line_number
from first_commit.paths import (
    MEBIBYTE,
    PathError,
    confined_path,
    read_regular_bytes,
    relative_path_problem,
)

MAX_REPORT_BYTES = 4 * MEBIBYTE
MAX_REPORT_ENTRIES = 10000
MAX_REPORT_PATH_CHARS = 4096
MAX_REPORT_LINE = 1 << 31
RULE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
# The only fields read: the rule matches .gitleaksignore entries and is never shown.
REPORT_FIELDS: tuple[str, ...] = ("RuleID", "File", "StartLine")


class ReportEntry(NamedTuple):
    rule: str | None
    path: str | None
    line: int | None


class ReportLocation(NamedTuple):
    path: str | None
    line: int | None


UNKNOWN_ENTRY = ReportEntry(None, None, None)


def _report_path(root: Path, value: object) -> str | None:
    if (
        not isinstance(value, str)
        or len(value) > MAX_REPORT_PATH_CHARS
        or relative_path_problem(value) is not None
    ):
        return None
    try:
        confined_path(root, value)
    except (PathError, OSError, ValueError):
        return None
    return value


def _report_rule(value: object) -> str | None:
    if not isinstance(value, str) or RULE.fullmatch(value) is None:
        return None
    return value


def report_fields(entry: Mapping[str, object]) -> tuple[object, ...]:
    return tuple(entry.get(key) for key in REPORT_FIELDS)


def _report_entry(root: Path, entry: object) -> ReportEntry:
    if not isinstance(entry, Mapping):
        return UNKNOWN_ENTRY
    rule, path, line = report_fields(entry)
    return ReportEntry(
        _report_rule(rule), _report_path(root, path), line_number(line, MAX_REPORT_LINE)
    )


# A missing, oversized, or malformed report gives one unknown entry: the scope fails.
def report_entries(root: Path, report: Path) -> tuple[ReportEntry, ...]:
    try:
        entries = json.loads(
            read_regular_bytes(report, MAX_REPORT_BYTES).decode("utf-8")
        )
    except (PathError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return (UNKNOWN_ENTRY,)
    if not isinstance(entries, list) or not entries:
        return (UNKNOWN_ENTRY,)
    return tuple(_report_entry(root, entry) for entry in entries[:MAX_REPORT_ENTRIES])


def report_locations(entries: tuple[ReportEntry, ...]) -> list[ReportLocation]:
    locations = {
        ReportLocation(entry.path, entry.line if entry.path is not None else None)
        for entry in entries
    }
    return sorted(locations, key=lambda item: (item.path or "", item.line or 0))
