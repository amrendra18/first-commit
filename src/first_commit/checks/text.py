import re
from collections.abc import Iterator

from first_commit.characters import has_control_characters
from first_commit.models import Candidate, Finding, capped

NO_COMMIT_LINES = frozenset(
    {
        "<!-- @no-commit -->",
        "# @no-commit",
        "// @no-commit",
        "; @no-commit",
        "-- @no-commit",
        "/* @no-commit */",
    }
)
# As in Git, a marker is 7 marker characters alone or before whitespace, so a
# Markdown heading underline of 8 or more "=" is not one.
MERGE_MARKER = re.compile(r"(?:<{7}|\|{7}|={7}|>{7})(?:\s|$)")


def _decoded_text(candidate: Candidate) -> str | None:
    if b"\0" in candidate.content:
        return None
    try:
        return candidate.content.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _no_commit_lines(candidate: Candidate) -> Iterator[Finding]:
    content = _decoded_text(candidate)
    if content is None:
        return
    # Lines are numbered by \n like the other checks, but an editor may show any
    # other line break inside one of them as a new line, so each part is checked.
    for number, line in enumerate(content.split("\n"), 1):
        if any(part.strip() in NO_COMMIT_LINES for part in line.splitlines()):
            yield Finding(
                rule_id="scaffold.no-commit",
                path=candidate.path,
                summary="Generated section must be reviewed or removed before committing.",
                line=number,
            )


def no_commit_findings(candidate: Candidate, *, max_findings: int) -> list[Finding]:
    return capped(_no_commit_lines(candidate), max_findings)


def _line_findings(
    path: str, line: str, line_number: int, *, vendor: bool
) -> list[Finding]:
    findings = []
    if not vendor and line.endswith((" ", "\t")):
        findings.append(
            Finding(
                rule_id="text.trailing-whitespace",
                path=path,
                summary="Line has trailing whitespace.",
                line=line_number,
            )
        )
    if MERGE_MARKER.match(line):
        findings.append(
            Finding(
                rule_id="text.merge-marker",
                path=path,
                summary="Line contains a merge-conflict marker.",
                line=line_number,
            )
        )
    if has_control_characters(line, allowed="\t"):
        findings.append(
            Finding(
                rule_id="text.control-character",
                path=path,
                summary="Line contains an unsupported control character.",
                line=line_number,
            )
        )
    return findings


def _text_problems(
    candidate: Candidate, *, immutable_vendor: bool
) -> Iterator[Finding]:
    text = _decoded_text(candidate)
    if text is None:
        if b"\0" not in candidate.content:
            yield Finding(
                rule_id="text.invalid-utf8",
                path=candidate.path,
                summary="Text is not valid UTF-8.",
            )
        return
    for line_number, raw_line in enumerate(text.split("\n"), 1):
        line = raw_line.removesuffix("\r")
        yield from _line_findings(
            candidate.path, line, line_number, vendor=immutable_vendor
        )
    if (
        not immutable_vendor
        and candidate.content
        and not candidate.content.endswith(b"\n")
    ):
        yield Finding(
            rule_id="text.final-newline",
            path=candidate.path,
            summary="Text file has no final newline.",
        )


def text_findings(
    candidate: Candidate, *, max_findings: int, immutable_vendor: bool = False
) -> list[Finding]:
    return capped(
        _text_problems(candidate, immutable_vendor=immutable_vendor), max_findings
    )
