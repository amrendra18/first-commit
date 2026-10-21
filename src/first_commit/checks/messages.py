import re
from collections.abc import Iterator, Sequence

from first_commit.characters import has_control_characters
from first_commit.models import Candidate, Finding, Severity, capped

TYPES = (
    "feat|fix|docs|style|refactor|test|build|chore|perf|ci|deps|revert|security|infra"
    "|release"
)
HEADER = re.compile(
    r"(?:" + TYPES + r")(?:\([a-z0-9]+(?:-[a-z0-9]+)*\))?!?: (?P<subject>\S.*)"
)
GENERATED = re.compile(r"(?:Merge |Revert |fixup! |squash! |amend! )\S")
SECTIONS = ("Why:", "Changes:", "Test Plan:", "Risks:")
PLACEHOLDERS = ("<reason>", "<changes>", "<commands and results>", "<risks>")
MAX_SUBJECT_CHARS = 100
PREFERRED_SUBJECT_CHARS = 72
HEADER_SUMMARY = (
    "Use <type>(<optional-kebab-case-scope>)!: <subject> with a supported type, "
    "optional !, and no leading whitespace or controls."
)
SECTIONS_SUMMARY = (
    "Add nonempty Why:, Changes:, Test Plan:, and Risks: sections once, in that order."
)


def _valid_sections(lines: Sequence[str], subject_index: int) -> bool:
    body = [line.removesuffix("\r") for line in lines[subject_index + 1 :]]
    headings = [(index, line) for index, line in enumerate(body) if line in SECTIONS]
    if [heading for _, heading in headings] != list(SECTIONS):
        return False
    for position, (start, _) in enumerate(headings):
        end = headings[position + 1][0] if position + 1 < len(headings) else len(body)
        content = []
        for line in body[start + 1 : end]:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            normalized = stripped.removeprefix("-").strip()
            if normalized in PLACEHOLDERS:
                continue
            content.append(stripped)
        if not content:
            return False
    return True


def _message_problems(
    candidate: Candidate, *, require_sections: bool
) -> Iterator[Finding]:
    lines = candidate.content.decode("utf-8").split("\n")
    subject_index, subject = next(
        (
            (index, line.removesuffix("\r"))
            for index, line in enumerate(lines)
            if line.strip() and not line.startswith("#")
        ),
        (0, ""),
    )
    for rule_id, severity, summary in _subject_problems(
        subject, lines, subject_index, require_sections=require_sections
    ):
        yield Finding(
            rule_id=rule_id,
            path=candidate.path,
            summary=summary,
            severity=severity,
            line=subject_index + 1,
        )


def message_findings(
    candidate: Candidate, *, max_findings: int, require_sections: bool = True
) -> list[Finding]:
    return capped(
        _message_problems(candidate, require_sections=require_sections), max_findings
    )


def _subject_problems(
    subject: str,
    lines: Sequence[str],
    subject_index: int,
    *,
    require_sections: bool,
) -> list[tuple[str, Severity, str]]:
    controls = has_control_characters(subject)
    match = HEADER.fullmatch(subject)
    if not controls and GENERATED.match(subject):
        return []
    if controls or match is None:
        return [("message.header", Severity.ERROR, HEADER_SUMMARY)]
    subject = match.group("subject")
    if len(subject) > MAX_SUBJECT_CHARS:
        return [
            (
                "message.subject-length",
                Severity.ERROR,
                (
                    f"Subject exceeds {MAX_SUBJECT_CHARS} characters; move details "
                    "to the body."
                ),
            )
        ]
    problems = []
    if require_sections and not _valid_sections(lines, subject_index):
        problems.append(("message.sections", Severity.ERROR, SECTIONS_SUMMARY))
    if len(subject) > PREFERRED_SUBJECT_CHARS:
        problems.append(
            (
                "message.subject-length",
                Severity.WARNING,
                (
                    f"Prefer a subject within {PREFERRED_SUBJECT_CHARS} characters; "
                    "move details to the body."
                ),
            )
        )
    if subject.endswith((".", "!", "?")):
        problems.append(
            (
                "message.subject-punctuation",
                Severity.WARNING,
                "Prefer a subject without trailing punctuation.",
            )
        )
    return problems
