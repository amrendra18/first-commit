import re
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import NamedTuple

from first_commit.checks.privacy import PrivacyPolicy, privacy_findings
from first_commit.git import (
    COMMAND_LINE_CONFIG,
    CONFIG_FILE_CHOICES,
    GitError,
    run_git,
)
from first_commit.gitleaks_blobs import MESSAGE_PATH, scan_message
from first_commit.models import Candidate, Finding, Origin, Severity

CUT_LINE = b"------------------------ >8 ------------------------\n"
COMMENT_CHAR_KEY = b"core.commentchar"
COMMENT_STRING_KEY = b"core.commentstring"
# Git reads core.commentString from this version on.
COMMENT_STRING_VERSION = (2, 45)
GIT_VERSION = re.compile(rb"git version (\d+)\.(\d+)")
CLEANUP_KEY = b"commit.cleanup"
# Git sets GIT_EDITOR to this for the commit-msg hook when no editor opened, as
# with -m or -F.
NO_EDITOR = ":"
# Configuration from `git -c` or from other files that run_git drops, so the hook
# cannot read the cleanup mode or comment string Git uses when one is set.
CONFIG_OVERRIDES = (*COMMAND_LINE_CONFIG, *CONFIG_FILE_CHOICES, "GIT_CONFIG")


def _strips_comments(cleanup: bytes | None, environment: Mapping[str, str]) -> bool:
    if any(name in environment for name in CONFIG_OVERRIDES):
        return False
    # As Git's get_cleanup_mode, unset and default strip only when an editor runs.
    # Here strip needs one too, so a hidden --cleanup=verbatim with -m still blocks.
    return (
        cleanup in (None, b"default", b"strip")
        and environment.get("GIT_EDITOR") != NO_EDITOR
    )


class MessageParts(NamedTuple):
    above: bytes
    below: bytes
    # Git removes the lines of `above` that start with this string; None when it
    # keeps them.
    comment: bytes | None


def _git_version(root: Path) -> tuple[int, int] | None:
    try:
        found = GIT_VERSION.match(run_git(root, ("version",)))
    except GitError:
        return None
    return None if found is None else (int(found[1]), int(found[2]))


def _message_settings(
    root: Path, environment: Mapping[str, str]
) -> tuple[bytes | None, bool]:
    try:
        listed = run_git(root, ("config", "--null", "--list"))
    except GitError:
        return None, False
    comment = char = b"#"
    from_string = False
    cleanup = None
    for entry in listed.split(b"\0"):
        key, _, value = entry.partition(b"\n")
        if key == COMMENT_CHAR_KEY:
            comment = char = value
            from_string = False
        elif key == COMMENT_STRING_KEY:
            comment = value
            from_string = True
        elif key == CLEANUP_KEY:
            cleanup = value
    if from_string:
        version = _git_version(root)
        if version is None:
            return None, False
        if version < COMMENT_STRING_VERSION:
            comment = char
    # With "auto", Git picks the character for each commit, so neither a scissors
    # line nor a comment line can be recognized here; the whole file is checked.
    if not comment or b"\n" in comment or comment.lower() == b"auto":
        return None, False
    return comment, _strips_comments(cleanup, environment)


def split_message(
    root: Path, content: bytes, environment: Mapping[str, str]
) -> MessageParts:
    # Git removes the scissors line and the diff below it before it records the
    # message, and matches the line exactly as here (wt_status_locate_end); it
    # removes comment lines as strbuf_stripspace does. Security limit: whether Git
    # removes either also depends on -v and --cleanup, which a commit-msg hook
    # cannot see, so a finding there only warns here; the pre-push and history
    # scans block it in the message Git recorded.
    comment, strips = _message_settings(root, environment)
    if comment is None:
        return MessageParts(content, b"", None)
    cut = comment + b" " + CUT_LINE
    if content.startswith(cut):
        above = b""
    else:
        found = content.find(b"\n" + cut)
        above = content if found < 0 else content[: found + 1]
    return MessageParts(above, content[len(above) :], comment if strips else None)


BELOW_SCISSORS = (
    " The text below the scissors line is committed unless Git removes it, as git "
    "commit -v does; the pre-push hook blocks it if it is committed."
)
COMMENT_LINE = (
    " A comment line is committed unless Git removes it, as git commit does when it "
    "opens an editor; the pre-push hook blocks it if it is committed."
)


def _lines(content: bytes) -> list[bytes]:
    lines = [line + b"\n" for line in content.split(b"\n")]
    lines[-1] = lines[-1].removesuffix(b"\n")
    return lines if lines[-1] else lines[:-1]


def _placed(finding: Finding, numbers: Sequence[int], warning: str | None) -> Finding:
    line = None if finding.line is None else numbers[finding.line - 1]
    if warning is None:
        return replace(finding, line=line)
    return replace(
        finding,
        line=line,
        severity=Severity.WARNING,
        summary=finding.summary + warning,
    )


def message_secret_findings(
    root: Path,
    parts: MessageParts,
    privacy: PrivacyPolicy,
    *,
    max_findings: int,
) -> list[Finding]:
    above = list(enumerate(_lines(parts.above), 1))
    below = list(enumerate(_lines(parts.below), len(above) + 1))
    kept: list[tuple[int, bytes]] = []
    comments: list[tuple[int, bytes]] = []
    for item in above:
        is_comment = parts.comment is not None and item[1].startswith(parts.comment)
        (comments if is_comment else kept).append(item)
    groups = (
        (kept, None),
        (comments, COMMENT_LINE),
        (below, BELOW_SCISSORS),
    )
    findings: list[Finding] = []
    for lines, warning in groups:
        if not lines:
            continue
        numbers = [number for number, _ in lines]
        text = b"".join(line for _, line in lines)
        candidate = Candidate(MESSAGE_PATH, text, Origin.MESSAGE)
        found = privacy_findings(
            candidate, privacy, max_findings=max_findings - len(findings)
        )
        found += scan_message(
            root, text, max_findings=max_findings - len(findings) - len(found)
        )
        findings += (_placed(item, numbers, warning) for item in found)
    return findings
