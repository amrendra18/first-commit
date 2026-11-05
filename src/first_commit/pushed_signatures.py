import re
from collections.abc import Iterator, Sequence
from pathlib import Path

from first_commit.candidates import object_sizes
from first_commit.contributor import setup_time
from first_commit.git import SHORT_COMMIT, cat_file_objects, listed_commits
from first_commit.gitleaks import HISTORY_SCOPE_PATH
from first_commit.models import Finding, capped
from first_commit.pushed import NO_SCOPE, PushedScope, signature_revisions

RULE_ID = "git.unsigned-commit"
# A SHA-1 repository signs in gpgsig, a SHA-256 one in gpgsig-sha256. Presence only:
# no command verifies a signature (ARCHITECTURE.md, Security rules 9).
SIGNATURE_HEADERS = (b"gpgsig ", b"gpgsig-sha256 ")
COMMITTER_TIME = re.compile(rb"committer .* (\d{1,18}) [+-]\d{4}")


# The commits of the push's revisions, parents before their children, so the first
# finding is the oldest commit.
def pushed_commits(root: Path, revisions: tuple[str, ...]) -> list[str]:
    return listed_commits(root, ("--reverse", "--topo-order", *revisions, "--"))


# The headers end at the first empty line; a continuation line starts with a space.
def _signed(content: bytes) -> bool:
    header = content.partition(b"\n\n")[0]
    return any(line.startswith(SIGNATURE_HEADERS) for line in header.split(b"\n"))


# The committer time decides, because an amend or a rebase updates it: a rewritten old
# commit counts as new. A time that cannot be read counts as new too.
def made_before(content: bytes, setup: int | None) -> bool:
    if setup is None:
        return False
    for line in content.partition(b"\n\n")[0].split(b"\n"):
        if line.startswith(b"committer "):
            match = COMMITTER_TIME.fullmatch(line)
            return match is not None and int(match[1]) < setup
    return False


def _unsigned(
    root: Path,
    commits: Sequence[str],
    max_bytes: int,
    setup: int | None,
    *,
    pushed: bool,
) -> Iterator[Finding]:
    sizes = object_sizes(root, commits, "commit", max_bytes, "Commit message")
    for commit, content in cat_file_objects(root, "commit", sizes):
        if not _signed(content) and not made_before(content, setup):
            short = commit[:SHORT_COMMIT]
            yield Finding(
                rule_id=RULE_ID,
                path=HISTORY_SCOPE_PATH,
                summary=f"Commit {short} has no signature.",
                commit=short,
                pushed=pushed,
            )


def unsigned_commit_findings(
    root: Path, scope: PushedScope | None, *, max_bytes: int, max_findings: int
) -> list[Finding]:
    if max_findings <= 0:
        return []
    commits = pushed_commits(root, signature_revisions(root, scope or NO_SCOPE))
    if not commits:
        return []
    return capped(
        _unsigned(root, commits, max_bytes, setup_time(root), pushed=True),
        max_findings,
    )


# What `check` reports early, so the first push holds no surprise. With no record the
# clone is not set up yet, and doctor already says so.
def unsigned_since_setup_findings(
    root: Path, *, max_bytes: int, max_findings: int
) -> list[Finding]:
    setup = setup_time(root)
    if setup is None or max_findings <= 0:
        return []
    commits = pushed_commits(root, signature_revisions(root, NO_SCOPE))
    if not commits:
        return []
    return capped(
        _unsigned(root, commits, max_bytes, setup, pushed=False), max_findings
    )
