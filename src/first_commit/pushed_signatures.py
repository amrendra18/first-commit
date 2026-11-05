from collections.abc import Iterator, Sequence
from pathlib import Path

from first_commit.candidates import object_sizes
from first_commit.git import SHORT_COMMIT, cat_file_objects, listed_commits
from first_commit.gitleaks import HISTORY_SCOPE_PATH
from first_commit.models import Finding, capped
from first_commit.pushed import NO_SCOPE, PushedScope, signature_revisions

RULE_ID = "git.unsigned-commit"
# A SHA-1 repository signs in gpgsig, a SHA-256 one in gpgsig-sha256. Presence only:
# no command verifies a signature (ARCHITECTURE.md, Security rules 9).
SIGNATURE_HEADERS = (b"gpgsig ", b"gpgsig-sha256 ")


# The commits of the push's revisions, parents before their children, so the first
# finding is the oldest commit.
def pushed_commits(root: Path, revisions: tuple[str, ...]) -> list[str]:
    return listed_commits(root, ("--reverse", "--topo-order", *revisions, "--"))


# The headers end at the first empty line; a continuation line starts with a space.
def _signed(content: bytes) -> bool:
    header = content.partition(b"\n\n")[0]
    return any(line.startswith(SIGNATURE_HEADERS) for line in header.split(b"\n"))


def _unsigned(root: Path, commits: Sequence[str], max_bytes: int) -> Iterator[Finding]:
    sizes = object_sizes(root, commits, "commit", max_bytes, "Commit message")
    for commit, content in cat_file_objects(root, "commit", sizes):
        if not _signed(content):
            short = commit[:SHORT_COMMIT]
            yield Finding(
                rule_id=RULE_ID,
                path=HISTORY_SCOPE_PATH,
                summary=f"Commit {short} has no signature.",
                commit=short,
                pushed=True,
            )


def unsigned_commit_findings(
    root: Path, scope: PushedScope | None, *, max_bytes: int, max_findings: int
) -> list[Finding]:
    if max_findings <= 0:
        return []
    commits = pushed_commits(root, signature_revisions(root, scope or NO_SCOPE))
    if not commits:
        return []
    return capped(_unsigned(root, commits, max_bytes), max_findings)
