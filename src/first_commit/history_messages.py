import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import replace
from pathlib import Path
from typing import NamedTuple

from first_commit.candidates import object_sizes
from first_commit.checks.privacy import PrivacyPolicy, privacy_findings, privacy_policy
from first_commit.git import (
    OBJECT_ID,
    SHORT_COMMIT,
    GitError,
    batch_check,
    cat_file_objects,
    listed_commits,
    run_git,
)
from first_commit.gitleaks import RULE_ID
from first_commit.gitleaks_blobs import MESSAGE_PATH, MESSAGE_SUMMARY, message_locations
from first_commit.models import Candidate, Finding, KeptFindings, Origin, Severity
from first_commit.policy import Policy
from first_commit.pushed import (
    HISTORY_REVISIONS,
    PushedScope,
    push_revisions,
    remote_patterns,
)

TAG_MESSAGE_PATH = "<tag-message>"
TAG_TARGET = re.compile(rb"object (" + OBJECT_ID.pattern.encode() + rb")\ntype tag\n")


class _MessageKind(NamedTuple):
    name: str
    path: str
    summary: str


class _MessageScan(NamedTuple):
    root: Path
    privacy: PrivacyPolicy
    pushed: frozenset[str]


COMMIT = _MessageKind("Commit", MESSAGE_PATH, MESSAGE_SUMMARY)
TAG = _MessageKind("Tag", TAG_MESSAGE_PATH, "Gitleaks reported a tag-message finding.")
ON_THE_REMOTE = (
    " This text is already on a remote: revoke a secret with its provider; "
    "rewording it needs a history rewrite."
)


def _object_sizes(
    root: Path, kind: _MessageKind, object_ids: Sequence[str], max_bytes: int
) -> dict[str, int]:
    label = f"{kind.name} message"
    return object_sizes(root, object_ids, kind.name.lower(), max_bytes, label)


def _commit_ids(root: Path, revisions: Sequence[str]) -> list[str]:
    return listed_commits(root, (*revisions, "--"))


def _commit_messages(
    root: Path, commits: Sequence[str], max_bytes: int
) -> Iterator[tuple[str, bytes]]:
    sizes = _object_sizes(root, COMMIT, commits, max_bytes)
    for commit, content in cat_file_objects(root, "commit", sizes):
        yield commit, content.partition(b"\n\n")[2]


def _tags_of(root: Path, tags: Sequence[str], commits: frozenset[str]) -> list[str]:
    peeled = batch_check(root, [f"{tag}^{{}}" for tag in tags])
    return [
        tag
        for tag, found in zip(tags, peeled, strict=True)
        if found is not None and found.kind == "commit" and found.object_id in commits
    ]


def _tag_messages(
    root: Path, max_bytes: int, pushed_commits: frozenset[str] | None
) -> Iterator[tuple[str, bytes]]:
    listed = run_git(root, ("for-each-ref", "--format=%(objectname) %(objecttype)"))
    pending = []
    for line in listed.decode("ascii").splitlines():
        object_id, _, object_type = line.partition(" ")
        if OBJECT_ID.fullmatch(object_id) is None:
            raise GitError("Git returned an invalid tag.")
        if object_type == "tag":
            pending.append(object_id)
    # A push reads only the tags of the commits it adds, so an old tag the remote
    # already has never blocks it.
    if pushed_commits is not None:
        pending = _tags_of(root, pending, pushed_commits)
    seen: set[str] = set()
    while pending:
        level = [tag for tag in dict.fromkeys(pending) if tag not in seen]
        seen.update(level)
        pending = []
        sizes = _object_sizes(root, TAG, level, max_bytes)
        for tag, content in cat_file_objects(root, "tag", sizes):
            header, _, message = content.partition(b"\n\n")
            target = TAG_TARGET.match(header)
            if target is not None:
                pending.append(target[1].decode("ascii"))
            yield tag, message


def _remote_commits(root: Path) -> frozenset[str]:
    # A ref under refs/remotes/ of no configured remote may be stale or hand-made.
    patterns = remote_patterns(root)
    if not patterns:
        return frozenset()
    return frozenset(listed_commits(root, (*patterns, "--")))


class MessageScope(NamedTuple):
    pushed: PushedScope | None
    warn_on_remote: bool = False
    # The commits to read when pushed is None.
    revisions: tuple[str, ...] = HISTORY_REVISIONS


def _named(
    finding: Finding, kind: _MessageKind, object_id: str | None, pushed: frozenset[str]
) -> Finding:
    if object_id is None:
        return finding
    named = replace(
        finding, summary=f"{kind.name} {object_id[:SHORT_COMMIT]}: {finding.summary}"
    )
    if object_id not in pushed:
        return named
    return replace(
        named,
        severity=Severity.WARNING,
        summary=named.summary + ON_THE_REMOTE,
        on_remote=True,
    )


# Reads on past warnings, such as findings in commits a remote holds, so a later
# error still decides; it stops once kept holds only errors.
def _message_findings(
    scan: _MessageScan,
    kind: _MessageKind,
    messages: Iterable[tuple[str, bytes]],
    kept: KeptFindings,
) -> None:
    if kept.full():
        return

    def privacy_checked() -> Iterator[Candidate]:
        for object_id, message in messages:
            if kept.full():
                return
            candidate = Candidate(kind.path, message, Origin.MESSAGE)
            for item in privacy_findings(
                candidate, scan.privacy, max_findings=kept.room
            ):
                kept.add(_named(item, kind, object_id, scan.pushed))
            yield Candidate(object_id, message, Origin.MESSAGE)

    for object_id, line in message_locations(scan.root, privacy_checked()):
        if kept.full():
            break
        secret = Finding(
            rule_id=RULE_ID, path=kind.path, summary=kind.summary, line=line
        )
        kept.add(_named(secret, kind, object_id, scan.pushed))


def history_message_findings(
    root: Path,
    policy: Policy,
    private_values: Sequence[str],
    scope: MessageScope,
    *,
    max_findings: int,
) -> list[Finding]:
    pushed = scope.pushed
    revisions = scope.revisions if pushed is None else push_revisions(root, pushed)
    max_bytes = policy.max_message_bytes
    # Only check warns about a commit the remote has; a tag can be re-created
    # without a history rewrite, so a tag finding always blocks.
    scan = _MessageScan(
        root,
        privacy_policy(policy, private_values),
        _remote_commits(root) if scope.warn_on_remote else frozenset(),
    )
    commits = _commit_ids(root, revisions)
    kept = KeptFindings(max_findings)
    _message_findings(scan, COMMIT, _commit_messages(root, commits, max_bytes), kept)
    tags = _tag_messages(
        root, max_bytes, None if pushed is None else frozenset(commits)
    )
    _message_findings(scan._replace(pushed=frozenset()), TAG, tags, kept)
    return kept.items
