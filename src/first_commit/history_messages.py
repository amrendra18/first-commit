import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import replace
from pathlib import Path
from typing import NamedTuple

from first_commit.candidates import CandidateError
from first_commit.checks.privacy import PrivacyPolicy, privacy_findings, privacy_policy
from first_commit.git import (
    OBJECT_ID,
    GitError,
    cat_file_objects,
    parse_batch_check,
    run_git,
)
from first_commit.gitleaks import RULE_ID
from first_commit.gitleaks_blobs import MESSAGE_PATH, MESSAGE_SUMMARY, message_locations
from first_commit.models import Candidate, Finding, Origin, Severity
from first_commit.policy import Policy
from first_commit.pushed import (
    HISTORY_REVISIONS,
    PushedScope,
    configured_remotes,
    push_revisions,
)

SHORT_ID_CHARS = 12
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
    if not object_ids:
        return {}
    names = "".join(object_id + "\n" for object_id in object_ids).encode("ascii")
    answers = parse_batch_check(
        run_git(root, ("cat-file", "--batch-check"), names), len(object_ids)
    )
    object_type = kind.name.lower()
    sizes = {}
    for object_id, found in zip(object_ids, answers, strict=True):
        if found is None or found.kind != object_type or found.object_id != object_id:
            raise GitError(f"Git returned an inconsistent {object_type}.")
        # The limit covers the whole object, headers and signature included.
        if found.size > max_bytes:
            raise CandidateError(
                f"{kind.name} message of {object_id[:SHORT_ID_CHARS]} exceeds the "
                "size limit."
            )
        sizes[object_id] = found.size
    return sizes


def _commit_ids(root: Path, revisions: Sequence[str]) -> list[str]:
    commits = run_git(root, ("rev-list", *revisions, "--")).decode("ascii").split()
    if any(OBJECT_ID.fullmatch(commit) is None for commit in commits):
        raise GitError("Git returned an invalid commit.")
    return commits


def _commit_messages(
    root: Path, commits: Sequence[str], max_bytes: int
) -> Iterator[tuple[str, bytes]]:
    sizes = _object_sizes(root, COMMIT, commits, max_bytes)
    for commit, content in cat_file_objects(root, "commit", sizes):
        yield commit, content.partition(b"\n\n")[2]


def _tags_of(root: Path, tags: Sequence[str], commits: frozenset[str]) -> list[str]:
    if not tags:
        return []
    names = "".join(f"{tag}^{{}}\n" for tag in tags).encode("ascii")
    peeled = parse_batch_check(
        run_git(root, ("cat-file", "--batch-check"), names), len(tags)
    )
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
    names = configured_remotes(root)
    if not names:
        return frozenset()
    patterns = [f"--remotes={name}" for name in names]
    commits = run_git(root, ("rev-list", *patterns, "--")).decode("ascii").split()
    if any(OBJECT_ID.fullmatch(commit) is None for commit in commits):
        raise GitError("Git returned an invalid remote commit.")
    return frozenset(commits)


class MessageScope(NamedTuple):
    pushed: PushedScope | None
    warn_on_remote: bool = False


def _named(
    finding: Finding, kind: _MessageKind, object_id: str | None, pushed: frozenset[str]
) -> Finding:
    if object_id is None:
        return finding
    named = replace(
        finding, summary=f"{kind.name} {object_id[:SHORT_ID_CHARS]}: {finding.summary}"
    )
    if object_id not in pushed:
        return named
    return replace(
        named,
        severity=Severity.WARNING,
        summary=named.summary + ON_THE_REMOTE,
        on_remote=True,
    )


def _message_findings(
    scan: _MessageScan,
    kind: _MessageKind,
    messages: Iterable[tuple[str, bytes]],
    max_findings: int,
) -> list[Finding]:
    if max_findings <= 0:
        return []
    findings: list[Finding] = []

    def privacy_checked() -> Iterator[Candidate]:
        for object_id, message in messages:
            if len(findings) >= max_findings:
                return
            candidate = Candidate(kind.path, message, Origin.MESSAGE)
            room = max_findings - len(findings)
            findings.extend(
                _named(item, kind, object_id, scan.pushed)
                for item in privacy_findings(candidate, scan.privacy, max_findings=room)
            )
            yield Candidate(object_id, message, Origin.MESSAGE)

    for object_id, line in message_locations(scan.root, privacy_checked()):
        if len(findings) >= max_findings:
            break
        secret = Finding(
            rule_id=RULE_ID, path=kind.path, summary=kind.summary, line=line
        )
        findings.append(_named(secret, kind, object_id, scan.pushed))
    return findings[:max_findings]


def history_message_findings(
    root: Path,
    policy: Policy,
    private_values: Sequence[str],
    scope: MessageScope,
    *,
    max_findings: int,
) -> list[Finding]:
    pushed = scope.pushed
    revisions = HISTORY_REVISIONS if pushed is None else push_revisions(root, pushed)
    max_bytes = policy.max_message_bytes
    # Only check warns about a commit the remote has; a tag can be re-created
    # without a history rewrite, so a tag finding always blocks.
    scan = _MessageScan(
        root,
        privacy_policy(policy, private_values),
        _remote_commits(root) if scope.warn_on_remote else frozenset(),
    )
    commits = _commit_ids(root, revisions)
    findings = _message_findings(
        scan, COMMIT, _commit_messages(root, commits, max_bytes), max_findings
    )
    tags = _tag_messages(
        root, max_bytes, None if pushed is None else frozenset(commits)
    )
    findings += _message_findings(
        scan._replace(pushed=frozenset()), TAG, tags, max_findings - len(findings)
    )
    return findings
