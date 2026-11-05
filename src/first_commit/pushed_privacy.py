import os
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import NamedTuple

from first_commit.candidates import (
    GITLINK_MODE,
    REGULAR_FILE_MODES,
    CandidateLimitError,
    object_sizes,
)
from first_commit.checks.privacy import PrivacyPolicy, privacy_findings, privacy_policy
from first_commit.finding_collector import TOO_LARGE_RULE, is_immutable_vendor
from first_commit.git import (
    OBJECT_ID,
    SHORT_COMMIT,
    GitError,
    batch_check,
    cat_file_blobs,
    run_git,
)
from first_commit.models import Candidate, Finding, Origin, capped
from first_commit.policy import MAX_POLICY_BYTES, POLICY_PATH, Policy, parse_policy
from first_commit.policy_fields import PolicyError
from first_commit.pushed import NO_SCOPE, PushedScope, push_revisions
from first_commit.pushed_signatures import pushed_commits

# Raw output of each commit's changes. For a merge, -c lists only the paths that
# differ from every parent: the content the merge itself adds, as the other content
# is in a parent, which this push sends or a remote already holds.
DIFF_TREE = (
    "diff-tree",
    "--stdin",
    "-r",
    "-z",
    "--root",
    "--no-renames",
    "--no-abbrev",
    "-c",
)
TOO_LARGE_SUMMARY = "File is over the size limit, so its content was not checked."
# Git creates a branch from <id>:<name> only when the name is a full ref.
PARTIAL_PUSH = "git push <remote> <full commit id>:refs/heads/<branch>"


class _Version(NamedTuple):
    path: str
    blob: str
    mode: str
    commit: str


class _Rules(NamedTuple):
    privacy: PrivacyPolicy
    vendor: Mapping[str, str]


def without_exceptions(policy: Policy) -> Policy:
    return replace(
        policy,
        environment_exceptions=(),
        literal_exceptions=(),
        detector_exceptions=(),
        public_emails=(),
        immutable_vendor_files=(),
        public_github_owner_urls=False,
    )


# ":<mode> ... <id> ... <status>", one colon, mode, and id per parent, then the
# result's mode and id; a deleted path's result id is all zeros.
def _result(meta: bytes) -> tuple[str, str]:
    parents = len(meta) - len(meta.lstrip(b":"))
    fields = meta[parents:].decode("ascii").split(" ")
    if len(fields) != 2 * parents + 3:
        raise GitError("Git returned an invalid change.")
    return fields[parents], fields[2 * parents + 1]


# Each file version once, with the oldest commit that adds it: parents come first.
def _versions(root: Path, commits: Sequence[str]) -> list[_Version]:
    names = "".join(commit + "\n" for commit in commits).encode("ascii")
    fields = iter(run_git(root, DIFF_TREE, names).split(b"\0"))
    versions: dict[tuple[str, str], _Version] = {}
    commit = None
    for field in fields:
        if not field:
            continue
        if not field.startswith(b":"):
            commit = field.decode("ascii")
            if OBJECT_ID.fullmatch(commit) is None:
                raise GitError("Git returned an invalid commit.")
            continue
        path = os.fsdecode(next(fields, b""))
        mode, blob = _result(field)
        if commit is None or not path:
            raise GitError("Git returned an invalid change.")
        if mode != GITLINK_MODE and blob.strip("0"):
            versions.setdefault((path, blob), _Version(path, blob, mode, commit))
    return list(versions.values())


def _short(commit: str) -> str:
    return commit[:SHORT_COMMIT]


# Each commit's own policy approves its lines, as the staged policy does at commit
# time: an approval only in the working copy is not in what the push sends. A commit
# whose policy is no valid file gets no exceptions, so a later fix of the policy
# never leaves an older commit unpushable.
def _commit_rules(
    root: Path, policy: Policy, private_values: Sequence[str], commits: Sequence[str]
) -> dict[str, _Rules]:
    policy_blobs: dict[str, str] = {}
    sizes: dict[str, int] = {}
    for commit, found in zip(
        commits,
        batch_check(root, [f"{item}:{POLICY_PATH}" for item in commits]),
        strict=True,
    ):
        if found is None or found.kind != "blob" or found.size > MAX_POLICY_BYTES:
            continue
        policy_blobs[commit] = found.object_id
        sizes.setdefault(found.object_id, found.size)
    parsed: dict[str | None, Policy] = {None: without_exceptions(policy)}
    for blob, content in cat_file_blobs(root, sizes):
        try:
            committed = parse_policy(content, root)
        except PolicyError:
            parsed[blob] = parsed[None]
            continue
        parsed[blob] = replace(committed, contributor_emails=policy.contributor_emails)
    rules = {
        key: _Rules(
            privacy_policy(value, private_values),
            {item.path: item.sha256 for item in value.immutable_vendor_files},
        )
        for key, value in parsed.items()
    }
    return {commit: rules[policy_blobs.get(commit)] for commit in commits}


def _in_commit(finding: Finding, commit: str) -> Finding:
    short = _short(commit)
    summary = f"{finding.summary.removesuffix('.')} in commit {short}."
    return replace(finding, summary=summary, commit=short, pushed=True)


def _version_findings(
    version: _Version, content: bytes, rules: _Rules, max_findings: int
) -> list[Finding]:
    candidate = Candidate(
        version.path, content, Origin.INDEX, version.mode in REGULAR_FILE_MODES
    )
    return privacy_findings(
        candidate,
        rules.privacy,
        max_findings=max_findings,
        immutable_vendor=is_immutable_vendor(candidate, rules.vendor),
    )


class _Scan(NamedTuple):
    root: Path
    versions: Sequence[_Version]
    rules: Mapping[str, _Rules]
    max_bytes: int
    max_findings: int


# Blobs are read in batch order, not commit order, so each rule, path, and line keeps
# only the finding of its oldest version, the commit to rewrite; memory grows with
# the distinct keys, not with the versions. A blob over the byte limit is never read.
def _findings(scan: _Scan) -> Iterator[Finding]:
    blobs = list(dict.fromkeys(version.blob for version in scan.versions))
    sizes = object_sizes(scan.root, blobs, "blob", None, "File")
    oldest: dict[tuple[str, str, int | None], tuple[int, Finding]] = {}

    def keep(index: int, item: Finding) -> None:
        key = (item.rule_id, item.path, item.line)
        held = oldest.get(key)
        if held is None or index < held[0]:
            # Moved to the end, so one commit's findings keep the order they came in.
            oldest.pop(key, None)
            oldest[key] = (index, item)

    by_blob: dict[str, list[int]] = {}
    for index, version in enumerate(scan.versions):
        if sizes[version.blob] <= scan.max_bytes:
            by_blob.setdefault(version.blob, []).append(index)
        else:
            too_large = Finding(
                rule_id=TOO_LARGE_RULE, path=version.path, summary=TOO_LARGE_SUMMARY
            )
            keep(index, too_large)
    readable = {blob: sizes[blob] for blob in by_blob}
    for blob, content in cat_file_blobs(scan.root, readable):
        for index in by_blob[blob]:
            version = scan.versions[index]
            rules = scan.rules[version.commit]
            for item in _version_findings(version, content, rules, scan.max_findings):
                keep(index, item)
    for index, item in sorted(oldest.values(), key=lambda pair: pair[0]):
        yield _in_commit(item, scan.versions[index].commit)


def _commit_versions(
    root: Path, scope: PushedScope | None, *, every_ref: bool
) -> list[_Version]:
    revisions = push_revisions(root, scope or NO_SCOPE, every_ref=every_ref)
    commits = pushed_commits(root, revisions)
    return _versions(root, commits) if commits else []


# Past the limit on the whole push set (see PUSHED_REFS), the pushed ref alone is
# read when it fits, so pushing the older commits first gets through; the other refs
# of the same push are then not read (ARCHITECTURE.md, Known gaps).
def pushed_versions(
    root: Path, scope: PushedScope | None, max_files: int
) -> list[_Version]:
    versions = _commit_versions(root, scope, every_ref=True)
    pushed_ref = scope is not None and scope.to_ref is not None
    if len(versions) > max_files and pushed_ref:
        versions = _commit_versions(root, scope, every_ref=False)
    if len(versions) <= max_files:
        return versions
    # Without a pushed ref, as in a run by hand or a first push that sends HEAD or
    # a short commit id, nothing narrower can be read.
    fix = (
        f"push the older commits first, {PARTIAL_PUSH} for a commit part way "
        "along, then push the rest."
        if pushed_ref
        else "the push names no branch or full commit id, so the check cannot read "
        "less. Push a branch by name, git push <remote> <branch>, or the older "
        f"commits first, {PARTIAL_PUSH}."
    )
    raise CandidateLimitError(
        f"The pushed commits hold more than {max_files:,} file versions.\nfix: {fix}"
    )


def pushed_privacy_findings(
    root: Path,
    policy: Policy,
    versions: Sequence[_Version],
    private_values: Sequence[str],
    *,
    max_findings: int,
) -> list[Finding]:
    if max_findings <= 0 or not versions:
        return []
    changed = list(dict.fromkeys(version.commit for version in versions))
    scan = _Scan(
        root,
        versions,
        _commit_rules(root, policy, private_values, changed),
        policy.max_file_bytes,
        max_findings,
    )
    return capped(_findings(scan), max_findings)
