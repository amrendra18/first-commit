import re
from collections.abc import Mapping
from pathlib import Path
from typing import NamedTuple

from first_commit.git import OBJECT_ID, GitError, run_git
from first_commit.models import GIT_CONFIG_PATH, Finding, Severity

# A remote name as one argument: no spaces, glob characters, or leading -.
REMOTE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,255}")
# Every local ref but the stash: Git pushes it only when it is named, and then it is
# scanned only as the first pushed ref with new commits (see pushed_scope).
HISTORY_REVISIONS = ("--exclude=refs/stash", "--all")
# Gitleaks takes the revisions as one --log-opts argument, and Linux refuses one
# argument over 128 KiB (MAX_ARG_STRLEN). Past this size the scan drops the
# exclusions and scans all local commits.
MAX_REVISION_BYTES = 64 * 1024


class PushedScope(NamedTuple):
    to_ref: str
    remote: str | None

    @property
    def valid(self) -> bool:
        return OBJECT_ID.fullmatch(self.to_ref) is not None and (
            self.remote is None or REMOTE_NAME.fullmatch(self.remote) is not None
        )


# pre-commit exports only the first pushed branch, so the scope is every local ref.
def pushed_scope(environment: Mapping[str, str]) -> PushedScope | None:
    end = environment.get("PRE_COMMIT_TO_REF", "")
    if OBJECT_ID.fullmatch(end) is None:
        return None
    remote = environment.get("PRE_COMMIT_REMOTE_NAME", "")
    return PushedScope(end, remote if REMOTE_NAME.fullmatch(remote) else None)


def _remote_names(root: Path) -> list[str]:
    return run_git(root, ("remote",)).decode("utf-8", "surrogateescape").splitlines()


def configured_remotes(root: Path) -> list[str]:
    # A hand-edited name may hold glob characters, spaces, or bytes that are not
    # UTF-8; such a remote is not trusted.
    return [name for name in _remote_names(root) if REMOTE_NAME.fullmatch(name)]


def _differ_only_in_case(name: str, other: str) -> bool:
    return name != other and name.casefold() == other.casefold()


# A case-insensitive disk files the refs of Origin/x under refs/remotes/origin/x/,
# and the refs of ORIGIN and origin under one folder. Both warnings also fire on a
# case-sensitive disk, where it is harmless, because the config may move to macOS.
def nested_remote_findings(root: Path) -> list[Finding]:
    names = _remote_names(root)
    folded = [name.casefold() for name in names]
    findings = []
    if any(name.startswith(other + "/") for name in folded for other in folded):
        findings.append(
            Finding(
                rule_id="hooks.nested-remote",
                path=GIT_CONFIG_PATH,
                summary=(
                    "A remote's name is another remote's name plus /; pre-commit then "
                    "skips the pre-push hooks for a new branch the nested remote has."
                ),
                severity=Severity.WARNING,
            )
        )
    if any(_differ_only_in_case(name, other) for name in names for other in names):
        findings.append(
            Finding(
                rule_id="hooks.remote-case",
                path=GIT_CONFIG_PATH,
                summary=(
                    "Two remotes' names differ only in letter case; on a "
                    "case-insensitive disk they share refs, so pre-commit may skip the "
                    "pre-push hooks for a new branch the other remote has."
                ),
                severity=Severity.WARNING,
            )
        )
    return findings


# Refs of a remote <remote>/<more>, in any case, are left out: the scan keeps their
# commits. A remote whose name differs only in case may share the refs.
def _remote_tips(root: Path, remote: str) -> tuple[str, ...]:
    names = _remote_names(root)
    if any(_differ_only_in_case(name, remote) for name in names):
        return ()
    nested = tuple(
        f"refs/remotes/{name}/".casefold()
        for name in names
        if name.casefold().startswith(remote.casefold() + "/")
    )
    raw = run_git(
        root,
        (
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            f"refs/remotes/{remote}/",
        ),
    )
    tips: dict[str, None] = {}
    for line in raw.decode("utf-8", "surrogateescape").splitlines():
        object_id, _, ref = line.partition(" ")
        if OBJECT_ID.fullmatch(object_id) is None:
            raise GitError("Git returned an invalid ref.")
        if not ref.casefold().startswith(nested):
            tips[object_id] = None
    return tuple(tips)


# No reflogs: an amended-away secret stays there up to 90 days and would block pushes.
def push_revisions(root: Path, scope: PushedScope) -> tuple[str, ...]:
    tips = () if scope.remote is None else _remote_tips(root, scope.remote)
    excluded = ("--not", *tips) if tips else ()
    revisions = (scope.to_ref, *HISTORY_REVISIONS, *excluded)
    if len(" ".join(revisions)) > MAX_REVISION_BYTES:
        return (scope.to_ref, *HISTORY_REVISIONS)
    return revisions
