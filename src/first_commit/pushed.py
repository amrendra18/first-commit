import re
from collections.abc import Mapping
from enum import Enum
from pathlib import Path
from typing import NamedTuple

from first_commit.git import OBJECT_ID, GitError, run_git
from first_commit.models import GIT_CONFIG_PATH, Finding, Severity

# A remote name as one argument: no spaces, glob characters, or leading -.
REMOTE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,255}")
# A local branch by its full name. The characters leave out every option and
# revision syntax but "..", which is refused on its own.
LOCAL_BRANCH = re.compile(r"refs/heads/[A-Za-z0-9_][A-Za-z0-9._/-]{0,255}")
HISTORY_REVISIONS = ("--exclude=refs/stash", "--all")
# The push set, which the secret, message, and file checks read (see
# push_revisions): the commits on the pushed ref, every local branch, and every
# remote-tracking branch, less those the push's remote holds. The signature check
# reads less: it leaves out every configured remote's commits (signature_revisions).
# pre-commit names only the first pushed ref, and a push may send another remote's
# tracking branch as a later ref, as git push public private/feature:feature does.
# Any other ref, such as a tag, the stash, notes, refs/original/ backups, or
# refs/prefetch/ copies, is read only as the pushed ref: Git pushes them only when a
# push names them, and keeps no record of which tags a remote holds (ARCHITECTURE.md,
# Known gaps).
PUSHED_REFS = ("--branches", "--remotes")
# Gitleaks takes the revisions as one --log-opts argument, and Linux refuses one
# argument over 128 KiB (MAX_ARG_STRLEN). Past this size check --new-only drops
# the exclusions and scans all local commits.
MAX_REVISION_BYTES = 64 * 1024


# check --new-only reads only the commits no configured remote's tracking branches
# hold, the same commits check only warns about.
class HistoryRange(Enum):
    NEW_ONLY = "new-only"


def _pushed_ref(value: str) -> bool:
    return OBJECT_ID.fullmatch(value) is not None or (
        LOCAL_BRANCH.fullmatch(value) is not None and ".." not in value
    )


# to_ref is a full commit id, or a local branch that push_revisions reads as its
# commit.
class PushedScope(NamedTuple):
    to_ref: str | None
    remote: str | None

    @property
    def valid(self) -> bool:
        to_ref = self.to_ref is None or _pushed_ref(self.to_ref)
        return to_ref and (
            self.remote is None or REMOTE_NAME.fullmatch(self.remote) is not None
        )


# A run with no pushed ref and no remote, as by hand: every local ref.
NO_SCOPE = PushedScope(None, None)


# The scope of the push set (see PUSHED_REFS). For a push that holds a root commit,
# pre-commit names no PRE_COMMIT_TO_REF, only the local ref the push sends: a full
# commit id, or a branch the pushed ref then names.
def pushed_scope(environment: Mapping[str, str]) -> PushedScope:
    if "PRE_COMMIT_TO_REF" in environment:
        end = environment["PRE_COMMIT_TO_REF"]
        to_ref = end if OBJECT_ID.fullmatch(end) else None
    else:
        branch = environment.get("PRE_COMMIT_LOCAL_BRANCH", "")
        to_ref = branch if _pushed_ref(branch) else None
    remote = environment.get("PRE_COMMIT_REMOTE_NAME", "")
    return PushedScope(to_ref, remote if REMOTE_NAME.fullmatch(remote) else None)


# Each check reads a branch's commit when it starts, as Git reads PUSHED_REFS.
def _pushed(root: Path, scope: PushedScope) -> tuple[str, ...]:
    ref = scope.to_ref
    if ref is None:
        return ()
    if OBJECT_ID.fullmatch(ref):
        return (ref,)
    if not _pushed_ref(ref):
        raise GitError("The pushed ref is not a commit id or a local branch.")
    raw = run_git(root, ("rev-parse", "--verify", f"{ref}^{{commit}}"))
    commit = raw.decode("ascii", "replace").removesuffix("\n")
    if OBJECT_ID.fullmatch(commit) is None:
        raise GitError("Git returned an invalid commit.")
    return (commit,)


def _remote_names(root: Path) -> list[str]:
    return run_git(root, ("remote",)).decode("utf-8", "surrogateescape").splitlines()


def configured_remotes(root: Path) -> list[str]:
    # A hand-edited name may hold glob characters, spaces, or bytes that are not
    # UTF-8; such a remote is not trusted.
    return [name for name in _remote_names(root) if REMOTE_NAME.fullmatch(name)]


def remote_patterns(root: Path) -> tuple[str, ...]:
    return tuple(f"--remotes={name}" for name in configured_remotes(root))


# None when the list of remotes to leave out is too long for one argument.
def new_revisions(root: Path) -> tuple[str, ...] | None:
    excluded = remote_patterns(root)
    if not excluded:
        return HISTORY_REVISIONS
    revisions = (*HISTORY_REVISIONS, "--not", *excluded)
    return None if len(" ".join(revisions)) > MAX_REVISION_BYTES else revisions


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


def _any_case(name: str) -> str:
    return "".join(f"[{c.lower()}{c.upper()}]" if c.isalpha() else c for c in name)


# The refs of the configured remote the push goes to, as --remotes=<remote>. Refs of
# a remote <remote>/<more>, in any case, are left out: the push keeps their commits.
# Git matches these --exclude patterns against the ref name after refs/remotes/. A
# remote whose name differs only in case may share the refs, and a nested name that
# is not a plain remote name cannot be written as a pattern; then nothing is left out.
def _remote_held(root: Path, remote: str | None) -> tuple[str, ...]:
    if remote is None:
        return ()
    names = _remote_names(root)
    if remote not in names or any(_differ_only_in_case(n, remote) for n in names):
        return ()
    nested = [n for n in names if n.casefold().startswith(remote.casefold() + "/")]
    if any(REMOTE_NAME.fullmatch(name) is None for name in nested):
        return ()
    excluded = tuple(f"--exclude={_any_case(name)}/*" for name in nested)
    return ("--not", *excluded, f"--remotes={remote}")


# The push set (see PUSHED_REFS); without every_ref, the pushed ref's commits alone.
# No reflogs: an amended-away secret stays there up to 90 days and would block
# pushes.
def push_revisions(
    root: Path, scope: PushedScope, *, every_ref: bool = True
) -> tuple[str, ...]:
    pushed = _pushed(root, scope)
    refs = PUSHED_REFS if every_ref else ()
    return (*pushed, *refs, *_remote_held(root, scope.remote))


# The signature check leaves out every configured remote's commits: a commit another
# remote holds, such as a fork's fetched upstream history, is someone else's to sign.
# The secret and privacy checks still read it when the push's remote lacks it. A ref
# of no configured remote leaves nothing out, as in _remote_held.
def signature_revisions(root: Path, scope: PushedScope) -> tuple[str, ...]:
    pushed = _pushed(root, scope)
    excluded = remote_patterns(root)
    return (*pushed, *PUSHED_REFS, *(("--not", *excluded) if excluded else ()))
