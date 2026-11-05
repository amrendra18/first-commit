import hashlib
import os
import shlex
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import NamedTuple

from first_commit.candidates import filtered_staged_paths
from first_commit.git import (
    GitError,
    batch_check,
    cat_file_blobs,
    listed_commits,
    run_git,
)
from first_commit.gitleaks_ignore_format import (
    IGNORE_PATH,
    MAX_IGNORE_BYTES,
    IgnoreEntry,
    IgnoreFileError,
    digest_command,
    ignore_file_error,
    parse_ignore,
)
from first_commit.paths import MEBIBYTE, PathError, confined_path, read_regular_bytes

MAX_SOURCE_BYTES = 10 * MEBIBYTE
MAX_SOURCES = 10000
MAX_TOTAL_SOURCE_BYTES = 256 * MEBIBYTE
LFS_POINTER = b"version https://git-lfs.github.com/spec/v1\n"


class _BlobDigest(NamedTuple):
    lines: int
    sha256: str
    lfs_pointer: bool


def _staged_ignore(root: Path) -> bytes | None:
    if not run_git(root, ("ls-files", "-z", "--cached", "--", IGNORE_PATH)):
        return None
    source = f":0:{IGNORE_PATH}"
    staged = _blob_ids_and_sizes(root, [source])[source]
    if staged is None or staged[1] > MAX_IGNORE_BYTES:
        raise GitError(
            f"The staged {IGNORE_PATH} is missing or exceeds the size limit."
        )
    object_id, size = staged
    return dict(cat_file_blobs(root, {object_id: size}))[object_id]


def _blob_ids_and_sizes(
    root: Path, names: Sequence[str]
) -> dict[str, tuple[str, int] | None]:
    answers = batch_check(root, names)
    return {
        name: (found.object_id, found.size)
        if found is not None and found.kind == "blob"
        else None
        for name, found in zip(names, answers, strict=True)
    }


def _changing_commits(
    root: Path, revisions: Sequence[str], path: str
) -> tuple[str, ...]:
    return tuple(listed_commits(root, ("--full-history", *revisions, "--", path)))


class _DigestCheck(NamedTuple):
    entry: IgnoreEntry
    source: str
    commit: str | None


def _checks(
    entries: Sequence[IgnoreEntry], root: Path, revisions: Sequence[str] | None
) -> Iterator[_DigestCheck]:
    covered = {
        (entry.commit, entry.path, entry.rule, entry.line)
        for entry in entries
        if entry.commit
    }
    commits: dict[str, tuple[str, ...]] = {}
    for entry in entries:
        yield _DigestCheck(entry, entry.source, None)
        if entry.commit or revisions is None:
            continue
        if entry.path not in commits:
            commits[entry.path] = _changing_commits(root, revisions, entry.path)
        for commit in commits[entry.path]:
            if (commit, entry.path, entry.rule, entry.line) not in covered:
                yield _DigestCheck(entry, f"{commit}:{entry.path}", commit)


def _digests(root: Path, sizes: dict[str, int]) -> dict[str, _BlobDigest]:
    if sum(sizes.values()) > MAX_TOTAL_SOURCE_BYTES:
        raise ignore_file_error(
            f"the exceptions need more than {MAX_TOTAL_SOURCE_BYTES // MEBIBYTE} MiB "
            "of file versions read",
            "remove exceptions for large or often-changed files.",
        )
    return {
        object_id: _digest_of(content)
        for object_id, content in cat_file_blobs(root, sizes)
    }


def _digest_of(content: bytes) -> _BlobDigest:
    lines = content.count(b"\n") + (bool(content) and not content.endswith(b"\n"))
    return _BlobDigest(
        lines, hashlib.sha256(content).hexdigest(), content.startswith(LFS_POINTER)
    )


def _working_digests(
    root: Path, checks: Sequence[_DigestCheck]
) -> dict[str, _BlobDigest]:
    staged = list(dict.fromkeys(c.entry.path for c in checks if c.commit is None))
    digests = {}
    for path in filtered_staged_paths(root, staged) if staged else ():
        try:
            content = read_regular_bytes(confined_path(root, path), MAX_SOURCE_BYTES)
        except PathError:
            continue
        digests[path] = _digest_of(content)
    return digests


def _where(entry: IgnoreEntry, commit: str | None = None) -> str:
    commit = commit or entry.commit
    return f"commit {commit}" if commit else "the staged snapshot"


def _missing(entry: IgnoreEntry) -> IgnoreFileError:
    return ignore_file_error(
        f"{entry.path} is not in {_where(entry)}",
        "delete the entry if the finding is gone; a finding only in history "
        "needs its <commit>:<path>:<rule>:<line> fingerprint.",
        entry.number,
    )


def _past_end(entry: IgnoreEntry) -> IgnoreFileError:
    return ignore_file_error(
        f"line {entry.line} of {entry.path} in {_where(entry)} is past the end of "
        "the file",
        "delete the entry if the finding is gone.",
        entry.number,
    )


def _too_large(check: _DigestCheck) -> IgnoreFileError:
    return ignore_file_error(
        f"{check.entry.path} in {_where(check.entry, check.commit)} is larger than "
        f"{MAX_SOURCE_BYTES // MEBIBYTE} MiB, so its digest is not checked",
        "delete the exception and make the file smaller, or keep it out of Git.",
        check.entry.number,
    )


def _mismatch(check: _DigestCheck, command: str) -> IgnoreFileError:
    entry = check.entry
    if check.commit is None:
        return ignore_file_error(
            f"{entry.path} in {_where(entry, check.commit)} no longer matches its file-sha256, so "
            f"line {entry.line} may hold a different secret",
            "review the Gitleaks finding again; if it is still a false positive, "
            f"set file-sha256 to the output of: {command}",
            entry.number,
        )
    return ignore_file_error(
        f"{entry.path} in {_where(entry, check.commit)} does not match its file-sha256, and "
        "Gitleaks applies this exception to every commit, so it may hide a "
        f"different secret at line {entry.line} there",
        "review that line; if it is not a secret, add the fingerprint "
        f"{check.commit}:{entry.path}:{entry.rule}:{entry.line} with a reason and "
        f"its file-sha256, the output of: {command}",
        entry.number,
    )


def _check_digests(
    root: Path, entries: Sequence[IgnoreEntry], revisions: Sequence[str] | None
) -> None:
    checks = list(_checks(entries, root, revisions))
    names = list(dict.fromkeys(check.source for check in checks))
    if len(names) > MAX_SOURCES:
        raise ignore_file_error(
            f"the exceptions need more than {MAX_SOURCES} file versions checked",
            "remove exceptions for often-changed files.",
        )
    resolved = _blob_ids_and_sizes(root, names)
    for check in checks:
        found = resolved[check.source]
        if found is None and check.commit is None:
            raise _missing(check.entry)
        if found is not None and found[1] > MAX_SOURCE_BYTES:
            raise _too_large(check)
    digests = _digests(root, dict(item for item in resolved.values() if item))
    working = _working_digests(root, checks)
    for check in checks:
        found = resolved[check.source]
        if found is None:
            continue
        stored = digests[found[0]]
        if not (stored.lfs_pointer and check.entry.path in working):
            _verify(check, stored, digest_command(check.source))
        elif check.commit is None:
            path = shlex.quote("./" + check.entry.path)
            _verify(check, working[check.entry.path], f"shasum -a 256 {path}")


def _verify(check: _DigestCheck, blob: _BlobDigest, command: str) -> None:
    if check.entry.line > blob.lines:
        if check.commit is None:
            raise _past_end(check.entry)
        return
    if blob.sha256 != check.entry.sha256:
        raise _mismatch(check, command)


def check_ignore_file(
    root: Path, revisions: Sequence[str] | None = None
) -> tuple[IgnoreEntry, ...]:
    path = root / IGNORE_PATH
    if not os.path.lexists(path):
        return ()
    try:
        content = read_regular_bytes(path, MAX_IGNORE_BYTES)
    except PathError as error:
        raise ignore_file_error(
            "the file is a link, not a regular file, or larger than "
            f"{MAX_IGNORE_BYTES // MEBIBYTE} MiB",
            "replace it with a regular file of reviewed exceptions.",
        ) from error
    try:
        staged = _staged_ignore(root)
    except (GitError, ValueError) as error:
        raise ignore_file_error(
            "Git cannot say whether the file is tracked",
            "run the check inside the Git repository that holds the file.",
        ) from error
    if staged is None:
        raise ignore_file_error(
            "the file is not tracked, so Gitleaks would apply exceptions nobody "
            "reviewed",
            f"run git add {IGNORE_PATH} to review it with your commit, or delete it.",
        )
    if staged != content:
        raise ignore_file_error(
            "the file differs from its staged copy, and Gitleaks reads this copy",
            f"run git add {IGNORE_PATH} to stage the change, or git restore "
            f"{IGNORE_PATH} to undo it.",
        )
    entries = parse_ignore(content)
    # Gitleaks applies a three-part entry to every scanned commit, so each must match.
    try:
        _check_digests(root, entries, revisions)
    except GitError as error:
        raise ignore_file_error(
            "Git could not read the files the exceptions name",
            "run the check inside the Git repository that holds the file.",
        ) from error
    return entries
