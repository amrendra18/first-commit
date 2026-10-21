import os
import stat
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from first_commit.git import (
    INCONSISTENT_OBJECT,
    OBJECT_ID,
    GitError,
    cat_file_blobs,
    parse_batch_check,
    run_git,
)
from first_commit.models import Candidate, EnvironmentFile, FileState, Origin
from first_commit.paths import (
    PathError,
    confined_path,
    read_worktree_bytes,
)

GITLINK_MODE = "160000"
REGULAR_FILE_MODES = ("100644", "100755")
STAGE_FIELDS = 3
# `git ls-tree` prints mode, type, and object id before the path.
TREE_FIELDS = 3
IndexEntries = Mapping[str, tuple[str, str]]
NOT_IN_INDEX = (
    "A staged file has no content in the Git index (the list of staged files).\n"
    "fix: run `git status` to find the file, stage it again with `git add`, then "
    "rerun."
)


class CandidateError(RuntimeError):
    pass


# One pass over items holds one file in memory; oversized is known before it starts.
@dataclass(frozen=True)
class LoadedCandidates:
    items: Iterable[Candidate] = ()
    oversized: list[str] = field(default_factory=list)

    def __iter__(self) -> Iterator[Candidate]:
        return iter(self.items)


def _require_count(count: int, max_files: int) -> None:
    if count > max_files:
        raise CandidateError(
            f"File count exceeds the limit of {max_files:,} paths. Tracked "
            "files count, and so do untracked files that .gitignore does not hide; "
            "a staged check counts only the staged files.\n"
            "fix: add generated folders such as node_modules/ to .gitignore, "
            "untrack any that Git tracks with `git rm -r --cached <folder>`, then "
            "rerun."
        )


def _split_paths(raw: bytes, max_files: int) -> tuple[str, ...]:
    entries = raw.rstrip(b"\0").split(b"\0") if raw else []
    _require_count(len(entries), max_files)
    return tuple(os.fsdecode(entry) for entry in entries)


def _mode(index_entries: IndexEntries, path: str) -> str | None:
    entry = index_entries.get(path)
    return None if entry is None else entry[0]


def _stage_zero_entries(raw: bytes) -> dict[str, tuple[str, str]]:
    entries = {}
    for entry in raw.rstrip(b"\0").split(b"\0") if raw else ():
        metadata, separator, raw_path = entry.partition(b"\t")
        fields = metadata.split()
        if separator and len(fields) == STAGE_FIELDS and fields[2] == b"0":
            try:
                entries[os.fsdecode(raw_path)] = (
                    fields[0].decode("ascii"),
                    fields[1].decode("ascii"),
                )
            except UnicodeDecodeError as error:
                raise CandidateError("Git returned invalid index metadata.") from error
    return entries


def _index_entries(root: Path) -> dict[str, tuple[str, str]]:
    return _stage_zero_entries(run_git(root, ("ls-files", "--stage", "-z")))


def _working_selection(
    root: Path, max_files: int, pathspecs: tuple[str, ...]
) -> tuple[str, ...]:
    paths = _split_paths(
        run_git(
            root,
            (
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                *pathspecs,
            ),
        ),
        max_files,
    )
    index_entries = _index_entries(root)
    return tuple(
        path
        for path in paths
        if _mode(index_entries, path) != GITLINK_MODE
        and os.path.lexists(confined_path(root, path))
    )


def working_candidate_paths(
    root: Path, max_files: int, pathspecs: tuple[str, ...] = ()
) -> tuple[str, ...]:
    try:
        return _working_selection(root, max_files, pathspecs)
    except (GitError, PathError) as error:
        raise CandidateError(str(error)) from error


def working_candidates(
    root: Path,
    max_files: int,
    max_bytes: int,
    paths: Sequence[str] | None = None,
) -> LoadedCandidates:
    selected = working_candidate_paths(root, max_files) if paths is None else paths
    _require_count(len(selected), max_files)
    oversized = _oversized_worktree_paths(root, selected, max_bytes)
    skipped = frozenset(oversized)
    readable = [path for path in selected if path not in skipped]
    return LoadedCandidates(_worktree_contents(root, readable, max_bytes), oversized)


def _oversized_worktree_paths(
    root: Path, selected: Sequence[str], max_bytes: int
) -> list[str]:
    try:
        return [path for path in selected if _over_limit(root, path, max_bytes)]
    except PathError as error:
        raise CandidateError(str(error)) from error
    except OSError as error:
        raise CandidateError("File cannot be read.") from error


def _over_limit(root: Path, path: str, max_bytes: int) -> bool:
    try:
        metadata = os.lstat(confined_path(root, path))
    except FileNotFoundError:
        return False
    kind = metadata.st_mode
    return (stat.S_ISREG(kind) or stat.S_ISLNK(kind)) and metadata.st_size > max_bytes


# A file that grew past max_bytes since the size pass makes the read raise.
def _worktree_contents(
    root: Path, selected: Sequence[str], max_bytes: int
) -> Iterator[Candidate]:
    try:
        for path in selected:
            location = confined_path(root, path)
            if not os.path.lexists(location):
                continue
            content = read_worktree_bytes(root, path, max_bytes)
            yield Candidate(
                path=path,
                content=content,
                origin=Origin.WORKTREE,
                regular_file=not location.is_symlink(),
            )
    except PathError as error:
        raise CandidateError(str(error)) from error


def _ls_files(
    root: Path, options: tuple[str, ...], pathspecs: tuple[str, ...], max_files: int
) -> set[str]:
    return set(
        _split_paths(
            run_git(root, ("ls-files", "-z", *options, "--", *pathspecs)), max_files
        )
    )


def environment_files(
    root: Path, pathspecs: tuple[str, ...], max_files: int
) -> tuple[EnvironmentFile, ...]:
    if not pathspecs:
        return ()
    per_directory = "--exclude-per-directory=.gitignore"
    try:
        tracked = _ls_files(root, ("--cached",), pathspecs, max_files)
        visible = _ls_files(root, ("--others", per_directory), pathspecs, max_files)
        ignored = _ls_files(
            root, ("--others", "--ignored", per_directory), pathspecs, max_files
        )
    except GitError as error:
        raise CandidateError(str(error)) from error
    paths = tracked | visible | ignored
    if len(paths) > max_files:
        raise CandidateError("Environment-file count exceeds the limit.")
    return tuple(
        EnvironmentFile(
            path=path,
            state=(
                FileState.TRACKED
                if path in tracked
                else FileState.VISIBLE
                if path in visible
                else FileState.IGNORED
            ),
        )
        for path in sorted(paths)
    )


def _batch_input(object_ids: Sequence[str]) -> bytes:
    if not all(OBJECT_ID.fullmatch(item) for item in object_ids):
        raise CandidateError("Git returned invalid index metadata.")
    return "".join(item + "\n" for item in object_ids).encode("ascii")


def _blob_sizes(root: Path, object_ids: Sequence[str]) -> dict[str, int]:
    try:
        raw = run_git(root, ("cat-file", "--batch-check"), _batch_input(object_ids))
        answers = parse_batch_check(raw, len(object_ids))
    except GitError as error:
        raise CandidateError(str(error)) from error
    sizes = {}
    for object_id, found in zip(object_ids, answers, strict=True):
        if found is not None and found.object_id != object_id:
            raise CandidateError(INCONSISTENT_OBJECT)
        if found is None or found.kind != "blob":
            raise CandidateError(NOT_IN_INDEX)
        sizes[object_id] = found.size
    return sizes


def _index_contents(
    root: Path, entries: IndexEntries, sizes: Mapping[str, int]
) -> Iterator[Candidate]:
    paths_by_object: dict[str, list[tuple[str, str]]] = {}
    for path, (mode, object_id) in entries.items():
        if object_id in sizes:
            paths_by_object.setdefault(object_id, []).append((path, mode))
    try:
        for object_id, content in cat_file_blobs(root, sizes):
            for path, mode in paths_by_object[object_id]:
                yield Candidate(
                    path=path,
                    content=content,
                    origin=Origin.INDEX,
                    regular_file=mode in REGULAR_FILE_MODES,
                )
    except GitError as error:
        raise CandidateError(str(error)) from error


# Sizes come first, so a blob over max_bytes is never read; two Git processes in all.
def _index_blobs(root: Path, entries: IndexEntries, max_bytes: int) -> LoadedCandidates:
    if any(mode == GITLINK_MODE for mode, _ in entries.values()):
        raise CandidateError(
            "Staged path is a submodule (a link to another Git repository), not a file."
        )
    if not entries:
        return LoadedCandidates()
    sizes = _blob_sizes(
        root, tuple(dict.fromkeys(object_id for _, object_id in entries.values()))
    )
    readable = {
        object_id: size for object_id, size in sizes.items() if size <= max_bytes
    }
    return LoadedCandidates(
        _index_contents(root, entries, readable),
        [path for path, (_, object_id) in entries.items() if object_id not in readable],
    )


def _staged_selection(
    root: Path, max_files: int
) -> tuple[tuple[str, ...], dict[str, tuple[str, str]]]:
    paths = _split_paths(
        run_git(
            root,
            ("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT"),
        ),
        max_files,
    )
    index_entries = _index_entries(root)
    return (
        tuple(path for path in paths if _mode(index_entries, path) != GITLINK_MODE),
        index_entries,
    )


def staged_candidate_paths(root: Path, max_files: int) -> tuple[str, ...]:
    try:
        return _staged_selection(root, max_files)[0]
    except GitError as error:
        raise CandidateError(str(error)) from error


def staged_candidates(
    root: Path,
    max_files: int,
    max_bytes: int,
    paths: Sequence[str] | None = None,
) -> LoadedCandidates:
    selected: Sequence[str]
    try:
        if paths is None:
            selected, index_entries = _staged_selection(root, max_files)
        else:
            _require_count(len(paths), max_files)
            selected, index_entries = paths, _index_entries(root)
    except GitError as error:
        raise CandidateError(str(error)) from error
    entries = {}
    for path in selected:
        entry = index_entries.get(path)
        if entry is None:
            raise CandidateError(NOT_IN_INDEX)
        if entry[0] != GITLINK_MODE:
            entries[path] = entry
    return _index_blobs(root, entries, max_bytes)


def head_candidate(root: Path, path: str, max_bytes: int) -> Candidate | None:
    try:
        run_git(root, ("rev-parse", "--verify", "--quiet", "HEAD^{commit}"))
    except GitError:
        return None
    unreadable = f"The committed copy of {path} in HEAD cannot be read."
    try:
        raw = run_git(root, ("ls-tree", "-z", "--full-tree", "HEAD", "--", path))
    except GitError as error:
        raise CandidateError(unreadable) from error
    metadata, separator, raw_path = raw.rstrip(b"\0").partition(b"\t")
    fields = metadata.split()
    if not separator or os.fsdecode(raw_path) != path or len(fields) != TREE_FIELDS:
        return None
    if fields[1] != b"blob":
        raise CandidateError(f"The committed copy of {path} in HEAD is not a file.")
    try:
        entry = (fields[0].decode("ascii"), fields[2].decode("ascii"))
    except UnicodeDecodeError as error:
        raise CandidateError(unreadable) from error
    try:
        loaded = _index_blobs(root, {path: entry}, max_bytes)
    except CandidateError as error:
        raise CandidateError(unreadable) from error
    if loaded.oversized:
        raise CandidateError(f"The committed copy of {path} exceeds the size limit.")
    return next(iter(loaded))


def index_candidate(root: Path, path: str, max_bytes: int) -> Candidate:
    try:
        entry = _stage_zero_entries(
            run_git(root, ("ls-files", "--stage", "-z", "--", path))
        ).get(path)
        if entry is None:
            raise CandidateError(NOT_IN_INDEX)
        loaded = _index_blobs(root, {path: entry}, max_bytes)
    except GitError as error:
        raise CandidateError(str(error)) from error
    if loaded.oversized:
        raise CandidateError(f"The staged copy of {path} exceeds the size limit.")
    return next(iter(loaded))
