import os
import re
import signal
import subprocess
import sys
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path, PurePosixPath
from typing import IO, NamedTuple, cast

from first_commit.executables import (
    absolute_entries,
    find_executable,
    path_inside_repository,
    repository_program_message,
)


class GitError(RuntimeError):
    pass


class IndexFileError(GitError):
    pass


class IgnoreStateError(GitError):
    pass


class GitUnavailableError(GitError):
    pass


GIT_TIMEOUT_SECONDS = 120
# `git check-ignore` exits 1 when no pattern matches the path.
CHECK_IGNORE_CODES = (0, 1)
# Source, line number, pattern, and path of the deciding pattern.
CHECK_IGNORE_FIELDS = 4
# A full object id: SHA-256 (64 hex digits) or SHA-1 (40). The group keeps it one
# unit inside a longer pattern; 64 comes first, so match and search take a whole
# SHA-256 id, not its 40-digit prefix.
OBJECT_ID = re.compile(r"(?:[0-9a-f]{64}|[0-9a-f]{40})")
# One `git cat-file --batch-check` answer: object id, type, and size.
BATCH_CHECK_ANSWER = re.compile(
    b"(" + OBJECT_ID.pattern.encode("ascii") + rb") ([a-z]+) ([0-9]+)"
)
BATCH_CHECK_MISSING = b" missing"
INDEX_FILE = "GIT_INDEX_FILE"
UNTRUSTED_GIT_ENVIRONMENT = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CURL_VERBOSE",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    INDEX_FILE,
    "GIT_OBJECT_DIRECTORY",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
    "GIT_QUARANTINE_PATH",
    "GIT_REPLACE_REF_BASE",
    "GIT_WORK_TREE",
}


# The variables that carry `git -c` settings; see commit_ident.
COMMAND_LINE_CONFIG = ("GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT")
# The variables that choose the global and system files Git reads the identity from.
CONFIG_FILE_CHOICES = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM")
COMMAND_LINE_CONFIG_PREFIXES = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
GIT_FOLDER_CACHE_SIZE = 16
REFUSED_INDEX_FILE = (
    f"{INDEX_FILE} names an index outside this repository's Git folder. "
    f"Unsetting {INDEX_FILE} makes Git use the default index (.git/index), "
    "which may hold different content."
)
GIT_MISSING = (
    "Git is unavailable.\nfix: install Git, or put the folder that holds it on PATH "
    "as an absolute path."
)
# Git's own output may hold private paths or values, so the message names only the
# subcommand and points to where Git's error can be read.
GIT_STATUS_FIX = (
    "fix: run `git status` in this repository to see Git's own error, then rerun."
)
# run_git checks GIT_INDEX_FILE against the Git folders, so without this cache each
# Git call made while it is set, as in a commit hook, would start one more rev-parse.
# A command checks one repository; the size of 16 only bounds the memory of a process
# that checks many, such as the test suite.
_GIT_FOLDERS: dict[Path, tuple[Path, Path]] = {}


# Not resolved, so a caller can still refuse a link; only the final newline is cut.
def git_path(root: Path, raw: bytes) -> Path:
    try:
        text = raw.removesuffix(b"\n").decode("utf-8")
    except UnicodeDecodeError as error:
        raise GitError("Git returned a path that is not UTF-8 text.") from error
    return root / text


def _git_folders(root: Path, environment: Mapping[str, str]) -> tuple[Path, ...]:
    cached = _GIT_FOLDERS.get(root)
    if cached is not None:
        return cached
    try:
        options = ("--absolute-git-dir", "--git-common-dir")
        raw = _execute(
            root, ("rev-parse", *options), None, sanitized_git_environment(environment)
        )
        entries = raw.removesuffix(b"\n").split(b"\n")
        if len(entries) != len(options):
            return ()
        # os.fsdecode keeps a Git folder whose path is not UTF-8 usable here.
        git_folder, common = ((root / os.fsdecode(item)).resolve() for item in entries)
    except (GitError, OSError, RuntimeError, ValueError):
        return ()
    if len(_GIT_FOLDERS) >= GIT_FOLDER_CACHE_SIZE:
        _GIT_FOLDERS.clear()
    _GIT_FOLDERS[root] = (git_folder, common)
    return git_folder, common


# git commit -a and git commit <path> name a temporary index the staged checks read.
def _commit_index_file(
    root: Path, value: str | None, environment: Mapping[str, str]
) -> str | None:
    if value is None:
        return None
    try:
        resolved = (root / value).resolve() if value else None
    except (OSError, RuntimeError, ValueError):
        resolved = None
    if resolved is not None:
        for folder in _git_folders(root, environment):
            if resolved != folder and resolved.is_relative_to(folder):
                return str(resolved)
    # Dropping the value would make the checks read a different index.
    raise IndexFileError(REFUSED_INDEX_FILE)


# With root, only a GIT_INDEX_FILE inside root's Git folder stays; without, none does.
def sanitized_git_environment(
    environment: Mapping[str, str] | None = None,
    root: Path | None = None,
) -> dict[str, str]:
    selected = dict(os.environ if environment is None else environment)
    index_file = (
        None
        if root is None
        else _commit_index_file(root, selected.get(INDEX_FILE), selected)
    )
    for key in tuple(selected):
        if key in UNTRUSTED_GIT_ENVIRONMENT or key.startswith(
            ("GIT_CONFIG_", "GIT_TRACE")
        ):
            selected.pop(key, None)
    if index_file is not None:
        selected[INDEX_FILE] = index_file
    # Every child gets this PATH. An empty PATH names the current folder, so a PATH
    # without an absolute entry becomes one that finds no program.
    if "PATH" in selected:
        selected["PATH"] = absolute_entries(selected["PATH"]) or os.devnull
    selected["GIT_TERMINAL_PROMPT"] = "0"
    selected["GCM_INTERACTIVE"] = "Never"
    selected["GIT_NO_REPLACE_OBJECTS"] = "1"
    # A partial clone would start `git fetch` to read a missing object.
    selected["GIT_NO_LAZY_FETCH"] = "1"
    return selected


def run_git(
    root: Path, arguments: Sequence[str], input_bytes: bytes | None = None
) -> bytes:
    return _execute(root, arguments, input_bytes, sanitized_git_environment(root=root))


# Keeps the GIT_CONFIG_* variables, so `git var` reads the identity `git commit`
# records: Git passes `git -c` settings to a hook in them, and they can name other
# global and system configuration files.
def commit_ident(root: Path, variable: str) -> bytes:
    environment = sanitized_git_environment(root=root)
    environment.update(
        (key, value)
        for key, value in os.environ.items()
        if key in COMMAND_LINE_CONFIG
        or key in CONFIG_FILE_CHOICES
        or key.startswith(COMMAND_LINE_CONFIG_PREFIXES)
    )
    return _execute(root, ("var", variable), None, environment)


def git_executable(
    environment: Mapping[str, str] | None = None, root: Path | None = None
) -> str:
    program = find_executable("git", environment)
    if program is None:
        raise GitUnavailableError(GIT_MISSING)
    inside = None if root is None else path_inside_repository(program, root)
    if inside is not None:
        raise GitUnavailableError(repository_program_message("Git", inside))
    return program


def _subcommand(arguments: Sequence[str]) -> str:
    return next((item for item in arguments if not item.startswith("-")), "")


def _failed(arguments: Sequence[str], code: int) -> GitError:
    return GitError(
        f"Git command `git {_subcommand(arguments)}` failed with exit code {code}.\n"
        + GIT_STATUS_FIX
    )


def _timed_out(arguments: Sequence[str]) -> GitError:
    return GitError(
        f"Git command `git {_subcommand(arguments)}` timed out after "
        f"{GIT_TIMEOUT_SECONDS} seconds.\n" + GIT_STATUS_FIX
    )


def _execute(
    root: Path,
    arguments: Sequence[str],
    input_bytes: bytes | None,
    environment: Mapping[str, str],
    success_codes: tuple[int, ...] = (0,),
) -> bytes:
    try:
        result = subprocess.run(
            [git_executable(environment, root), "-C", str(root), *arguments],
            input=input_bytes,
            env=environment,
            capture_output=True,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise _timed_out(arguments) from error
    except OSError as error:
        raise GitError("Git is unavailable.") from error
    if result.returncode not in success_codes:
        raise _failed(arguments, result.returncode)
    return result.stdout


# An empty group raises ProcessLookupError; on macOS a zombie group, PermissionError.
def _kill_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)


if sys.platform != "darwin" or sys.version_info >= (3, 13):
    # An unreaped process keeps its id, so killing its group reaches no other process.
    def _end_children(process: subprocess.Popen[bytes]) -> None:
        try:
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)
        except ChildProcessError:
            return
        _kill_group(process)

else:
    # Python on macOS has os.waitid only from 3.13, so the children keep running.
    def _end_children(_process: subprocess.Popen[bytes]) -> None:
        pass


BATCH_ARGUMENTS = ("cat-file", "--batch")
BATCH_STOPPED = (
    "Git command `git cat-file` stopped before it answered.\n" + GIT_STATUS_FIX
)
INCONSISTENT_OBJECT = "Git returned inconsistent object content."


@contextmanager
def _kill_on_timeout(process: subprocess.Popen[bytes]) -> Iterator[None]:
    expired = threading.Event()

    def expire() -> None:
        expired.set()
        if process.returncode is None:
            _kill_group(process)

    timer = threading.Timer(GIT_TIMEOUT_SECONDS, expire)
    timer.start()
    try:
        yield
    except (GitError, OSError) as error:
        if expired.is_set():
            raise _timed_out(BATCH_ARGUMENTS) from error
        if isinstance(error, GitError):
            raise
        raise GitError(BATCH_STOPPED) from error
    finally:
        timer.cancel()


# One answer is "<id> <kind> <size>", a newline, the bytes, and a newline.
def _read_object(stdout: IO[bytes], object_id: str, kind: str, size: int) -> bytes:
    header = f"{object_id} {kind} {size}\n".encode("ascii")
    if stdout.readline(len(header)) != header:
        raise GitError(INCONSISTENT_OBJECT)
    content = stdout.read(size)
    if len(content) != size or stdout.read(1) != b"\n":
        raise GitError(INCONSISTENT_OBJECT)
    return content


def cat_file_blobs(root: Path, sizes: Mapping[str, int]) -> Iterator[tuple[str, bytes]]:
    return cat_file_objects(root, "blob", sizes)


# Sends each id after the previous object is read, so memory holds one object.
def cat_file_objects(
    root: Path, kind: str, sizes: Mapping[str, int]
) -> Iterator[tuple[str, bytes]]:
    if not sizes:
        return
    environment = sanitized_git_environment(root=root)
    try:
        process = subprocess.Popen(
            [git_executable(environment, root), "-C", str(root), *BATCH_ARGUMENTS],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            start_new_session=True,
        )
    except OSError as error:
        raise GitError("Git is unavailable.") from error
    stdin, stdout = cast(IO[bytes], process.stdin), cast(IO[bytes], process.stdout)
    try:
        for object_id, size in sizes.items():
            with _kill_on_timeout(process):
                stdin.write(f"{object_id}\n".encode("ascii"))
                stdin.flush()
                content = _read_object(stdout, object_id, kind, size)
            yield object_id, content
        with _kill_on_timeout(process):
            stdin.close()
            extra = stdout.read(1)
            _end_children(process)
            code = process.wait()
        if extra:
            raise GitError(INCONSISTENT_OBJECT)
        if code != 0:
            raise _failed(BATCH_ARGUMENTS, code)
    finally:
        # Once wait() has reaped Git, its process id may name a new process.
        if process.returncode is None:
            _kill_group(process)
            process.wait()
        with suppress(OSError):
            stdin.close()
        stdout.close()


class ObjectInfo(NamedTuple):
    object_id: str
    kind: str
    size: int


def parse_batch_check(raw: bytes, count: int) -> list[ObjectInfo | None]:
    answers = raw.removesuffix(b"\n").split(b"\n") if count else []
    if len(answers) != count:
        raise GitError("Git returned an inconsistent object.")
    parsed: list[ObjectInfo | None] = []
    for answer in answers:
        match = BATCH_CHECK_ANSWER.fullmatch(answer)
        if match is not None:
            object_id, kind = match[1].decode("ascii"), match[2].decode("ascii")
            parsed.append(ObjectInfo(object_id, kind, int(match[3])))
        elif answer.endswith(BATCH_CHECK_MISSING):
            parsed.append(None)
        else:
            raise GitError("Git returned an inconsistent object.")
    return parsed


def is_tracked(root: Path, relative_path: str) -> bool:
    return bool(run_git(root, ("ls-files", "-z", "--cached", "--", relative_path)))


def _ignored_by_gitignore(root: Path, relative_path: str) -> bool:
    output = _execute(
        root,
        ("check-ignore", "--stdin", "-z", "--verbose", "--non-matching"),
        os.fsencode(relative_path) + b"\0",
        sanitized_git_environment(root=root),
        CHECK_IGNORE_CODES,
    )
    fields = output.split(b"\0")
    if len(fields) < CHECK_IGNORE_FIELDS:
        raise GitError("Git returned an inconsistent ignore answer.")
    source = PurePosixPath(os.fsdecode(fields[0]))
    # .git/info/exclude and core.excludesFile protect the file on this machine only.
    return (
        source.name == ".gitignore"
        and not source.is_absolute()
        and not fields[2].startswith(b"!")
    )


def require_ignored(root: Path, relative_path: str, subject: str) -> None:
    try:
        tracked = is_tracked(root, relative_path)
        ignored = not tracked and _ignored_by_gitignore(root, relative_path)
    except GitError as error:
        raise IgnoreStateError(f"{subject} Git state cannot be determined.") from error
    if tracked:
        raise IgnoreStateError(f"{subject} must not be tracked.")
    if not ignored:
        raise IgnoreStateError(f"{subject} must be protected by repository .gitignore.")


def repository_root(value: str | None) -> Path:
    start = Path(value).resolve() if value else Path.cwd().resolve()
    # The top is found before GIT_INDEX_FILE is checked: start may be a subfolder,
    # and Git resolves a relative GIT_INDEX_FILE against the top.
    raw = _execute(
        start, ("rev-parse", "--show-toplevel"), None, sanitized_git_environment()
    )
    return git_path(start, raw).resolve()
