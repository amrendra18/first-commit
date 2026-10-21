import os
import stat
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from first_commit.characters import has_control_characters

MEBIBYTE = 1024 * 1024


class PathError(ValueError):
    pass


class PathPermissionsError(PathError):
    pass


class PathSizeError(PathError):
    pass


def relative_path_problem(value: str) -> str | None:
    parsed = PurePosixPath(value)
    rules = (
        (not parsed.parts, "names no file"),
        (parsed.is_absolute(), "is absolute"),
        # A path that starts with '~' may mean the home folder.
        (value.startswith("~"), "starts with '~'"),
        ("\\" in value, "holds a backslash"),
        (has_control_characters(value), "holds a control character"),
        (parsed.as_posix() != value, "is not in normal form"),
        (".." in parsed.parts, "has a '..' part"),
    )
    return next((problem for broken, problem in rules if broken), None)


# Git file names may hold control characters, backslashes, or a leading '~', and such
# files are still checked, so relative_path_problem does not apply here.
def confined_path(root: Path, relative_path: str) -> Path:
    parsed = PurePosixPath(relative_path)
    if parsed.is_absolute() or any(part in ("", ".", "..") for part in parsed.parts):
        raise PathError("File path is not relative to the repository.")
    root = root.resolve()
    destination = root.joinpath(*parsed.parts)
    try:
        destination.parent.resolve().relative_to(root)
    except ValueError as error:
        raise PathError("File path escapes the repository.") from error
    return destination


def read_regular_bytes(
    path: Path, max_bytes: int, forbidden_mode_bits: int = 0
) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PathError("File cannot be read.") from error
    try:
        content = _read_open_file(descriptor, max_bytes, forbidden_mode_bits)
    except OSError as error:
        raise PathError("File cannot be read.") from error
    finally:
        os.close(descriptor)
    if len(content) > max_bytes:
        raise PathSizeError("File exceeds the size limit.")
    return content


def _read_open_file(descriptor: int, max_bytes: int, forbidden_mode_bits: int) -> bytes:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise PathError("Path is not a regular file.")
    if stat.S_IMODE(metadata.st_mode) & forbidden_mode_bits:
        raise PathPermissionsError("File permissions are too broad.")
    if metadata.st_size > max_bytes:
        raise PathSizeError("File exceeds the size limit.")
    chunks = []
    remaining = max_bytes + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, MEBIBYTE))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def create_exclusive(path: Path, content: bytes, mode: int) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode
    )
    owned = os.fstat(descriptor)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
    except OSError:
        current = path.lstat()
        if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
            path.unlink()
        raise


# A symlink in place of a folder would put private files wherever it points.
def make_private_folders(folders: Iterable[Path], created: list[Path]) -> None:
    for folder in folders:
        if folder.is_symlink() or (folder.exists() and not folder.is_dir()):
            raise PathError(f"{folder.name} is not a plain folder.")
        if not folder.exists():
            folder.mkdir(mode=0o700)
            created.append(folder)


def read_explicit_file_bytes(root: Path, path: Path, max_bytes: int) -> bytes:
    resolved_root = root.resolve()
    destination = path if path.is_absolute() else resolved_root / path
    try:
        destination.resolve(strict=False).relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise PathError("File path escapes the repository.") from error
    return read_regular_bytes(destination, max_bytes)


def read_worktree_bytes(root: Path, relative_path: str, max_bytes: int) -> bytes:
    path = confined_path(root, relative_path)
    try:
        if path.is_symlink():
            content = os.fsencode(path.readlink())
        elif path.is_file():
            content = read_regular_bytes(path, max_bytes)
        else:
            return b""
    except OSError as error:
        raise PathError("File cannot be read.") from error
    if len(content) > max_bytes:
        raise PathSizeError("File exceeds the size limit.")
    return content
