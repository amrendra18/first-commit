import os
import tempfile
from pathlib import Path, PurePosixPath

from first_commit.models import SetupError
from first_commit.paths import (
    MEBIBYTE,
    PathError,
    confined_path,
    create_exclusive,
    make_private_folders,
    read_regular_bytes,
)

MAX_SETUP_BYTES = MEBIBYTE


def read_if_present(path: Path) -> bytes | None:
    if not os.path.lexists(path):
        return None
    try:
        return read_regular_bytes(path, MAX_SETUP_BYTES)
    except PathError as error:
        raise SetupError(
            "Setup paths must be bounded regular files, not symlinks or special files."
        ) from error


def create_local_file(root: Path, relative: str, content: bytes, label: str) -> Path:
    try:
        path = confined_path(root, relative)
    except PathError as error:
        raise SetupError(f"Local {label} path is unsafe.") from error
    folder = PurePosixPath(relative).parent
    try:
        make_private_folders((root / ".local", path.parent), [])
    except PathError as error:
        raise SetupError(
            f"The .local folder or {folder} is a link or not a folder, so setup "
            f"cannot write {relative} safely.\n"
            f"fix: run `ls -ld .local {folder}` to see what they are, move the one "
            "that is not a folder aside, then rerun setup."
        ) from error
    create_exclusive(path, content, 0o600)
    path.chmod(0o600)
    return path


def restore_git_config(path: Path, expected: bytes, original: bytes | None) -> None:
    if read_if_present(path) != expected:
        return
    if original is None:
        path.unlink()
        return
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(original)
            stream.flush()
            temporary.chmod(path.stat(follow_symlinks=False).st_mode & 0o777)
            if read_if_present(path) == expected:
                temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
