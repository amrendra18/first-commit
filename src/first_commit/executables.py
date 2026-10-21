import os
import shutil
from collections.abc import Mapping
from pathlib import Path


# A relative entry such as "." or "" names the folder a command runs in, which can be
# the repository, so a file there named git or curl would run with the user's rights.
def absolute_entries(path: str) -> str:
    return os.pathsep.join(
        entry for entry in path.split(os.pathsep) if Path(entry).is_absolute()
    )


def find_executable(
    name: str, environment: Mapping[str, str] | None = None
) -> str | None:
    variables = os.environ if environment is None else environment
    search = absolute_entries(variables.get("PATH", os.defpath))
    return shutil.which(name, path=search) if search else None


# By file identity, so a case-insensitive disk matches every casing of root.
def _same_folder(folder: Path, root: Path) -> bool:
    try:
        return folder.samefile(root)
    except OSError:
        return False


# Git runs from any folder below the top, or from a folder outside every repository
# (such as / before setup), so the check measures from the top folder that holds .git.
def _repository_top(start: Path) -> Path | None:
    folder = start.resolve()
    return next(
        (top for top in (folder, *folder.parents) if os.path.lexists(top / ".git")),
        None,
    )


# An absolute PATH entry inside the repository lets repository content choose the
# program, as a relative entry would.
def path_inside_repository(program: str, start: Path) -> str | None:
    top = _repository_top(start)
    if top is None:
        return None
    resolved = Path(program).resolve()
    return next(
        (
            resolved.relative_to(folder).as_posix()
            for folder in (resolved, *resolved.parents)
            if _same_folder(folder, top)
        ),
        None,
    )


# Names the program by its path inside the repository, so the message never prints
# the repository's own location, which may hold a private value such as a user name.
def repository_program_message(label: str, inside: str) -> str:
    return (
        f"{label} on PATH is {inside} inside this repository, so repository "
        f"content would choose the {label} that runs.\n"
        f"fix: remove the folder that holds {inside} from PATH, then rerun."
    )
