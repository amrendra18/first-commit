from collections.abc import Mapping, Sequence
from pathlib import Path

from first_commit.git import GitError, run_git


def local_git_settings(root: Path, keys: Sequence[str]) -> Mapping[str, str]:
    values = {}
    for key in keys:
        try:
            raw = run_git(root, ("config", "--local", "--get", key))
        except GitError:
            continue
        try:
            values[key] = raw.decode("utf-8").rstrip("\n")
        except UnicodeDecodeError:
            continue
    return values


# Git lists the section and the setting name in lower case and keeps a subsection's
# case, so a key matches as `git config --get` matches it.
def _listed_name(key: bytes) -> bytes:
    section, dot, rest = key.partition(b".")
    subsection, inner, name = rest.rpartition(b".")
    return section.lower() + dot + subsection + inner + name.lower()


def effective_git_settings(root: Path, keys: Sequence[str]) -> Mapping[str, str]:
    values = {}
    selected = {_listed_name(key.encode("ascii")): key for key in keys}
    for entry in run_git(root, ("config", "--null", "--list")).split(b"\0"):
        listed, _, value = entry.partition(b"\n")
        key = selected.get(listed)
        if key is not None:
            try:
                values[key] = value.decode("utf-8")
            except UnicodeDecodeError as error:
                raise GitError("Git returned invalid configuration text.") from error
    return values
