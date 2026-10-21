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


def effective_git_settings(root: Path, keys: Sequence[str]) -> Mapping[str, str]:
    values = {}
    selected = {key.encode("ascii") for key in keys}
    for entry in run_git(root, ("config", "--null", "--list")).split(b"\0"):
        key, _, value = entry.partition(b"\n")
        if key in selected:
            try:
                values[key.decode("ascii")] = value.decode("utf-8")
            except UnicodeDecodeError as error:
                raise GitError("Git returned invalid configuration text.") from error
    return values
