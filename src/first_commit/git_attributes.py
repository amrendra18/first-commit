import os
from collections.abc import Collection, Sequence
from pathlib import Path

from first_commit.git import run_git

# A `git check-attr -z` answer is three fields: path, attribute, and value.
ATTRIBUTE_FIELDS = 3


# The <driver> names of each <section>.<driver>.<setting> key the Git config sets.
def configured_drivers(
    root: Path, section: str, settings: Collection[str]
) -> set[bytes]:
    prefix = f"{section}.".encode("ascii")
    suffixes = tuple(f".{setting}".encode("ascii") for setting in settings)
    drivers = set()
    for entry in run_git(root, ("config", "--null", "--list")).split(b"\0"):
        key = entry.partition(b"\n")[0]
        for suffix in suffixes:
            if key.startswith(prefix) and key.endswith(suffix):
                drivers.add(key.removeprefix(prefix).removesuffix(suffix))
    return drivers


def _attribute_values(
    root: Path, paths: Sequence[str], attribute: str, options: tuple[str, ...]
) -> dict[str, bytes]:
    raw = run_git(
        root,
        ("check-attr", *options, "--stdin", "-z", attribute),
        b"".join(os.fsencode(path) + b"\0" for path in paths),
    )
    fields = raw.split(b"\0")
    return {
        os.fsdecode(fields[start]): fields[start + 2]
        for start in range(0, len(fields) - ATTRIBUTE_FIELDS + 1, ATTRIBUTE_FIELDS)
    }


# Each options tuple is one attribute source, such as () for the working copy's
# .gitattributes or ("--cached",) for the staged ones; a path counts when any names
# one of the drivers.
def paths_with_driver(
    root: Path,
    paths: Sequence[str],
    attribute: str,
    drivers: Collection[bytes],
    sources: Sequence[tuple[str, ...]] = ((),),
) -> set[str]:
    if not drivers or not paths:
        return set()
    return {
        path
        for options in sources
        for path, value in _attribute_values(root, paths, attribute, options).items()
        if value in drivers
    }
