import shlex
from collections.abc import Mapping
from typing import Any

PUSH_CHECK_PROGRAMS = ("first-commit", "bin/first-commit")
PUSH_CHECK_COMMAND = ("hook", "pre-push")
FORMAT_OPTION = "--format"
# pre-commit skips a hook for a push whose files these keys filter out.
FILE_FILTERS = frozenset({"files", "types", "types_or", "exclude"})
# The stage names before pre-commit 3.2.0, which pre-commit 3.8.0 still maps.
OLD_STAGE_NAMES = {
    "commit": "pre-commit",
    "merge-commit": "pre-merge-commit",
    "push": "pre-push",
}


def current_stage(name: object) -> object:
    return OLD_STAGE_NAMES.get(name, name) if isinstance(name, str) else name


def lists_pre_push(hook: Mapping[str, Any]) -> bool:
    # Without stages, a hook takes the config's default_stages or its manifest's.
    stages = hook.get("stages")
    return isinstance(stages, list) and any(
        current_stage(name) == "pre-push" for name in stages
    )


def runs_push_check(hook: Mapping[str, Any]) -> bool:
    entry, arguments = hook.get("entry"), hook.get("args", [])
    if not (
        hook.get("language") == "system"
        and hook.get("always_run") is True
        and hook.get("pass_filenames") is False
        and not FILE_FILTERS.intersection(hook)
        and lists_pre_push(hook)
        and isinstance(entry, str)
        and isinstance(arguments, list)
        and all(isinstance(argument, str) for argument in arguments)
    ):
        return False
    try:
        words = [*shlex.split(entry), *arguments]
    except ValueError:
        return False
    if not words or words[0] not in PUSH_CHECK_PROGRAMS:
        return False
    options = words[3:]
    return tuple(words[1:3]) == PUSH_CHECK_COMMAND and (
        not options
        or (options[0] == FORMAT_OPTION and options[1:] in (["human"], ["json"]))
    )
