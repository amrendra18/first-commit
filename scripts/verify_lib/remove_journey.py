import shlex
from pathlib import Path

from verify_lib.clones import clone, clone_commit, setup_hook
from verify_lib.core import (
    GIT_HOOKS,
    IDENTITY,
    STAGED_HOOK,
    Run,
    exited,
    git_commit,
    hook_passed,
    require,
    signed,
)
from verify_lib.interpreter import PROJECT

REMOVE_HEADING = "\n## Remove\n"
LOCK_FILE = ".git/first-commit-setup.lock"
REMOVED_FILES = (".local/first-commit", ".local/bin/gitleaks")
HOOK_STAGES = ("pre-commit", "commit-msg", "pre-push")
PLAIN_IDENTITY = ("-c", "user.name=Plain", "-c", "user.email=plain@example.com")


def readme_remove_block() -> str:
    section = (PROJECT / "README.md").read_text("utf-8").split(REMOVE_HEADING, 1)[1]
    return section.split("```sh\n", 1)[1].split("```", 1)[0]


def _local_settings(run: Run, target: Path) -> str:
    return run.command(["git", "config", "--local", "--list"], target, expect=0)[1]


# The README block calls `pre-commit`; the harness Python provides it.
def _pre_commit_on_path(run: Run) -> dict[str, str]:
    tools = run.work / "remove-tools"
    tools.mkdir()
    command = tools / "pre-commit"
    command.write_text(
        f'#!/bin/sh\nexec {shlex.quote(run.python)} -m pre_commit "$@"\n', "utf-8"
    )
    command.chmod(0o755)
    return dict(run.environment, PATH=f"{tools}:{run.environment.get('PATH', '')}")


# The Remove proofs are absences, so the same clone first shows the hook and the
# signature present.
def _commit_after_setup(run: Run, target: Path) -> list[str]:
    (target / "set-up.txt").write_text("committed after setup\n", "utf-8")
    run.command(["git", "add", "set-up.txt"], target, expect=0)
    committed, output = git_commit(run, target)
    return [
        exited(committed, 0, "a commit after setup"),
        require(
            condition=hook_passed(output, STAGED_HOOK) and signed(run, target),
            observed=f"'{STAGED_HOOK}' printed Passed and the commit is signed",
        ),
    ]


def feature_remove(run: Run) -> list[str]:
    target = clone(run, "remove-clone", reuse_gitleaks=True)
    before = _local_settings(run, target)
    identity = {
        **IDENTITY,
        "FIRST_COMMIT_SIGNING_KEY": run.environment["VERIFY_KEY"] + ".pub",
        "FIRST_COMMIT_IDENTITY_FILE": str(run.work / "remove identity/me.json"),
        "FIRST_COMMIT_TRUST_SELF": "1",
    }
    set_up = exited(
        setup_hook(run, target, identity)[0], 0, "clone setup with self-trust"
    )
    hooked = _commit_after_setup(run, target)
    removed, _ = run.command(
        ["/bin/sh", "-c", readme_remove_block()],
        target,
        environment=_pre_commit_on_path(run),
    )
    after = _local_settings(run, target)
    committed, output = clone_commit(run, target, PLAIN_IDENTITY)
    lock = target / LOCK_FILE
    return [
        set_up,
        *hooked,
        exited(removed, 0, "the README Remove block, run as printed,"),
        require(
            condition=after == before,
            observed="the local Git config is the same as before setup",
        ),
        require(
            condition=not any((target / GIT_HOOKS / s).exists() for s in HOOK_STAGES),
            observed="no pre-commit, commit-msg, or pre-push hook script is left",
        ),
        require(
            condition=not any((target / name).exists() for name in REMOVED_FILES),
            observed=f"{' and '.join(REMOVED_FILES)} are gone",
        ),
        require(
            condition=lock.is_file() and lock.stat().st_size == 0,
            observed=f"the empty lock file {LOCK_FILE} stays, as README Remove says",
        ),
        exited(committed, 0, "a commit of a new file with a plain Git identity"),
        require(
            condition=STAGED_HOOK not in output and not signed(run, target),
            observed="no first-commit hook ran and the commit is not signed",
        ),
    ]
