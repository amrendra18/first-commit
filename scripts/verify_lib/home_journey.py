import shutil
from pathlib import Path

from verify_lib.core import PRIVATE_MODE, Run, blocked, exited, git_commit, require

KEPT_LIST = "privacy/terms.txt"
MASKED_FINDING = 'text.trailing-whitespace "privacy/<private value>-notes.txt"'


def home_repository(run: Run, project: Path, canary: str, user_list: str) -> list[str]:
    link = Path(run.environment["HOME"]) / user_list
    kept = project / KEPT_LIST
    named = f"privacy/{canary}-notes.txt"
    kept.parent.mkdir()
    kept.write_text(canary + "\n", "utf-8")
    kept.chmod(PRIVATE_MODE)
    (project / named).write_text("trailing space \n", "utf-8")
    link.symlink_to(kept)
    try:
        run.command(["git", "add", KEPT_LIST, named], project, expect=0)
        masked_code, masked = git_commit(run, project)
        run.command(["git", "reset", "-q", "--", named], project, expect=0)
        code, output = git_commit(run, project)
        if code == 0:
            run.command(["git", "reset", "-q", "HEAD~1"], project, expect=0)
    finally:
        run.command(["git", "reset", "-q", "--", KEPT_LIST, named], project)
        link.unlink()
        shutil.rmtree(kept.parent)
    line = (
        f"Private values: ~/{user_list} is kept in this repository, so it does not "
        "apply here."
    )
    said = (masked.count(line), output.count(line))
    printed = (masked + output).count(canary)
    return [
        blocked(masked_code, "a commit of a file named with a kept value"),
        require(
            condition=MASKED_FINDING in masked,
            observed=f"{MASKED_FINDING} reported",
        ),
        require(
            condition="privacy.private-" not in masked,
            observed="no private-value finding for the kept value",
        ),
        exited(code, 0, "a commit of the user-level list in its own repository"),
        require(
            condition=said == (1, 1),
            observed=f"'{line}' printed {said[0]} and {said[1]} time(s)",
        ),
        require(
            condition=printed == 0,
            observed=f"the kept value was never printed (count {printed})",
        ),
    ]
