from pathlib import Path

from verify_lib.core import Run, blocked, git_commit, require

FILTERED_FILE = "data.dat"
FILTER_CONFIG = "filter.lfs.clean"


# A clean filter, as Git LFS installs, stores only a pointer in the index. The
# commit hook reads the working copy of such a file, so a planted value in it is
# still blocked. The filter is a local sed, so no LFS install and no network.
def filtered_value(run: Run, project: Path, canary: str) -> list[str]:
    attributes = project / ".git/info/attributes"
    attributes.parent.mkdir(exist_ok=True)
    attributes.write_text("*.dat filter=lfs\n", "utf-8")
    run.command(
        ["git", "config", FILTER_CONFIG, "sed s/.*/pointer/"], project, expect=0
    )
    try:
        (project / FILTERED_FILE).write_text(f"written by {canary}\n", "utf-8")
        run.command(["git", "add", FILTERED_FILE], project, expect=0)
        _, staged = run.command(["git", "show", f":{FILTERED_FILE}"], project, expect=0)
        code, output = git_commit(run, project)
    finally:
        run.command(["git", "reset", "-q", "--", FILTERED_FILE], project)
        (project / FILTERED_FILE).unlink(missing_ok=True)
        run.command(["git", "config", "--unset", FILTER_CONFIG], project)
        attributes.unlink(missing_ok=True)
    printed = output.count(canary)
    return [
        require(
            condition=staged.strip() == "pointer",
            observed="the clean filter stored only a pointer in the index",
        ),
        blocked(code, "a commit of a filtered file whose working copy holds the value"),
        require(
            condition=f'privacy.private-literal "{FILTERED_FILE}"' in output,
            observed=f"privacy.private-literal reported at {FILTERED_FILE}",
        ),
        require(
            condition=printed == 0,
            observed=f"the private value was never printed (count {printed})",
        ),
    ]
