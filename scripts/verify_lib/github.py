import sqlite3

from verify_lib.core import (
    MESSAGE_HOOK,
    SSH,
    STAGED_HOOK,
    FeatureSkippedError,
    Run,
    exited,
    git_commit,
    hook_passed,
    remove_markers,
    require,
    signed,
)
from verify_lib.interpreter import PROJECT
from verify_lib.journeys import setup_journey

PRODUCT_FILES = ("src", ".pre-commit-hooks.yaml", "pyproject.toml")
SSH_PORT_22 = "ssh -o BatchMode=yes -o ConnectTimeout=15"
SSH_PORT_443 = SSH_PORT_22 + " -o HostName=ssh.github.com -o Port=443"


def _github_main(run: Run, environment: dict[str, str]) -> str:
    code, output = 0, ""
    # Port 22 first, then GitHub's SSH endpoint on port 443 for networks that block 22.
    for command in (SSH_PORT_22, SSH_PORT_443):
        environment["GIT_SSH_COMMAND"] = command
        code, output = run.command(
            ["git", "ls-remote", SSH, "refs/heads/main"],
            run.work,
            environment=environment,
        )
        if code == 0:
            break
    else:
        raise FeatureSkippedError(
            f"could not read GitHub over SSH on port 22 or 443 (git ls-remote exited "
            f"{code}): unreachable, or access refused"
        )
    head = output.split()[0] if output.split() else ""
    known, _ = run.command(["git", "cat-file", "-e", head + "^{commit}"], PROJECT)
    if not head or known != 0:
        raise FeatureSkippedError(
            f"GitHub main {head[:7] or 'is empty'} is not in this clone; run git fetch"
        )
    differs, _ = run.command(
        ["git", "diff", "--quiet", head, "--", *PRODUCT_FILES], PROJECT
    )
    _, untracked = run.command(
        ["git", "ls-files", "--others", "--exclude-standard", "--", *PRODUCT_FILES],
        PROJECT,
        expect=0,
    )
    if differs != 0 or untracked.strip():
        raise FeatureSkippedError(
            f"product files ({', '.join(PRODUCT_FILES)}) differ from GitHub main "
            f"{head[:7]}; push them to prove this path"
        )
    return head


def feature_github(run: Run) -> list[str]:
    if not run.ssh_auth_sock:
        raise FeatureSkippedError(
            "no SSH agent in this shell, so GitHub cannot be read over SSH"
        )
    home = run.work / "home-github"
    home.mkdir()
    environment = {
        **run.environment,
        "HOME": str(home),
        "PRE_COMMIT_HOME": str(run.work / "pre-commit-github"),
        "SSH_AUTH_SOCK": run.ssh_auth_sock,
    }
    head = _github_main(run, environment)
    project = run.work / "github-project"
    project.mkdir()
    snapshot, run.revision = run.revision, head
    try:
        code, _ = setup_journey(
            run, project, preflight=True, transport="ssh", environment=environment
        )
    finally:
        run.revision = snapshot
    set_up = exited(
        code,
        0,
        "setup from GitHub over SSH, its hook source preflight (git ls-remote to "
        "GitHub) included,",
    )
    hook_file = (project / ".pre-commit-config.yaml").read_text("utf-8")
    with sqlite3.connect(run.work / "pre-commit-github/db.db") as database:
        fetched = database.execute(
            "SELECT COUNT(*) FROM repos WHERE repo = ? AND ref = ?", (SSH, head)
        ).fetchone()[0]
    remove_markers(project)
    signing = {**environment, "SSH_AUTH_SOCK": run.environment["SSH_AUTH_SOCK"]}
    run.command(["git", "add", "-A"], project, expect=0, environment=signing)
    committed, commit_output = git_commit(run, project, environment=signing)
    return [
        set_up,
        require(
            condition=f'repo: "{SSH}"' in hook_file and f'rev: "{head}"' in hook_file,
            observed=f"hooks pinned to the SSH address and GitHub main {head[:7]}",
        ),
        require(
            condition=fetched >= 1,
            observed="pre-commit downloaded the hooks from GitHub",
        ),
        exited(committed, 0, "the first commit through the downloaded hooks"),
        require(
            condition=hook_passed(commit_output, STAGED_HOOK)
            and hook_passed(commit_output, MESSAGE_HOOK),
            observed=f"'{STAGED_HOOK}' and '{MESSAGE_HOOK}' each printed Passed",
        ),
        require(
            condition=signed(run, project),
            observed="the commit carries an SSH signature",
        ),
    ]
