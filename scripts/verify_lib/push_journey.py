from pathlib import Path

from verify_lib.core import (
    MESSAGE,
    PUSH_HOOK,
    Run,
    blocked,
    exited,
    hook_passed,
    require,
)

# Split so this source holds no token; Gitleaks reports the joined value.
PUSH_SECRET = 'token = "' + "ghp_" + "skxSJ9z5EMBO3vXNo2" + "Ga7qDBKsBMuOsI2XOq" + '"\n'
REMOTE = "origin"
STASHED = "stashed-secret.txt"
BRANCHES = ("first", "second")
BEFORE_ANY_SETUP = "2001-01-01T00:00:00 +0000"


def _remote_has(run: Run, remote: Path, branch: str) -> bool:
    code, _ = run.command(
        [
            "git",
            "--git-dir",
            remote,
            "rev-parse",
            "-q",
            "--verify",
            "refs/heads/" + branch,
        ],
        run.work,
    )
    return code == 0


def feature_push(run: Run) -> list[str]:
    project = run.project
    remote = run.work / "remote.git"
    run.command(["git", "init", "-q", "--bare", remote], run.work, expect=0)
    run.command(["git", "remote", "add", REMOTE, remote], project, expect=0)
    try:
        stashed = _stash_secret(run)
        code, output = run.command(["git", "push", "-q", REMOTE, "main"], project)
        return [
            require(condition=stashed, observed="the stash holds a token"),
            exited(code, 0, "git push of main to a local bare remote"),
            require(
                condition=hook_passed(output, PUSH_HOOK),
                observed=f"Git ran the pre-push hook, which printed '{PUSH_HOOK}' Passed",
            ),
            require(
                condition=_remote_has(run, remote, "main"),
                observed="the bare remote holds main",
            ),
            *_push_unsigned_commit(run, remote),
            *_push_commit_older_than_setup(run, remote),
            *_push_two_branches(run, remote),
        ]
    finally:
        run.command(["git", "stash", "drop", "-q"], project)
        for branch in BRANCHES:
            run.command(["git", "update-ref", "-d", "refs/heads/" + branch], project)
        run.command(["git", "remote", "remove", REMOTE], project)


# Git never pushes the stash, so the pre-push hook must not scan it.
def _stash_secret(run: Run) -> bool:
    project = run.project
    (project / STASHED).write_text(PUSH_SECRET, "utf-8")
    run.command(["git", "add", "--", STASHED], project, expect=0)
    run.command(["git", "stash", "push", "-q", "--", STASHED], project, expect=0)
    code, _ = run.command(["git", "rev-parse", "-q", "--verify", "refs/stash"], project)
    return code == 0 and not (project / STASHED).exists()


# Written with Git plumbing, past every commit hook, so only the pre-push hook sees it.
def _plumbing_commit(run: Run, parent: str, message: str, *, secret: bool) -> str:
    project = run.project
    index = {**run.environment, "GIT_INDEX_FILE": str(run.work / "push-branch.index")}
    run.command(["git", "read-tree", parent], project, environment=index, expect=0)
    if secret:
        _, blob = run.command(
            ["git", "hash-object", "-w", "--stdin"],
            project,
            stdin=PUSH_SECRET,
            expect=0,
        )
        run.command(
            [
                "git",
                "update-index",
                "--add",
                "--cacheinfo",
                f"100644,{blob.strip()},second-secret.txt",
            ],
            project,
            environment=index,
            expect=0,
        )
    _, tree = run.command(["git", "write-tree"], project, environment=index, expect=0)
    _, commit = run.command(
        [
            "git",
            "commit-tree",
            "--no-gpg-sign",
            "-p",
            parent,
            "-m",
            message,
            tree.strip(),
        ],
        project,
        expect=0,
    )
    return commit.strip()


# Git gives the hook one line per new branch, in the order pushed; pre-commit passes
# the hook only the first branch's range, so the hook must find the second itself.
def _push_two_branches(run: Run, remote: Path) -> list[str]:
    project = run.project
    _, head = run.command(["git", "rev-parse", "HEAD"], project, expect=0)
    commits = (
        _plumbing_commit(run, head.strip(), "feat: clean", secret=False),
        _plumbing_commit(run, head.strip(), "feat: plant", secret=True),
    )
    for branch, commit in zip(BRANCHES, commits, strict=True):
        run.command(
            ["git", "update-ref", "refs/heads/" + branch, commit], project, expect=0
        )
    code, output = run.command(["git", "push", "-q", REMOTE, *BRANCHES], project)
    return [
        blocked(
            code,
            "git push of two new branches: first (clean), then second (a commit "
            "holding a token)",
        ),
        require(
            condition="secrets.gitleaks" in output and "second-secret.txt" in output,
            observed="secrets.gitleaks reported second-secret.txt",
        ),
        require(
            condition=not any(_remote_has(run, remote, branch) for branch in BRANCHES),
            observed="the bare remote received neither branch",
        ),
    ]


# An adopted project's older commits have no signature, and the push leaves them be.
def _push_commit_older_than_setup(run: Run, remote: Path) -> list[str]:
    project = run.project
    message = run.work / "unsigned-message.txt"
    message.write_text(MESSAGE, "utf-8")
    run.command(
        [
            *("git", "commit", "-q", "--allow-empty", "--no-gpg-sign"),
            *("-F", message),
        ],
        project,
        environment={**run.environment, "GIT_COMMITTER_DATE": BEFORE_ANY_SETUP},
        expect=0,
    )
    _, older = run.command(["git", "rev-parse", "HEAD"], project, expect=0)
    code, _ = run.command(["git", "push", "-q", REMOTE, "main"], project)
    _, remote_main = run.command(
        ["git", "--git-dir", remote, "rev-parse", "refs/heads/main"], run.work
    )
    return [
        exited(
            code, 0, "git push of main with an unsigned commit older than the setup"
        ),
        require(
            condition=remote_main.strip() == older.strip(),
            observed="the bare remote's main is the older unsigned commit",
        ),
    ]


def _push_unsigned_commit(run: Run, remote: Path) -> list[str]:
    project = run.project
    _, pushed = run.command(["git", "rev-parse", "HEAD"], project, expect=0)
    message = run.work / "unsigned-message.txt"
    message.write_text(MESSAGE, "utf-8")
    try:
        run.command(
            [
                *("git", "commit", "-q", "--allow-empty", "--no-gpg-sign"),
                *("-F", message),
            ],
            project,
            expect=0,
        )
        _, unsigned = run.command(["git", "rev-parse", "HEAD"], project, expect=0)
        code, output = run.command(["git", "push", "-q", REMOTE, "main"], project)
        _, remote_main = run.command(
            ["git", "--git-dir", remote, "rev-parse", "refs/heads/main"], run.work
        )
    finally:
        run.command(
            ["git", "update-ref", "refs/heads/main", pushed.strip()], project, expect=0
        )
    return [
        blocked(code, "git push of main with a commit made with --no-gpg-sign"),
        require(
            condition=f'git.unsigned-commit ".git": Commit {unsigned.strip()[:12]} '
            in output,
            observed="git.unsigned-commit named the unsigned commit's short id",
        ),
        require(
            condition=remote_main.strip() == pushed.strip(),
            observed="the bare remote's main stayed at the last signed commit",
        ),
    ]
