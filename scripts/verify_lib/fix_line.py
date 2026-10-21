import re
import shlex
import shutil
from collections.abc import Mapping
from pathlib import Path

from verify_lib.core import (
    HTTPS,
    Run,
    blocked,
    exited,
    git_commit,
    remove_markers,
    require,
    signed,
)
from verify_lib.journeys import setup_journey

FIX_COMMAND = re.compile(r"^  fix: Run (.+?) in this checkout;", re.MULTILINE)
HOOKS_AT_REVISION = """\
repos:
  - repo: "{source}"
    rev: "{revision}"
    hooks:
      - id: first-commit-staged
      - id: first-commit-message
      - id: first-commit-push
"""
LOCAL_HOOK = """\
      - id: first-commit-{name}
        name: first-commit {name}
        entry: first-commit hook {stage}
        language: system
        always_run: true
        pass_filenames: {pass_filenames}
        stages: [{stage}]
"""
LOCAL_HOOKS = "repos:\n  - repo: local\n    hooks:\n" + "".join(
    LOCAL_HOOK.format(name=name, stage=stage, pass_filenames=passed)
    for name, stage, passed in (
        ("staged", "pre-commit", "false"),
        ("message", "commit-msg", "true"),
        ("push", "pre-push", "false"),
    )
)


def install_tool(run: Run, name: str, requirement: str, *flags: str) -> Path:
    tool = run.work / name
    script = tool / "bin/first-commit"
    if not script.is_file():
        run.command([run.python, "-m", "venv", tool], run.work, expect=0)
        run.command(
            [tool / "bin/python", "-m", "pip", "install", "-q", *flags, requirement],
            run.work,
            expect=0,
        )
        require(
            condition=script.is_file(),
            observed=f"installing {requirement} made {name}/bin/first-commit",
        )
    return tool / "bin"


def project_without_setup_hook(run: Run, name: str, hooks: str) -> Path:
    project = run.work / name
    project.mkdir()
    (project / ".pre-commit-config.yaml").write_text(hooks, "utf-8")
    local = project / ".local/bin"
    local.mkdir(parents=True)
    shutil.copy2(run.project / ".local/bin/gitleaks", local / "gitleaks")
    return project


def prove_fix_line(
    run: Run, project: Path, environment: Mapping[str, str], case: str
) -> list[str]:
    code, _ = setup_journey(run, project, preflight=False, transport="https")
    exited(code, 0, f"{case}: setup in a project with its own hook file")
    remove_markers(project)
    run.command(["git", "add", "-A"], project, expect=0)
    first, _ = git_commit(run, project, environment=environment)
    exited(first, 0, f"{case}: the first commit")
    run.command(["git", "config", "--local", "--unset", "user.useConfigOnly"], project)
    (project / "change.txt").write_text("one change\n", "utf-8")
    run.command(["git", "add", "change.txt"], project, expect=0)
    stopped, output = git_commit(run, project, environment=environment)
    match = FIX_COMMAND.search(output)
    command = match.group(1) if match else ""
    fixed, _ = run.command(
        shlex.split(command) or ["false"], project, environment=environment
    )
    committed, _ = git_commit(run, project, environment=environment)
    hook_file = (project / ".pre-commit-config.yaml").read_text("utf-8")
    return [
        require(
            condition="first-commit-setup" not in hook_file,
            observed=f"{case}: the project's own .pre-commit-config.yaml declares no setup hook",
        ),
        blocked(stopped, f"{case}: a commit without user.useConfigOnly"),
        require(
            condition="git.explicit-identity" in output,
            observed=f"{case}: git.explicit-identity reported",
        ),
        require(
            condition=bool(command) and "first-commit-setup" not in command,
            observed=f"{case}: the fix line names `{command}`, not the missing setup hook",
        ),
        exited(fixed, 0, f"{case}: `{command}`, run exactly as the fix line prints it"),
        exited(committed, 0, f"{case}: the next commit"),
        require(
            condition=signed(run, project),
            observed=f"{case}: the commit carries an SSH signature",
        ),
    ]


def with_tool(run: Run, tool: Path) -> dict[str, str]:
    return dict(run.environment, PATH=f"{tool}:{run.environment.get('PATH', '')}")


def readme_install(run: Run) -> Path:
    return install_tool(
        run, "tool", f"first-commit[setup] @ git+{HTTPS}@{run.revision}"
    )


def feature_fix_line_works(run: Run) -> list[str]:
    pinned_tool = readme_install(run)
    pinned = project_without_setup_hook(
        run,
        "own-hooks-project",
        HOOKS_AT_REVISION.format(source=HTTPS, revision=run.revision),
    )
    observed = prove_fix_line(
        run, pinned, with_tool(run, pinned_tool), "pinned hooks, README install"
    )
    editable_tool = install_tool(
        run, "tool-editable", f"{run.work / 'source'}[setup]", "-e"
    )
    local = project_without_setup_hook(run, "local-hooks-project", LOCAL_HOOKS)
    observed += prove_fix_line(
        run, local, with_tool(run, editable_tool), "local hooks, editable install"
    )
    return observed
