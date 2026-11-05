import shlex
import shutil

from verify_lib.core import (
    GIT_HOOKS,
    IDENTITY,
    SETUP_HOOK_COMMAND,
    Run,
    exited,
    require,
)

# Runs the snapshot with the harness Python, so the hooks find this tool on PATH.
WRAPPER = '#!/bin/sh\nPYTHONPATH={source} exec {python} -m first_commit.cli "$@"\n'
DOCTOR_HOOK = "pre-commit run first-commit-doctor --hook-stage manual"


def _installed_tool(run: Run) -> tuple[str, dict[str, str]]:
    folder = run.work / "installed-tool"
    folder.mkdir()
    tool = folder / "first-commit"
    tool.write_text(
        WRAPPER.format(
            source=shlex.quote(str(run.work / "source/src")),
            python=shlex.quote(run.python),
        ),
        "utf-8",
    )
    tool.chmod(0o755)
    environment = dict(
        run.environment,
        **IDENTITY,
        PATH=f"{folder}:{run.environment.get('PATH', '')}",
        FIRST_COMMIT_SIGNING_KEY=run.environment["VERIFY_KEY"] + ".pub",
        # Later features expect no saved identity in the harness HOME.
        FIRST_COMMIT_IDENTITY_FILE=str(run.work / "installed-identity.json"),
    )
    return str(tool), environment


# The scanner comes from the setup feature's project, so setup downloads nothing.
def installed_form_journey(run: Run) -> list[str]:
    tool, environment = _installed_tool(run)
    project = run.work / "installed-project"
    (project / ".local/bin").mkdir(parents=True)
    shutil.copy2(run.project / ".local/bin/gitleaks", project / ".local/bin/gitleaks")
    code, output = run.command(
        [tool, "setup", "--hooks", "installed", "--yes"],
        project,
        environment=environment,
    )
    exited(code, 0, "setup --hooks installed")
    hook_file = (project / ".pre-commit-config.yaml").read_text("utf-8")
    readme = (project / "README.md").read_text("utf-8")
    doctor, doctor_output = run.command([tool, "doctor"], project, environment)
    hook, hook_output = run.command(
        [run.python, "-m", "pre_commit", *shlex.split(DOCTOR_HOOK)[1:]],
        project,
        environment,
    )
    hooks = [
        project / GIT_HOOKS / stage
        for stage in ("pre-commit", "commit-msg", "pre-push")
    ]
    return [
        require(
            condition="Verification: passed" in output,
            observed="installed form: setup printed Verification: passed",
        ),
        require(
            condition="  - repo: local\n" in hook_file
            and "        entry: first-commit hook pre-commit\n" in hook_file
            and "rev:" not in hook_file,
            observed="installed form: local hooks run first-commit, with no rev",
        ),
        require(
            condition=all(path.is_file() for path in hooks),
            observed="installed form: pre-commit, commit-msg, and pre-push hooks installed",
        ),
        require(
            condition="first-commit setup\n" in readme
            and SETUP_HOOK_COMMAND not in readme,
            observed="installed form: the starter README names first-commit setup",
        ),
        exited(doctor, 0, "installed form: first-commit doctor"),
        require(
            condition=not any(
                line.startswith("hooks.") for line in doctor_output.splitlines()
            ),
            observed="installed form: doctor reports no hooks warning",
        ),
        exited(hook, 0, f"installed form: `{DOCTOR_HOOK}`"),
        require(
            condition="first-commit doctor" in hook_output
            and "doctor policy passed" in hook_output,
            observed="installed form: the manual doctor hook ran first-commit from PATH",
        ),
    ]
