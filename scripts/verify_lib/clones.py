import os
import re
import shlex
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path

from verify_lib.core import (
    GITLEAKS_DOWNLOADED,
    IDENTITY,
    PRIVATE_MODE,
    SETUP_HOOK_COMMAND,
    Run,
    blocked,
    exited,
    git_commit,
    require,
    signed,
)

CHECK_HOOK_COMMAND = "pre-commit run first-commit-check --hook-stage manual --all-files"


def clone(run: Run, name: str, *, reuse_gitleaks: bool) -> Path:
    target = run.work / name
    run.command(["git", "clone", "-q", run.project, target], run.work, expect=0)
    run.command([run.python, "-m", "pre_commit", "install"], target, expect=0)
    if reuse_gitleaks:
        local = target / ".local/bin"
        local.mkdir(parents=True)
        shutil.copy2(run.project / ".local/bin/gitleaks", local / "gitleaks")
    return target


def clone_commit(run: Run, target: Path, extra: Sequence[str] = ()) -> tuple[int, str]:
    (target / "clone.txt").write_text(f"{target.name}\n", "utf-8")
    run.command(["git", "add", "clone.txt"], target, expect=0)
    return git_commit(run, target, extra=extra)


def setup_hook(
    run: Run, target: Path, extra_environment: Mapping[str, str]
) -> tuple[int, str]:
    environment = dict(run.environment, **extra_environment)
    return run.command(
        [
            run.python,
            "-m",
            "pre_commit",
            "run",
            "first-commit-setup",
            "--hook-stage",
            "manual",
        ],
        target,
        environment=environment,
    )


def default_identity(run: Run) -> Path:
    return Path(run.environment["HOME"]) / ".config/first-commit/identity.json"


def guided(run: Run, target: Path, chosen: Mapping[str, str]) -> tuple[list[str], str]:
    stranger = ("-c", "user.name=Other", "-c", "user.email=other@example.com")
    early, early_output = clone_commit(run, target, stranger)
    missing, missing_output = setup_hook(run, target, chosen)
    variables = dict(
        chosen,
        **IDENTITY,
        FIRST_COMMIT_SIGNING_KEY=run.environment["VERIFY_KEY"] + ".pub",
    )
    done, done_output = setup_hook(run, target, variables)
    path = Path(chosen.get("FIRST_COMMIT_IDENTITY_FILE") or default_identity(run))
    committed, _ = git_commit(run, target)
    observed = [
        blocked(early, "a commit before setup"),
        require(
            condition=SETUP_HOOK_COMMAND in early_output,
            observed="the blocked commit names the setup command",
        ),
        blocked(missing, "setup without an identity"),
        require(
            condition=str(path) in missing_output
            and "FIRST_COMMIT_AUTHOR_NAME=" in missing_output,
            observed="setup without an identity printed the file and the exact command",
        ),
        exited(done, 0, "setup with the three variables"),
        require(
            condition=f"Machine identity: saved to {path}" in done_output
            and path.is_file(),
            observed="the identity was saved to the expected file",
        ),
        require(
            condition=path.stat().st_mode & 0o777 == PRIVATE_MODE,
            observed="the identity file is mode 600",
        ),
        exited(committed, 0, "the commit after setup"),
        require(
            condition=signed(run, target),
            observed="the clone's commit carries an SSH signature",
        ),
    ]
    return observed, done_output


def manual_hook(run: Run, target: Path, name: str) -> tuple[int, str]:
    arguments = ["run", name, "--hook-stage", "manual", "--all-files"]
    return run.command([run.python, "-m", "pre_commit", *arguments], target)


def checks_without_tool(run: Run, target: Path, setup_output: str) -> list[str]:
    found = shutil.which("first-commit", path=run.environment.get("PATH", ""))
    doctor_code, doctor_output = manual_hook(run, target, "first-commit-doctor")
    printed = re.search(r"^Next action: run (.+)$", setup_output, re.MULTILINE)
    next_action = printed.group(1) if printed else ""
    check_code, check_output = run_printed(run, next_action, target)
    return [
        require(
            condition=next_action == CHECK_HOOK_COMMAND,
            observed=f"clone setup printed the next action {CHECK_HOOK_COMMAND}",
        ),
        require(
            condition=found is None,
            observed="no first-commit command on PATH for the next two runs",
        ),
        exited(doctor_code, 0, "pre-commit run first-commit-doctor in the clone"),
        require(
            condition=re.search(
                r"^first-commit doctor\.+Passed$", doctor_output, re.MULTILINE
            )
            is not None
            and re.search(r"^(PASS|WARN) doctor$", doctor_output, re.MULTILINE)
            is not None,
            observed="the doctor hook ran first-commit doctor, which passed",
        ),
        exited(check_code, 0, "the printed next action in the clone"),
        require(
            condition=re.search(
                r"^first-commit check\.+Passed$", check_output, re.MULTILINE
            )
            is not None
            and all(
                f"PASS {step}" in check_output
                for step in ("working", "staged", "history")
            ),
            observed="the check hook ran first-commit check: working, staged, and history passed",
        ),
    ]


def feature_clone_guided(run: Run) -> list[str]:
    target = clone(run, "clone-guided", reuse_gitleaks=False)
    observed, setup_output = guided(run, target, {})
    scanner = target / ".local/bin/gitleaks"
    observed.append(
        require(
            condition=GITLEAKS_DOWNLOADED.search(setup_output) is not None
            and scanner.is_file()
            and os.access(scanner, os.X_OK),
            observed="setup printed Gitleaks: downloaded and installed, and the "
            "clone's .local/bin/gitleaks is an executable file",
        )
    )
    return observed + checks_without_tool(run, target, setup_output)


def feature_clone_saved(run: Run) -> list[str]:
    target = clone(run, "clone-saved", reuse_gitleaks=True)
    saved = require(
        condition=default_identity(run).is_file(),
        observed="the saved identity file exists before this clone",
    )
    code, output = setup_hook(run, target, {})
    committed, _ = clone_commit(run, target)
    return [
        saved,
        exited(code, 0, "setup with only the saved identity"),
        require(
            condition="Machine identity: saved" not in output,
            observed="no new identity was written",
        ),
        exited(committed, 0, "the commit after setup"),
        require(
            condition=signed(run, target),
            observed="the clone's commit carries an SSH signature",
        ),
    ]


def feature_clone_chosen_path(run: Run) -> list[str]:
    chosen = run.work / "chosen place/me.json"
    default = default_identity(run)
    before = default.stat().st_mtime_ns if default.exists() else None
    observed, _ = guided(
        run,
        clone(run, "clone-chosen", reuse_gitleaks=True),
        {"FIRST_COMMIT_IDENTITY_FILE": str(chosen)},
    )
    after = default.stat().st_mtime_ns if default.exists() else None
    observed.append(
        require(
            condition=before == after,
            observed="the default identity file was not touched",
        )
    )
    return observed


DOCTOR_DRIVER = (
    "import sys; sys.path.insert(0, sys.argv[1]); "
    "from first_commit.cli import main; raise SystemExit(main(sys.argv[2:]))"
)
TRUST_FIX = re.compile(r"^  fix: Run (.+?) in this checkout to trust", re.MULTILINE)
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
TRUST_RULE = "git.signature-verification-trust"


def doctor_journey(run: Run, target: Path) -> tuple[int, str]:
    return run.command(
        [run.python, "-I", "-c", DOCTOR_DRIVER, run.work / "source/src", "doctor"],
        target,
    )


def run_printed(run: Run, command: str, target: Path) -> tuple[int, str]:
    words = shlex.split(command)
    assignments: dict[str, str] = {}
    while words and ASSIGNMENT.match(words[0]):
        name, value = words.pop(0).split("=", 1)
        assignments[name] = value
    program = words
    if program[:1] == ["pre-commit"]:
        program = [run.python, "-m", "pre_commit", *program[1:]]
    return run.command(
        program or ["false"], target, environment=dict(run.environment, **assignments)
    )


def feature_clone_trust(run: Run) -> list[str]:
    target = clone(run, "clone-trust", reuse_gitleaks=True)
    identity = {
        **IDENTITY,
        "FIRST_COMMIT_SIGNING_KEY": run.environment["VERIFY_KEY"] + ".pub",
        "FIRST_COMMIT_IDENTITY_FILE": str(run.work / "trust identity/me.json"),
    }
    set_up = exited(
        setup_hook(run, target, identity)[0], 0, "clone setup without trust"
    )
    committed, _ = clone_commit(run, target)
    first_commit = exited(committed, 0, "the clone's first commit")
    unverified, _ = run.command(["git", "verify-commit", "HEAD"], target)
    before, warned = doctor_journey(run, target)
    match = TRUST_FIX.search(warned)
    command = match.group(1) if match else ""
    trusted, _ = run_printed(run, command, target)
    after, checked = doctor_journey(run, target)
    verified, _ = run.command(["git", "verify-commit", "HEAD"], target)
    return [
        set_up,
        first_commit,
        blocked(unverified, "git verify-commit before trust"),
        exited(before, 0, "doctor before trust (a warning only)"),
        require(
            condition=TRUST_RULE in warned, observed=f"doctor warned with {TRUST_RULE}"
        ),
        require(
            condition=command.startswith("FIRST_COMMIT_TRUST_SELF=1 ")
            and "first-commit-setup" in command,
            observed=f"the fix line names `{command}`",
        ),
        exited(trusted, 0, f"`{command}`, run exactly as the fix line prints it"),
        exited(after, 0, "doctor after trust"),
        require(
            condition=TRUST_RULE not in checked,
            observed="doctor's trust warning is gone",
        ),
        exited(verified, 0, "git verify-commit after trust"),
    ]
