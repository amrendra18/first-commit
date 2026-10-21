import json
import os
import select
import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from verify_lib.core import (
    COMMAND_TIMEOUT_SECONDS,
    IDENTITY,
    PRIVATE_MODE,
    FeatureFailedError,
    Run,
    exited,
    require,
    stop_group,
)
from verify_lib.fix_line import readme_install
from verify_lib.interpreter import PROJECT

FIRST_RUN_PAGE = "verify/features/first-run.md"
DRY_RUN_HEADING = (
    "Expected dry run in an empty folder, with no saved identity:\n\n```text\n"
)
PROMPTS = (
    "Public Git author name: ",
    "Public Git author email: ",
    "SSH public signing-key path (ends in .pub, for example ~/.ssh/id_ed25519.pub): ",
    "Apply this setup? [y/N] ",
)
READ_BYTES = 4096
POLL_SECONDS = 1.0


def documented_dry_run() -> list[str]:
    page = (PROJECT / FIRST_RUN_PAGE).read_text("utf-8")
    return page.split(DRY_RUN_HEADING, 1)[1].split("```", 1)[0].splitlines()


def _read_until_exit(
    primary: int, process: subprocess.Popen[bytes], pending: list[tuple[str, str]]
) -> bytes:
    output = bytearray()
    seen = 0
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        ready, _, _ = select.select([primary], [], [], POLL_SECONDS)
        if not ready:
            continue
        try:
            chunk = os.read(primary, READ_BYTES)
        except OSError:
            chunk = b""
        if not chunk:
            return bytes(output)
        output += chunk
        if pending:
            prompt, answer = pending[0]
            found = output.find(prompt.encode("utf-8"), seen)
            if found >= 0:
                os.write(primary, answer.encode("utf-8") + b"\n")
                seen = found + len(prompt)
                pending.pop(0)
    process.kill()
    raise FeatureFailedError(f"no exit within {COMMAND_TIMEOUT_SECONDS} s")


def terminal(
    run: Run,
    args: Sequence[str | Path],
    cwd: Path,
    environment: Mapping[str, str],
    answers: Sequence[tuple[str, str]],
) -> tuple[int, str]:
    shown = " ".join(str(a) for a in args)
    primary, secondary = os.openpty()
    try:
        process = subprocess.Popen(
            [str(a) for a in args],
            cwd=cwd,
            env=dict(environment),
            stdin=secondary,
            stdout=secondary,
            stderr=secondary,
            start_new_session=True,
        )
    finally:
        os.close(secondary)
    pending = list(answers)
    try:
        raw = _read_until_exit(primary, process, pending)
    except BaseException:
        stop_group(process)
        raise
    finally:
        os.close(primary)
    code = process.wait(timeout=COMMAND_TIMEOUT_SECONDS)
    text = raw.decode("utf-8", "replace").replace("\r\n", "\n")
    run.log.append(f"$ {shown}  (in a pseudo-terminal)\n[exit {code}]\n{text}")
    if pending:
        raise FeatureFailedError(
            f"`{shown}` never printed the prompt {pending[0][0]!r}"
        )
    return code, text


def feature_first_run(run: Run) -> list[str]:
    tool = readme_install(run)
    home = run.work / "first-run-home"
    home.mkdir()
    shutil.copy2(Path(run.environment["HOME"]) / ".gitconfig", home / ".gitconfig")
    environment = dict(
        run.environment,
        HOME=str(home),
        PATH=f"{tool}:{run.environment.get('PATH', '')}",
    )
    project = run.work / "first-run-project"
    project.mkdir()
    command = tool / "first-commit"
    previewed, preview = run.command(
        [command, "setup", "--dry-run"],
        project,
        environment={k: v for k, v in environment.items() if k != "PRE_COMMIT_HOME"},
    )
    untouched = not any(project.iterdir())
    person = (
        IDENTITY["FIRST_COMMIT_AUTHOR_NAME"],
        IDENTITY["FIRST_COMMIT_AUTHOR_EMAIL"],
        run.environment["VERIFY_KEY"] + ".pub",
        "y",
    )
    code, output = terminal(
        run,
        [command, "setup"],
        project,
        environment,
        tuple(zip(PROMPTS, person, strict=True)),
    )
    identity = home / ".config/first-commit/identity.json"
    saved = json.loads(identity.read_text("utf-8")) if identity.is_file() else {}
    doctored, doctor_output = run.command(
        [command, "doctor"], project, environment=environment
    )
    return [
        exited(previewed, 0, "the installed `first-commit setup --dry-run`"),
        require(
            condition=preview.splitlines() == documented_dry_run(),
            observed=f"the dry run printed the expected block in {FIRST_RUN_PAGE}, line for line",
        ),
        require(condition=untouched, observed="the dry run left the folder empty"),
        exited(code, 0, "the installed `first-commit setup` in a pseudo-terminal"),
        "setup asked for the name, email, and signing key, then for confirmation",
        require(
            condition=f"Identity: {person[0]} <{person[1]}>, signing key {person[2]} "
            "(from the answers typed above)" in output,
            observed="the plan named the typed identity and its source",
        ),
        require(
            condition="Verification: passed" in output,
            observed="setup printed Verification: passed",
        ),
        require(
            condition=f"Machine identity: saved to {identity}" in output
            and saved.get("email") == IDENTITY["FIRST_COMMIT_AUTHOR_EMAIL"]
            and identity.stat().st_mode & 0o777 == PRIVATE_MODE,
            observed="the typed identity was saved to "
            "~/.config/first-commit/identity.json, mode 600",
        ),
        require(
            condition=(project / ".local/first-commit/contributor.json").is_file(),
            observed="the contributor record was written",
        ),
        exited(doctored, 0, "`first-commit doctor` after setup"),
        require(
            condition="WARN doctor" in doctor_output
            and "git.signature-verification-trust" in doctor_output,
            observed="the first doctor printed WARN doctor with "
            "git.signature-verification-trust, as the README says",
        ),
    ]
