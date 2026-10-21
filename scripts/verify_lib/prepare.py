import contextlib
import os
import re
import shutil
import signal
import subprocess
import tempfile
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import NamedTuple

from verify_lib.core import HTTPS, SSH, FeatureFailedError, Run, without_first_commit
from verify_lib.interpreter import PROJECT, handling_signals


class Plant(NamedTuple):
    feature: str
    caught_by: str
    edits: tuple[tuple[str, str, str], ...]


PLANTS = {
    "private-literal": Plant(
        "privacy",
        "a commit with a planted private value exited 0",
        (
            (
                "src/first_commit/checks/privacy.py",
                (
                    "    for value in policy.private_values:\n"
                    "        start = normalized.find(value)"
                ),
                "    for value in ():\n        start = normalized.find(value)",
            ),
        ),
    ),
    # Setup alone leaving commit.gpgsign unset is caught by setup's own
    # verification and the commit hook; with both quiet, only the signature check
    # sees the unsigned commit.
    "unsigned-commits": Plant(
        "commit",
        "not observed: the commit carries an SSH signature",
        (
            ("src/first_commit/setup_plan.py", '    "commit.gpgsign": "true",\n', ""),
            (
                "src/first_commit/checks/identity.py",
                'not git_enabled(git_settings.get("commit.gpgsign", ""))',
                "False",
            ),
        ),
    ),
}
PREREQUISITE_TIMEOUT_SECONDS = 30
STOP_SIGNALS = (signal.SIGTERM, signal.SIGHUP)
IGNORED = (signal.SIGINT, *STOP_SIGNALS)
AGENT_OUTPUT = "ssh-agent.out"
AGENT_VARIABLES = ("SSH_AUTH_SOCK", "SSH_AGENT_PID")


def plant(tree: Path, name: str) -> None:
    for relative, old, new in PLANTS[name].edits:
        path = tree / relative
        text = path.read_text("utf-8")
        if text.count(old) != 1:
            raise ValueError(
                f"plant {name}: anchor not found exactly once in {relative}"
            )
        path.write_text(text.replace(old, new), "utf-8")


def check_prerequisites(python: str) -> list[tuple[str, bool, str]]:
    checks = []

    def tool(name: str, args: list[str], fix: str) -> None:
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                timeout=PREREQUISITE_TIMEOUT_SECONDS,
                check=False,
            )
            ok = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            ok = False
        checks.append((name, ok, fix))

    tool(
        "Python with pre-commit and PyYAML",
        [python, "-c", "import pre_commit, yaml"],
        "create .venv with the test extra (python3.13 -m venv .venv; "
        ".venv/bin/pip install -e '.[test]'), or set FIRST_COMMIT_VERIFY_PYTHON",
    )
    tool("git", ["git", "--version"], "install git")
    tool("ssh-keygen", ["which", "ssh-keygen"], "install OpenSSH")
    tool("ssh-agent", ["which", "ssh-agent"], "install OpenSSH")
    tool(
        "network to PyPI",
        ["curl", "-sSfI", "-m", "15", "https://pypi.org/simple/pre-commit/"],
        "allow HTTPS to pypi.org (hook environments install from PyPI)",
    )
    tool(
        "network to GitHub Releases",
        ["curl", "-sSfI", "-m", "15", "https://github.com/gitleaks/gitleaks/releases"],
        "allow HTTPS to github.com (setup downloads Gitleaks)",
    )
    return checks


def prerequisites_ready(python: str) -> bool:
    ready = True
    for name, ok, fix in check_prerequisites(python):
        state = "ready" if ok else f"missing - {fix}"
        print(f"prerequisite: {name}: {state}")
        ready = ready and ok
    return ready


# Each feature puts the tool it tests on PATH itself. An inherited first-commit,
# such as the harness .venv's, would answer in its place.
def harness_path() -> tuple[str, list[str]]:
    return without_first_commit(os.environ.get("PATH", ""))


def prepare_run(python: str, work: Path, search_path: tuple[str, list[str]]) -> Run:
    path, removed = search_path
    home = work / "home"
    home.mkdir()
    (home / ".gitconfig").write_text(
        f'[url "{work / "source"}"]\n\tinsteadOf = {HTTPS}\n\tinsteadOf = {SSH}\n',
        "utf-8",
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("GIT_", "FIRST_COMMIT_", "PRE_COMMIT", "SSH_A", "XDG_"))
    }
    environment.update(
        PATH=path,
        HOME=str(home),
        PRE_COMMIT_HOME=str(work / "pre-commit"),
        PIP_CACHE_DIR=str(PROJECT / ".local/verify-cache/pip"),
        PIP_DISABLE_PIP_VERSION_CHECK="1",
    )
    return Run(
        work=work,
        python=python,
        environment=environment,
        ssh_auth_sock=os.environ.get("SSH_AUTH_SOCK", ""),
        removed_path_folders=removed,
    )


# The work folder is made inside the try that removes it, so no failure or signal
# after mkdtemp leaves the folder, with its private key, behind. Signals are ignored
# once cleanup starts, so none can stop it halfway.
@contextlib.contextmanager
def private_run(python: str, search_path: tuple[str, list[str]]) -> Iterator[Run]:
    work = None
    try:
        work = Path(tempfile.mkdtemp(prefix="first-commit-verify-"))
        yield prepare_run(python, work, search_path)
    finally:
        with handling_signals(IGNORED, signal.SIG_IGN):
            if work is not None:
                stop_agent(_agent_variables(work))
                shutil.rmtree(work, ignore_errors=True)


def _agent_variables(work: Path) -> dict[str, str]:
    try:
        output = (work / AGENT_OUTPUT).read_text("utf-8")
    except FileNotFoundError:
        return {}
    found = {}
    for name in AGENT_VARIABLES:
        match = re.search(rf"{name}=([^;]+);", output)
        if match is not None:
            found[name] = match.group(1)
    return found


# ssh-agent writes its variables to a file in the work folder, so cleanup finds the
# agent even when a signal stops the run before they reach the environment.
def start_agent(run: Run) -> None:
    key = run.work / "key"
    run.command(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "verify", "-f", key],
        run.work,
        expect=0,
    )
    output = run.work / AGENT_OUTPUT
    run.command(
        ["/bin/sh", "-c", 'exec ssh-agent -s > "$1"', "sh", output], run.work, expect=0
    )
    found = _agent_variables(run.work)
    for name in AGENT_VARIABLES:
        if name not in found:
            raise FeatureFailedError("ssh-agent did not print " + name)
    run.environment.update(found)
    run.environment["VERIFY_KEY"] = str(key)
    run.command(["ssh-add", "-q", key], run.work, expect=0)


# A stopped agent removed its socket, and its old process id may name a new process.
def stop_agent(environment: Mapping[str, str]) -> None:
    pid = environment.get("SSH_AGENT_PID", "")
    socket = environment.get("SSH_AUTH_SOCK", "")
    if pid.isdigit() and socket and Path(socket).exists():
        with contextlib.suppress(OSError):
            os.kill(int(pid), signal.SIGTERM)


def snapshot(run: Run, plant_name: str | None) -> Path:
    source = run.work / "source"
    run.command(
        ["git", "clone", "-q", "--no-hardlinks", PROJECT, source], run.work, expect=0
    )
    # Compare with HEAD, so staged and unstaged changes both count.
    _, changed = run.command(
        ["git", "diff", "-z", "--name-only", "--no-renames", "HEAD"], PROJECT, expect=0
    )
    _, untracked = run.command(
        ["git", "ls-files", "-z", "-o", "--exclude-standard"], PROJECT, expect=0
    )
    for name in filter(None, (changed + untracked).split("\0")):
        if (PROJECT / name).is_file():
            (source / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(PROJECT / name, source / name)
        elif (source / name).exists():
            (source / name).unlink()
    if plant_name is not None:
        plant(source, plant_name)
    git = ["git", "-c", "user.name=verify", "-c", "user.email=verify@example.com"]
    git += ["-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"]
    run.command(["git", "add", "-A"], source, expect=0)
    run.command(
        [*git, "commit", "-q", "--allow-empty", "-m", "verify snapshot"],
        source,
        expect=0,
    )
    _, head = run.command(["git", "rev-parse", "HEAD"], source, expect=0)
    run.revision = head.strip()
    return source


def redact(text: str, run: Run) -> str:
    text = text.replace(str(run.work), "<work>")
    return text.replace(str(Path.home()), "~")
