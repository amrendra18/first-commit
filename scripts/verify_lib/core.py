import argparse
import contextlib
import os
import re
import signal
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple, NoReturn

from verify_lib.interpreter import PROJECT


# Reads the constant as text: the harness must not import the product.
def _product_repository() -> str:
    source = (PROJECT / "src/first_commit/hooks.py").read_text("utf-8")
    match = re.search(r'^GITHUB_REPOSITORY = "([^"]+)"$', source, re.MULTILINE)
    if match is None:
        raise RuntimeError("src/first_commit/hooks.py has no GITHUB_REPOSITORY.")
    return match.group(1)


HTTPS = f"https://github.com/{_product_repository()}"
SSH = f"ssh://git@github.com/{_product_repository()}"
SETUP_HOOK_COMMAND = "pre-commit run first-commit-setup --hook-stage manual"
PRIVATE_MODE = 0o600
GIT_HOOKS = ".git/hooks"
IDENTITY = {
    "FIRST_COMMIT_AUTHOR_NAME": "Verify Contributor",
    "FIRST_COMMIT_AUTHOR_EMAIL": "verify-contributor@example.com",
}
MESSAGE = (
    "chore: verify the project\n\nWhy:\n- Harness run.\n\nChanges:\n- One file.\n\n"
    "Test Plan:\n- Not run: harness fixture.\n\nRisks:\n- None.\n"
)
COMMAND_TIMEOUT_SECONDS = 900
PATH_TOOLS = ("git", "ssh", "ssh-add", "ssh-agent", "ssh-keygen")
STAGED_HOOK = "first-commit staged hygiene"
MESSAGE_HOOK = "first-commit commit-message hygiene"
PUSH_HOOK = "first-commit pre-push hygiene"
GITLEAKS_DOWNLOADED = re.compile(r"^Gitleaks: downloaded and installed ", re.MULTILINE)
GITLEAKS_REUSED = re.compile(r"^Gitleaks: ready$", re.MULTILINE)


# Each command runs in its own process group, so a stopped run can end the helpers
# the command started (pre-commit starts pip, for example) without ending itself.
def stop_group(process: subprocess.Popen[str] | subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


class FeatureFailedError(Exception):
    pass


class PathFolderError(Exception):
    pass


class UsageError(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise UsageError(message)


class FeatureSkippedError(Exception):
    pass


class Feature(NamedTuple):
    level: str
    needs: tuple[str, ...] = ()


@dataclass
class FeatureResult:
    state: str
    observed: list[str] = field(default_factory=list)
    reason: str = ""
    optional: bool = False
    log: str = ""


@dataclass
class Run:
    work: Path
    python: str
    environment: dict[str, str]
    revision: str = ""
    project: Path = Path()
    log: list[str] = field(default_factory=list)
    ssh_auth_sock: str = ""
    feature: str = ""
    features_without_preflight: list[str] = field(default_factory=list)
    removed_path_folders: list[str] = field(default_factory=list)

    def command(
        self,
        args: Sequence[str | Path],
        cwd: Path,
        environment: Mapping[str, str] | None = None,
        stdin: str | None = None,
        expect: int | None = None,
    ) -> tuple[int, str]:
        with subprocess.Popen(
            [str(a) for a in args],
            cwd=cwd,
            env=environment or self.environment,
            # Never the caller's terminal: a command that prompts there would wait
            # unseen until the timeout, because its output is captured.
            stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        ) as process:
            try:
                stdout, stderr = process.communicate(stdin, COMMAND_TIMEOUT_SECONDS)
            except BaseException:
                stop_group(process)
                raise
        output = stdout + stderr
        shown = " ".join(str(a) for a in args)
        self.log.append(f"$ {shown}\n[exit {process.returncode}]\n{output}")
        if expect is not None and process.returncode != expect:
            raise FeatureFailedError(
                f"`{shown}` exited {process.returncode}, expected {expect}"
            )
        return process.returncode, output


def without_first_commit(path: str) -> tuple[str, list[str]]:
    kept, removed = [], []
    for part in filter(None, path.split(os.pathsep)):
        if not (Path(part) / "first-commit").exists():
            kept.append(part)
            continue
        needed = [tool for tool in PATH_TOOLS if (Path(part) / tool).exists()]
        if needed:
            raise PathFolderError(
                f"PATH folder {part} holds first-commit and {', '.join(needed)}; "
                "the harness removes such a folder from PATH, so move first-commit "
                "out of it, or leave the folder off PATH."
            )
        if part not in removed:
            removed.append(part)
    return os.pathsep.join(kept), removed


def require(*, condition: bool, observed: str) -> str:
    if not condition:
        raise FeatureFailedError("not observed: " + observed)
    return observed


# pre-commit prints the hook's own result line: its name, dots, then Passed.
def hook_passed(output: str, name: str) -> bool:
    line = re.compile(rf"^{re.escape(name)}\.*Passed$", re.MULTILINE)
    return line.search(output) is not None


def exited(code: int, want: int, what: str) -> str:
    if code != want:
        raise FeatureFailedError(f"{what} exited {code}, expected {want}")
    return f"{what} exited {code}"


def blocked(code: int, what: str) -> str:
    if code == 0:
        raise FeatureFailedError(f"{what} exited {code}, expected non-zero")
    return f"{what} exited {code}"


def git_commit(
    run: Run,
    cwd: Path,
    message: str = MESSAGE,
    extra: Sequence[str] = (),
    environment: Mapping[str, str] | None = None,
) -> tuple[int, str]:
    path = run.work / "message.txt"
    path.write_text(message, "utf-8")
    return run.command(
        ["git", *extra, "commit", "-q", "-F", path], cwd, environment=environment
    )


def signed(run: Run, cwd: Path) -> bool:
    _, body = run.command(["git", "cat-file", "-p", "HEAD"], cwd, expect=0)
    return "-----BEGIN SSH SIGNATURE-----" in body


def remove_markers(project: Path) -> None:
    for name in ("README.md", "AGENTS.md"):
        path = project / name
        lines = [
            line
            for line in path.read_text("utf-8").splitlines(keepends=True)
            if "@no-commit" not in line and "Generated starter text" not in line
        ]
        path.write_text("".join(lines), "utf-8")
