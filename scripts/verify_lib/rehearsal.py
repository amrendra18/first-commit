import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from verify_lib.core import FeatureFailedError, Parser, Run, UsageError
from verify_lib.interpreter import PROJECT
from verify_lib.prepare import snapshot, stop_agent
from verify_lib.report import fact_lines, run_facts

WORKFLOW = PROJECT / ".github/workflows/ci.yml"
STAND_INS = {
    "actions/checkout": "a fresh clone of the working tree, uncommitted changes included",
    "actions/setup-python": "a new virtual environment from --python",
}
# The keys this rehearsal implements; any other key is refused, so a workflow
# change it cannot run never passes unnoticed. YAML reads a bare `on` as True.
# A rehearsal is one run, so concurrency has nothing to cancel.
WORKFLOW_KEYS = frozenset({"name", "on", True, "permissions", "concurrency", "jobs"})
JOB_KEYS = frozenset({"name", "runs-on", "strategy", "timeout-minutes", "steps"})
STEP_KEYS = frozenset({"name", "uses", "with", "run", "if", "env", "shell"})
# Actions runs a step with no shell as `bash -e {0}`, and `shell: bash` as below.
SHELLS = {
    None: ("bash", "-e"),
    "bash": ("bash", "--noprofile", "--norc", "-eo", "pipefail"),
}
SYSTEM_PATH = ("/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin")
KEPT_VARIABLES = ("TMPDIR", "LANG", "LC_ALL", "USER", "LOGNAME", "TERM")
ACTIONS_TIMEOUT_MINUTES = 360
TIMED_OUT = 124
USAGE = """Usage: scripts/ci-local [--python PATH]

Rehearses .github/workflows/ci.yml on this machine. For each job it runs every step in
order, in a fresh clone of the working tree (uncommitted changes included), with a
scratch HOME, no system Git config, and a minimal PATH. The workflow's own steps create
the throwaway test-ci-key. RUNNER_TEMP, GITHUB_ENV, and GITHUB_PATH work as on Actions.
A step runs with `bash -e`, or with `bash -eo pipefail` when it names `shell: bash`,
as on Actions. A job stops at its timeout-minutes (default 360, as on Actions): the
running step gets exit 124. concurrency has no effect, because a rehearsal is one run.
A workflow, job, or step key this rehearsal does not implement (such as env, defaults,
working-directory, or continue-on-error) is refused.

Stand-ins for the two actions: actions/checkout is the fresh clone; actions/setup-python
is a new virtual environment from --python (default: this Python). The matrix cell is
this machine's operating system and that Python's version.
Needs network: PyPI and GitHub Releases (setup downloads Gitleaks), as CI does.
Writes .local/ci-local/<UTC time>/ with summary.md and one log per step.
Exit 0 every step exited 0; 1 a step failed; 2 usage or a workflow feature this
rehearsal cannot run; 3 no Python 3.11 or newer to run on (see scripts/verify --help)."""


class WorkflowError(ValueError):
    pass


@dataclass
class StepResult:
    name: str
    code: int | None
    seconds: float = 0.0
    note: str = ""


@dataclass
class Job:
    steps: list[dict[str, Any]]
    minutes: int = ACTIONS_TIMEOUT_MINUTES


@dataclass
class JobState:
    work: Path
    environment: dict[str, str]
    paths: list[str] = field(default_factory=list)
    exported: dict[str, str] = field(default_factory=dict)
    checkout: Path = Path()


def _no_expression(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise WorkflowError(f"{where} must be text")
    if "${{" in value:
        raise WorkflowError(f"{where} uses a ${{{{ }}}} expression")
    return value


def _known_keys(
    mapping: dict[Any, Any], allowed: frozenset[object], where: str
) -> None:
    for key in mapping:
        if key not in allowed:
            raise WorkflowError(
                f"{where} uses {key}, which scripts/ci-local does not implement; "
                "remove it from the workflow or add it to scripts/verify_lib/rehearsal.py"
            )


def check_step(step: object, number: int) -> dict[str, Any]:
    if not isinstance(step, dict):
        raise WorkflowError(f"step {number} is not a mapping")
    where = f"step {number} ({step.get('name', 'unnamed')})"
    _known_keys(step, STEP_KEYS, where)
    if step.get("shell") not in SHELLS:
        raise WorkflowError(f"{where} uses shell {step['shell']}; only bash runs here")
    if step.get("if", "always()") != "always()":
        raise WorkflowError(f"{where} has a condition other than always()")
    uses = step.get("uses")
    if uses is not None:
        if str(uses).split("@", 1)[0] not in STAND_INS:
            raise WorkflowError(f"{where} uses {uses}, which has no local stand-in")
        return step
    _no_expression(step.get("run"), where + " run")
    environment = step.get("env", {})
    if not isinstance(environment, dict):
        raise WorkflowError(where + " env must be a mapping")
    for key, value in environment.items():
        _no_expression(value, f"{where} env {key}")
    return step


def _job_minutes(job: dict[str, Any], where: str) -> int:
    minutes = job.get("timeout-minutes", ACTIONS_TIMEOUT_MINUTES)
    if isinstance(minutes, bool) or not isinstance(minutes, int) or minutes < 1:
        raise WorkflowError(f"{where} timeout-minutes must be a whole number above 0")
    return minutes


def load_jobs(path: Path) -> dict[str, Job]:
    workflow = yaml.safe_load(path.read_text("utf-8"))
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    if not isinstance(workflow, dict) or not isinstance(jobs, dict) or not jobs:
        raise WorkflowError(f"{path.name} has no jobs")
    _known_keys(workflow, WORKFLOW_KEYS, path.name)
    loaded = {}
    for name, job in jobs.items():
        steps = job.get("steps") if isinstance(job, dict) else None
        if not isinstance(job, dict) or not isinstance(steps, list) or not steps:
            raise WorkflowError(f"job {name} has no steps")
        _known_keys(job, JOB_KEYS, f"job {name}")
        loaded[name] = Job(
            [check_step(step, n) for n, step in enumerate(steps, 1)],
            _job_minutes(job, f"job {name}"),
        )
    return loaded


# GITHUB_ENV lines are NAME=value, or NAME<<DELIMITER, the value lines, DELIMITER.
def parse_github_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    lines = iter(text.splitlines())
    for line in lines:
        if "<<" in line and ("=" not in line or line.index("<<") < line.index("=")):
            name, delimiter = line.split("<<", 1)
            body = []
            for part in lines:
                if part == delimiter:
                    break
                body.append(part)
            else:
                raise WorkflowError(f"GITHUB_ENV value {name} has no closing line")
            values[name] = "\n".join(body)
        elif "=" in line:
            name, value = line.split("=", 1)
            values[name] = value
        elif line.strip():
            raise WorkflowError("GITHUB_ENV has a line without NAME=value")
    return values


def base_environment(work: Path) -> dict[str, str]:
    environment = {key: os.environ[key] for key in KEPT_VARIABLES if key in os.environ}
    cache = PROJECT / ".local/ci-local/cache"
    environment.update(
        CI="true",
        HOME=str(work / "home"),
        RUNNER_TEMP=str(work / "runner-temp"),
        GIT_CONFIG_NOSYSTEM="1",
        PIP_CACHE_DIR=str(cache / "pip"),
        PIP_DISABLE_PIP_VERSION_CHECK="1",
    )
    return environment


def stand_in(state: JobState, step: dict[str, Any], python: str) -> str:
    action = str(step["uses"]).split("@", 1)[0]
    if action == "actions/checkout":
        path = os.pathsep.join(SYSTEM_PATH)
        run = Run(
            work=state.work,
            python=python,
            environment={**state.environment, "PATH": path},
        )
        try:
            state.checkout = snapshot(run, None)
        except FeatureFailedError as error:
            raise WorkflowError(f"could not clone the working tree: {error}") from error
        state.environment["GITHUB_WORKSPACE"] = str(state.checkout)
        return f"cloned the working tree at snapshot {run.revision[:12]}"
    environment = state.work / "python"
    subprocess.run([python, "-m", "venv", environment], check=True)
    state.paths.insert(0, str(environment / "bin"))
    return f"virtual environment from {python}"


def run_step(state: JobState, step: dict[str, Any], log: Path, timeout: float) -> int:
    script = state.work / "step.sh"
    script.write_text(step["run"], "utf-8")
    github_env = state.work / "github-env"
    github_path = state.work / "github-path"
    github_env.write_text("", "utf-8")
    github_path.write_text("", "utf-8")
    environment = {
        **state.environment,
        **state.exported,
        **{str(key): str(value) for key, value in step.get("env", {}).items()},
        "GITHUB_ENV": str(github_env),
        "GITHUB_PATH": str(github_path),
        "PATH": os.pathsep.join([*state.paths, *SYSTEM_PATH]),
    }
    with log.open("w", encoding="utf-8") as stream:
        try:
            result = subprocess.run(
                [*SHELLS[step.get("shell")], str(script)],
                cwd=state.checkout,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            stream.write("stopped: the job reached its timeout-minutes\n")
            return TIMED_OUT
    state.exported.update(parse_github_env(github_env.read_text("utf-8")))
    for entry in github_path.read_text("utf-8").splitlines():
        if entry.strip():
            state.paths.insert(0, entry.strip())
    return result.returncode


def run_job(name: str, job: Job, python: str, logs: Path) -> list[StepResult]:
    deadline = time.monotonic() + job.minutes * 60
    work = Path(tempfile.mkdtemp(prefix="first-commit-ci-local-"))
    (work / "home").mkdir()
    (work / "runner-temp").mkdir()
    state = JobState(work=work, environment=base_environment(work))
    results: list[StepResult] = []
    failed = False
    try:
        for number, step in enumerate(job.steps, 1):
            title = str(step.get("name") or step.get("uses") or f"step {number}")
            if failed and step.get("if") != "always()":
                results.append(
                    StepResult(title, None, note="not run: an earlier step failed")
                )
                print(f"{name} {number} {title}: not run")
                continue
            begin = time.time()
            if "uses" in step:
                note = stand_in(state, step, python)
                code = 0
            else:
                log = logs / f"{name}-{number:02d}.log"
                code = run_step(state, step, log, deadline - time.monotonic())
                note = f"log: {log.relative_to(PROJECT)}"
            took = round(time.time() - begin, 1)
            results.append(StepResult(title, code, took, note))
            print(f"{name} {number} {title}: exit {code} ({took} s)", flush=True)
            failed = failed or code != 0
    finally:
        # The workflow's own cleanup step may have stopped the agent already.
        stop_agent(state.exported)
        shutil.rmtree(work, ignore_errors=True)
    return results


def write_summary(
    evidence: Path, python: str, results: dict[str, list[StepResult]], code: int
) -> None:
    facts = run_facts(python)
    lines = [
        "# scripts/ci-local",
        "",
        f"- workflow: {WORKFLOW.relative_to(PROJECT)}",
        *fact_lines(facts),
        (
            f"- matrix cell: this machine ({platform.system()} {platform.machine()}), "
            f"Python {facts['python']}"
        ),
        f"- stand-ins: {'; '.join(f'{k}: {v}' for k, v in STAND_INS.items())}",
        f"- exit: {code}",
        "",
        "| # | job | step | exit | seconds | note |",
        "|---|---|---|---|---|---|",
    ]
    number = 0
    for job, steps in results.items():
        for step in steps:
            number += 1
            shown = "not run" if step.code is None else str(step.code)
            lines.append(
                f"| {number} | {job} | {step.name} | {shown} | {step.seconds} | "
                f"{step.note} |"
            )
    (evidence / "summary.md").write_text("\n".join(lines) + "\n", "utf-8")


def main(arguments: list[str]) -> int:
    parser = Parser(add_help=False)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("-h", "--help", action="store_true")
    try:
        options = parser.parse_args(arguments)
        if options.help:
            print(USAGE)
            return 0
        jobs = load_jobs(WORKFLOW)
    except UsageError:
        print("error: invalid arguments", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    except WorkflowError as error:
        print(f"error: {error}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    evidence = PROJECT / ".local/ci-local" / stamp
    (evidence / "logs").mkdir(parents=True)
    results: dict[str, list[StepResult]] = {}
    try:
        for name, job in jobs.items():
            results[name] = run_job(name, job, options.python, evidence / "logs")
    except WorkflowError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    ok = all(step.code == 0 for steps in results.values() for step in steps)
    code = 0 if ok else 1
    write_summary(evidence, options.python, results, code)
    print(f"evidence: {evidence.relative_to(PROJECT)}/")
    print(f"ci-local: exit {code}")
    return code
