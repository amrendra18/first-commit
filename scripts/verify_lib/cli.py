import argparse
import contextlib
import re
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from types import FrameType

from verify_lib.clones import (
    feature_clone_chosen_path,
    feature_clone_guided,
    feature_clone_saved,
    feature_clone_trust,
)
from verify_lib.core import (
    Feature,
    FeatureFailedError,
    FeatureResult,
    FeatureSkippedError,
    Parser,
    PathFolderError,
    Run,
    UsageError,
)
from verify_lib.effects import feature_preview_matches_apply
from verify_lib.first_run import feature_first_run
from verify_lib.fix_line import feature_fix_line_works
from verify_lib.github import PRODUCT_FILES, feature_github
from verify_lib.interpreter import PROJECT, handling_signals, harness_python
from verify_lib.journeys import (
    feature_commit,
    feature_commit_all,
    feature_control_character,
    feature_message,
    feature_privacy,
    feature_setup,
)
from verify_lib.prepare import (
    PLANTS,
    STOP_SIGNALS,
    harness_path,
    prerequisites_ready,
    private_run,
    redact,
    snapshot,
    start_agent,
)
from verify_lib.push_journey import feature_push
from verify_lib.remove_journey import feature_remove
from verify_lib.report import finish

ENTRY = PROJECT / "scripts/verify"
FEATURES = {
    "setup": Feature("fast"),
    "commit": Feature("fast", ("setup",)),
    "privacy": Feature("fast", ("setup", "commit")),
    "message": Feature("fast", ("setup", "commit")),
    "push": Feature("fast", ("setup", "commit")),
    "clone-guided": Feature("fast", ("setup", "commit")),
    "control-character": Feature("fast", ("setup", "commit")),
    "preview-matches-apply": Feature("fast"),
    "fix-line-works": Feature("fast", ("setup",)),
    "first-run": Feature("fast"),
    "clone-trust": Feature("fast", ("setup", "commit")),
    "commit-all": Feature("fast", ("setup", "commit")),
    "clone-saved": Feature("full", ("setup", "commit", "clone-guided")),
    "clone-chosen-path": Feature("full", ("setup", "commit")),
    "remove": Feature("full", ("setup", "commit")),
    "github": Feature("full"),
}
RUNNERS: dict[str, Callable[[Run], list[str]]] = {
    "setup": feature_setup,
    "commit": feature_commit,
    "privacy": feature_privacy,
    "message": feature_message,
    "push": feature_push,
    "clone-guided": feature_clone_guided,
    "control-character": feature_control_character,
    "preview-matches-apply": feature_preview_matches_apply,
    "fix-line-works": feature_fix_line_works,
    "first-run": feature_first_run,
    "clone-trust": feature_clone_trust,
    "commit-all": feature_commit_all,
    "clone-saved": feature_clone_saved,
    "clone-chosen-path": feature_clone_chosen_path,
    "remove": feature_remove,
    "github": feature_github,
}
USAGE = f"""Usage: scripts/verify [fast|full|control] [--feature NAME] [--require-github]

The end-to-end harness: real setup, commits, hooks, and clones in a temporary folder.
scripts/check covers lint, unit tests, coverage, and packaging; this covers the journeys.
Run `fast` before you open a pull request, and `full` when setup, identity, clone, or
hook code changed. Default: fast.

fast     setup, commit, privacy, message, push, clone-guided, control-character,
         preview-matches-apply, fix-line-works, first-run, clone-trust, commit-all.
full     Also clone-saved, clone-chosen-path, remove, and github.
control  Runs once per planted defect and expects the feature it breaks to fail:
         private-literal (the private-literal check finds nothing) breaks privacy;
         unsigned-commits (setup leaves commit.gpgsign unset and the commit hook
         stops requiring it) breaks commit. Exits 0 when the harness catches both.
--feature NAME    Runs NAME and the features it needs first. Names: {", ".join(FEATURES)}.
--require-github  Counts a skipped github feature as failed.

github sets up a project from the real GitHub repository over SSH, with setup's source
preflight, and commits through hooks pre-commit downloaded from GitHub. It reads GitHub
through the SSH agent of this shell, read-only, and tests GitHub main only when GitHub
main has the same product files ({", ".join(PRODUCT_FILES)}) as this
tree; otherwise it is skipped with the reason. It tries SSH on port 22, then 443.

The other features snapshot the working tree (uncommitted changes included) into a temporary
clone, set the snapshot as the hooks' revision, and map the GitHub address to it through a
scratch HOME. It uses a throwaway SSH key in a private agent and never reads or writes
the real ~/.gitconfig, ~/.config, or pre-commit cache. Their setup skips the source
preflight, because the snapshot is not on GitHub.
Needs network: PyPI for the hook environments and the tool install that fix-line-works
and first-run share, GitHub Releases for Gitleaks.
Writes .local/verify/<UTC time>/ with summary.md, summary.json, and logs/.
Runs on Python 3.11 or newer. Started by an older python3, it re-runs itself under
FIRST_COMMIT_VERIFY_PYTHON when that is set, otherwise under .venv/bin/python; when
that Python is missing or older, it exits 3.
Exit 0 every feature proven (github may be skipped); 1 a feature failed; 2 usage;
3 the environment is not ready; 143 or 129 stopped by SIGTERM or SIGHUP, after ending
its commands, removing the temporary folder, and stopping its SSH agent.
Feature map: verify/features/README.md."""


# A BaseException, so the `except Exception` that fails one feature cannot catch it.
class StoppedError(BaseException):
    def __init__(self, number: int) -> None:
        super().__init__(signal.Signals(number).name)
        self.number = number


# The first signal stops the run; later ones are ignored, so none interrupts cleanup.
@contextlib.contextmanager
def stop_on_signals() -> Iterator[None]:
    received: list[int] = []

    def stop(number: int, _frame: FrameType | None) -> None:
        received.append(number)
        if len(received) == 1:
            raise StoppedError(number)

    with handling_signals(STOP_SIGNALS, stop):
        yield


def selected(level: str, feature: str | None) -> list[str]:
    if feature is not None:
        return [*FEATURES[feature].needs, feature]
    wanted = {"fast"} if level == "fast" else {"fast", "full"}
    return [name for name, entry in FEATURES.items() if entry.level in wanted]


def _control_plant(name: str) -> bool:
    planned = PLANTS[name]
    feature = planned.feature
    result = subprocess.run(
        [sys.executable, str(ENTRY), "--feature", feature, "--plant", name],
        capture_output=True,
        text=True,
        check=False,
    )
    sys.stdout.write(result.stdout)
    states = dict(
        re.findall(r"^(\S+): (proven|failed|skipped)", result.stdout, re.MULTILINE)
    )
    state = states.get(feature, "not reported")
    reason = re.search(
        rf"^{re.escape(feature)}: failed \([^)]*\) - (.*)$", result.stdout, re.MULTILINE
    )
    if result.returncode != 1 or state != "failed":
        print(
            f"control: missed - plant {name}: the planted run exited "
            f"{result.returncode}, {feature} {state}"
        )
        return False
    if reason is None or planned.caught_by not in reason.group(1):
        print(
            f"control: missed - plant {name}: {feature} failed, but not with "
            f'"{planned.caught_by}"'
        )
        return False
    print(f"control: caught - plant {name} made {feature} fail and the run exit 1")
    return True


def control() -> int:
    caught = [_control_plant(name) for name in PLANTS]
    return 0 if all(caught) else 1


def parse_options(arguments: list[str]) -> argparse.Namespace:
    parser = Parser(add_help=False)
    parser.add_argument(
        "level", nargs="?", default="fast", choices=("fast", "full", "control")
    )
    parser.add_argument("--feature", choices=tuple(FEATURES))
    parser.add_argument("--plant", choices=tuple(PLANTS))
    parser.add_argument("--require-github", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    return parser.parse_args(arguments)


def run_feature(run: Run, name: str, *, require_github: bool) -> FeatureResult:
    begin = time.time()
    try:
        result = FeatureResult("proven", RUNNERS[name](run))
    except FeatureSkippedError as error:
        if require_github:
            result = FeatureResult("failed", reason=f"{error} (--require-github)")
        else:
            result = FeatureResult("skipped", reason=str(error), optional=True)
    except FeatureFailedError as error:
        result = FeatureResult("failed", reason=str(error))
    except Exception as error:  # noqa: BLE001 - one feature's defect fails only it
        # Any other error is a defect in this feature or its harness code; the
        # feature fails with the error named and the run goes on to the next one.
        reason = redact(f"{type(error).__name__}: {error}", run)
        result = FeatureResult("failed", reason=reason)
    took = round(time.time() - begin, 1)
    result.log = "\n".join(run.log)
    print(
        f"{name}: {result.state} ({took} s)"
        + (f" - {redact(result.reason, run)}" if result.reason else "")
    )
    return result


def _run_each(
    run: Run,
    names: list[str],
    options: argparse.Namespace,
    results: dict[str, FeatureResult],
) -> None:
    blocker = None
    for name in names:
        run.log = []
        run.feature = name
        if blocker is not None:
            reason = f"not reached: {blocker} failed"
            results[name] = FeatureResult("skipped", reason=reason)
            print(f"{name}: skipped - {reason}")
            continue
        results[name] = run_feature(run, name, require_github=options.require_github)
        if results[name].state == "failed" and name in {"setup", "commit"}:
            blocker = name


def run_features(
    run: Run, names: list[str], options: argparse.Namespace
) -> dict[str, FeatureResult]:
    results: dict[str, FeatureResult] = {}
    try:
        start_agent(run)
        snapshot(run, options.plant)
        _run_each(run, names, options, results)
    except FeatureFailedError as error:
        print(f"harness: could not prepare the run - {redact(str(error), run)}")
        results["prepare"] = FeatureResult(
            "failed", reason=str(error), log="\n".join(run.log)
        )
    return results


def drive(
    python: str,
    search_path: tuple[str, list[str]],
    options: argparse.Namespace,
    started: float,
) -> int:
    names = selected(options.level, options.feature)
    print(f"drive: {', '.join(names)} ({options.feature or options.level})")
    try:
        with stop_on_signals(), private_run(python, search_path) as run:
            results = run_features(run, names, options)
    except StoppedError as stopped:
        print(
            f"harness: stopped by {stopped}; the temporary folder was removed and "
            "its SSH agent stopped",
            file=sys.stderr,
        )
        return 128 + stopped.number
    return finish(run, results, options, started)


def main(arguments: list[str]) -> int:
    try:
        options = parse_options(arguments)
    except UsageError:
        print(USAGE, file=sys.stderr)
        return 2
    if options.help:
        print(USAGE)
        return 0
    if options.level == "control":
        return control()
    python = harness_python()
    if not prerequisites_ready(python):
        return 3
    started = time.time()
    try:
        search_path = harness_path()
    except PathFolderError as error:
        print(f"error: {error}", file=sys.stderr)
        return 3
    return drive(python, search_path, options, started)
