import fcntl
import os
import signal
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import TypeVar

from first_commit.checks.identity import (
    ALLOWED_SIGNERS_PATH,
    IDENTITY_KEYS,
    TRUST_SETTING,
    identity_findings,
)
from first_commit.checks.templates import template_findings
from first_commit.contributor import (
    CONTRIBUTOR_PATH,
    Contributor,
    ContributorError,
    contributor_findings,
    create_contributor,
)
from first_commit.git import GitError, run_git
from first_commit.git_settings import local_git_settings
from first_commit.gitleaks_scanner import LOCAL_SCANNER_PATH, DependencyError
from first_commit.hooks import HOOK_TYPES, hook_findings
from first_commit.models import GIT_CONFIG_PATH, GIT_HOOKS_PATH, SetupError
from first_commit.paths import create_exclusive
from first_commit.policy import POLICY_PATH, PRIVATE_VALUES_PATH, parse_policy
from first_commit.policy_fields import PolicyError
from first_commit.pre_commit_runner import run_pre_commit
from first_commit.scanner_install import install_scanner
from first_commit.setup_files import (
    create_local_file,
    read_if_present,
    restore_git_config,
)
from first_commit.setup_files_plan import TEMPLATE_PATH
from first_commit.setup_plan import (
    RepositoryState,
    SetupPlan,
    require_local_files_ignored,
)
from first_commit.setup_trust import TrustAction

PRIVATE_VALUES_TEMPLATE = (
    b"# One private value per line, such as your real name or home folder name.\n"
    b"# The hooks block commits whose files, file names, or messages contain a value\n"
    b"# here, and pushes whose commit messages contain one.\n"
    b"# Git ignores this file; never commit it.\n"
)
SETUP_FAILURES = (
    SetupError,
    PolicyError,
    ContributorError,
    DependencyError,
    GitError,
    KeyboardInterrupt,
    OSError,
)
Progress = Callable[[str], None] | None
SETUP_LOCK_NAME = "first-commit-setup.lock"
TERMINATING_SIGNALS = (signal.SIGTERM, signal.SIGHUP)
HELD_SIGNALS = (*TERMINATING_SIGNALS, signal.SIGINT)
Result = TypeVar("Result")


class SetupTerminatedError(SetupError):
    pass


def terminated_error(number: int) -> SetupTerminatedError:
    name = "Ctrl-C" if number == signal.SIGINT else signal.Signals(number).name
    return SetupTerminatedError(f"Setup stopped on {name}; its changes were undone.")


# Signal handlers work only in the main thread; elsewhere the block runs unchanged.
@contextmanager
def _signal_handler(
    handler: Callable[[int, FrameType | None], None],
    numbers: tuple[signal.Signals, ...] = TERMINATING_SIGNALS,
) -> Iterator[None]:
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {number: signal.signal(number, handler) for number in numbers}
    try:
        yield
    finally:
        for number, old in previous.items():
            signal.signal(number, old)


# Ctrl-C raises KeyboardInterrupt, so a stop before setup changed anything keeps
# the plain Ctrl-C line. Signals after the first are ignored until the block ends,
# so none can land between a failure and the start of its rollback.
class _StopOnce:
    def __init__(self) -> None:
        self.received: list[int] = []

    def __call__(self, number: int, _frame: FrameType | None) -> None:
        self.received.append(number)
        if len(self.received) > 1:
            return
        if number == signal.SIGINT:
            raise KeyboardInterrupt
        raise terminated_error(number)


# A nested block keeps the outer handler, so a signal it ignores stays ignored.
@contextmanager
def terminating_signals_raise() -> Iterator[None]:
    if isinstance(signal.getsignal(signal.SIGINT), _StopOnce):
        yield
        return
    with _signal_handler(_StopOnce(), HELD_SIGNALS):
        yield


# Held, so a rollback, or git init and its snapshot, runs to its end. A held signal
# also counts as the first one for the surrounding block.
@contextmanager
def signals_held() -> Iterator[list[int]]:
    received: list[int] = []
    stop = signal.getsignal(signal.SIGINT)

    def hold(number: int, _frame: FrameType | None) -> None:
        received.append(number)
        if isinstance(stop, _StopOnce):
            stop.received.append(number)

    with _signal_handler(hold, HELD_SIGNALS):
        yield received


# A first signal can stop the handler of another failure before the rollback holds
# signals. The outer handler then rolls back; only the first signal raises.
def roll_back_on_failure(
    body: Callable[[], Result], roll_back: Callable[[], None]
) -> Result:
    started = False

    def roll_back_once() -> None:
        nonlocal started
        with signals_held():
            if not started:
                started = True
                roll_back()

    try:
        try:
            return body()
        except SETUP_FAILURES:
            roll_back_once()
            raise
    except SETUP_FAILURES:
        roll_back_once()
        raise


@contextmanager
def setup_lock(root: Path) -> Iterator[None]:
    path = root / ".git" / SETUP_LOCK_NAME
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as error:
        raise SetupError("Setup lock could not be acquired safely.") from error
    try:
        regular = stat.S_ISREG(os.fstat(descriptor).st_mode)
        if regular:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise SetupError("Another first-commit setup is already running.") from error
    except OSError as error:
        os.close(descriptor)
        raise SetupError("Setup lock could not be acquired safely.") from error
    if not regular:
        os.close(descriptor)
        raise SetupError(
            f"The setup lock .git/{SETUP_LOCK_NAME} is not a regular file, so setup "
            "cannot run; setup changed nothing.\n"
            f"fix: run `ls -ld .git/{SETUP_LOCK_NAME}` to see what it is; if nothing "
            "uses it, delete it, then rerun setup."
        )
    try:
        with terminating_signals_raise():
            yield
    finally:
        _release_lock(descriptor)


# The lock file stays. A setup that opened it before an unlink would lock a file that
# a later setup no longer sees, and the two would run at once.
def _release_lock(descriptor: int) -> None:
    with suppress(OSError):
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    with suppress(OSError):
        os.close(descriptor)


@dataclass
class _Applied:
    plan: SetupPlan
    local_existed: bool
    bin_existed: bool
    created: list[tuple[Path, bytes | None]] = field(default_factory=list)
    configured: bytes | None = None
    scanner: os.stat_result | None = None
    hooks: dict[Path, bytes | None] = field(default_factory=dict)


def _write_files(applied: _Applied, contributor: Contributor) -> None:
    plan = applied.plan
    root = plan.root
    for path, content in plan.pending.items():
        create_exclusive(path, content, 0o644)
        applied.created.append((path, content))
    require_local_files_ignored(plan)
    if not plan.contributor_exists:
        create_contributor(root, contributor)
        record = root / CONTRIBUTOR_PATH
        applied.created.append((record, read_if_present(record)))
    if not plan.private_values_exist:
        path = create_local_file(
            root, PRIVATE_VALUES_PATH, PRIVATE_VALUES_TEMPLATE, "values"
        )
        applied.created.append((path, PRIVATE_VALUES_TEMPLATE))
    trust = plan.git.trust
    if trust is not None and trust.action is TrustAction.WRITE:
        path = create_local_file(root, ALLOWED_SIGNERS_PATH, trust.content, "trust")
        applied.created.append((path, trust.content))


def _set_git_setting(applied: _Applied, arguments: tuple[str, ...]) -> None:
    git_config = applied.plan.root / GIT_CONFIG_PATH
    expected = (
        applied.configured
        if applied.configured is not None
        else applied.plan.git.git_config
    )
    if read_if_present(git_config) != expected:
        raise SetupError(
            f"{GIT_CONFIG_PATH} changed while setup ran, so setup stopped and left "
            "the file as it is.\n"
            "fix: run `git config --local --list` to review the settings, then rerun "
            "setup."
        )
    run_git(applied.plan.root, ("config", "--local", *arguments))
    applied.configured = read_if_present(git_config)


def _write_settings(applied: _Applied) -> None:
    git = applied.plan.git
    for key, value in git.identity_settings.items():
        _set_git_setting(applied, ("--replace-all", key, value))
    if git.activate_template:
        _set_git_setting(applied, ("--add", "commit.template", TEMPLATE_PATH))
    if git.trust is not None and git.trust.sets_setting:
        _set_git_setting(applied, ("--add", TRUST_SETTING, ALLOWED_SIGNERS_PATH))


def _install_tools(applied: _Applied, progress: Progress) -> None:
    plan = applied.plan
    root = plan.root
    # A scanner that appeared after planning is not setup's to roll back.
    if plan.install_scanner and install_scanner(root):
        applied.scanner = (root / LOCAL_SCANNER_PATH).stat()
    run_pre_commit(
        root,
        ("install-hooks",),
        progress=progress,
        offer_rerun=plan.existing_hooks and plan.repository is RepositoryState.EXISTING,
    )
    missing = plan.git.missing_hooks
    if not missing:
        return
    try:
        run_pre_commit(
            root,
            (
                "install",
                *(item for stage in missing for item in ("--hook-type", stage)),
            ),
            progress=progress,
        )
    finally:
        applied.hooks = {
            root / GIT_HOOKS_PATH / stage: read_if_present(
                root / GIT_HOOKS_PATH / stage
            )
            for stage in HOOK_TYPES
            if stage in missing
        }


def _verify(root: Path, contributor: Contributor) -> None:
    if hook_findings(root) or template_findings(root):
        raise SetupError("Installed hooks or template failed readiness verification.")
    policy = read_if_present(root / POLICY_PATH)
    if policy is None:
        raise SetupError("The policy file was removed during setup; restore it.")
    parse_policy(policy, root, contributor)
    settings = local_git_settings(root, IDENTITY_KEYS)
    if identity_findings(settings, (contributor.email,)) or contributor_findings(
        contributor, settings
    ):
        raise SetupError("Local identity/signing settings failed verification.")


def _same_file(current: os.stat_result, installed: os.stat_result) -> bool:
    return (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
    ) == (
        installed.st_dev,
        installed.st_ino,
        installed.st_size,
        installed.st_mtime_ns,
    )


def roll_back_applied(applied: _Applied) -> None:
    plan = applied.plan
    root = plan.root
    for path, expected in applied.hooks.items():
        if expected is not None and read_if_present(path) == expected:
            path.unlink()
    scanner = root / LOCAL_SCANNER_PATH
    if (
        applied.scanner is not None
        and scanner.exists()
        and _same_file(scanner.stat(), applied.scanner)
    ):
        scanner.unlink()
    if applied.configured is not None:
        restore_git_config(
            root / GIT_CONFIG_PATH, applied.configured, plan.git.git_config
        )
    for path, content in reversed(applied.created):
        if content is not None and read_if_present(path) == content:
            path.unlink()
    for folder, existed in (
        (root / ".local/bin", applied.bin_existed),
        (
            root / ".local/first-commit",
            plan.contributor_exists or plan.private_values_exist,
        ),
        (root / ".local", applied.local_existed),
    ):
        if not existed and folder.is_dir():
            with suppress(OSError):
                folder.rmdir()


def apply_plan(
    plan: SetupPlan, contributor: Contributor, progress: Progress = None
) -> None:
    applied = _Applied(
        plan,
        local_existed=(plan.root / ".local").exists(),
        bin_existed=(plan.root / ".local/bin").exists(),
    )

    def apply() -> None:
        _write_files(applied, contributor)
        _write_settings(applied)
        _install_tools(applied, progress)
        _verify(plan.root, contributor)

    def recover() -> None:
        try:
            roll_back_applied(applied)
        except (OSError, SetupError) as error:
            raise SetupError(
                "Setup recovery failed; inspect generated files and Git settings."
            ) from error

    try:
        roll_back_on_failure(apply, recover)
    except KeyboardInterrupt as error:
        raise terminated_error(signal.SIGINT) from error
