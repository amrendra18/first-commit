import os
import shutil
import signal
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from first_commit.contributor import Contributor, load_contributor
from first_commit.generated_files import HOOK_PROPOSAL
from first_commit.git import (
    GitError,
    git_executable,
    git_path,
    run_git,
    sanitized_git_environment,
)
from first_commit.gitleaks_scanner import DependencyError
from first_commit.hooks import (
    APPROVED_REPOSITORIES,
    HTTPS_REPOSITORY,
    REVISION,
    REVISION_CHARS,
    SSH_REPOSITORY,
    installed_revision,
)
from first_commit.machine_identity import (
    EMAIL_VARIABLE,
    KEY_VARIABLE,
    NAME_VARIABLE,
    PATH_VARIABLE,
)
from first_commit.models import SetupError
from first_commit.paths import create_exclusive
from first_commit.setup_apply import (
    SETUP_LOCK_NAME,
    Progress,
    apply_plan,
    roll_back_on_failure,
    setup_lock,
    signals_held,
    terminated_error,
    terminating_signals_raise,
)
from first_commit.setup_command import HOOK_CONFIG
from first_commit.setup_files import read_if_present
from first_commit.setup_files_plan import (
    RERUN_WITH_REVISION,
    REVISION_REQUIRED,
    SetupOptions,
)
from first_commit.setup_hooks import HooksMissingError, configured_source
from first_commit.setup_plan import RepositoryState, plan_setup
from first_commit.setup_preview import plan_lines

SOURCE_PREFLIGHT_TIMEOUT_SECONDS = 60
IDENTITY_REQUIRED = (
    "Setup needs a contributor identity: run `first-commit setup` in a terminal to "
    f"type it, save it in the identity file ({PATH_VARIABLE} chooses the file), or "
    f"set {NAME_VARIABLE}, {EMAIL_VARIABLE}, and {KEY_VARIABLE}."
)
TRANSPORTS = {"https": HTTPS_REPOSITORY, "ssh": SSH_REPOSITORY}
GitSnapshot = tuple[tuple[str, int, bytes | None], ...]


@dataclass(frozen=True)
class SetupRequest:
    revision: str | None = None
    transport: str | None = None
    license_choice: str = "none"
    docs: str = "core"
    trust_self: bool = False
    dry_run: bool = False
    confirmed: bool = False
    preflight: bool = True


def _revision(
    explicit: str | None, transport: str | None = None, *, optional: bool = False
) -> tuple[str | None, str]:
    if transport is not None and transport not in TRANSPORTS:
        raise SetupError("Transport must be 'https' or 'ssh'.")
    installed = installed_revision()
    if explicit is not None and not REVISION.fullmatch(explicit):
        raise SetupError(
            f"Use a full lowercase {REVISION_CHARS}-character immutable revision."
        )
    if explicit is not None and installed is not None and explicit != installed:
        raise SetupError("Requested revision differs from the installed revision.")
    revision = explicit or installed
    if revision is None and not optional:
        raise SetupError(REVISION_REQUIRED)
    source = TRANSPORTS[transport] if transport is not None else HTTPS_REPOSITORY
    return revision, source


# Setup keeps the project's hook file, so the revision only compares pinned hooks.
def _project_revision(root: Path) -> str | None:
    try:
        revision, _ = configured_source(root)
    except SetupError:
        return None
    return revision if REVISION.fullmatch(revision) else None


def _preflight_source(root: Path, source: str) -> None:
    if source not in APPROVED_REPOSITORIES:
        raise SetupError("Hook source preflight requires an approved repository URL.")
    environment = sanitized_git_environment()
    try:
        result = subprocess.run(
            [git_executable(environment, root), "ls-remote", "--exit-code", source],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=SOURCE_PREFLIGHT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DependencyError(
            f"Hook source preflight: Git could not access {source}; check network "
            "access and authentication, then retry setup."
        ) from error
    if result.returncode:
        suggestion = (
            "retry with --transport ssh"
            if source == HTTPS_REPOSITORY
            else "check SSH authentication and host trust, or retry with "
            "--transport https"
        )
        raise DependencyError(
            f"Hook source preflight: Git exited {result.returncode} for {source}; "
            f"{suggestion}."
        )


def _git_snapshot(folder: Path) -> GitSnapshot | None:
    if not folder.is_dir() or folder.is_symlink():
        return None
    entries = []
    for parent, names, filenames in os.walk(folder, followlinks=False):
        for name in (*names, *filenames):
            path = Path(parent) / name
            # Setup keeps its lock file, so the comparison leaves it out.
            if path == folder / SETUP_LOCK_NAME:
                continue
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                content = None
            elif stat.S_ISREG(mode):
                content = read_if_present(path)
            else:
                return None
            entries.append((path.relative_to(folder).as_posix(), mode, content))
    return tuple(sorted(entries))


def _repository_exists(root: Path) -> bool:
    try:
        raw = run_git(root, ("rev-parse", "--show-toplevel"))
    except GitError:
        return False
    try:
        found = git_path(root, raw).resolve()
    except GitError as error:
        raise SetupError("Git returned an invalid repository root.") from error
    if found != root:
        raise SetupError("Run setup from the repository root.")
    return True


def _require_standard_git(root: Path) -> None:
    if (root / ".git").is_symlink() or not (root / ".git").is_dir():
        raise SetupError("Setup currently requires a standard Git repository root.")


def _apply_locked(
    root: Path,
    options: SetupOptions,
    contributor: Contributor,
    repository: RepositoryState,
    progress: Progress,
) -> tuple[str, ...]:
    _require_standard_git(root)
    with setup_lock(root):
        plan = plan_setup(root, options, contributor, repository)
        if (
            options.preflight
            and repository is RepositoryState.EXISTING
            and not plan.existing_hooks
        ):
            _preflight_source(root, options.source)
        apply_plan(plan, contributor, progress)
    return plan_lines(plan, dry_run=False)


def _initialize_and_apply(
    root: Path,
    options: SetupOptions,
    contributor: Contributor,
    *,
    confirmed: bool,
    progress: Progress,
) -> tuple[str, ...]:
    plan = plan_setup(
        root,
        options,
        contributor,
        RepositoryState.WOULD_INITIALIZE,
        check_scanner=False,
    )
    if not confirmed:
        raise SetupError("Confirm the setup plan before initializing Git.")
    if options.preflight and not plan.existing_hooks:
        _preflight_source(root, options.source)
    return _apply_in_new_repository(root, options, contributor, progress)


# Only the setup that creates .git may remove it. Another setup that planned in the
# same empty folder stops here, before it could take that setup's .git for its own.
def _create_git_folder(root: Path) -> None:
    try:
        (root / ".git").mkdir()
    except FileExistsError as error:
        raise SetupError(
            "Another process created .git after setup started; setup changed "
            "nothing.\nfix: wait for that process to end, then rerun setup."
        ) from error


def _apply_in_new_repository(
    root: Path, options: SetupOptions, contributor: Contributor, progress: Progress
) -> tuple[str, ...]:
    initial_git: GitSnapshot | None = None
    created_git = False
    initialized = False

    def initialize_and_apply() -> tuple[str, ...]:
        nonlocal initial_git, created_git, initialized
        with signals_held() as received:
            _create_git_folder(root)
            created_git = True
            run_git(root, ("init", "-q"))
            initialized = True
            initial_git = _git_snapshot(root / ".git")
        if initial_git is None:
            raise SetupError(
                "Git initialization produced unsafe metadata; inspect .git."
            )
        if received:
            raise terminated_error(received[0])
        return _apply_locked(
            root, options, contributor, RepositoryState.INITIALIZED, progress
        )

    def remove_git() -> None:
        if initial_git is None:
            # After a finished `git init`, unsafe metadata stays for the user to inspect.
            if created_git and not initialized:
                shutil.rmtree(root / ".git", ignore_errors=True)
            return
        if _git_snapshot(root / ".git") != initial_git:
            raise SetupError(
                "Setup failed after it created .git, and the new .git folder changed "
                "while setup ran, so setup kept it.\n"
                "fix: run `git status` and `git log` to see what .git holds; if "
                "nothing in it is yours, delete .git, then rerun setup."
            )
        shutil.rmtree(root / ".git")

    # The handlers come first, so a signal after `git init` also removes .git.
    with terminating_signals_raise():
        try:
            return roll_back_on_failure(initialize_and_apply, remove_git)
        except KeyboardInterrupt as error:
            if initial_git is None:
                raise
            raise terminated_error(signal.SIGINT) from error


def hook_proposal_error(
    root: Path, error: HooksMissingError, *, dry_run: bool
) -> SetupError:
    if error.proposal is None:
        return SetupError(
            f"{error}\nfix: {RERUN_WITH_REVISION} to write the block to merge to "
            f"{HOOK_PROPOSAL}."
        )
    path = root.resolve() / HOOK_PROPOSAL
    proposal_exists = read_if_present(path) is not None
    if dry_run and not proposal_exists:
        action = f"setup without --dry-run writes the block to merge to {HOOK_PROPOSAL}"
    else:
        if not proposal_exists:
            create_exclusive(path, error.proposal, 0o644)
        action = (
            f"merge {HOOK_PROPOSAL} into {HOOK_CONFIG}, delete the proposal, then "
            "rerun setup; setup changed nothing else"
        )
    return SetupError(f"{error}\nfix: {action}.")


def setup_repository(
    root: Path,
    request: SetupRequest,
    *,
    contributor: Contributor | None = None,
    progress: Progress = None,
) -> tuple[str, ...]:
    root = root.resolve()
    if not root.is_dir():
        raise SetupError("Setup requires an existing folder.")
    keeps_hooks = read_if_present(root / HOOK_CONFIG) is not None
    revision, source = _revision(
        request.revision, request.transport, optional=keeps_hooks
    )
    if revision is None:
        revision = _project_revision(root)
    options = SetupOptions(
        revision=revision,
        source=source,
        license_choice=request.license_choice,
        docs=request.docs,
        trust_self=request.trust_self,
        preflight=request.preflight,
    )
    if contributor is None:
        contributor = load_contributor(root)
    existing = _repository_exists(root)
    if not existing and os.path.lexists(root / ".git"):
        raise SetupError(
            "The .git folder exists, but Git cannot use it as a repository; setup "
            "changed nothing.\n"
            "fix: run `git status` in this folder to see Git's own error, repair or "
            "move .git, then rerun setup."
        )
    state = RepositoryState.EXISTING if existing else RepositoryState.WOULD_INITIALIZE
    if request.dry_run:
        if existing:
            _require_standard_git(root)
        plan = plan_setup(root, options, contributor, state, check_scanner=False)
        return plan_lines(plan, dry_run=True)
    if contributor is None:
        raise SetupError(IDENTITY_REQUIRED)
    if existing:
        return _apply_locked(root, options, contributor, state, progress)
    return _initialize_and_apply(
        root, options, contributor, confirmed=request.confirmed, progress=progress
    )
