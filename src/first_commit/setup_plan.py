import importlib.util
import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NamedTuple

from first_commit.checks.identity import (
    ALLOWED_SIGNERS_PATH,
    IDENTITY_KEYS,
    TRUST_SETTING,
    git_enabled,
)
from first_commit.checks.templates import read_template
from first_commit.contributor import (
    CONTRIBUTOR_PATH,
    CONTRIBUTOR_SUBJECT,
    LOCAL_FILE_FIX,
    Contributor,
    load_contributor,
    parse_contributor,
    record_bytes,
)
from first_commit.git import IgnoreStateError, require_ignored
from first_commit.git_settings import effective_git_settings, local_git_settings
from first_commit.gitleaks_scanner import (
    LOCAL_SCANNER_PATH,
    UNSAFE_LOCAL_SCANNER,
    DependencyError,
    validate_scanner,
)
from first_commit.hooks import HOOK_TYPES, INVALID_RULE, hook_problems
from first_commit.models import GIT_CONFIG_PATH, GIT_HOOKS_PATH, SetupError
from first_commit.paths import PathError
from first_commit.policy import PRIVATE_VALUES_PATH
from first_commit.private_values import PRIVATE_VALUES_SUBJECT
from first_commit.scanner_install import local_scanner_failed
from first_commit.setup_command import (
    HOOK_CONFIG,
)
from first_commit.setup_files import read_if_present
from first_commit.setup_files_plan import SetupOptions, files_plan, require_template
from first_commit.setup_trust import (
    TrustAction,
    TrustPlan,
    check_signing_key,
    trust_plan,
)

SIGNING_SETTINGS = {
    "gpg.format": "ssh",
    "commit.gpgsign": "true",
    "tag.gpgsign": "true",
    "user.useConfigOnly": "true",
}
ALLOWED_SIGNERS_SUBJECT = "Allowed-signers file"
TEMPLATE_SETTING = "commit.template"


class RepositoryState(Enum):
    EXISTING = "existing"
    WOULD_INITIALIZE = "would initialize"
    INITIALIZED = "initialized"


class GitFacts(NamedTuple):
    configure_identity: bool
    activate_template: bool
    trust: TrustPlan | None
    trust_ready: bool
    trust_configured: bool
    missing_hooks: tuple[str, ...]
    identity_settings: Mapping[str, str]
    git_config: bytes | None


@dataclass(frozen=True)
class SetupPlan:
    root: Path
    options: SetupOptions
    repository: RepositoryState
    contributor: Contributor | None
    pending: Mapping[Path, bytes]
    kept: tuple[str, ...]
    existing_hooks: bool
    contributor_exists: bool
    private_values_exist: bool
    install_scanner: bool
    scanner_checked: bool
    git: GitFacts

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(path.name for path in self.pending)


def _identity_plan(root: Path, contributor: Contributor) -> dict[str, str]:
    parse_contributor(record_bytes(contributor))
    current = load_contributor(root)
    if current is not None and current != contributor:
        raise SetupError(
            "Existing contributor record differs from the identity this setup was "
            f"given; setup leaves {CONTRIBUTOR_PATH} unchanged.\n"
            "fix: rerun setup with the identity the record holds, or delete "
            f"{CONTRIBUTOR_PATH} to save a new one."
        )
    desired = {
        "user.name": contributor.name,
        "user.email": contributor.email,
        "user.signingkey": contributor.signing_key,
        **SIGNING_SETTINGS,
    }
    return _missing_settings(root, desired)


def _conflict_error(keys: list[str]) -> SetupError:
    commands = "".join(f"\n  git config --local --unset-all {key}" for key in keys)
    return SetupError(
        "Existing local Git settings differ from what setup sets: "
        + ", ".join(keys)
        + ".\nfix: keep them by making your identity match them, or remove them "
        f"so setup can set them, then rerun setup:{commands}"
    )


def _missing_settings(root: Path, desired: Mapping[str, str]) -> dict[str, str]:
    existing = local_git_settings(root, tuple(desired))
    conflicts = [
        key
        for key, value in existing.items()
        if value != desired[key] and not (desired[key] == "true" and git_enabled(value))
    ]
    if conflicts:
        raise _conflict_error(conflicts)
    return {key: value for key, value in desired.items() if key not in existing}


def _check_git_metadata(root: Path) -> None:
    if importlib.util.find_spec("pre_commit") is None:
        raise DependencyError("Setup requires pre-commit in this Python environment.")
    if "core.hookspath" in effective_git_settings(root, ("core.hookspath",)):
        raise SetupError(
            "The Git setting core.hooksPath conflicts with hook installation, "
            f"because pre-commit installs hooks in {GIT_HOOKS_PATH}.\n"
            "fix: run `git config --show-origin core.hooksPath` to find where it is "
            "set, unset it there (for example `git config --local --unset "
            "core.hooksPath`), then rerun setup."
        )
    hooks = root / GIT_HOOKS_PATH
    if hooks.is_symlink() or not hooks.is_dir():
        raise SetupError("Git hooks folder is unsafe.")


def _missing_hooks(root: Path) -> tuple[str, ...]:
    problems = hook_problems(root)
    invalid = [stage for stage, rule in problems.items() if rule == INVALID_RULE]
    if invalid:
        names = ", ".join(f"{GIT_HOOKS_PATH}/{stage}" for stage in invalid)
        raise SetupError(
            f"Existing Git hook conflicts: {names} is not a pre-commit hook for "
            f"{HOOK_CONFIG}, or the Python it names is gone.\n"
            "fix: move it aside (for example add .old to its name), move what it "
            f"ran into {HOOK_CONFIG}, then rerun setup."
        )
    return tuple(stage for stage in HOOK_TYPES if stage in problems)


def _template_needed(root: Path) -> bool:
    local = local_git_settings(root, (TEMPLATE_SETTING,)).get(TEMPLATE_SETTING)
    if local is not None:
        require_template(
            root,
            local,
            subject=f"the file the local {TEMPLATE_SETTING} setting names",
            fix=f"run `git config --local --unset {TEMPLATE_SETTING}`, then rerun "
            "setup; setup then sets its own template.",
        )
        return False
    value = effective_git_settings(root, (TEMPLATE_SETTING,)).get(TEMPLATE_SETTING)
    if value is None:
        return True
    # A global or system template outside this repository stays untouched; the
    # local setting setup adds takes precedence in this repository only.
    try:
        read_template(root, value)
    except PathError:
        return True
    return False


def _scanner_missing(root: Path, *, check_scanner: bool) -> bool:
    path = root / LOCAL_SCANNER_PATH
    if not os.path.lexists(path):
        return True
    if path.is_symlink() or not path.is_file():
        raise SetupError(UNSAFE_LOCAL_SCANNER)
    if check_scanner:
        try:
            validate_scanner(root, executable=str(path))
        except DependencyError as error:
            raise local_scanner_failed(error) from error
    return False


def _blank_git_facts(root: Path, options: SetupOptions) -> GitFacts:
    return GitFacts(
        configure_identity=True,
        activate_template=_template_needed(root),
        trust=trust_plan(
            root,
            None,
            trust_self=options.trust_self,
            settings={},
            repository_exists=False,
        ),
        trust_ready=options.trust_self,
        trust_configured=False,
        missing_hooks=HOOK_TYPES,
        identity_settings={},
        git_config=None,
    )


def _git_facts(
    root: Path, options: SetupOptions, contributor: Contributor | None
) -> GitFacts:
    if contributor is None:
        identity: Mapping[str, str] = {}
        missing_signing = _missing_settings(root, SIGNING_SETTINGS)
        present = local_git_settings(root, IDENTITY_KEYS)
        configure_identity = bool(missing_signing) or len(present) < len(IDENTITY_KEYS)
    else:
        identity = _identity_plan(root, contributor)
        configure_identity = bool(identity)
    trust_settings = local_git_settings(root, (TRUST_SETTING,))
    trust = trust_plan(
        root, contributor, trust_self=options.trust_self, settings=trust_settings
    )
    git_config = read_if_present(root / GIT_CONFIG_PATH)
    if os.path.lexists(root / f"{GIT_CONFIG_PATH}.lock"):
        raise SetupError("Git configuration is locked; retry later.")
    return GitFacts(
        configure_identity=configure_identity,
        activate_template=_template_needed(root),
        trust=trust,
        trust_ready=bool(trust_settings.get(TRUST_SETTING)) or options.trust_self,
        trust_configured=bool(trust_settings.get(TRUST_SETTING)),
        missing_hooks=_missing_hooks(root),
        identity_settings=identity,
        git_config=git_config,
    )


def _local_files(plan: SetupPlan) -> tuple[tuple[str, str], ...]:
    local = [(CONTRIBUTOR_PATH, CONTRIBUTOR_SUBJECT)]
    if not plan.private_values_exist:
        local.append((PRIVATE_VALUES_PATH, PRIVATE_VALUES_SUBJECT))
    trust = plan.git.trust
    if trust is not None and trust.action is TrustAction.WRITE:
        local.append((ALLOWED_SIGNERS_PATH, ALLOWED_SIGNERS_SUBJECT))
    return tuple(local)


def require_local_files_ignored(plan: SetupPlan) -> None:
    for path, subject in _local_files(plan):
        try:
            require_ignored(plan.root, path, subject)
        except IgnoreStateError as error:
            fix = LOCAL_FILE_FIX.format(path=path)
            raise SetupError(f"{error}\nfix: {fix}") from error


def plan_setup(
    root: Path,
    options: SetupOptions,
    contributor: Contributor | None,
    repository: RepositoryState,
    *,
    check_scanner: bool = True,
) -> SetupPlan:
    blank = repository is RepositoryState.WOULD_INITIALIZE
    if contributor is not None:
        check_signing_key(root, contributor.signing_key)
    if not blank:
        _check_git_metadata(root)
    existing_hooks = read_if_present(root / HOOK_CONFIG) is not None
    planned_files = files_plan(root, options)
    git = (
        _blank_git_facts(root, options)
        if blank
        else _git_facts(root, options, contributor)
    )
    plan = SetupPlan(
        root=root,
        options=options,
        repository=repository,
        contributor=contributor,
        pending=planned_files.pending,
        kept=planned_files.kept,
        existing_hooks=existing_hooks,
        contributor_exists=load_contributor(root) is not None,
        private_values_exist=os.path.lexists(root / PRIVATE_VALUES_PATH),
        install_scanner=_scanner_missing(root, check_scanner=check_scanner),
        scanner_checked=check_scanner,
        git=git,
    )
    # Git cannot answer before the repository exists or before .gitignore is written.
    if not blank and root / ".gitignore" not in plan.pending:
        require_local_files_ignored(plan)
    return plan
