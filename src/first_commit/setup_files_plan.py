import hashlib
import importlib.metadata
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import NamedTuple

from first_commit import __version__
from first_commit.checks.templates import read_template
from first_commit.generated_files import proposal_name
from first_commit.gitleaks_scanner import DependencyError
from first_commit.hooks import (
    HTTPS_REPOSITORY,
    LOCAL_REPOSITORY,
    foreign_launcher,
    hook_entries,
    installed_command_problem,
    load_hook_config,
    runs_installed_command,
)
from first_commit.models import SetupError
from first_commit.paths import PathError
from first_commit.policy import POLICY_PATH, parse_policy
from first_commit.setup_command import (
    CHECK_HOOK_ID,
    HOOK_CONFIG,
    SETUP_HOOK_ID,
    declares_hook,
)
from first_commit.setup_files import read_if_present
from first_commit.setup_hooks import (
    PROPOSAL_HEADER,
    HooksMissingError,
    check_hook_config,
    hook_bytes,
    local_hook_bytes,
)
from first_commit.starter import (
    DOCUMENT_SETS,
    DOCUMENTS,
    IGNORE_FILE,
    proposal_content,
    starter_files,
)

DEFAULT_POLICY = b'{\n  "schema_version": 1\n}\n'
LICENSE_DIGEST = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
TEMPLATE_PATH = ".gitmessage"
RERUN_WITH_REVISION = (
    f"run `git ls-remote {HTTPS_REPOSITORY} 'v{__version__}^{{}}'` to print the "
    "release tag's commit, then rerun setup with --revision and that 40-character SHA"
)
REVISION_REQUIRED = (
    "Setup needs an immutable Git revision; use --revision FULL_SHA.\n"
    f"fix: {RERUN_WITH_REVISION}."
)
INSTALLED_COMMAND_FIX = (
    "fix: put first-commit on PATH in a folder outside this repository (see Install "
    "in the first-commit README), then rerun setup"
)
LOCAL_IGNORE_LINES = (b".local/", b".local", b"/.local", b"/.local/", b".local/*")
LOCAL_NOT_IGNORED = (
    "Existing .gitignore does not ignore the .local/ folder.\n"
    "fix: add the line .local/ to .gitignore (.local, /.local, /.local/, or "
    ".local/* also work), then rerun setup."
)


# source is an approved address for pinned hooks, or LOCAL_REPOSITORY for hooks that
# run the installed command.
@dataclass(frozen=True)
class SetupOptions:
    revision: str | None
    source: str = HTTPS_REPOSITORY
    license_choice: str = "none"
    docs: str = "core"
    trust_self: bool = False
    preflight: bool = True


def _required_revision(options: SetupOptions) -> str:
    if options.revision is None:
        raise SetupError(REVISION_REQUIRED)
    return options.revision


def _require_installed_command(root: Path, alternative: str = "") -> None:
    problem = installed_command_problem(root)
    if problem is not None:
        raise DependencyError(
            f"Setup stopped: {problem}\n{INSTALLED_COMMAND_FIX}{alternative}."
        )


def _hook_file(root: Path, options: SetupOptions) -> bytes:
    if options.source != LOCAL_REPOSITORY:
        return hook_bytes(_required_revision(options), options.source)
    _require_installed_command(root, "; or rerun setup with --hooks pinned")
    return local_hook_bytes()


class FilesPlan(NamedTuple):
    pending: dict[Path, bytes]
    kept: tuple[str, ...]


# The onboarding text follows the hook file the project ends up with.
def _onboarding_source(existing: bytes | None, options: SetupOptions) -> str:
    if existing is None:
        return options.source
    if runs_installed_command(hook_entries(load_hook_config(existing))):
        return LOCAL_REPOSITORY
    return HTTPS_REPOSITORY if options.source == LOCAL_REPOSITORY else options.source


def _starter_plan(root: Path, options: SetupOptions) -> FilesPlan:
    pending: dict[Path, bytes] = {}
    kept: list[str] = []
    existing_hooks = read_if_present(root / HOOK_CONFIG)
    writes_hooks = existing_hooks is None
    writes_setup_hook = writes_hooks and options.source != LOCAL_REPOSITORY
    generated = starter_files(
        options.docs,
        source=_onboarding_source(existing_hooks, options),
        setup_hook=writes_setup_hook or declares_hook(root, SETUP_HOOK_ID),
        check_hook=writes_hooks or declares_hook(root, CHECK_HOOK_ID),
    )
    for name, content in generated.items():
        path = root / name
        existing = read_if_present(path)
        if existing is None:
            pending[path] = content
        elif name in DOCUMENTS:
            proposal = root / proposal_name(name)
            if read_if_present(proposal) is not None:
                raise SetupError(
                    "A generated document proposal already exists; resolve it "
                    "before setup."
                )
            pending[proposal] = proposal_content(name, content)
        elif existing != content:
            kept.append(name)
    return FilesPlan(pending, tuple(kept))


def _license_bytes() -> bytes:
    try:
        content = importlib.metadata.distribution("first-commit").read_text(
            "licenses/LICENSE"
        )
    except importlib.metadata.PackageNotFoundError:
        content = None
    if content is None:
        content = (Path(__file__).resolve().parents[2] / "LICENSE").read_text(
            encoding="utf-8"
        )
    if hashlib.sha256(content.encode("utf-8")).hexdigest() != LICENSE_DIGEST:
        raise DependencyError("Packaged Apache-2.0 license is unavailable.")
    return content.encode("utf-8")


def _license_plan(root: Path, license_choice: str) -> dict[Path, bytes]:
    if license_choice != "apache-2.0":
        return {}
    path = root / "LICENSE"
    content = _license_bytes()
    existing = read_if_present(path)
    if existing is None:
        return {path: content}
    if existing != content:
        raise SetupError(
            "Existing LICENSE differs from the Apache-2.0 text, so setup leaves it "
            "unchanged.\n"
            "fix: keep your LICENSE and rerun setup without --license apache-2.0, or "
            "delete LICENSE and rerun setup to write the Apache-2.0 text."
        )
    return {}


def require_template(root: Path, value: str, *, subject: str, fix: str) -> None:
    try:
        read_template(root, value)
    except PathError as error:
        raise SetupError(
            f"Existing commit template is unusable: {subject} must be a non-empty "
            f"UTF-8 text file in this repository.\nfix: {fix}"
        ) from error


def _support_plan(root: Path, options: SetupOptions) -> dict[Path, bytes]:
    pending: dict[Path, bytes] = {}
    existing_hooks = read_if_present(root / HOOK_CONFIG)
    if existing_hooks is None:
        pending[root / HOOK_CONFIG] = _hook_file(root, options)
    else:
        try:
            entries = check_hook_config(existing_hooks, options.revision)
        except HooksMissingError as error:
            if options.source == LOCAL_REPOSITORY or options.revision is not None:
                error.proposal = PROPOSAL_HEADER.encode("utf-8") + _hook_file(
                    root, options
                )
            raise
        if foreign_launcher(root, entries):
            raise SetupError("The first-commit hook declaration conflicts.")
        if runs_installed_command(entries):
            _require_installed_command(root)
    ignore = read_if_present(root / ".gitignore")
    if ignore is None:
        pending[root / ".gitignore"] = IGNORE_FILE
    elif not set(LOCAL_IGNORE_LINES).intersection(ignore.splitlines()):
        raise SetupError(LOCAL_NOT_IGNORED)
    if read_if_present(root / TEMPLATE_PATH) is None:
        pending[root / TEMPLATE_PATH] = (
            files("first_commit").joinpath("data/commit-message.txt").read_bytes()
        )
    else:
        require_template(
            root,
            TEMPLATE_PATH,
            subject=TEMPLATE_PATH,
            fix=f"correct {TEMPLATE_PATH}, or delete it so setup writes one, then "
            "rerun setup.",
        )
    return pending


def files_plan(root: Path, options: SetupOptions) -> FilesPlan:
    if options.license_choice not in ("none", "apache-2.0"):
        raise SetupError("License choice must be none or apache-2.0.")
    if options.docs not in DOCUMENT_SETS:
        raise SetupError("Document set must be core or full.")
    pending: dict[Path, bytes] = {}
    kept: tuple[str, ...] = ()
    existing_policy = read_if_present(root / POLICY_PATH)
    parse_policy(DEFAULT_POLICY if existing_policy is None else existing_policy, root)
    if existing_policy is None:
        pending[root / POLICY_PATH] = DEFAULT_POLICY
        starter = _starter_plan(root, options)
        pending.update(starter.pending)
        kept = starter.kept
    pending.update(_license_plan(root, options.license_choice))
    pending.update(_support_plan(root, options))
    return FilesPlan(pending, kept)
