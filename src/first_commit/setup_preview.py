import os
from pathlib import Path

from first_commit.checks.text import no_commit_findings
from first_commit.gitleaks_scanner import SCANNER_VERSION
from first_commit.models import Candidate, Origin
from first_commit.paths import PathError, read_regular_bytes
from first_commit.policy import POLICY_PATH, PRIVATE_VALUES_PATH
from first_commit.policy_fields import DEFAULT_LIMITS
from first_commit.setup_command import (
    CHECK_HOOK_COMMAND,
    CHECK_HOOK_ID,
    HOOK_CONFIG,
    SETUP_HOOK_ID,
    declares_hook,
)
from first_commit.setup_plan import RepositoryState, SetupPlan
from first_commit.setup_trust import trust_line
from first_commit.starter import DOCUMENTS
from first_commit.validation import GENERATED_DOCUMENTS


def _step(label: str, *, needed: bool, dry_run: bool, verbs: tuple[str, str]) -> str:
    if not needed:
        return f"{label}: ready"
    return f"{label}: {verbs[0] if dry_run else verbs[1]}"


def _verification_trust(plan: SetupPlan, *, dry_run: bool) -> str:
    if not plan.git.trust_ready:
        return "Signature verification: not performed; trust is not checked"
    state = (
        "would be configured"
        if dry_run and not plan.git.trust_configured
        else "is configured"
    )
    return (
        f"Signature verification: local trust {state}; no existing signature was "
        "verified"
    )


def _setup_context(plan: SetupPlan, *, dry_run: bool) -> tuple[str, ...]:
    source = plan.options.source
    transport = "SSH" if source.startswith("ssh://") else "HTTPS"
    cache = (
        "custom PRE_COMMIT_HOME"
        if os.environ.get("PRE_COMMIT_HOME")
        else "pre-commit default"
    )
    hook_source = (
        "Hook source: existing project-owned configuration retained"
        if plan.existing_hooks
        else f"Hook source: {transport} ({source})"
    )
    return (
        hook_source,
        f"Hook cache: {cache}",
        _verification_trust(plan, dry_run=dry_run),
    )


def _record_lines(plan: SetupPlan, *, dry_run: bool) -> tuple[str, ...]:
    names = ", ".join(plan.names)
    files_line = (
        "Files: " + ("would create " if dry_run else "created ") + names
        if names
        else "Files: already present"
    )
    kept_lines = (
        ("Files kept as they are: " + ", ".join(plan.kept),) if plan.kept else ()
    )
    skipped_documents_lines = (
        (f"Documents: not created; {POLICY_PATH} exists",)
        if plan.options.docs == "full" and plan.root / POLICY_PATH not in plan.pending
        else ()
    )
    if plan.contributor is None:
        contributor_line = "Local contributor: required"
    elif plan.contributor_exists:
        contributor_line = "Local contributor: retained"
    else:
        contributor_line = "Local contributor: " + (
            "would create" if dry_run else "created"
        )
    values_line = (
        "Private values: retained"
        if plan.private_values_exist
        else "Private values: "
        + ("would create " if dry_run else "created ")
        + PRIVATE_VALUES_PATH
        + "; add one private value per line"
    )
    return (
        files_line,
        *kept_lines,
        *skipped_documents_lines,
        contributor_line,
        values_line,
    )


def _verification_line(plan: SetupPlan, *, dry_run: bool) -> str:
    if not dry_run:
        return "Verification: passed"
    if plan.repository is RepositoryState.WOULD_INITIALIZE:
        return (
            "Verification: Git-dependent checks will run after initialization; "
            "no changes made"
        )
    if plan.contributor is None:
        return "Verification: local identity input is needed; no changes made"
    return "Verification: preflight passed; no changes made"


def _scanner_line(plan: SetupPlan, *, dry_run: bool) -> str:
    if not plan.install_scanner and not plan.scanner_checked:
        return "Gitleaks: present, not validated; setup validates it"
    return _step(
        "Gitleaks",
        needed=plan.install_scanner,
        dry_run=dry_run,
        verbs=(
            f"would download and install {SCANNER_VERSION} from GitHub Releases",
            f"downloaded and installed {SCANNER_VERSION}",
        ),
    )


# A rerun creates no files, so the reminder comes from markers still on disk; the
# check refuses them until they are gone.
def _markers_remain(root: Path) -> bool:
    for name in GENERATED_DOCUMENTS:
        try:
            content = read_regular_bytes(root / name, DEFAULT_LIMITS["max_file_bytes"])
        except PathError:
            continue
        document = Candidate(name, content, Origin.WORKTREE)
        if no_commit_findings(document, max_findings=1):
            return True
    return False


def _next_action(plan: SetupPlan) -> str:
    review = any(
        name in DOCUMENTS or name.endswith(".first-commit-proposal.md")
        for name in plan.names
    )
    if review or _markers_remain(plan.root):
        return "Next action: review generated documents and remove @no-commit markers"
    # A clone has pre-commit only; setup writes a hook file that declares the check.
    if not plan.existing_hooks or declares_hook(plan.root, CHECK_HOOK_ID):
        return f"Next action: run {CHECK_HOOK_COMMAND}"
    if declares_hook(plan.root, SETUP_HOOK_ID):
        return (
            f"Next action: add {CHECK_HOOK_ID} to {HOOK_CONFIG}, then run "
            + CHECK_HOOK_COMMAND
        )
    return "Next action: run first-commit check"


def plan_lines(plan: SetupPlan, *, dry_run: bool) -> tuple[str, ...]:
    git = plan.git
    repository = (
        ()
        if plan.repository is RepositoryState.EXISTING
        else ("Git repository: " + plan.repository.value,)
    )
    return (
        *repository,
        *_record_lines(plan, dry_run=dry_run),
        _step(
            "Git identity/signing",
            needed=git.configure_identity,
            dry_run=dry_run,
            verbs=("would configure", "configured"),
        ),
        _step(
            "Commit template",
            needed=git.activate_template,
            dry_run=dry_run,
            verbs=("would set commit.template", "set commit.template"),
        ),
        *((trust_line(git.trust, dry_run=dry_run),) if git.trust is not None else ()),
        *_setup_context(plan, dry_run=dry_run),
        _scanner_line(plan, dry_run=dry_run),
        _step(
            "Hook scripts",
            needed=bool(git.missing_hooks),
            dry_run=dry_run,
            verbs=("would install", "installed"),
        ),
        "Hook environments: "
        + (
            "would install or verify; not checked (dry run)"
            if dry_run
            else "installed or verified"
        ),
        _verification_line(plan, dry_run=dry_run),
        _next_action(plan),
    )
