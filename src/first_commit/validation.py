import os
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import replace
from pathlib import Path

from first_commit.candidates import (
    CandidateError,
    LoadedCandidates,
    environment_files,
    head_candidate,
    index_candidate,
    staged_candidate_paths,
    staged_candidates,
    working_candidate_paths,
    working_candidates,
)
from first_commit.checks.environment import DOTENV_PATHSPECS, environment_findings
from first_commit.checks.identity import (
    ALLOWED_SIGNERS_PATH,
    COMMIT_IDENTITIES,
    GIT_POLICY_KEYS,
    commit_identity_findings,
    ident_email,
    identity_findings,
    signature_trust_findings,
    signing_file_findings,
    tracked_signers_findings,
)
from first_commit.checks.messages import message_findings
from first_commit.checks.privacy import forbidden_path_findings, privacy_policy
from first_commit.checks.templates import template_findings
from first_commit.checks.text import no_commit_findings
from first_commit.contributor import contributor_findings, load_contributor
from first_commit.finding_collector import (
    FindingCollector,
    evaluate,
    split_forbidden,
    too_large_findings,
)
from first_commit.generated_files import DOCUMENT_NAMES, HOOK_PROPOSAL, proposal_name
from first_commit.git import (
    GitError,
    commit_ident,
    git_path,
    is_tracked,
    run_git,
)
from first_commit.git_settings import local_git_settings
from first_commit.gitleaks import scan_history, scan_pushed, scan_staged
from first_commit.gitleaks_blobs import MESSAGE_PATH, scan_hidden_staged
from first_commit.gitleaks_scanner import (
    LOCAL_SCANNER_PATH,
    DependencyError,
    validate_scanner,
)
from first_commit.history_messages import MessageScope, history_message_findings
from first_commit.hooks import hook_findings, push_check_findings
from first_commit.message_scissors import message_secret_findings, split_message
from first_commit.models import Candidate, Finding, Origin, Result
from first_commit.paths import PathError, read_explicit_file_bytes, read_regular_bytes
from first_commit.policy import (
    MAX_POLICY_BYTES,
    POLICY_PATH,
    REQUIRED_DOCUMENTS,
    Policy,
    parse_policy,
)
from first_commit.policy_fields import PolicyError
from first_commit.pushed import PushedScope

GENERATED_DOCUMENTS = (
    *(path for name in DOCUMENT_NAMES for path in (name, proposal_name(name))),
    HOOK_PROPOSAL,
)


def _working_documents(
    root: Path, policy: Policy, allowed: Sequence[str]
) -> dict[str, Candidate]:
    paths = [path for path in REQUIRED_DOCUMENTS if path in allowed]
    return {
        candidate.path: candidate
        for candidate in working_candidates(
            root, policy.max_files, policy.max_file_bytes, paths=paths
        )
    }


def _index_documents(
    root: Path, policy: Policy, excluded: frozenset[str] = frozenset()
) -> dict[str, Candidate]:
    documents = {}
    for path in REQUIRED_DOCUMENTS:
        if path in excluded:
            continue
        try:
            documents[path] = index_candidate(root, path, policy.max_file_bytes)
        except CandidateError:
            continue
    return documents


def working(root: Path, policy: Policy, private_values: Sequence[str] = ()) -> Result:
    found = FindingCollector(policy.max_findings)
    paths = working_candidate_paths(root, policy.max_files)
    found.add(
        forbidden_path_findings(paths, policy.forbidden_paths, max_findings=found.room)
    )
    allowed, _ = split_forbidden(paths, policy)
    loaded = working_candidates(
        root, policy.max_files, policy.max_file_bytes, paths=allowed
    )
    found.add(too_large_findings(loaded.oversized, max_findings=found.room))
    documents = _working_documents(root, policy, allowed)
    evaluate(found, loaded, policy, documents, private_values)
    _add_environment_findings(found, root, policy)
    return found.result("working")


def _add_environment_findings(
    found: FindingCollector, root: Path, policy: Policy
) -> None:
    files = environment_files(root, DOTENV_PATHSPECS, policy.max_files)
    found.add(
        environment_findings(
            files, policy.environment_exceptions, max_findings=found.room
        )
    )


# Exemptions come from the staged policy: a worktree edit cannot approve staged bytes.
# Without a staged or committed policy, no exemption applies, so an approval that no
# reviewer can see in Git never lets staged bytes through.
def _staged_policy(root: Path, policy: Policy) -> Policy:
    tracked = is_tracked(root, POLICY_PATH)
    label = "staged" if tracked else "committed"
    staged_file: Candidate | None = (
        index_candidate(root, POLICY_PATH, MAX_POLICY_BYTES)
        if tracked
        else head_candidate(root, POLICY_PATH, MAX_POLICY_BYTES)
    )
    if staged_file is None:
        return replace(
            policy,
            environment_exceptions=(),
            literal_exceptions=(),
            detector_exceptions=(),
            public_emails=(),
            immutable_vendor_files=(),
            public_github_owner_urls=False,
        )
    if not staged_file.regular_file:
        raise PolicyError(
            f"The {label} {POLICY_PATH} is a link; stage the file itself."
        )
    try:
        parsed = parse_policy(staged_file.content, root)
    except PolicyError as error:
        raise PolicyError(f"The {label} {POLICY_PATH} is invalid: {error}") from error
    return replace(parsed, contributor_emails=policy.contributor_emails)


EMPTY_INDEX = Finding(
    rule_id="git.empty-index",
    path="<index>",
    summary="Staged snapshot is empty; stage the required documents before validation.",
)


# A commit stays blocked until every visible copy is reviewed, staged or not.
def _generated_documents(root: Path, policy: Policy) -> LoadedCandidates:
    allowed, _ = split_forbidden(
        working_candidate_paths(root, policy.max_files, GENERATED_DOCUMENTS), policy
    )
    return working_candidates(
        root, policy.max_files, policy.max_file_bytes, paths=allowed
    )


def _unseen(found: FindingCollector, findings: Iterable[Finding]) -> Iterator[Finding]:
    seen = {(item.rule_id, item.path, item.line) for item in found.items}
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.line)
        if key not in seen:
            seen.add(key)
            yield finding


# Asks each document for cap findings: _unseen drops at most what found holds.
def _add_generated_no_commit_findings(
    found: FindingCollector, generated: LoadedCandidates
) -> None:
    for candidate in generated:
        if found.full():
            break
        found.add(_unseen(found, no_commit_findings(candidate, max_findings=found.cap)))


def staged(root: Path, policy: Policy, private_values: Sequence[str] = ()) -> Result:
    policy = _staged_policy(root, policy)
    found = FindingCollector(policy.max_findings)
    paths = staged_candidate_paths(root, policy.max_files)
    index_empty = not run_git(root, ("ls-files", "-z", "--cached", "--"))
    if index_empty:
        found.add((EMPTY_INDEX,))
    found.add(
        forbidden_path_findings(paths, policy.forbidden_paths, max_findings=found.room)
    )
    allowed, excluded = split_forbidden(paths, policy)
    loaded = staged_candidates(
        root, policy.max_files, policy.max_file_bytes, paths=allowed
    )
    found.add(too_large_findings(loaded.oversized, max_findings=found.room))
    # A too-large generated document is reported before the content findings,
    # so a full finding budget keeps it. Every path is listed before the repeats
    # are dropped, so a repeat never takes the room of a new path.
    generated = _generated_documents(root, policy)
    found.add(
        _unseen(
            found,
            too_large_findings(
                generated.oversized, max_findings=len(generated.oversized)
            ),
        )
    )
    # An empty index reports EMPTY_INDEX in place of each missing document.
    documents = None if index_empty else _index_documents(root, policy, excluded)
    evaluate(found, loaded, policy, documents, private_values)
    _add_environment_findings(found, root, policy)
    _add_generated_no_commit_findings(found, generated)
    if not excluded:
        found.add(scan_staged(root, max_findings=found.room))
        found.add(
            scan_hidden_staged(
                root,
                allowed,
                (policy.max_files, policy.max_file_bytes),
                max_findings=found.room,
            )
        )
    return found.result("staged")


def _git_managed(message_path: Path, expected: Path) -> Path:
    if message_path.resolve() != expected.resolve():
        raise PathError("Commit message path is not Git-managed.")
    return expected


def _commit_message_bytes(root: Path, policy: Policy, message_path: Path) -> bytes:
    try:
        content = read_explicit_file_bytes(root, message_path, policy.max_message_bytes)
    except PathError:
        try:
            expected = git_path(
                root, run_git(root, ("rev-parse", "--git-path", "COMMIT_EDITMSG"))
            )
            content = read_regular_bytes(
                _git_managed(message_path, expected), policy.max_message_bytes
            )
        except (GitError, PathError) as error:
            raise CandidateError("Commit message cannot be read.") from error
    try:
        content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CandidateError("Commit message must be valid UTF-8 text.") from error
    if b"\0" in content:
        raise CandidateError("Commit message must not contain NUL bytes.")
    return content


def _commit_emails(root: Path) -> dict[str, str | None]:
    emails: dict[str, str | None] = {}
    for variable, _, _ in COMMIT_IDENTITIES:
        try:
            emails[variable] = ident_email(commit_ident(root, variable))
        except GitError:
            emails[variable] = None
    return emails


def message(
    root: Path,
    policy: Policy,
    message_path: Path,
    private_values: Sequence[str] = (),
) -> Result:
    policy = _staged_policy(root, policy)
    raw = _commit_message_bytes(root, policy, message_path)
    parts = split_message(root, raw, os.environ)
    candidate = Candidate(MESSAGE_PATH, parts.above, Origin.MESSAGE)
    found = FindingCollector(policy.max_findings)
    privacy = privacy_policy(policy, private_values)
    found.add(message_secret_findings(root, parts, privacy, max_findings=found.room))
    git_settings = local_git_settings(root, GIT_POLICY_KEYS)
    found.add(identity_findings(git_settings, policy.contributor_emails))
    found.add(
        commit_identity_findings(
            _commit_emails(root), policy.contributor_emails, git_settings
        )
    )
    found.add(no_commit_findings(candidate, max_findings=found.room))
    found.add(
        message_findings(
            candidate,
            max_findings=found.room,
            require_sections=policy.commit_body_sections,
        )
    )
    found.add(contributor_findings(load_contributor(root), git_settings))
    return found.result("message")


def history(
    root: Path,
    policy: Policy,
    scope: PushedScope | None = None,
    private_values: Sequence[str] = (),
    *,
    warn_on_remote: bool = False,
) -> Result:
    found = FindingCollector(policy.max_findings)
    found.add(
        scan_history(root, max_findings=found.room)
        if scope is None
        else scan_pushed(root, scope, max_findings=found.room)
    )
    messages = MessageScope(scope, warn_on_remote=warn_on_remote)
    found.add(
        history_message_findings(
            root, policy, private_values, messages, max_findings=found.room
        )
    )
    return found.result("history")


def _scanner_findings(root: Path) -> list[Finding]:
    try:
        validate_scanner(root)
    except DependencyError as error:
        return [
            Finding(
                rule_id="secrets.scanner-unavailable",
                path=LOCAL_SCANNER_PATH,
                summary=str(error),
            )
        ]
    return []


def doctor(root: Path, policy: Policy) -> Result:
    git_settings = local_git_settings(root, GIT_POLICY_KEYS)
    found = FindingCollector(policy.max_findings)
    found.add(identity_findings(git_settings, policy.contributor_emails))
    found.add(signature_trust_findings(git_settings))
    found.add(signing_file_findings(root, git_settings))
    found.add(tracked_signers_findings(tracked=is_tracked(root, ALLOWED_SIGNERS_PATH)))
    found.add(_scanner_findings(root))
    found.add(hook_findings(root))
    found.add(push_check_findings(root))
    found.add(template_findings(root))
    found.add(contributor_findings(load_contributor(root), git_settings))
    return found.result("doctor")
