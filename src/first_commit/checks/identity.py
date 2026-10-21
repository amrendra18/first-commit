import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from first_commit.contributor import CONTRIBUTOR_PATH
from first_commit.models import GIT_CONFIG_PATH, Finding, Severity

TRUST_SETTING = "gpg.ssh.allowedSignersFile"
ALLOWED_SIGNERS_PATH = ".local/first-commit/allowed-signers"
TRACKED_SIGNERS_RULE = "git.tracked-allowed-signers"
TRACKED_SIGNERS_SUMMARY = (
    "The allowed-signers file is tracked by Git, so a pulled commit can choose whose "
    "signatures verify in this checkout."
)
IDENTITY_KEYS = (
    "user.name",
    "user.email",
    "user.signingkey",
    "gpg.format",
    "commit.gpgsign",
    "tag.gpgsign",
    "user.useConfigOnly",
)
GIT_POLICY_KEYS = (*IDENTITY_KEYS, TRUST_SETTING)
# In a hook, `git var` prints the identity the commit records: Git passes --author
# and the author of `git -c user.email=...` as GIT_AUTHOR_* variables, and keeps
# GIT_COMMITTER_* variables. The `git var` query keeps the `git -c` settings, so
# a committer email set with `-c user.email` or `-c committer.email` is seen.
COMMIT_IDENTITIES = (
    (
        "GIT_AUTHOR_IDENT",
        "git.author-email",
        "Commit author email is not an approved contributor email.",
    ),
    (
        "GIT_COMMITTER_IDENT",
        "git.committer-email",
        "Committer email is not an approved contributor email.",
    ),
)
IDENT = re.compile(rb"[^<>\n]*<([^<>\n]*)> [0-9]+ [+-][0-9]{4}\n?")
SIGNATURE_TRUST_RULE = "git.signature-verification-trust"
SIGNATURE_TRUST_SUMMARY = (
    f"{TRUST_SETTING} is not set in {GIT_CONFIG_PATH}, so signed commits may not "
    "verify in this checkout."
)
SIGNING_KEY_FILE_RULE = "git.signing-key-file"
SIGNERS_FILE_RULE = "git.allowed-signers-file"
# Git reads these user.signingkey forms as the key itself, not as a file.
LITERAL_KEY_PREFIXES = ("key::", "ssh-")


# Resolves as Git does: a relative path from the repository root, and ~ expanded.
def _names_no_file(root: Path, value: str) -> bool:
    try:
        path = Path(value).expanduser()
    except RuntimeError:
        return True
    return not (path if path.is_absolute() else root / path).is_file()


# Only the paths are checked; the key and allowed-signers files are never read.
def signing_file_findings(root: Path, git_settings: Mapping[str, str]) -> list[Finding]:
    findings = []
    key = git_settings.get("user.signingkey", "")
    if key and not key.startswith(LITERAL_KEY_PREFIXES) and _names_no_file(root, key):
        findings.append(
            Finding(
                rule_id=SIGNING_KEY_FILE_RULE,
                path=GIT_CONFIG_PATH,
                summary="The signing-key file that user.signingkey names is missing.",
            )
        )
    signers = git_settings.get(TRUST_SETTING, "")
    if signers and _names_no_file(root, signers):
        findings.append(
            Finding(
                rule_id=SIGNERS_FILE_RULE,
                severity=Severity.WARNING,
                path=GIT_CONFIG_PATH,
                summary=(
                    f"The allowed-signers file that {TRUST_SETTING} names is "
                    "missing; signed commits do not verify in this checkout."
                ),
            )
        )
    return findings


def signature_trust_findings(git_settings: Mapping[str, str]) -> list[Finding]:
    if git_settings.get(TRUST_SETTING):
        return []
    return [
        Finding(
            rule_id=SIGNATURE_TRUST_RULE,
            severity=Severity.WARNING,
            path=GIT_CONFIG_PATH,
            summary=SIGNATURE_TRUST_SUMMARY,
        )
    ]


def tracked_signers_findings(*, tracked: bool) -> list[Finding]:
    if not tracked:
        return []
    return [
        Finding(
            rule_id=TRACKED_SIGNERS_RULE,
            path=ALLOWED_SIGNERS_PATH,
            summary=TRACKED_SIGNERS_SUMMARY,
        )
    ]


def git_enabled(value: str) -> bool:
    return value.lower() in {"1", "on", "true", "yes"}


def identity_findings(
    git_settings: Mapping[str, str],
    contributor_emails: Sequence[str],
) -> list[Finding]:
    email = git_settings.get("user.email")
    missing = (
        (
            not git_settings.get("user.name"),
            "git.local-name",
            f"user.name is not set in {GIT_CONFIG_PATH}.",
        ),
        (not email, "git.local-email", f"user.email is not set in {GIT_CONFIG_PATH}."),
        (
            email not in contributor_emails,
            "git.allowed-email",
            f"user.email in {GIT_CONFIG_PATH} is not the email in {CONTRIBUTOR_PATH}.",
        ),
        (
            not git_settings.get("user.signingkey"),
            "git.signing-key",
            f"user.signingkey is not set in {GIT_CONFIG_PATH}.",
        ),
        (
            git_settings.get("gpg.format") != "ssh",
            "git.ssh-format",
            f"gpg.format is not ssh in {GIT_CONFIG_PATH}.",
        ),
        (
            not git_enabled(git_settings.get("commit.gpgsign", "")),
            "git.signed-commits",
            f"commit.gpgsign is not true in {GIT_CONFIG_PATH}.",
        ),
        (
            not git_enabled(git_settings.get("tag.gpgsign", "")),
            "git.signed-tags",
            f"tag.gpgsign is not true in {GIT_CONFIG_PATH}.",
        ),
        (
            not git_enabled(git_settings.get("user.useConfigOnly", "")),
            "git.explicit-identity",
            f"user.useConfigOnly is not true in {GIT_CONFIG_PATH}.",
        ),
    )
    return [
        Finding(rule_id=rule_id, path=GIT_CONFIG_PATH, summary=summary)
        for failed, rule_id, summary in missing
        if failed
    ]


def ident_email(raw: bytes) -> str | None:
    match = IDENT.fullmatch(raw)
    if match is None:
        return None
    try:
        return match.group(1).decode("utf-8")
    except UnicodeDecodeError:
        return None


# An email equal to the local user.email is skipped: identity_findings reports it.
def commit_identity_findings(
    emails: Mapping[str, str | None],
    contributor_emails: Sequence[str],
    git_settings: Mapping[str, str],
) -> list[Finding]:
    local_email = git_settings.get("user.email")
    return [
        Finding(rule_id=rule_id, path=GIT_CONFIG_PATH, summary=summary)
        for variable, rule_id, summary in COMMIT_IDENTITIES
        if (email := emails.get(variable)) is None
        or (email not in contributor_emails and email != local_email)
    ]
