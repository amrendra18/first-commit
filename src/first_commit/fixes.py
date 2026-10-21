from first_commit.checks.identity import (
    ALLOWED_SIGNERS_PATH,
    SIGNATURE_TRUST_RULE,
    SIGNERS_FILE_RULE,
    SIGNING_KEY_FILE_RULE,
    TRUST_SETTING,
)
from first_commit.contributor import CONTRIBUTOR_PATH
from first_commit.gitleaks_blobs import MESSAGE_PATH
from first_commit.gitleaks_ignore_format import IGNORE_PATH
from first_commit.gitleaks_scanner import LOCAL_SCANNER_PATH, SCANNER_VERSION
from first_commit.history_messages import TAG_MESSAGE_PATH
from first_commit.models import Finding
from first_commit.paths import MEBIBYTE
from first_commit.policy import POLICY_PATH, REQUIRED_DOCUMENTS
from first_commit.policy_fields import DEFAULT_LIMITS
from first_commit.setup_command import (
    HOOK_CONFIG,
    SETUP_HOOK_COMMAND,
    TOOL_SETUP_COMMAND,
    TRUST_SELF_VARIABLE,
)

CONTRIBUTOR_RULES = (
    "git.contributor-email",
    "git.contributor-name",
    "git.contributor-signing-key",
)
SETUP_RULES = (
    "git.allowed-email",
    "git.contributor-record",
    "git.explicit-identity",
    "git.local-email",
    "git.local-name",
    "git.signed-commits",
    "git.signed-tags",
    "git.signing-key",
    "git.ssh-format",
    "hooks.invalid",
    "hooks.missing",
    "template.missing",
    "template.unusable",
)
# An approval counts only once the policy is staged, so each fix that adds one says so.
STAGE_POLICY = f", then stage {POLICY_PATH}"
DETECTOR_EXCEPTION = (
    "or approve this exact line with a privacy_detector_exceptions entry "
    f"in {POLICY_PATH}" + STAGE_POLICY
)
REVOKE = (
    "Remove it from the file, revoke it with its provider, and read it from an "
    "environment variable or secret store instead."
)


def _declare_fix(identifier: str) -> str:
    return (
        f"Declare {identifier} once in {HOOK_CONFIG}, from the first-commit "
        "repository, with no keys but id and stages; remove args, entry, and other "
        "overrides."
    )


COMMON_FIXES = {
    "documents.required": "Add the missing document at the repository root and stage it.",
    "environment.not-ignored": (
        "Add this file to .gitignore, or list it in public_environment_files in "
        f"{POLICY_PATH} if it holds no secrets{STAGE_POLICY}."
    ),
    "environment.tracked-private-file": (
        "Run git rm --cached on this path, add it to .gitignore, and replace any "
        "secret it held."
    ),
    "files.too-large": (
        f"Make the file smaller than {DEFAULT_LIMITS['max_file_bytes'] // MEBIBYTE} "
        "MiB, or keep it out of Git: git rm --cached it if staged, and add it to "
        ".gitignore."
    ),
    "git.author-email": (
        "Commit as yourself: drop --author, GIT_AUTHOR_EMAIL, and git -c user.email, "
        f"or set them to the email in {CONTRIBUTOR_PATH}."
    ),
    "git.committer-email": (
        "Commit as yourself: unset GIT_COMMITTER_EMAIL and drop git -c user.email "
        f"and -c committer.email, or set them to the email in {CONTRIBUTOR_PATH}."
    ),
    "git.empty-index": (
        "Stage the files to commit with git add, including "
        + " and ".join(REQUIRED_DOCUMENTS)
        + "."
    ),
    "hooks.nested-remote": (
        "Rename the nested remote so its name is not another remote's name plus /, "
        "for example git remote rename origin/x origin-x."
    ),
    "hooks.push-check": (
        f"Add the first-commit-push hook to {HOOK_CONFIG}, or a pre-push hook whose "
        "entry is first-commit hook pre-push."
    ),
    "hooks.staged-check": _declare_fix("first-commit-staged"),
    "hooks.message-check": _declare_fix("first-commit-message"),
    "hooks.remote-case": (
        "Rename one of the remotes so no two names differ only in letter case."
    ),
    SIGNING_KEY_FILE_RULE: (
        "Restore the public-key file that git config --local user.signingkey "
        'prints, or replace the identity as "Stop and recover" in the first-commit '
        "README describes."
    ),
    "git.tracked-allowed-signers": (
        f"Run git rm --cached {ALLOWED_SIGNERS_PATH}, commit that, and "
        "check that the file holds only your own key."
    ),
    "message.header": (
        "Start the message with <type>(<scope>): <subject>, for example "
        "fix(setup): keep the existing policy."
    ),
    "message.sections": (
        "Add Why:, Changes:, Test Plan:, and Risks: to the message body, in that "
        "order; .gitmessage shows the layout."
    ),
    "message.subject-length": "Shorten the subject and move the details to the body.",
    "message.subject-punctuation": "Delete the punctuation at the end of the subject.",
    "privacy.aws-access-key": "This looks like an AWS access key. " + REVOKE,
    "privacy.forbidden-path": (
        f"Run git rm --cached on this path; forbidden_paths in {POLICY_PATH} "
        "forbids it in Git."
    ),
    "privacy.github-token": "This looks like a GitHub token. " + REVOKE,
    "privacy.private-key": (
        "Remove the key from the file, and replace the key if it was ever committed "
        "or shared."
    ),
    "privacy.private-literal": (
        "Remove the private value from this line, or approve this exact line with a "
        f"private_literal_exceptions entry in {POLICY_PATH}{STAGE_POLICY}."
    ),
    "privacy.private-path": (
        "Rename the file or folder so its path leaves out the private value; no "
        "exception can approve a path."
    ),
    "privacy.ssh-fingerprint": "Remove the fingerprint, " + DETECTOR_EXCEPTION + ".",
    "privacy.unapproved-email": (
        "Replace the address with a placeholder such as name@example.com, or add it "
        f"to public_emails in {POLICY_PATH} if it is public{STAGE_POLICY}."
    ),
    "privacy.user-home-path": (
        "Replace the home folder path with ~ or a relative path, "
        + DETECTOR_EXCEPTION
        + "."
    ),
    "scaffold.no-commit": "Review the generated section, then delete the @no-commit line.",
    "secrets.gitleaks": (
        "Remove the secret and revoke it; record a reviewed false positive in "
        f"a tracked {IGNORE_PATH} (ARCHITECTURE.md in first-commit, Gitleaks "
        "exceptions)."
    ),
    "text.control-character": "Delete the control character from this line.",
    "text.final-newline": "End the file with a newline.",
    "text.invalid-utf8": "Save the file as UTF-8 text.",
    "text.merge-marker": "Resolve the merge conflict and delete the marker line.",
    "text.trailing-whitespace": "Delete the spaces or tabs at the end of this line.",
}


# Under pre-commit, setup runs the pinned revision, so it cannot name the installed one.
def _setup_fixes(setup: str, trust: str, revision_source: str = "") -> dict[str, str]:
    setup_fix = (
        f"Run {setup} in this checkout; it sets the local identity, signing, "
        "contributor record, hooks, and commit template."
    )
    contributor_fix = (
        f"Set this Git setting back to the value in {CONTRIBUTOR_PATH}, or run {setup}."
    )
    return {
        "hooks.push-revision": (
            f"Set rev in {HOOK_CONFIG} to the installed first-commit's commit"
            f"{revision_source}, or install first-commit at the pinned rev."
        ),
        **dict.fromkeys(SETUP_RULES, setup_fix),
        **dict.fromkeys(CONTRIBUTOR_RULES, contributor_fix),
        "secrets.scanner-unavailable": (
            f"Run {setup} in this checkout (first delete {LOCAL_SCANNER_PATH} if the "
            f"summary says to), or install Gitleaks {SCANNER_VERSION} on PATH."
        ),
        SIGNATURE_TRUST_RULE: f"Run {trust} in this checkout to trust your own signing key.",
        SIGNERS_FILE_RULE: (
            f"Run git config --local --unset {TRUST_SETTING}, then run {trust} to "
            "write the file again."
        ),
    }


HOOK_FIXES = {
    **COMMON_FIXES,
    **_setup_fixes(SETUP_HOOK_COMMAND, f"{TRUST_SELF_VARIABLE}=1 {SETUP_HOOK_COMMAND}"),
}
TOOL_FIXES = {
    **COMMON_FIXES,
    **_setup_fixes(
        TOOL_SETUP_COMMAND,
        f"{TOOL_SETUP_COMMAND} --trust-self",
        f" ({TOOL_SETUP_COMMAND} names it)",
    ),
}


MESSAGE_CHANGES = {
    "privacy.aws-access-key": (
        "Revoke this AWS access key and delete it from the commit message"
    ),
    "privacy.github-token": "Revoke this GitHub token and delete it from the commit message",
    "privacy.private-key": "Replace this key and delete it from the commit message",
    "privacy.private-literal": "Delete the private value from the commit message",
    "privacy.ssh-fingerprint": "Delete the fingerprint from the commit message",
    "privacy.unapproved-email": (
        "Use name@example.com in the message, or add a public one to public_emails"
        + STAGE_POLICY
    ),
    "privacy.user-home-path": (
        "Replace the home folder path in the commit message with ~ or a relative path"
    ),
    "secrets.gitleaks": (
        "Revoke the secret and delete it from the commit message; "
        f"{IGNORE_PATH} does not apply to it"
    ),
}
COMMIT_REWORD = (
    ". Commit again, or reword a commit: git commit --amend (last) or git rebase -i "
    "(earlier)."
)
MESSAGE_FIXES = {
    rule: change + COMMIT_REWORD for rule, change in MESSAGE_CHANGES.items()
}
PUSHED_MESSAGE_FIX = (
    "Revoke a secret, token, or key with its provider. Rewording a pushed message "
    "needs a history rewrite and a force push; a home path, email, fingerprint, or "
    "private value needs nothing else."
)
TAG_MESSAGE_FIX = (
    "Revoke any secret with its provider. Delete the tag with git tag -d (git tag "
    "--points-at <id> names it) and, if pushed, git push --delete <remote> <tag>, as "
    "its text is public; then tag again."
)


def fix_for(finding: Finding, *, setup_hook: bool = True) -> str | None:
    if finding.path == MESSAGE_PATH and finding.rule_id in MESSAGE_FIXES:
        if finding.on_remote:
            return PUSHED_MESSAGE_FIX
        return MESSAGE_FIXES[finding.rule_id]
    if finding.path == TAG_MESSAGE_PATH and finding.rule_id in MESSAGE_FIXES:
        return TAG_MESSAGE_FIX
    return (HOOK_FIXES if setup_hook else TOOL_FIXES).get(finding.rule_id)
