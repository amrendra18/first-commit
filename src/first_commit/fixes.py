from pathlib import Path

from first_commit import git
from first_commit.checks.identity import (
    ALLOWED_SIGNERS_PATH,
    SIGNATURE_TRUST_RULE,
    SIGNERS_FILE_RULE,
    SIGNING_KEY_FILE_RULE,
    TRUST_SETTING,
)
from first_commit.contributor import CONTRIBUTOR_PATH
from first_commit.generated_files import proposal_name
from first_commit.gitleaks_blobs import MESSAGE_PATH
from first_commit.gitleaks_ignore_format import IGNORE_PATH
from first_commit.gitleaks_scanner import LOCAL_SCANNER_PATH, SCANNER_VERSION
from first_commit.history_messages import TAG_MESSAGE_PATH
from first_commit.models import Finding
from first_commit.paths import MEBIBYTE
from first_commit.policy import POLICY_PATH, REQUIRED_DOCUMENTS
from first_commit.policy_fields import DEFAULT_LIMITS
from first_commit.pushed_signatures import RULE_ID as UNSIGNED_COMMIT_RULE
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


LOCAL_DECLARE_FIXES = {
    f"hooks.{name}-check": (
        f"Declare first-commit-{name} once as a repo: local hook with entry "
        f"first-commit hook {stage}, language system, always_run true, "
        f"pass_filenames {str(stage == 'commit-msg').lower()}, and stages [{stage}]."
    )
    for name, stage in (("staged", "pre-commit"), ("message", "commit-msg"))
}
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
    "files.filtered-unreadable": (
        "Move whatever is at that path aside, then restore the file with git "
        "checkout -- on its path, or unstage it with git restore --staged; then "
        "commit again."
    ),
    "files.filtered-too-large": (
        "Review the file by hand before you push: first-commit reads at most 10 MiB "
        "of a clean-filter file's working copy."
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
    UNSIGNED_COMMIT_RULE: (
        "Sign each unpushed commit from the oldest unsigned one on: git commit "
        "--amend --no-edit --gpg-sign for the newest, else git rebase --force-rebase "
        "--gpg-sign <its id>^; then push again."
    ),
    "history.whole-history": (
        "Nothing was left out: this run checked every commit. To check only new "
        "commits, remove the remotes you no longer use with git remote remove <name>."
    ),
    "hooks.installed-command": (
        "Put first-commit on PATH in a folder outside this repository, as Install in "
        "the first-commit README shows, or declare the pinned first-commit hooks."
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
        "Give Why:, Changes:, Test Plan:, and Risks: each a line of your own, in that "
        "order, and replace the template lines <reason>, <changes>, "
        "<commands and results>, and <risks>."
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
            f"Run {trust} to write {ALLOWED_SIGNERS_PATH} again; if {TRUST_SETTING} "
            "names another file, restore it."
        ),
    }


SETUP_NAMING_RULES = (
    *SETUP_RULES,
    *CONTRIBUTOR_RULES,
    "secrets.scanner-unavailable",
    SIGNATURE_TRUST_RULE,
    SIGNERS_FILE_RULE,
)
UNNAMED_MAIN_WORKTREE = "the folder that `git worktree list` prints first"
WORKTREE_FIX = (
    "Linked worktrees are not supported, and setup refuses to run in one; commit "
    "from the main worktree at {main}."
)


def linked_main_worktree(root: Path) -> Path | None:
    git_file = root / ".git"
    if git_file.is_symlink() or not git_file.is_file():
        return None
    try:
        return git.main_worktree(root)
    except git.GitError:
        return None


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
HISTORY_SECRET_FIX = (
    "Revoke the secret, then remove it from commit {commit}: git rebase -i "
    "{commit}^ when that commit is not pushed (git rebase -i --root when it is the "
    "first commit); a pushed commit needs a history "
    "rewrite and a force push. Record a reviewed false positive as a "
    f"<commit>:<path>:<rule>:<line> entry in a tracked {IGNORE_PATH} "
    "(ARCHITECTURE.md in first-commit, Gitleaks exceptions)."
)
UNSIGNED_COMMIT_FIX = (
    "Sign commit {commit} on each local branch that holds it (git branch --contains "
    "{commit} lists them). On a branch where it is the newest commit, switch to "
    "that branch and run git commit --amend --no-edit --gpg-sign. Where commits "
    "without a merge follow it, switch to that branch and run git rebase "
    "--force-rebase --gpg-sign {commit}^ (git rebase --force-rebase --gpg-sign "
    "--root when it is the first commit). After a merge, re-create those commits "
    "by hand: a rebase can drop a change made in a merge commit. Then push again."
)
PUSHED_FILE_FIX = (
    " Make the change in commit {commit} itself, on each local branch that holds it "
    "(git branch --contains {commit} lists them): switch to that branch, run git "
    "rebase -i {commit}^ (git rebase -i --root when it is the first commit), mark it "
    "edit, amend it, and continue. When {commit} is a merge commit, or a merge "
    "follows it, re-create those commits by hand: a rebase drops merges. Then push "
    "again. A later commit that deletes the line leaves it in {commit}."
)
FETCH_FIRST = (
    " When the remote already holds commit {commit}, run git fetch <remote>, then "
    "push again."
)
PROPOSAL_SUFFIX = proposal_name("")
PROPOSAL_FIX = "Merge this proposal into {document}, then delete the proposal."
PUSHED_FILE_RULES = frozenset(
    rule
    for rule in COMMON_FIXES
    if rule.startswith("privacy.") or rule == "files.too-large"
) - {"privacy.forbidden-path"}
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


def _message_fix(finding: Finding) -> str | None:
    if finding.rule_id not in MESSAGE_FIXES:
        return None
    if finding.path == MESSAGE_PATH:
        return (
            PUSHED_MESSAGE_FIX if finding.on_remote else MESSAGE_FIXES[finding.rule_id]
        )
    return TAG_MESSAGE_FIX if finding.path == TAG_MESSAGE_PATH else None


def _commit_fix(finding: Finding) -> str | None:
    commit = finding.commit
    if commit is None:
        return None
    if finding.rule_id == "secrets.gitleaks":
        fix = HISTORY_SECRET_FIX.format(commit=commit)
    elif finding.rule_id == UNSIGNED_COMMIT_RULE:
        fix = UNSIGNED_COMMIT_FIX.format(commit=commit)
    elif finding.rule_id in PUSHED_FILE_RULES:
        change = (
            COMMON_FIXES[finding.rule_id]
            .replace(STAGE_POLICY, "")
            .replace(f"in {POLICY_PATH}", f"in the {POLICY_PATH} of commit {commit}")
        )
        fix = change + PUSHED_FILE_FIX.format(commit=commit)
    else:
        return None
    return fix + FETCH_FIRST.format(commit=commit) if finding.pushed else fix


def fix_for(
    finding: Finding, *, setup_hook: bool = True, main_worktree: str | None = None
) -> str | None:
    if main_worktree is not None and finding.rule_id in SETUP_NAMING_RULES:
        return WORKTREE_FIX.format(main=main_worktree)
    message = _message_fix(finding)
    if message is not None:
        return message
    commit = _commit_fix(finding)
    if commit is not None:
        return commit
    if finding.rule_id == "scaffold.no-commit" and finding.path.endswith(
        PROPOSAL_SUFFIX
    ):
        document = finding.path.removesuffix(PROPOSAL_SUFFIX)
        return PROPOSAL_FIX.format(document=document)
    if finding.local_hook and finding.rule_id in LOCAL_DECLARE_FIXES:
        return LOCAL_DECLARE_FIXES[finding.rule_id]
    return (HOOK_FIXES if setup_hook else TOOL_FIXES).get(finding.rule_id)
