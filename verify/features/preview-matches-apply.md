# Setup does what the dry run announced

Proves: [README, Start a project](../../README.md#start-a-project).

## What it is

`first-commit setup --dry-run` lists the actions setup would take, so a person can trust the
preview. Each announced action must leave its effect after setup runs.

## How to get to it

A person runs `first-commit setup --dry-run` in an empty folder, then `first-commit
setup`.

## Driving it

1. In a new empty scratch folder, run the setup dry run with the throwaway identity.
2. Run setup in the same folder.
3. For each dry-run line that says "would", check that action's effect on disk or in
   `.git/config` (`scripts/verify_lib/effects.py`).

## Proof

The dry run exits 0 and leaves the folder empty. Setup exits 0. Every "would" line has an
effect check, and each effect exists:

| Dry-run label | Effect checked after setup |
| --- | --- |
| Git repository | `git rev-parse --git-dir` exits 0 |
| Files | every file the line names exists |
| Local contributor | `.local/first-commit/contributor.json` exists |
| Private values | the file the line names exists |
| Git identity/signing | `user.name`, `user.email`, `user.signingkey`, `gpg.format`, `commit.gpgsign`, `tag.gpgsign`, and `user.useConfigOnly` hold the expected values |
| Commit template | `commit.template` names an existing file |
| Local signature trust, Signature verification | `gpg.ssh.allowedSignersFile` is set and `.local/first-commit/allowed-signers` exists |
| Gitleaks | `.local/bin/gitleaks` is executable and `version` prints the announced version |
| Hook scripts | the pre-commit, commit-msg, and pre-push hooks are executable |
| Hook environments | pre-commit's `db.db` lists the HTTPS address at the snapshot commit, and its folder exists (the cache is shared with the setup feature) |

A "would" line with no effect check fails the feature, so a new setup action needs a new check.
