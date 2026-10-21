# A clone set up through pre-commit

Proves: [README, Set up a clone](../../README.md#set-up-a-clone).

## What it is

Someone who clones a project sets it up with pre-commit alone; first-commit is never installed
by hand.

## How to get to it

In a fresh clone: `pre-commit install`, then
`pre-commit run first-commit-setup --hook-stage manual`.

## Driving it

1. Clone the project and run `pre-commit install`. Gitleaks is not copied in, so setup
   downloads it.
2. Try a commit with another identity (`-c user.name=Other -c user.email=other@example.com`);
   it stops because the clone is not set up.
3. Run the setup command with no identity.
4. Run it again with `FIRST_COMMIT_AUTHOR_NAME`, `FIRST_COMMIT_AUTHOR_EMAIL`, and
   `FIRST_COMMIT_SIGNING_KEY`.
5. Commit.
6. With no `first-commit` command on `PATH` (the harness removes every folder that holds
   one), run `pre-commit run first-commit-doctor --hook-stage manual --all-files`, then
   the command that setup's `Next action: run` line printed.

## Proof

The blocked commit names the setup command. Without an identity, setup exits non-zero, and
its output names the identity file path and a command that sets `FIRST_COMMIT_AUTHOR_NAME=`.
With the variables it exits 0, prints `Machine identity: saved to <default file>`, and the
file exists with mode 600. That setup prints `Gitleaks: downloaded and installed`, and the
clone's `.local/bin/gitleaks` is an executable file. The next commit exits 0 and is signed.
Setup's printed next action is
`pre-commit run first-commit-check --hook-stage manual --all-files`. No `first-commit`
command is on `PATH` for step 6. The doctor hook and the printed next action both exit 0:
doctor prints `first-commit doctor...Passed` and `PASS doctor` or `WARN doctor`; the next
action prints `first-commit check...Passed`, `PASS working`, `PASS staged`, and
`PASS history`.
