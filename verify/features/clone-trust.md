# The printed trust command works in a clone

Proves: [README, Set up a clone](../../README.md#set-up-a-clone).

## What it is

In a clone whose `.pre-commit-config.yaml` declares the setup hook, `doctor` warns that local
signature-verification trust is not set. Its fix line names
`FIRST_COMMIT_TRUST_SELF=1 pre-commit run first-commit-setup --hook-stage manual`, and that
command must make the warning go away.

## How to get to it

A person sets up a clone, runs `first-commit doctor`, and runs the command on the
`git.signature-verification-trust` fix line.

## Driving it

1. Clone the project from the setup feature, run `pre-commit install`, run the setup hook
   with the identity variables (the identity file goes to a scratch path), and commit.
2. Run `git verify-commit HEAD`, then doctor (`first_commit.cli` from the snapshot source).
3. Read the command from the trust fix line and run it as printed: its leading `NAME=value`
   words become environment variables, and `pre-commit` runs as the harness Python's
   `-m pre_commit`, so no other `first-commit` comes onto `PATH`.
4. Run doctor and `git verify-commit HEAD` again.

## Proof

Clone setup and the clone's first commit exit 0. Before trust, `git verify-commit HEAD`
exits non-zero, and doctor exits 0 and its output contains `git.signature-verification-trust`.
The fix line's command starts with `FIRST_COMMIT_TRUST_SELF=1 ` and contains
`first-commit-setup`. That command exits 0. Afterwards doctor exits 0 without the
warning, and `git verify-commit HEAD` exits 0.
