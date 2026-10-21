# Remove first-commit from a checkout

Proves: [README, Remove](../../README.md#remove).

## What it is

README "Remove" undoes setup in one checkout: the hook scripts, the local Git settings
setup writes, `.local/first-commit`, and `.local/bin/gitleaks`. Setup's empty lock file
`.git/first-commit-setup.lock` stays.

## How to get to it

A person runs the `sh` block under README "Remove" in the checkout.

## Driving it

1. Clone the project from the setup feature, run `pre-commit install`, and record
   `git config --local --list`. Gitleaks is copied in to save a download.
2. Run the setup hook with the identity variables and `FIRST_COMMIT_TRUST_SELF=1`, so setup
   writes every setting the Remove loop names. The identity file goes to a scratch path.
3. Commit a new file with the identity setup wrote. This shows the hook and the signature
   that the Remove proofs later find absent.
4. Run the README's block as printed with `/bin/sh -c`. `pre-commit` on its `PATH` is the
   harness Python's `-m pre_commit`.
5. Commit a new file with `-c user.name=Plain -c user.email=plain@example.com`.

## Proof

Clone setup exits 0. The commit after setup exits 0, prints the `first-commit staged
hygiene` line ending in `Passed`, and carries an SSH signature. The Remove block exits 0.
`git config --local --list` prints the same lines as before setup. No `pre-commit`,
`commit-msg`, or `pre-push` hook script is left. `.local/first-commit` and
`.local/bin/gitleaks` are gone. The empty lock file `.git/first-commit-setup.lock` is still
there. The plain commit exits 0, prints no `first-commit staged hygiene` line, and carries
no SSH signature.
