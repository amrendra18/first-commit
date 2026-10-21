# A private value blocks a commit

Proves: [README, Project settings](../../README.md#project-settings).

## What it is

A value listed in `.local/first-commit/private-values.txt` cannot reach a commit, in a
file's content or in its name.

## How to get to it

A person adds a value to the list, then tries to commit a file that contains it, or a file
named with it.

## Driving it

1. Add a synthetic canary value to the list.
2. Commit a file that contains it.
3. Commit a file whose name contains it.

## Proof

The first commit exits non-zero, reports `privacy.private-literal` with the line
`  fix: Remove the private value`, and the output never contains the canary. The second
commit exits non-zero, reports `privacy.private-path` at the path
`<private value>-notes.txt`, and the output never contains the canary. Cleanup (not
checked): the harness unstages and deletes both files and restores the list.
