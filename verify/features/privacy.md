# A private value blocks a commit

Proves: [README, Project settings](../../README.md#project-settings).

## What it is

A value listed in `.local/first-commit/private-values.txt` cannot reach a commit, in a
file's content or in its name. A value listed only in the user-level list
`~/.config/first-commit/private-values.txt` is blocked the same way, and a broad mode
on that list is set to 600 instead of stopping the check.

## How to get to it

A person adds a value to the project list or the user-level list, then tries to commit a
file that contains it, or a file named with it.

## Driving it

1. Add a synthetic canary value to the list.
2. Commit a file that contains it.
3. Commit a file whose name contains it.
4. Restore the project list. Put the canary only in the user-level list under the
   harness's scratch HOME, as a link to a mode 644 file in the run's work folder.
   Commit a file that contains it.

## Proof

The first commit exits non-zero, reports `privacy.private-literal` with the line
`  fix: Remove the private value`, and the output never contains the canary. The second
commit exits non-zero, reports `privacy.private-path` at the path
`<private value>-notes.txt`, and the output never contains the canary. The third
commit exits non-zero, reports `privacy.private-literal`, and the output never contains
the canary. The link's target is then mode 600, and the output holds the line
`Private values: set ~/.config/first-commit/private-values.txt to mode 600.` exactly
once. Cleanup (not checked): the harness unstages and deletes the files, restores the
project list, and removes the user-level link and its target.
