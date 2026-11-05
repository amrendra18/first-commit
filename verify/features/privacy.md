# A private value blocks a commit

Proves: [README, Project settings](../../README.md#project-settings).

## What it is

A value listed in `.local/first-commit/private-values.txt` cannot reach a commit, in a
file's content or in its name. A value listed only in the user-level list
`~/.config/first-commit/private-values.txt` is blocked the same way, and a broad mode
on that list is set to 600 instead of stopping the check. In the repository that tracks
the user-level list, that list blocks nothing, so the list itself can be committed there;
its values still mask output.
A value committed past the commit hooks, and deleted in a later commit, still blocks
the push of those commits.

## How to get to it

A person adds a value to the project list or the user-level list, then tries to commit a
file that contains it, or a file named with it. Or the person commits it with
`git commit --no-verify`, deletes it in the next commit, and pushes.

## Driving it

1. Add a synthetic canary value to the list.
2. Commit a file that contains it.
3. Commit a file whose name contains it.
4. Add a local bare remote and push `main` to it with `git push --no-verify`. Commit a
   file that contains the canary with `git commit --no-verify`, delete the file in a
   second `--no-verify` commit, and push `main` again. Then set a local clean filter, as
   Git LFS installs one (`filter.lfs.clean = sed s/.*/pointer/` for `*.dat` in
   `.git/info/attributes`), and commit `data.dat` holding the canary.
5. Restore the project list. Put the canary only in the user-level list under the
   harness's scratch HOME, as a link to a mode 644 file in the run's work folder.
   Commit a file that contains it.
6. Put the canary in a new project file, `privacy/terms.txt`, and link the user-level
   list to it. Commit it together with `privacy/<canary>-notes.txt`, a file that holds
   trailing whitespace. Then unstage that file and commit `privacy/terms.txt` alone.

## Proof

The step 2 commit exits non-zero, reports `privacy.private-literal` with the line
`  fix: Remove the private value`, and the output never contains the canary. The step 3
commit exits non-zero, reports `privacy.private-path` at the path
`<private value>-notes.txt`, and the output never contains the canary. The second push
of step 4 exits non-zero, reports `privacy.private-literal` at `"notes.txt":1` with the
short id of the commit that added the file, and the output never contains the canary.
The filtered `data.dat` of step 4 has only `pointer` in the index, yet its commit exits
non-zero with `privacy.private-literal` at `data.dat`, and the output never contains the
canary.
The step 5 commit exits non-zero, reports `privacy.private-literal`, and the output
never contains the canary. The link's target is then mode 600, and the output holds
the line `Private values: set ~/.config/first-commit/private-values.txt to mode 600.`
exactly once. The first step 6 commit exits non-zero, reports
`text.trailing-whitespace` at `privacy/<private value>-notes.txt`, and reports no
`privacy.private-` finding. The second step 6 commit exits 0. Each of these two outputs holds the line
`Private values: ~/.config/first-commit/private-values.txt is kept in this repository,
so it does not apply here.` exactly once (pre-commit shows a failing hook's output and
the message hook's output, and hides a passing staged hook's output), and neither output
contains the canary. Cleanup (not checked): the harness moves `main` back to where
step 4 started, removes the remote, undoes the second step 6 commit, unstages and
deletes the files, restores the project list, and removes the user-level links and
their targets.
