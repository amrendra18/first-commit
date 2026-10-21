# The pre-push hook

Proves: [ARCHITECTURE, How a commit is checked](../../ARCHITECTURE.md#how-a-commit-is-checked).

## What it is

Before a push, the hook checks the working tree, the index, and every local commit the
remote does not have yet, on every local branch. It skips the stash, which Git never pushes
unless it is named.

## How to get to it

A person runs `git push`.

## Driving it

The harness adds a remote `origin` that is a bare repository in the run's temporary folder,
so `git push` needs no network. Git runs the installed `.git/hooks/pre-push` itself, with
the remote name, the address, and one ref line per new branch on standard input.

1. Stage a new file `stashed-secret.txt` holding a token and stash it with `git stash push`.
   Then `git push origin main`, which the remote does not have yet. Cleanup (not checked):
   `git stash drop`.
2. `git push origin first second`: two new branches. `first` holds one clean commit;
   `second` holds one commit that adds `second-secret.txt` holding a token. The harness
   writes both commits with Git plumbing, past every commit hook. pre-commit passes the
   hook only the first branch's range, so the hook must find `second` itself. Cleanup
   (not checked): it deletes both branches and the remote afterwards.

## Proof

1. The stash exists and the file is gone from the working tree. The push exits 0, the hook
   prints the result line `first-commit pre-push hygiene...Passed`, and the bare remote holds
   `main`.
2. The push exits non-zero, its output contains both `secrets.gitleaks` and
   `second-secret.txt`, and the bare remote holds neither `first` nor `second`.
