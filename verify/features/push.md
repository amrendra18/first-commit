# The pre-push hook

Proves: [ARCHITECTURE, How a commit is checked](../../ARCHITECTURE.md#how-a-commit-is-checked).

## What it is

Before a push, the hook checks readiness (`doctor`) and every local commit the remote does
not have yet, on the pushed ref, every local branch, and every remote-tracking branch, and
that each of those commits that no configured remote holds carries a signature, unless the commit is older than the clone's setup. Only the pushed remote's tracking refs leave commits out.
It skips the stash, which Git never pushes unless it is named. It leaves out the
working tree and the index, which a push does not send; the commit hooks and
`first-commit check` cover them.

## How to get to it

A person runs `git push`.

## Driving it

The harness adds a remote `origin` that is a bare repository in the run's temporary folder,
so `git push` needs no network. Git runs the installed `.git/hooks/pre-push` itself, with
the remote name, the address, and one ref line per new branch on standard input.

1. Stage a new file `stashed-secret.txt` holding a token and stash it with `git stash push`.
   Then `git push origin main`, which the remote does not have yet. Cleanup (not checked):
   `git stash drop`.
2. `git commit --allow-empty --no-gpg-sign` makes an unsigned commit on `main`, which the
   commit hooks pass. Then `git push origin main`. Cleanup (not checked): `main` goes back to
   the commit the remote holds.
3. `git commit --allow-empty --no-gpg-sign` with `GIT_COMMITTER_DATE` set before the setup
   makes an unsigned commit that stands for a project's older history. Then
   `git push origin main`.
4. `git push origin first second`: two new branches. `first` holds one clean commit;
   `second` holds one commit that adds `second-secret.txt` holding a token. The harness
   writes both commits with Git plumbing, past every commit hook. pre-commit passes the
   hook only the first branch's range, so the hook must find `second` itself. Cleanup
   (not checked): it deletes both branches and the remote afterwards.

## Proof

1. The stash exists and the file is gone from the working tree. The push exits 0, the hook
   prints the result line `first-commit pre-push hygiene...Passed`, and the bare remote holds
   `main`.
2. The push exits non-zero, its output contains `git.unsigned-commit` with the unsigned
   commit's short id, and the bare remote's `main` is still the commit step 1 pushed.
3. The push exits 0, and the bare remote's `main` is that older commit.
4. The push exits non-zero, its output contains both `secrets.gitleaks` and
   `second-secret.txt`, and the bare remote holds neither `first` nor `second`.
