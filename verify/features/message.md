# A bad message blocks a commit

Proves: [ARCHITECTURE, Commit messages](../../ARCHITECTURE.md#commit-messages).

## What it is

The commit-message hook enforces the `<type>(<scope>)!: <subject>` header, and Gitleaks scans
the message for secrets.

1. Below a scissors line the hook only warns, because `git commit -v` removes that text.
2. A hand-written scissors line keeps the text below it, so the pre-push hook scans the
   recorded message and blocks a secret there.
3. Git's comment lines, such as `# On branch <name>`, also only warn, because Git removes
   them from a message it opens in an editor. Git keeps them in a `-m` or `-F` message that
   no editor opens, so there they block.
4. The pre-push hook never warns. Only `first-commit check` warns, about a commit a configured
   remote already has.

## How to get to it

A person commits with a message such as "did stuff", or pastes a token into a commit body.

## Driving it

1. Stage a change and commit it with the message `did stuff`.
2. Commit the same change with a valid message whose last line holds a Slack token.
3. Commit the same change with a valid message.
4. Stage another change and commit it with `-F` and a valid message, then the line
   `# ------------------------ >8 ------------------------`, then a line holding a Slack token.
   Run the installed `.git/hooks/pre-push` for that commit, as the push feature does. Cleanup
   (not checked): `git reset` back to the commit of step 3 and restore the file.
5. On a new branch whose name holds a home path (`verify/home/` and a name), stage a change
   and commit it with `-e`, `-F`, a valid message, and `GIT_EDITOR=true`, so Git adds its
   comment lines, one naming the branch, and keeps the message as it is. Cleanup (not
   checked): check out the first branch again and delete the new one.

## Proof

The first commit exits non-zero with `message.header` and a `fix:` line. The second exits
non-zero with `secrets.gitleaks` at `<commit-message>`, and the token is never printed. The
third exits 0. The fourth commit exits 0, because the commit-message hook only warns about a
secret below the scissors line: its output says the text below the line is committed unless Git
removes it. Its pre-push hook exits non-zero with `secrets.gitleaks` at `<commit-message>` and
the commit's first 12 hex digits. Neither prints the token. The fifth commit exits 0: its
output holds `privacy.user-home-path` and says a comment line is committed unless Git removes
it, and the recorded message does not hold the branch name.
