# Contributing

How to set up a clone of first-commit, run its checks, and propose a change.
Read [ARCHITECTURE.md](ARCHITECTURE.md) before you change a rule, a public
interface, or the structure.

## Set up a clone

You need Python 3.11 to 3.14, Git, an SSH signing key, and network access to
GitHub, GitHub Releases, and PyPI.

```sh
git clone https://github.com/amrendra18/first-commit.git
cd first-commit
python3 -m venv .venv  # or python3.13 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/first-commit setup
```

The last command sets up this clone like any project: identity, signing,
Gitleaks at `.local/bin/gitleaks`, and this repository's Git hooks. It keeps
the repository's own files. The checks need it, because `scripts/check` ends
with `first-commit check` on this repository. CI does the same with a
temporary key and `first-commit setup --yes`.

A machine that cannot install Gitleaks can still run the unit tests.
`FIRST_COMMIT_TEST_ALLOW_NO_GITLEAKS=1` skips the tests that need the real
scanner, so those checks stay unproven:

```sh
FIRST_COMMIT_TEST_ALLOW_NO_GITLEAKS=1 .venv/bin/python -m unittest discover -s tests -q
```

## Run the checks

```sh
scripts/lint
scripts/lint types
scripts/check fast
scripts/check full
scripts/verify fast
```

1. `scripts/lint` takes seconds; the pre-commit hook runs it.
   `scripts/lint types` adds mypy and pylint.
2. `scripts/check` (default `full`) is the offline gate: lint, unit tests,
   coverage, a wheel build and install, and `first-commit check`. Run it
   before every commit.
3. `scripts/verify` (default `fast`) is the end-to-end harness. It drives the
   journeys in [verify/features](verify/features/README.md) in a temporary
   folder and prints its evidence folder, `.local/verify/<UTC time>/`. It
   needs network. Run `full` when setup, identity, clone, or hook code
   changed. A new journey needs a page there and an entry in
   `scripts/verify_lib/cli.py`; a test keeps the two in step.
4. `scripts/ci-local` replays the CI workflow in a fresh clone. Run it after
   changing `.github/workflows/ci.yml`.

This repository's pre-push hook runs the push checks, then
`scripts/check full`, then `scripts/verify fast`, on every push that adds
commits. Together they take about 7 minutes (301 s and 106 s on an
Apple-silicon Mac) and need network.

Both run through `scripts/check-pushed` on exactly the pushed commit, so an
uncommitted fix cannot pass a broken commit and an uncommitted edit cannot
block a good one. When the pushed commit is `HEAD` and the clone has no
changes, no untracked files, and no file marked assume-unchanged or
skip-worktree, they run in place. Otherwise each runs in a temporary
worktree of that commit, with the clone's virtual environment, `.local/bin`,
and verify cache. The verify evidence still lands in the clone's
`.local/verify/`. The worktree is removed afterwards, also after a
failure or Ctrl-C. pre-commit exports only the first pushed ref with new
commits, so the wrapper does not test other refs in the same push. It also
runs the pushed commit's own scripts, so that commit decides what is checked.

## Write code and tests

1. Names say what the code does. A comment is only for a fact the code cannot
   show: why it is written this way, a security condition, or an outside
   limit. No docstrings; `tests/test_no_docstrings.py` enforces it.
2. Use red-green-refactor and synthetic fixtures. Each file under
   `src/first_commit` needs at least 90% line and branch coverage
   (`scripts/check-coverage`).
3. Never weaken tests, thresholds, signing, or scanner controls.
4. `tests/__init__.py` points HOME, the identity file, and the global Git
   configuration at scratch files. The system Git configuration (for example
   `/etc/gitconfig`) still applies and can change a result.

## Commit messages

Follow the format in [ARCHITECTURE.md](ARCHITECTURE.md#commit-messages); the
template `.gitmessage` lists the types.

CI runs `first-commit check`, which fails on any email address in a pull
request's commit messages that `.repo-policy.json` does not list in
`public_emails` (documentation addresses such as `@example.com` pass). So do
not add a personal or GitHub noreply address in a `Signed-off-by:` or
`Co-authored-by:` line; `git commit -s` adds one. Your clone's commit-message
hook reports it first.

## Before you open a pull request

1. Stage only the files you changed, by name.
2. Inspect the staged bytes with `git diff --cached` and
   `git diff --cached --check`.
3. Confirm that no private values, keys, or machine paths are staged.
4. Run `scripts/check full` and `scripts/verify fast` after the last change.

Report a vulnerability as [SECURITY.md](SECURITY.md) describes, never in a
public issue.

## Release

For maintainers. The version is `__version__` in
`src/first_commit/__init__.py`, and the README installs the tag
`v<version>`; a test keeps the two equal. The repository name is
`GITHUB_REPOSITORY` in `src/first_commit/hooks.py`; tests compare every
document with it.

1. In one commit, set the new version in `src/first_commit/__init__.py`,
   `pyproject.toml`, and the README install and tag-check lines. From the
   second release on, keep a `CHANGELOG.md` with one entry per major release,
   and add it to the document list in `tests/test_metadata.py`.
2. Run `scripts/release`. It stops unless the tree is clean, HEAD is on a
   branch, and the tag is new or already names HEAD. It then runs
   `scripts/check full`, `scripts/check matrix`, and `scripts/verify full`,
   then `scripts/verify control`, and prints the tag, the commit SHA, and the
   tag and push commands. The matrix needs python3.11 to python3.14 on PATH,
   or a build of each in the folder `FIRST_COMMIT_PYTHONS` names. A missing
   version stops the release before the first check, and the message names
   it. It never tags or pushes; the maintainer runs those commands.
3. After the push, run `scripts/verify full --require-github`, and install the
   tag from the README's HTTPS address.
4. Publish a GitHub release for the tag whose notes name the printed commit
   SHA. The README's install check compares the tag against it.
